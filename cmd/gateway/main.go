package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/shellwarden/shellwarden/internal/agent"
	"github.com/shellwarden/shellwarden/internal/api"
	"github.com/shellwarden/shellwarden/internal/auditlog"
	"github.com/shellwarden/shellwarden/internal/auth"
	"github.com/shellwarden/shellwarden/internal/bulk"
	"github.com/shellwarden/shellwarden/internal/config"
	"github.com/shellwarden/shellwarden/internal/crypto"
	"github.com/shellwarden/shellwarden/internal/db"
	"github.com/shellwarden/shellwarden/internal/notify"
	"github.com/shellwarden/shellwarden/internal/proxy"
	"github.com/shellwarden/shellwarden/internal/sshca"
)

func main() {
	cfg := config.Load()

	database, err := db.Open(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	if err := database.Migrate(); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Println("migrations applied")
	seedAdminIfEmpty(database.DB)

	registry := agent.NewRegistry()
	jwtMgr := auth.NewManager(cfg.JWTSecret)
	cipher := crypto.New(cfg.SecretKey)
	hub := proxy.NewHub()
	notifier := notify.New(cfg.WebhookURL)
	siem := notify.New(cfg.SIEMWebhookURL)

	// SSH certificate authority: use the configured key, else auto-generate and
	// persist one so credential-less (cert) auth works out of the box.
	var ca *sshca.CA
	caPEM := cfg.SSHCAKey
	if caPEM == "" {
		caPEM = loadOrCreateCAKey(database.DB)
	}
	if caPEM != "" {
		if ca, err = sshca.Load(caPEM); err != nil {
			log.Printf("ssh CA load failed (cert auth disabled): %v", err)
			ca = nil
		} else {
			log.Println("SSH certificate authority ready")
		}
	}

	// Stream meaningful audit events to the SIEM sink (skip high-volume output).
	auditlog.Sink = func(eventType, data, session, server, user string) {
		if eventType == "output" {
			return
		}
		if len(data) > 1000 {
			data = data[:1000]
		}
		siem.Send(notify.Event{
			Type:    "audit." + eventType,
			Session: session,
			Server:  server,
			User:    user,
			Message: data,
		})
	}

	a := &api.API{
		DB:       database.DB,
		Cfg:      cfg,
		JWT:      jwtMgr,
		Registry: registry,
		Cipher:   cipher,
		Notifier: notifier,
		CAPubKey: func() string {
			if ca != nil {
				return ca.PublicKey()
			}
			return ""
		}(),
		Executor: bulk.NewExecutor(database.DB, registry, cipher, cfg.BulkTimeout),
		SSHProxy: func() *proxy.SSHProxy {
			sp := proxy.NewSSHProxy(database.DB, registry, cfg.RecordingPath, cipher, hub, cfg.SessionIdleMin, cfg.SessionMaxMin)
			sp.JITRequired = cfg.JITRequired
			sp.Notifier = notifier
			sp.CA = ca
			sp.CertTTL = time.Duration(cfg.SSHCertTTLMin) * time.Minute
			return sp
		}(),
		RDPProxy: proxy.NewRDPProxy(database.DB, cfg.GuacdHost, cfg.GuacdPort),
		Tunnel:   agent.NewTunnelHandler(database.DB, registry),
	}

	handler := withCORS(a.Router())

	srv := &http.Server{
		Addr:              ":" + cfg.GatewayPort,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("ShellWarden gateway listening on :%s", cfg.GatewayPort)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
		os.Exit(1)
	}
}

// loadOrCreateCAKey returns the persisted SSH CA key from the settings table,
// generating and storing a new one on first run.
func loadOrCreateCAKey(database *sql.DB) string {
	var pem string
	err := database.QueryRow(`SELECT value FROM settings WHERE key = 'ssh_ca_key'`).Scan(&pem)
	if err == nil && pem != "" {
		return pem
	}
	pem, gerr := sshca.Generate()
	if gerr != nil {
		log.Printf("ssh CA generate failed: %v", gerr)
		return ""
	}
	if _, err := database.Exec(
		`INSERT INTO settings (key, value) VALUES ('ssh_ca_key', $1)
		 ON CONFLICT (key) DO NOTHING`, pem,
	); err != nil {
		log.Printf("ssh CA persist failed: %v", err)
	}
	log.Println("generated a new SSH certificate authority")
	return pem
}

// seedAdminIfEmpty creates a default admin (admin/changeme) on a fresh database
// so the stack is usable out of the box. Logs a loud warning to change it.
func seedAdminIfEmpty(db *sql.DB) {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil || n > 0 {
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("changeme"), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	if _, err := db.Exec(
		`INSERT INTO users (username, password_hash, role) VALUES ('admin', $1, 'admin')`,
		string(hash),
	); err != nil {
		log.Printf("seed admin failed: %v", err)
		return
	}
	log.Println("seeded default admin user 'admin' / 'changeme' — CHANGE THIS")
}

// withCORS adds permissive CORS headers for the SPA dev server.
// TODO: restrict allowed origins in production.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
