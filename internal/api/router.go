package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/shellwarden/shellwarden/internal/agent"
	"github.com/shellwarden/shellwarden/internal/auth"
	"github.com/shellwarden/shellwarden/internal/bulk"
	"github.com/shellwarden/shellwarden/internal/config"
	"github.com/shellwarden/shellwarden/internal/crypto"
	"github.com/shellwarden/shellwarden/internal/notify"
	"github.com/shellwarden/shellwarden/internal/proxy"
)

// Roles.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleAuditor  = "auditor"
)

// guard wraps a handler so only the listed roles may invoke it.
func (a *API) guard(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			c, ok := auth.ClaimsFrom(r.Context())
			if !ok || !roleAllowed(c.Role, roles) {
				writeErr(w, http.StatusForbidden, "forbidden: requires role "+strings.Join(roles, "/"))
				return
			}
			h(w, r)
		}
	}
}

// roleMW is the same check as a gorilla/mux middleware (for WS subrouters).
func (a *API) roleMW(roles ...string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := auth.ClaimsFrom(r.Context())
			if !ok || !roleAllowed(c.Role, roles) {
				writeErr(w, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// emit is a nil-safe notification helper.
func (a *API) emit(e notify.Event) {
	if a.Notifier != nil {
		a.Notifier.Send(e)
	}
}

func roleAllowed(role string, allowed []string) bool {
	for _, a := range allowed {
		if a == role {
			return true
		}
	}
	return false
}

// API bundles all dependencies shared by the HTTP handlers.
type API struct {
	DB       *sql.DB
	Cfg      *config.Config
	JWT      *auth.Manager
	Registry *agent.Registry
	Executor *bulk.Executor
	Cipher   *crypto.Cipher
	Notifier *notify.Notifier
	CAPubKey string // SSH CA public key (authorized_keys format), if enabled
	oidc     *OIDC
	brute    *bruteForce

	SSHProxy *proxy.SSHProxy
	RDPProxy *proxy.RDPProxy
	Tunnel   *agent.TunnelHandler
}

// Router builds the full gateway HTTP routing tree.
func (a *API) Router() http.Handler {
	r := mux.NewRouter()

	// Public.
	a.initOIDC()
	a.brute = newBruteForce()
	r.HandleFunc("/api/auth/login", a.Login).Methods(http.MethodPost)
	r.HandleFunc("/api/auth/methods", a.AuthMethods).Methods(http.MethodGet)
	r.HandleFunc("/api/auth/oidc/login", a.OIDCLogin).Methods(http.MethodGet)
	r.HandleFunc("/api/auth/oidc/callback", a.OIDCCallback).Methods(http.MethodGet)

	// Authenticated REST API.
	api := r.PathPrefix("/api").Subrouter()
	api.Use(a.JWT.Middleware)

	api.HandleFunc("/auth/logout", a.Logout).Methods(http.MethodPost)

	// MFA enrollment (self-service).
	api.HandleFunc("/auth/mfa/setup", a.MFASetup).Methods(http.MethodPost)
	api.HandleFunc("/auth/mfa/enable", a.MFAEnable).Methods(http.MethodPost)
	api.HandleFunc("/auth/mfa/disable", a.MFADisable).Methods(http.MethodPost)

	// Read access: all roles (incl. auditor). Mutations: admin/operator only.
	rw := a.guard(RoleAdmin, RoleOperator)
	adminOnly := a.guard(RoleAdmin)

	api.HandleFunc("/dashboard", a.Dashboard).Methods(http.MethodGet)

	api.HandleFunc("/servers", a.ListServers).Methods(http.MethodGet)
	api.HandleFunc("/servers", rw(a.CreateServer)).Methods(http.MethodPost)
	api.HandleFunc("/servers/{id}", a.GetServer).Methods(http.MethodGet)
	api.HandleFunc("/servers/{id}", rw(a.UpdateServer)).Methods(http.MethodPut)
	api.HandleFunc("/servers/{id}", rw(a.DeleteServer)).Methods(http.MethodDelete)
	api.HandleFunc("/servers/{id}/token", rw(a.RotateToken)).Methods(http.MethodPost)
	api.HandleFunc("/servers/{id}/metrics", a.ServerMetrics).Methods(http.MethodGet)
	api.HandleFunc("/servers/{id}/vulns", a.ServerVulns).Methods(http.MethodGet)

	// SFTP file browser (operator/admin).
	api.HandleFunc("/servers/{id}/sftp", rw(a.SFTPList)).Methods(http.MethodGet)
	api.HandleFunc("/servers/{id}/sftp/download", rw(a.SFTPDownload)).Methods(http.MethodGet)
	api.HandleFunc("/servers/{id}/sftp/upload", rw(a.SFTPUpload)).Methods(http.MethodPost)

	// JIT access requests.
	api.HandleFunc("/access/request", a.RequestAccess).Methods(http.MethodPost)
	api.HandleFunc("/access/requests", a.ListAccessRequests).Methods(http.MethodGet)
	api.HandleFunc("/access/requests/{id}/approve", adminOnly(a.ApproveAccess)).Methods(http.MethodPost)
	api.HandleFunc("/access/requests/{id}/deny", adminOnly(a.DenyAccess)).Methods(http.MethodPost)

	api.HandleFunc("/groups", a.ListGroups).Methods(http.MethodGet)
	api.HandleFunc("/groups", rw(a.CreateGroup)).Methods(http.MethodPost)
	api.HandleFunc("/groups/{id}", rw(a.UpdateGroup)).Methods(http.MethodPut)
	api.HandleFunc("/groups/{id}", rw(a.DeleteGroup)).Methods(http.MethodDelete)
	api.HandleFunc("/groups/{id}/members", rw(a.AddMember)).Methods(http.MethodPost)
	api.HandleFunc("/groups/{id}/members/{server_id}", rw(a.RemoveMember)).Methods(http.MethodDelete)

	api.HandleFunc("/sessions", a.ListSessions).Methods(http.MethodGet)
	api.HandleFunc("/sessions/{id}", a.GetSession).Methods(http.MethodGet)
	api.HandleFunc("/sessions/{id}/cast", a.GetSessionCast).Methods(http.MethodGet)
	api.HandleFunc("/sessions/{id}/commands", a.SessionCommands).Methods(http.MethodGet)
	api.HandleFunc("/commands/search", a.CommandSearch).Methods(http.MethodGet)
	api.HandleFunc("/sessions/{id}/terminate", adminOnly(a.TerminateSession)).Methods(http.MethodPost)

	api.HandleFunc("/audit", a.QueryAudit).Methods(http.MethodGet)
	api.HandleFunc("/audit/export", a.ExportAudit).Methods(http.MethodGet)
	api.HandleFunc("/audit/verify", a.VerifyAudit).Methods(http.MethodGet)

	api.HandleFunc("/bulk", rw(a.CreateBulk)).Methods(http.MethodPost)
	api.HandleFunc("/bulk/{job_id}", a.GetBulk).Methods(http.MethodGet)
	api.HandleFunc("/bulk/{job_id}/stream", a.StreamBulk).Methods(http.MethodGet)

	api.HandleFunc("/users", adminOnly(a.ListUsers)).Methods(http.MethodGet)
	api.HandleFunc("/users", adminOnly(a.CreateUser)).Methods(http.MethodPost)

	// Compliance reports (admin only).
	api.HandleFunc("/reports/access-review", adminOnly(a.AccessReview)).Methods(http.MethodGet)
	api.HandleFunc("/reports/sessions.csv", adminOnly(a.SessionReportCSV)).Methods(http.MethodGet)

	// WebSocket endpoints (auth via ?token= handled by middleware).
	// Interactive sessions require operator/admin; shadowing is read-only (all).
	ws := r.PathPrefix("/ws").Subrouter()
	ws.Use(a.JWT.Middleware)
	ws.Handle("/ssh/{server_id}", a.roleMW(RoleAdmin, RoleOperator)(a.SSHProxy)).Methods(http.MethodGet)
	ws.Handle("/rdp/{server_id}", a.roleMW(RoleAdmin, RoleOperator)(a.RDPProxy)).Methods(http.MethodGet)
	ws.Handle("/watch/{session_id}", http.HandlerFunc(a.SSHProxy.ServeWatch)).Methods(http.MethodGet)
	ws.Handle("/forward/{server_id}", a.roleMW(RoleAdmin, RoleOperator)(http.HandlerFunc(a.SSHProxy.ServeForward))).Methods(http.MethodGet)

	// Agent reverse tunnel (authenticated by agent_token inside the handler).
	r.Handle("/agent/connect", a.Tunnel)

	// Health check.
	r.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}).Methods(http.MethodGet)

	// SSH CA public key (public — it's a public key; targets/install.sh fetch it
	// to populate TrustedUserCAKeys).
	r.HandleFunc("/ca/pubkey", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(a.CAPubKey))
	}).Methods(http.MethodGet)

	// Agent installer + binary downloads (consumed by scripts/install.sh).
	r.HandleFunc("/install.sh", a.serveInstall).Methods(http.MethodGet)
	r.HandleFunc("/downloads/agent/{os}/{arch}", a.serveAgentBinary).Methods(http.MethodGet)

	// SPA static files with client-side routing fallback to index.html.
	r.PathPrefix("/").Handler(a.spaHandler()).Methods(http.MethodGet)

	return r
}

// --- shared response helpers ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, dst interface{}) error {
	return json.NewDecoder(r.Body).Decode(dst)
}
