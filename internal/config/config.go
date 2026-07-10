package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds all gateway runtime configuration sourced from environment
// variables (see CLAUDE.md "Environment Variables").
type Config struct {
	DatabaseURL    string
	JWTSecret      string
	GuacdHost      string
	GuacdPort      string
	RecordingPath  string
	BulkTimeout    int // seconds
	GatewayPort    string
	StaticPath     string // built SPA directory served at /
	AgentsPath     string // directory of cross-compiled agent binaries for /downloads
	SecretKey      string // key for encrypting stored credentials at rest
	SessionIdleMin int    // disconnect after N minutes of no I/O (0 = disabled)
	SessionMaxMin  int    // hard cap on session length in minutes (0 = disabled)
	JITRequired    bool   // require approved JIT access grant to open a session

	// OIDC / SSO (optional). Enabled when OIDCIssuer + OIDCClientID are set.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string

	// Notifications / SIEM streaming (optional).
	WebhookURL     string // general security/ops events (Slack-compatible JSON sink)
	SIEMWebhookURL string // every meaningful audit event streamed here

	// SSH certificate authority (optional). When SSHCAKey is set, the gateway
	// signs short-lived user certificates instead of relying on stored secrets.
	SSHCAKey      string // PEM private key for the SSH CA (or path via SSH_CA_KEY_FILE)
	SSHCertTTLMin int    // certificate validity in minutes
}

// Load reads configuration from the environment, applying a .env file first if
// present, then sensible defaults for everything except secrets.
func Load() *Config {
	// Best-effort: load .env if it exists; ignore error when absent.
	_ = godotenv.Load()

	return &Config{
		DatabaseURL:   getenv("DATABASE_URL", "postgres://shellwarden:shellwarden@localhost:5432/shellwarden?sslmode=disable"),
		JWTSecret:     getenv("JWT_SECRET", "dev-insecure-secret-change-me-please-change-me-32bytes-min"),
		GuacdHost:     getenv("GUACD_HOST", "localhost"),
		GuacdPort:     getenv("GUACD_PORT", "4822"),
		RecordingPath: getenv("RECORDING_PATH", "./recordings"),
		BulkTimeout:   getenvInt("BULK_TIMEOUT_SEC", 30),
		GatewayPort:   getenv("GATEWAY_PORT", "8080"),
		StaticPath:    getenv("STATIC_PATH", "./static"),
		AgentsPath:    getenv("AGENTS_PATH", "./agents"),
		// Default the encryption key to the JWT secret so secrets are encrypted
		// out of the box; set SECRET_KEY explicitly to rotate independently.
		SecretKey:      getenv("SECRET_KEY", getenv("JWT_SECRET", "dev-insecure-secret-change-me-please-change-me-32bytes-min")),
		SessionIdleMin: getenvInt("SESSION_IDLE_MIN", 0),
		SessionMaxMin:  getenvInt("SESSION_MAX_MIN", 0),
		JITRequired:    getenv("JIT_REQUIRED", "false") == "true",

		OIDCIssuer:       getenv("OIDC_ISSUER", ""),
		OIDCClientID:     getenv("OIDC_CLIENT_ID", ""),
		OIDCClientSecret: getenv("OIDC_CLIENT_SECRET", ""),
		OIDCRedirectURL:  getenv("OIDC_REDIRECT_URL", ""),

		WebhookURL:     getenv("WEBHOOK_URL", ""),
		SIEMWebhookURL: getenv("SIEM_WEBHOOK_URL", ""),

		SSHCAKey:      loadSSHCAKey(),
		SSHCertTTLMin: getenvInt("SSH_CERT_TTL_MIN", 5),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// loadSSHCAKey returns the SSH CA private key from SSH_CA_KEY or, if a path is
// given via SSH_CA_KEY_FILE, the file contents.
func loadSSHCAKey() string {
	if k := os.Getenv("SSH_CA_KEY"); k != "" {
		return k
	}
	if p := os.Getenv("SSH_CA_KEY_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return string(b)
		}
	}
	return ""
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
