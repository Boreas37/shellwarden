# ShellWarden

A self-hosted Privileged Access Management (PAM) platform. Access managed servers through a single web UI — no per-server accounts, no VPN. Every keystroke and screen frame is recorded.

## Capabilities

### Session Gateway
- **Web SSH** — xterm.js terminal in the browser, proxied through the gateway
- **Web RDP** — Full remote desktop via Apache Guacamole (guacd)
- **Direct + Agent modes** — Connect directly to reachable hosts, or run the agent for behind-NAT/air-gapped servers (reverse tunnel)
- **Multi-terminal UI** — Tabs, split view, keyboard shortcuts, broadcast input to multiple sessions

### Security
- **Credentials encrypted at rest** — AES-256-GCM on all stored secrets, backward-compatible
- **SSH host-key pinning** — Trust-On-First-Use (TOFU) enforcement on every outbound connection
- **SSH Certificate Authority** — Short-lived, per-connection signed certificates. Zero static secrets on target hosts
- **MFA (TOTP)** — RFC 6238 self-service enrollment, enforced at login
- **RBAC** — admin / operator / auditor roles enforced on every mutation, WebSocket, and admin action
- **JIT access approval** — Time-boxed grants; admin approval required before connecting
- **OIDC / SSO** — Authorization-code flow against any identity provider
- **Append-only, hash-chained audit log** — Tamper-evident with verification endpoint
- **Brute-force detection** — Alerts on failed-login bursts
- **Session policy** — Configurable idle and max-duration auto-disconnect

### Session Recording & Replay
- **asciinema v2 recording** — Every terminal session recorded server-side
- **Live shadowing** — Read-only session watch by admins
- **Session resume** — Survives browser disconnects; reattach to the same shell with screen repaint
- **Searchable command timeline** — Reconstructed per-command timeline; click to seek the player

### Operations
- **Live Operations Dashboard** — Active sessions, 24h activity, event feed, stat cards
- **Per-host resource metrics** — CPU / memory / disk / network / load time-series (agent reports every 30s)
- **Vulnerability scanning** — Distro-native CVE detection on managed hosts
- **SFTP file browser** — List, upload, download files through the gateway
- **Port forwarding** — Tunnel arbitrary TCP connections
- **Bulk command execution** — Run commands across host groups with SSE streaming
- **Host command logging** — Kernel proc-connector (real-time) or /proc poll fallback
- **SIEM / webhook streaming** — Every audit event + security alert to external systems
- **Compliance reports** — Access review per-user posture + session CSV export

## Architecture

```
Browser ──► Gateway (Go) ──► guacd (RDP)
                │
                ├──► Agent (reverse tunnel, behind NAT)
                │
                └──► PostgreSQL
```

## Quick Start

### Prerequisites

- Go 1.22+
- Node.js 20+
- Docker & Docker Compose (for PostgreSQL + guacd)

### 1. Build

```bash
# Gateway + agent
make build

# Frontend SPA
cd web && npm install && npm run build
```

### 2. Configure

```bash
cp .env.example .env
```

Set `JWT_SECRET` and `SECRET_KEY` to cryptographically random values. All other variables have working defaults for local development.

### 3. Start

```bash
docker compose up -d    # postgres + guacd
make run                # gateway (port 8080)
```

Open `http://localhost:8080`. Default credentials: `admin` / `changeme` (change immediately).

### 4. Register a server

```bash
curl -sSL https://your-gateway:8080/install.sh | bash -s -- --gateway https://your-gateway:8080 --token <token>
```

## Testing

```bash
make test                       # unit tests
make test-e2e                   # full end-to-end suite (requires docker compose)
```

## Configuration

See `.env.example` for all variables. Key settings:

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SECRET` | JWT signing key (min 32 chars) |
| `SECRET_KEY` | AES-256-GCM encryption key for stored credentials |
| `GUACD_HOST` / `GUACD_PORT` | Guacamole daemon for RDP |
| `JIT_REQUIRED` | Require admin approval before session start |
| `SESSION_IDLE_MIN` / `SESSION_MAX_MIN` | Auto-disconnect policy |
| `SSH_CA_KEY` / `SSH_CERT_TTL_MIN` | SSH certificate authority |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Gateway | Go 1.22 (gorilla/mux, gorilla/websocket) |
| Agent | Go 1.22 |
| Frontend | React 18 + TypeScript + Vite + xterm.js |
| Database | PostgreSQL 16 |
| RDP | Apache Guacamole (guacd) |
| Auth | golang-jwt/jwt, bcrypt, TOTP (RFC 6238) |
| Encryption | AES-256-GCM (crypto/aes + crypto/cipher) |
