# ShellWarden — Feature Overview (beyond the MVP spec)

Everything below was built on top of the original `CLAUDE.md` MVP and is covered
by automated tests (`make test` for unit, `scripts/e2e_test.sh` for end-to-end —
**38 e2e checks, all green**).

## Core (MVP)
- Web SSH (xterm.js) + RDP (guacd) via a single gateway
- Agent (reverse tunnel, behind-NAT) and direct connection modes
- Session recording (asciinema v2) + real-time audit log
- Server/group management, bulk command execution (SSE), JWT auth

## Security
- **Credentials encrypted at rest** (AES-256-GCM, transparent, backward-compatible)
- **SSH host-key pinning** (TOFU) — MITM protection
- **SSH Certificate Authority** — credential-less access via short-lived,
  per-connection signed certificates. Targets trust `GET /ca/pubkey`
  (`TrustedUserCAKeys`); no static secrets on hosts. Per-server `use_ssh_ca`.
- **MFA (TOTP, RFC 6238)** — self-service enrollment, enforced at login
- **RBAC** — `admin` / `operator` / `auditor` (read-only) enforced on every
  mutation, WebSocket, and admin action
- **JIT access approval** — request → admin approve (time-boxed) → connect;
  enforced when `JIT_REQUIRED=true`
- **OIDC / SSO** — authorization-code flow against any IdP (config-gated)
- **Append-only, hash-chained audit log** — tamper-evident; `GET /api/audit/verify`
- **Brute-force detection** — alerts on failed-login bursts
- **Session policy** — idle / max-duration auto-disconnect

## Reliability
- **Heartbeat fix** — agents no longer false-timeout every 90s
- **Auto-reconnect** terminals (backoff; honors admin-terminate/timeout codes)
- **Server-side session resume** — the shell survives browser disconnects;
  reconnect reattaches to the *same* session with screen repaint (3-min grace)

## Observability
- **Live Operations Dashboard** (landing view) — active sessions, 24h activity, live event feed, stat cards
- **Per-host resource dashboard** — CPU / memory / disk / network / load time-series charts (agent reports every 30s, stored as a time series)
- **Vulnerability scanning** — agent runs distro-native CVE tooling on a schedule:
  Debian/Ubuntu `debsecan` (+ apt), RHEL `dnf updateinfo` (native CVE+severity),
  Arch `arch-audit`. Findings surfaced per host with severity + a sidebar badge;
  high/critical raises an alert. (Demo target ships with `debsecan` → ~200 real CVEs.)
- **Searchable session replay** — reconstructed command timeline; click a command to seek the player; global search across sessions

## Operations & compliance
- **Live session shadowing** (`/ws/watch/{id}`, read-only) + **admin terminate**
- **SFTP file browser** (list / upload / download)
- **Port-forward** over the tunnel (`/ws/forward/{id}`)
- **Host command logging** — kernel proc-connector (real-time) or `/proc` poll
  fallback; captures commands from ANY source incl. direct SSH
- **Agent telemetry** — load / mem / disk / uptime / OS in the UI
- **SIEM / webhook streaming** — every audit event + security alerts
- **Compliance reports** — access review (per-user posture) + session CSV export
- **Multi-terminal UI** — tabs, split view, broadcast input, keyboard shortcuts

## Config (see `.env.example`)
Key new env vars: `SECRET_KEY`, `JIT_REQUIRED`, `SESSION_IDLE_MIN`/`MAX_MIN`,
`SSH_CA_KEY`/`SSH_CERT_TTL_MIN`, `WEBHOOK_URL`, `SIEM_WEBHOOK_URL`, `OIDC_*`.

## Testing
```bash
make test                       # unit tests
docker compose -f docker-compose.test.yml up --build -d
make test-e2e                   # full end-to-end suite (38 checks)
```

## Deferred (noted, not built)
- Redis-backed HA / horizontal scale; multi-tenancy + billing (SaaS — out of scope here)
- Vault/KMS secret backend (encryption-at-rest is implemented; external vault is the next step)
- Database session proxy (Postgres/MySQL), Kubernetes `exec` proxy
- eBPF execsnoop (the netlink proc-connector already provides kernel real-time capture)
