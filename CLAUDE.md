# ShellWarden — Architecture & Implementation Guide

This file is the single source of truth for the ShellWarden MVP. Read it fully before writing any code.

---

## What Is ShellWarden

ShellWarden lets security engineers access any managed server through a single web UI without needing separate accounts on each server. Every keystroke and output is recorded to a database. Servers are registered by running a one-liner install script that sets up a lightweight agent.

Two session types for MVP:
- **SSH** — handled natively in Go using `golang.org/x/crypto/ssh`
- **RDP** — proxied through `guacd` (Apache Guacamole daemon, Apache 2.0 license)

---

## Repository Layout

```
shellwarden/
├── cmd/
│   ├── gateway/
│   │   └── main.go
│   └── agent/
│       └── main.go
├── internal/
│   ├── config/
│   │   └── config.go
│   ├── db/
│   │   ├── db.go
│   │   └── migrations/
│   │       ├── 001_initial.sql
│   │       └── 002_sessions.sql
│   ├── models/
│   │   ├── server.go
│   │   ├── session.go
│   │   ├── audit.go
│   │   ├── group.go
│   │   └── user.go
│   ├── auth/
│   │   ├── jwt.go
│   │   └── middleware.go
│   ├── api/
│   │   ├── router.go
│   │   ├── servers.go
│   │   ├── groups.go
│   │   ├── sessions.go
│   │   ├── audit.go
│   │   ├── bulk.go
│   │   └── users.go
│   ├── proxy/
│   │   ├── ssh.go
│   │   ├── rdp.go
│   │   └── recorder.go
│   ├── agent/
│   │   ├── tunnel.go
│   │   └── registry.go
│   └── bulk/
│       └── executor.go
├── web/
│   ├── package.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── api/
│   │   │   └── client.ts
│   │   ├── components/
│   │   │   ├── Terminal/
│   │   │   │   ├── SshTerminal.tsx
│   │   │   │   └── RdpCanvas.tsx
│   │   │   ├── ServerList.tsx
│   │   │   ├── GroupManager.tsx
│   │   │   ├── BulkExec.tsx
│   │   │   └── AuditLog.tsx
│   │   └── pages/
│   │       ├── Login.tsx
│   │       ├── Dashboard.tsx
│   │       ├── Servers.tsx
│   │       ├── Session.tsx
│   │       └── Audit.tsx
├── scripts/
│   └── install.sh
├── docker-compose.yml
├── Dockerfile.gateway
├── Dockerfile.agent
├── go.mod
└── Makefile
```

---

## Architecture

### Connection Modes (Hybrid)

Every server record has a `connection_mode` field:

- **`agent`** — the agent on the target server opens a persistent reverse WebSocket tunnel to the gateway. The gateway routes terminal traffic through this tunnel. Works behind NAT/firewalls.
- **`direct`** — the gateway connects outbound via standard SSH/RDP. No agent required. Server must be network-reachable from the gateway.

When a user opens a session, the gateway checks `connection_mode` and picks the right path transparently. The web UI does not know which mode is active.

### SSH Flow

```
Browser (xterm.js)
  │  WebSocket  /ws/ssh/{server_id}
  ▼
Gateway SSH handler (internal/proxy/ssh.go)
  │
  ├─[agent mode]──► Agent tunnel registry (internal/agent/registry.go)
  │                   │  multiplexed over agent's reverse WebSocket
  │                   ▼
  │               Target server sshd :22
  │
  └─[direct mode]─► Target server sshd :22
                     (golang.org/x/crypto/ssh client)
```

The recorder (`internal/proxy/recorder.go`) wraps the SSH channel io.ReadWriter for both modes. It writes every chunk to `audit_logs` in real time and buffers the asciinema v2 cast file, which is written to disk at session end.

### RDP Flow

```
Browser (canvas, Guacamole JS client)
  │  WebSocket  /ws/rdp/{server_id}
  ▼
Gateway RDP handler (internal/proxy/rdp.go)
  │  Guacamole tunnel protocol (github.com/wwt/guac)
  ▼
guacd daemon (localhost:4822)
  │  FreeRDP
  ▼
Target server RDP :3389
```

guacd is a sidecar Docker container. The gateway is a WebSocket↔Guacamole-tunnel bridge using the `wwt/guac` library. RDP sessions are recorded at the guacd instruction stream level, not at pixel level.

### Agent Architecture

The agent binary runs as a systemd service on target servers. On startup it:

1. Reads `/etc/shellwarden/agent.conf` (gateway URL + auth token + server UUID written by install.sh)
2. Opens a persistent WebSocket to `wss://gateway/agent/connect` with the token in the `Authorization` header
3. Registers itself in the gateway's in-memory registry (`internal/agent/registry.go`) keyed by `server_id`
4. Listens for incoming SSH session requests from the gateway over this WebSocket
5. For each request, dials local sshd at `127.0.0.1:22` and bridges the connection back through the WebSocket

The agent sends a heartbeat ping every 30 seconds. If the gateway receives no ping for 90 seconds it marks the server as `offline` in the database.

### Bulk Executor

`internal/bulk/executor.go`:

1. Resolves all servers in the requested group(s) from the database
2. Spawns one goroutine per server, concurrency capped at 50 with a semaphore channel
3. Each goroutine dials the server (agent tunnel or direct SSH), runs the command, collects stdout/stderr, writes the result to `bulk_results`
4. Per-host timeout: 30 seconds (configurable via `BULK_TIMEOUT_SEC` env var)
5. A server being offline or unreachable is NOT a fatal error — result row gets `status = unreachable`, executor continues
6. Results stream to the client over SSE at `/api/bulk/{job_id}/stream` as each host completes

### Session Recording — Asciinema v2

Asciinema v2 is newline-delimited JSON:

```
{"version":2,"width":220,"height":50,"timestamp":1700000000,"title":"session-uuid"}
[0.123, "o", "$ "]
[1.456, "o", "ls -la\r\n"]
[1.789, "o", "total 48\r\n..."]
```

The recorder accumulates lines in memory and flushes the complete `.cast` file to disk at session end. Path: `{RECORDING_PATH}/{session_id}.cast`. The session row holds the file path. Every output chunk is also written to `audit_logs` in real time so operators can query commands from ongoing sessions.

---

## Database Schema

Run migrations in order at gateway startup.

### 001_initial.sql

```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operator',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE servers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    host TEXT NOT NULL,
    port INT NOT NULL DEFAULT 22,
    protocol TEXT NOT NULL DEFAULT 'ssh',
    connection_mode TEXT NOT NULL DEFAULT 'direct',
    agent_token TEXT UNIQUE,
    agent_connected_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'unknown',
    os_info TEXT,
    ssh_user TEXT,
    ssh_key TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE server_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE group_members (
    group_id UUID REFERENCES server_groups(id) ON DELETE CASCADE,
    server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, server_id)
);
```

### 002_sessions.sql

```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID REFERENCES servers(id),
    user_id UUID REFERENCES users(id),
    protocol TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    recording_path TEXT,
    bytes_read BIGINT NOT NULL DEFAULT 0,
    bytes_written BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID REFERENCES sessions(id),
    server_id UUID REFERENCES servers(id),
    user_id UUID REFERENCES users(id),
    event_type TEXT NOT NULL,
    data TEXT,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_session ON audit_logs(session_id);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_ts ON audit_logs(ts DESC);

CREATE TABLE bulk_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    group_id UUID REFERENCES server_groups(id),
    command TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE bulk_results (
    id BIGSERIAL PRIMARY KEY,
    job_id UUID REFERENCES bulk_jobs(id),
    server_id UUID REFERENCES servers(id),
    status TEXT NOT NULL,
    stdout TEXT,
    stderr TEXT,
    exit_code INT,
    duration_ms INT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## Environment Variables

### Gateway

```
DATABASE_URL        postgres://user:pass@localhost:5432/shellwarden
JWT_SECRET          random 64-char string
GUACD_HOST          localhost
GUACD_PORT          4822
RECORDING_PATH      ./recordings
BULK_TIMEOUT_SEC    30
GATEWAY_PORT        8080
```

### Agent

```
GATEWAY_URL         wss://gateway.internal:8080
AGENT_TOKEN         <token written by install.sh>
SERVER_ID           <uuid written by install.sh>
```

---

## API Endpoints

All endpoints except `/api/auth/login` require `Authorization: Bearer <jwt>`.

```
POST   /api/auth/login
POST   /api/auth/logout

GET    /api/servers
POST   /api/servers
GET    /api/servers/{id}
PUT    /api/servers/{id}
DELETE /api/servers/{id}
POST   /api/servers/{id}/token

GET    /api/groups
POST   /api/groups
PUT    /api/groups/{id}
DELETE /api/groups/{id}
POST   /api/groups/{id}/members
DELETE /api/groups/{id}/members/{server_id}

GET    /api/sessions
GET    /api/sessions/{id}

GET    /api/audit?session_id=&user_id=&from=&to=&q=

POST   /api/bulk
GET    /api/bulk/{job_id}
GET    /api/bulk/{job_id}/stream     (SSE)

GET    /api/users
POST   /api/users

WS     /ws/ssh/{server_id}
WS     /ws/rdp/{server_id}
WS     /agent/connect
```

---

## Go Module & Dependencies

```
module github.com/shellwarden/shellwarden

go 1.22
```

```
github.com/gorilla/websocket    v1.5.x   BSD-2
github.com/gorilla/mux          v1.8.x   BSD-3
github.com/golang-jwt/jwt/v5    v5.x     MIT
github.com/lib/pq               v1.10.x  MIT
github.com/google/uuid          v1.x     BSD-3
golang.org/x/crypto             latest   BSD-3
github.com/wwt/guac             latest   Apache-2.0
github.com/joho/godotenv        v1.5.x   MIT
```

---

## Web Frontend

React 18 + TypeScript + Vite. No UI component library — plain CSS modules.

```
xterm                   ^5.x
xterm-addon-fit         latest
@guacamole-common-js    latest   (Apache-2.0)
```

**SshTerminal.tsx** — opens WebSocket to `/ws/ssh/{serverId}`, attaches xterm.js Terminal, pipes WebSocket↔terminal bidirectionally, closes both on unmount.

**RdpCanvas.tsx** — uses `@guacamole-common-js`. Creates `Guacamole.WebSocketTunnel` to `/ws/rdp/{serverId}`, attaches `Guacamole.Client`, appends its display element to a container div, forwards mouse and keyboard events to the Guacamole client.

**BulkExec.tsx** — group selector, command input, results table. On submit: POST `/api/bulk`, then open SSE to `/api/bulk/{jobId}/stream`. Each SSE event appends a row: server name, status badge, stdout/stderr snippet, duration.

---

## install.sh

Runs on the target server as root:

1. Detect OS (Debian/Ubuntu vs RHEL/CentOS vs Arch)
2. Download agent binary from gateway's `/downloads/agent/{os}/{arch}`
3. Write `/etc/shellwarden/agent.conf` with `GATEWAY_URL`, `AGENT_TOKEN`, `SERVER_ID`
4. Create systemd unit at `/etc/systemd/system/shellwarden-agent.service`
5. Enable and start the service
6. Print success message with server UUID

```bash
curl -fsSL https://gateway.internal/install.sh | \
  bash -s -- \
    --gateway wss://gateway.internal:8080 \
    --token   <agent_token> \
    --id      <server_uuid>
```

---

## docker-compose.yml Services

- **gateway** — builds from `Dockerfile.gateway`, exposes 8080, depends on postgres and guacd
- **guacd** — `guacamole/guacd:latest` (Apache-2.0), port 4822 internal only
- **postgres** — `postgres:16-alpine`, named volume, creates `shellwarden` database

---

## Makefile Targets

```
make dev        starts docker-compose, runs gateway with Air live reload
make build      compiles gateway and agent binaries to ./bin/
make migrate    runs SQL migrations against DATABASE_URL
make seed       inserts default admin user (admin / changeme)
make lint       golangci-lint
make test       go test ./...
make web        cd web && npm install && npm run dev
make build-web  cd web && npm run build → ./static/
```

---

## Implementation Order

Work in this exact sequence:

1. `go.mod` and fetch all Go dependencies
2. `internal/config/config.go` — reads env vars into a Config struct
3. `internal/db/db.go` — opens PG connection, runs migrations on startup
4. Migration SQL files
5. All model structs in `internal/models/`
6. `internal/auth/jwt.go` and `internal/auth/middleware.go`
7. `internal/api/router.go` and all REST handlers (stub 501 for WebSocket routes initially)
8. `internal/agent/registry.go` — thread-safe in-memory map of server_id → WebSocket conn
9. `internal/agent/tunnel.go` — gateway-side agent WebSocket handler
10. `internal/proxy/recorder.go` — asciinema v2 writer
11. `internal/proxy/ssh.go` — SSH session proxy, both direct and agent modes
12. `internal/proxy/rdp.go` — Guacamole WebSocket bridge
13. `internal/bulk/executor.go` — fan-out executor with SSE streaming
14. `cmd/gateway/main.go` — wires everything together
15. `cmd/agent/main.go` — reverse tunnel agent binary
16. `scripts/install.sh`
17. `docker-compose.yml`, `Dockerfile.gateway`, `Dockerfile.agent`, `Makefile`
18. Web frontend: `package.json`, `vite.config.ts`, `src/main.tsx`, `src/App.tsx`
19. `web/src/api/client.ts` — typed fetch wrapper for all API endpoints
20. All page and component files

After completing all steps, run `make build` and `make build-web`. Fix any compilation errors before finishing.
