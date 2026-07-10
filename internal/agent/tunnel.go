package agent

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/shellwarden/shellwarden/internal/auditlog"
	"github.com/shellwarden/shellwarden/internal/cve"
)

// telemetrySample is the subset of agent telemetry persisted to the time series.
type telemetrySample struct {
	CPUPct      float64 `json:"cpu_pct"`
	Load1       float64 `json:"load1"`
	MemTotalMB  uint64  `json:"mem_total_mb"`
	MemAvailMB  uint64  `json:"mem_avail_mb"`
	DiskTotalGB float64 `json:"disk_total_gb"`
	DiskFreeGB  float64 `json:"disk_free_gb"`
	NetRxKBs    float64 `json:"net_rx_kbs"`
	NetTxKBs    float64 `json:"net_tx_kbs"`
}

// vulnFinding mirrors the agent's finding shape (mutable for enrichment).
type vulnFinding struct {
	ID       string `json:"id"`
	Package  string `json:"package"`
	Severity string `json:"severity"`
}

// scanFull is the full vuln scan payload (used for enrichment + storage).
type scanFull struct {
	Tool            string        `json:"tool"`
	Distro          string        `json:"distro"`
	Upgradable      int           `json:"upgradable"`
	SecurityUpdates int           `json:"security_updates"`
	Findings        []vulnFinding `json:"findings"`
	ScannedAt       string        `json:"scanned_at"`
	Note            string        `json:"note,omitempty"`
}

const (
	// heartbeatTimeout: if no ping/pong/read for this long, the agent is dead.
	heartbeatTimeout = 90 * time.Second
)

var upgrader = websocket.Upgrader{
	// TODO: tighten CheckOrigin for production; agents connect machine-to-machine.
	CheckOrigin: func(r *http.Request) bool { return true },
}

// TunnelHandler is the gateway-side HTTP handler for WS /agent/connect. It
// authenticates the agent by its token, registers the connection, and pumps
// frames until the agent disconnects.
type TunnelHandler struct {
	DB       *sql.DB
	Registry *Registry
}

// NewTunnelHandler builds the handler.
func NewTunnelHandler(db *sql.DB, reg *Registry) *TunnelHandler {
	return &TunnelHandler{DB: db, Registry: reg}
}

// ServeHTTP upgrades the connection and serves one agent for its lifetime.
func (h *TunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	if token == "" {
		http.Error(w, "missing agent token", http.StatusUnauthorized)
		return
	}

	var serverID string
	err := h.DB.QueryRow(`SELECT id FROM servers WHERE agent_token = $1`, token).Scan(&serverID)
	if err == sql.ErrNoRows {
		http.Error(w, "unknown agent token", http.StatusUnauthorized)
		return
	} else if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("agent upgrade failed for server %s: %v", serverID, err)
		return
	}

	ac := NewAgentConn(serverID, ws)
	// Persist host exec events (any source on the host, incl. direct SSH that
	// bypasses the gateway) into the append-only audit chain.
	ac.OnLog = func(payload []byte) {
		_ = auditlog.Append(h.DB, "", serverID, "", "host_exec", string(payload))
	}
	// Store the latest telemetry snapshot + append to the time-series history.
	ac.OnTelemetry = func(payload []byte) {
		_, _ = h.DB.Exec(
			`UPDATE servers SET metrics = $1, metrics_at = NOW() WHERE id = $2`,
			string(payload), serverID,
		)
		var t telemetrySample
		if json.Unmarshal(payload, &t) == nil {
			memUsed, diskUsed := 0.0, 0.0
			if t.MemTotalMB > 0 {
				memUsed = float64(t.MemTotalMB-t.MemAvailMB) / float64(t.MemTotalMB) * 100
			}
			if t.DiskTotalGB > 0 {
				diskUsed = (t.DiskTotalGB - t.DiskFreeGB) / t.DiskTotalGB * 100
			}
			_, _ = h.DB.Exec(
				`INSERT INTO server_metrics (server_id, cpu_pct, mem_used_pct, disk_used_pct, net_rx_kbs, net_tx_kbs, load1)
				 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
				serverID, t.CPUPct, memUsed, diskUsed, t.NetRxKBs, t.NetTxKBs, t.Load1,
			)
		}
	}

	// Store vulnerability scan results, enriching each CVE with a CVSS-based
	// severity (OSV.dev) in the background, then alert on high/critical findings.
	ac.OnScan = func(payload []byte) {
		go func() {
			var s scanFull
			if json.Unmarshal(payload, &s) != nil {
				return
			}

			// Enrich severities from OSV/CVSS (cached). Keep the agent-reported
			// severity when no CVSS is available.
			ids := make([]string, 0, len(s.Findings))
			for _, f := range s.Findings {
				ids = append(ids, f.ID)
			}
			sevMap := cve.Enrich(ids)
			crit := 0
			for i := range s.Findings {
				if e := sevMap[s.Findings[i].ID]; e != "" {
					s.Findings[i].Severity = e
				}
				if s.Findings[i].Severity == "critical" || s.Findings[i].Severity == "high" {
					crit++
				}
			}

			enriched, err := json.Marshal(s)
			if err != nil {
				enriched = payload
			}
			_, _ = h.DB.Exec(
				`UPDATE servers SET vuln_scan=$1, vuln_scanned_at=NOW(), vuln_count=$2, vuln_critical=$3 WHERE id=$4`,
				string(enriched), len(s.Findings), crit, serverID,
			)
			_ = auditlog.Append(h.DB, "", serverID, "", "vuln_scan",
				fmt.Sprintf("%d findings (%d high/critical), %d security updates", len(s.Findings), crit, s.SecurityUpdates))
		}()
	}

	h.Registry.Register(serverID, ac)
	h.markOnline(serverID)
	log.Printf("agent connected: server %s", serverID)

	// Heartbeat: the agent sends pings every 30s. Reset the read deadline on
	// each ping (and reply with a pong) AND on each pong, so a healthy agent is
	// never falsely timed out. (Previously only pongs reset the deadline, but
	// the agent sends pings — so the gateway dropped every agent at ~90s.)
	bump := func() { ws.SetReadDeadline(time.Now().Add(heartbeatTimeout)) }
	bump()
	ws.SetPongHandler(func(string) error { bump(); h.touch(serverID); return nil })
	ws.SetPingHandler(func(msg string) error {
		bump()
		h.touch(serverID)
		err := ws.WriteControl(websocket.PongMessage, []byte(msg), time.Now().Add(10*time.Second))
		if err == websocket.ErrCloseSent {
			return nil
		}
		return err
	})

	// The gateway never receives Open frames (nil callback).
	err = ac.ReadLoop(nil)

	h.Registry.Unregister(serverID, ac)
	h.markOffline(serverID)
	log.Printf("agent disconnected: server %s (%v)", serverID, err)
}

func (h *TunnelHandler) markOnline(serverID string) {
	_, _ = h.DB.Exec(
		`UPDATE servers SET status = $1, agent_connected_at = NOW() WHERE id = $2`,
		"online", serverID,
	)
}

func (h *TunnelHandler) markOffline(serverID string) {
	_, _ = h.DB.Exec(`UPDATE servers SET status = $1 WHERE id = $2`, "offline", serverID)
}

func (h *TunnelHandler) touch(serverID string) {
	_, _ = h.DB.Exec(`UPDATE servers SET agent_connected_at = NOW() WHERE id = $1`, serverID)
}

// bearer extracts the agent token from the Authorization header or token query.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return r.URL.Query().Get("token")
}
