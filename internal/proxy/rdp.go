package proxy

import (
	"database/sql"
	"fmt"
	"net"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/wwt/guac"
)

// RDPProxy bridges browser WebSocket traffic to guacd using the Guacamole
// tunnel protocol. The gateway is a thin WS<->guacd bridge; guacd speaks FreeRDP
// to the target. RDP sessions are recorded at the instruction-stream level.
// TODO: tee the guac instruction stream into audit_logs / a .guac recording.
type RDPProxy struct {
	DB        *sql.DB
	GuacdAddr string

	ws *guac.WebsocketServer
}

// NewRDPProxy builds the proxy. guacdHost/guacdPort point at the guacd sidecar.
func NewRDPProxy(db *sql.DB, guacdHost, guacdPort string) *RDPProxy {
	p := &RDPProxy{
		DB:        db,
		GuacdAddr: net.JoinHostPort(guacdHost, guacdPort),
	}
	p.ws = guac.NewWebsocketServer(p.connect)
	return p
}

// ServeHTTP delegates to the guac websocket server.
func (p *RDPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.ws.ServeHTTP(w, r)
}

// connect is invoked per WebSocket connection. It resolves the target server,
// dials guacd, performs the Guacamole handshake, and returns a tunnel.
func (p *RDPProxy) connect(r *http.Request) (guac.Tunnel, error) {
	serverID := mux.Vars(r)["server_id"]
	if serverID == "" {
		// mux.Vars may be empty if the guac server strips routing context;
		// fall back to a query parameter.
		serverID = r.URL.Query().Get("server_id")
	}

	srv, err := loadServer(p.DB, serverID)
	if err != nil {
		return nil, fmt.Errorf("server not found: %w", err)
	}

	cfg := guac.NewGuacamoleConfiguration()
	cfg.Protocol = "rdp"
	cfg.Parameters = map[string]string{
		"hostname":    srv.Host,
		"port":        fmt.Sprintf("%d", srv.Port),
		"ignore-cert": "true", // TODO: validate certs in production
	}
	if srv.SSHUser != nil {
		cfg.Parameters["username"] = *srv.SSHUser
	}
	if w := queryInt(r, "width"); w > 0 {
		cfg.OptimalScreenWidth = w
	}
	if h := queryInt(r, "height"); h > 0 {
		cfg.OptimalScreenHeight = h
	}

	conn, err := net.DialTimeout("tcp", p.GuacdAddr, guac.SocketTimeout)
	if err != nil {
		return nil, fmt.Errorf("dial guacd: %w", err)
	}

	stream := guac.NewStream(conn, guac.SocketTimeout)
	if err := stream.Handshake(cfg); err != nil {
		conn.Close()
		return nil, fmt.Errorf("guac handshake: %w", err)
	}

	return guac.NewSimpleTunnel(stream), nil
}

func queryInt(r *http.Request, key string) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return 0
	}
	var n int
	_, _ = fmt.Sscanf(v, "%d", &n)
	return n
}
