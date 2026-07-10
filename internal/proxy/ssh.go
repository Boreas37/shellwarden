package proxy

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/shellwarden/shellwarden/internal/access"
	"github.com/shellwarden/shellwarden/internal/agent"
	"github.com/shellwarden/shellwarden/internal/auth"
	"github.com/shellwarden/shellwarden/internal/crypto"
	"github.com/shellwarden/shellwarden/internal/models"
	"github.com/shellwarden/shellwarden/internal/notify"
	"github.com/shellwarden/shellwarden/internal/sshca"
)

// notifySend is a nil-safe helper for emitting events.
func (p *SSHProxy) notify(e notify.Event) {
	if p.Notifier != nil {
		p.Notifier.Send(e)
	}
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true }, // TODO: tighten for prod
}

// SSHProxy handles WS /ws/ssh/{server_id} for both direct and agent modes.
type SSHProxy struct {
	DB            *sql.DB
	Registry      *agent.Registry
	RecordingPath string
	Cipher        *crypto.Cipher
	Hub           *Hub
	Notifier      *notify.Notifier
	CA            *sshca.CA     // optional SSH certificate authority
	CertTTL       time.Duration // certificate validity
	IdleTimeout   time.Duration // 0 = disabled
	MaxDuration   time.Duration // 0 = disabled
	JITRequired   bool          // require an approved access grant to connect

	store *sessionStore // resumable sessions
}

// NewSSHProxy builds the proxy handler.
func NewSSHProxy(db *sql.DB, reg *agent.Registry, recordingPath string, cipher *crypto.Cipher, hub *Hub, idleMin, maxMin int) *SSHProxy {
	p := &SSHProxy{
		DB:            db,
		Registry:      reg,
		RecordingPath: recordingPath,
		Cipher:        cipher,
		Hub:           hub,
		IdleTimeout:   time.Duration(idleMin) * time.Minute,
		MaxDuration:   time.Duration(maxMin) * time.Minute,
		store:         newSessionStore(),
	}
	go p.store.reap()
	return p
}

// notifySessionEnd emits a session.end event (nil-safe).
func (p *SSHProxy) notifySessionEnd(id, server, user string, rec *Recorder) {
	p.notify(notify.Event{
		Type: "session.end", Severity: "info", Session: id, Server: server, User: user,
		Data: map[string]interface{}{"bytes_read": rec.BytesRead, "bytes_written": rec.BytesWritten},
	})
}

// watchdogMS enforces idle/max limits and ends the managed session on breach.
func (p *SSHProxy) watchdogMS(ms *managedSession, stop <-chan struct{}) {
	start := time.Now()
	lastBytes := ms.rec.Bytes()
	lastChange := time.Now()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if b := ms.rec.Bytes(); b != lastBytes {
				lastBytes = b
				lastChange = time.Now()
			}
			if p.MaxDuration > 0 && time.Since(start) >= p.MaxDuration {
				ms.writeWS(websocket.TextMessage, []byte("\r\n[shellwarden] session ended: max duration\r\n"))
				ms.end()
				return
			}
			if p.IdleTimeout > 0 && time.Since(lastChange) >= p.IdleTimeout {
				ms.writeWS(websocket.TextMessage, []byte("\r\n[shellwarden] session ended: idle timeout\r\n"))
				ms.end()
				return
			}
		}
	}
}

// resizeMsg is the control message xterm.js sends on terminal resize. Plain
// terminal input arrives as binary/text WS frames and is forwarded verbatim.
type resizeMsg struct {
	Type string `json:"type"`
	Cols int    `json:"cols"`
	Rows int    `json:"rows"`
}

// ServeHTTP upgrades the browser WebSocket and proxies an interactive shell.
func (p *SSHProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["server_id"]

	var userID, role string
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		userID = claims.UserID
		role = claims.Role
	}

	// Just-in-time access enforcement (admins bypass).
	if p.JITRequired && role != "admin" {
		ok, _ := access.HasActiveGrant(p.DB, userID, serverID)
		if !ok {
			http.Error(w, "access not approved — request JIT access for this host", http.StatusForbidden)
			return
		}
	}

	srv, err := loadServer(p.DB, serverID)
	if err != nil {
		http.Error(w, "server not found", http.StatusNotFound)
		return
	}

	// Decrypt stored credentials for use (encrypted at rest).
	srv.SSHKey = p.Cipher.DecryptPtr(srv.SSHKey)
	srv.SSHPassword = p.Cipher.DecryptPtr(srv.SSHPassword)

	// Optional compliance reason/ticket supplied by the operator on connect.
	reason := r.URL.Query().Get("reason")

	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ssh ws upgrade failed: %v", err)
		return
	}
	defer ws.Close()

	// Resume path: reattach to a still-alive shell after a browser drop.
	if resumeID := r.URL.Query().Get("resume"); resumeID != "" {
		if ms := p.store.get(resumeID); ms != nil && ms.userID == userID && !ms.isEnded() {
			ms.attach(ws)
			ms.runInput(ws) // blocks until the browser WS closes
			ms.detach(ws)   // shell stays alive for the grace window
			return
		}
		// Not resumable — fall through and start a fresh session.
	}

	// Obtain a transport connection to the target's sshd.
	conn, err := p.dial(srv)
	if err != nil {
		writeWSError(ws, fmt.Sprintf("connect failed: %v", err))
		return
	}

	sshClient, err := p.newSSHClient(conn, srv, p.hostKeyCallback(srv))
	if err != nil {
		conn.Close()
		writeWSError(ws, fmt.Sprintf("ssh handshake failed: %v", err))
		return
	}

	session, err := sshClient.NewSession()
	if err != nil {
		sshClient.Close()
		writeWSError(ws, fmt.Sprintf("ssh session failed: %v", err))
		return
	}

	// Persist a session row and build the recorder.
	sessionID := p.createSession(serverID, userID, srv.Protocol, reason)
	rec := NewRecorder(p.DB, sessionID, serverID, userID, 220, 50)
	rec.audit(models.EventSessionStart, reason)
	if p.Hub != nil && sessionID != "" {
		rec.Publish = func(b []byte) { p.Hub.Publish(sessionID, b) }
	}
	p.notify(notify.Event{
		Type: "session.start", Severity: "info", Session: sessionID,
		Server: srv.Name, User: userID, Message: reason,
	})

	// Build the resumable, WS-independent shell.
	ms, err := p.newManagedSession(sessionID, userID, srv.Name, sshClient, session, rec)
	if err != nil {
		session.Close()
		sshClient.Close()
		writeWSError(ws, fmt.Sprintf("shell start failed: %v", err))
		p.endSession(sessionID, rec)
		return
	}
	p.store.add(ms)

	// Register for live shadowing / termination (terminate ends the session).
	if p.Hub != nil && sessionID != "" {
		p.Hub.Register(sessionID, userID, serverID, func() { ms.end() })
	}

	ms.attach(ws)

	stopWatch := make(chan struct{})
	if p.MaxDuration > 0 || p.IdleTimeout > 0 {
		go p.watchdogMS(ms, stopWatch)
	}

	ms.runInput(ws) // blocks until the browser WS closes
	close(stopWatch)
	ms.detach(ws) // shell stays alive (resumable) until grace expires or it exits
}

// Connect establishes an authenticated SSH client to a server (decrypting
// stored credentials and applying host-key TOFU). The caller must Close it.
// Used by the SFTP and port-forward features.
func (p *SSHProxy) Connect(serverID string) (*ssh.Client, error) {
	srv, err := loadServer(p.DB, serverID)
	if err != nil {
		return nil, err
	}
	srv.SSHKey = p.Cipher.DecryptPtr(srv.SSHKey)
	srv.SSHPassword = p.Cipher.DecryptPtr(srv.SSHPassword)

	conn, err := p.dial(srv)
	if err != nil {
		return nil, err
	}
	client, err := p.newSSHClient(conn, srv, p.hostKeyCallback(srv))
	if err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
}

// dial returns a transport connection to the target sshd, choosing agent or
// direct mode based on the server record.
func (p *SSHProxy) dial(srv *models.Server) (net.Conn, error) {
	if srv.ConnectionMode == models.ModeAgent {
		return p.Registry.Dial(srv.ID)
	}
	addr := net.JoinHostPort(srv.Host, fmt.Sprintf("%d", srv.Port))
	return net.DialTimeout("tcp", addr, 15*time.Second)
}

// ServeForward bridges a browser WebSocket to an arbitrary TCP endpoint reached
// THROUGH the target server (SSH local port forward): /ws/forward/{server_id}
// ?host=&port=. Enables reaching services bound on the target or its network.
func (p *SSHProxy) ServeForward(w http.ResponseWriter, r *http.Request) {
	serverID := mux.Vars(r)["server_id"]
	host := r.URL.Query().Get("host")
	if host == "" {
		host = "127.0.0.1"
	}
	port := r.URL.Query().Get("port")
	if port == "" {
		http.Error(w, "port required", http.StatusBadRequest)
		return
	}

	var userID, role string
	if claims, ok := auth.ClaimsFrom(r.Context()); ok {
		userID, role = claims.UserID, claims.Role
	}
	if p.JITRequired && role != "admin" {
		if ok, _ := access.HasActiveGrant(p.DB, userID, serverID); !ok {
			http.Error(w, "access not approved (JIT)", http.StatusForbidden)
			return
		}
	}

	client, err := p.Connect(serverID)
	if err != nil {
		http.Error(w, "ssh connect failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer client.Close()

	remote, err := client.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		http.Error(w, "forward dial failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer remote.Close()

	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	done := make(chan struct{}, 2)
	// remote -> ws
	go func() { pipeToWS(ws, remote); done <- struct{}{} }()
	// ws -> remote
	go func() {
		for {
			mt, data, err := ws.ReadMessage()
			if err != nil {
				break
			}
			if mt == websocket.BinaryMessage || mt == websocket.TextMessage {
				if _, err := remote.Write(data); err != nil {
					break
				}
			}
		}
		done <- struct{}{}
	}()
	<-done
}

// ServeWatch streams a live session's output to a read-only observer (session
// shadowing). Client input is ignored. Closes when the session ends.
func (p *SSHProxy) ServeWatch(w http.ResponseWriter, r *http.Request) {
	sessionID := mux.Vars(r)["session_id"]

	sub, cancel := p.Hub.Subscribe(sessionID)
	if sub == nil {
		http.Error(w, "session not live", http.StatusNotFound)
		return
	}
	defer cancel()

	ws, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	// Drain any client input so the read side detects disconnects.
	go func() {
		for {
			if _, _, err := ws.ReadMessage(); err != nil {
				cancel()
				return
			}
		}
	}()

	_ = ws.WriteMessage(websocket.TextMessage, []byte("\r\n[shellwarden] live shadow — read only\r\n"))
	for chunk := range sub {
		if err := ws.WriteMessage(websocket.BinaryMessage, chunk); err != nil {
			return
		}
	}
	_ = ws.WriteMessage(websocket.TextMessage, []byte("\r\n[shellwarden] session ended\r\n"))
}

// hostKeyCallback implements trust-on-first-use host key pinning. The first
// time we connect, the presented key is stored. Subsequent connections must
// match or the session is refused (MITM protection).
func (p *SSHProxy) hostKeyCallback(srv *models.Server) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		presented := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		if srv.SSHHostKey != nil && strings.TrimSpace(*srv.SSHHostKey) != "" {
			if strings.TrimSpace(*srv.SSHHostKey) != presented {
				return fmt.Errorf("host key mismatch for %s — possible MITM; refusing", srv.Name)
			}
			return nil
		}
		// TOFU: learn and pin this key.
		if _, err := p.DB.Exec(`UPDATE servers SET ssh_host_key = $1 WHERE id = $2`, presented, srv.ID); err != nil {
			log.Printf("pin host key failed for %s: %v", srv.ID, err)
		}
		return nil
	}
}

// newSSHClient performs the SSH handshake over an existing transport conn.
func (p *SSHProxy) newSSHClient(conn net.Conn, srv *models.Server, hostKey ssh.HostKeyCallback) (*ssh.Client, error) {
	user := "root"
	if srv.SSHUser != nil && *srv.SSHUser != "" {
		user = *srv.SSHUser
	}

	var authMethods []ssh.AuthMethod

	// Credential-less path: sign a short-lived CA certificate for this login.
	if srv.UseSSHCA && p.CA != nil {
		ttl := p.CertTTL
		if ttl <= 0 {
			ttl = 5 * time.Minute
		}
		certSigner, err := p.CA.SignUserCert(user, ttl)
		if err != nil {
			return nil, fmt.Errorf("sign ssh cert: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(certSigner))
	}

	if srv.SSHKey != nil && *srv.SSHKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(*srv.SSHKey))
		if err != nil {
			return nil, fmt.Errorf("parse ssh key: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}
	if srv.SSHPassword != nil && *srv.SSHPassword != "" {
		pw := *srv.SSHPassword
		authMethods = append(authMethods, ssh.Password(pw))
		// Some servers offer keyboard-interactive instead of plain password.
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			},
		))
	}
	if len(authMethods) == 0 {
		return nil, fmt.Errorf("no SSH credentials configured for this server (add a password or private key)")
	}
	// TODO: support agent-forwarded credentials.

	if hostKey == nil {
		hostKey = ssh.InsecureIgnoreHostKey()
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKey,
		Timeout:         15 * time.Second,
	}

	addr := net.JoinHostPort(srv.Host, fmt.Sprintf("%d", srv.Port))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// pipeToWS copies a reader to a WebSocket as binary frames.
func pipeToWS(ws *websocket.Conn, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func writeWSError(ws *websocket.Conn, msg string) {
	_ = ws.WriteMessage(websocket.TextMessage, []byte("\r\n[shellwarden] "+msg+"\r\n"))
}

// Application close codes signal the browser whether to auto-reconnect.
const (
	closeTerminated = 4001 // admin terminated — do NOT reconnect
	closeTimeout    = 4002 // idle/max duration — do NOT reconnect
)

// closeWS sends a close frame with an application code, then closes.
func closeWS(ws *websocket.Conn, code int, reason string) {
	_ = ws.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(code, reason),
		time.Now().Add(2*time.Second),
	)
	_ = ws.Close()
}

// createSession inserts a session row and returns its id.
func (p *SSHProxy) createSession(serverID, userID, protocol, reason string) string {
	var id string
	err := p.DB.QueryRow(
		`INSERT INTO sessions (server_id, user_id, protocol, reason) VALUES ($1, $2, $3, $4) RETURNING id`,
		nullable(serverID), nullable(userID), protocol, nullable(reason),
	).Scan(&id)
	if err != nil {
		log.Printf("create session failed: %v", err)
	}
	return id
}

// endSession flushes the recording, updates byte counters, and marks ended_at.
func (p *SSHProxy) endSession(sessionID string, rec *Recorder) {
	rec.audit(models.EventSessionEnd, "")
	path, err := rec.Flush(p.RecordingPath)
	if err != nil {
		log.Printf("flush recording failed: %v", err)
	}
	if sessionID == "" {
		return
	}
	_, err = p.DB.Exec(
		`UPDATE sessions SET ended_at = NOW(), recording_path = $1, bytes_read = $2, bytes_written = $3 WHERE id = $4`,
		path, rec.BytesRead, rec.BytesWritten, sessionID,
	)
	if err != nil {
		log.Printf("end session update failed: %v", err)
	}
}

// loadServer fetches a server record by id.
func loadServer(db *sql.DB, id string) (*models.Server, error) {
	s := &models.Server{}
	err := db.QueryRow(
		`SELECT id, name, host, port, protocol, connection_mode, agent_token,
		        agent_connected_at, status, os_info, ssh_user, ssh_key, ssh_password, ssh_host_key, use_ssh_ca, created_at
		 FROM servers WHERE id = $1`, id,
	).Scan(
		&s.ID, &s.Name, &s.Host, &s.Port, &s.Protocol, &s.ConnectionMode, &s.AgentToken,
		&s.AgentConnectedAt, &s.Status, &s.OSInfo, &s.SSHUser, &s.SSHKey, &s.SSHPassword, &s.SSHHostKey, &s.UseSSHCA, &s.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}
