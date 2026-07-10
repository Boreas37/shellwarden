package proxy

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// resumeGrace is how long a detached session stays alive awaiting reattach.
const resumeGrace = 3 * time.Minute

// repaintBytes is the size of the replay buffer shown when a client reattaches.
const repaintBytes = 256 * 1024

// ringBuffer keeps the most recent output for screen repaint on reattach.
type ringBuffer struct {
	mu  sync.Mutex
	buf []byte
	cap int
}

func newRing(capBytes int) *ringBuffer { return &ringBuffer{cap: capBytes} }

func (r *ringBuffer) write(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	if len(r.buf) > r.cap {
		r.buf = append([]byte(nil), r.buf[len(r.buf)-r.cap:]...)
	}
}

func (r *ringBuffer) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.buf))
	copy(out, r.buf)
	return out
}

// managedSession owns an SSH shell independently of any browser WebSocket, so
// the shell survives disconnects and can be reattached (resumed).
type managedSession struct {
	id         string
	userID     string
	serverName string

	proxy   *SSHProxy
	client  *ssh.Client
	session *ssh.Session
	stdin   io.Writer
	rec     *Recorder
	ring    *ringBuffer

	mu         sync.Mutex
	ws         *websocket.Conn
	wmu        sync.Mutex // serializes writes to ws
	detachedAt time.Time
	ended      bool
	endOnce    sync.Once
}

// newManagedSession sets up the PTY + shell and starts the output pump.
func (p *SSHProxy) newManagedSession(id, userID, serverName string, client *ssh.Client, session *ssh.Session, rec *Recorder) (*managedSession, error) {
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	modes := ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("xterm-256color", 50, 220, modes); err != nil {
		return nil, err
	}
	if err := session.Shell(); err != nil {
		return nil, err
	}

	m := &managedSession{
		id: id, userID: userID, serverName: serverName,
		proxy: p, client: client, session: session, stdin: stdin, rec: rec,
		ring: newRing(repaintBytes),
	}

	go m.pump(stdout)
	go m.pump(stderr)
	return m, nil
}

// pump reads one output stream, records it, buffers it, and forwards to the
// attached WebSocket (if any). When stdout reaches EOF the shell has exited.
func (m *managedSession) pump(rd io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := rd.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			m.rec.RecordOutput(chunk) // cast + audit + hub publish
			m.ring.write(chunk)
			m.writeWS(websocket.BinaryMessage, chunk)
		}
		if err != nil {
			m.end() // stream closed → shell ended
			return
		}
	}
}

func (m *managedSession) writeWS(mt int, data []byte) {
	m.mu.Lock()
	ws := m.ws
	m.mu.Unlock()
	if ws == nil {
		return
	}
	m.wmu.Lock()
	_ = ws.WriteMessage(mt, data)
	m.wmu.Unlock()
}

// attach binds a WebSocket and repaints the recent screen buffer.
func (m *managedSession) attach(ws *websocket.Conn) {
	m.mu.Lock()
	m.ws = ws
	m.detachedAt = time.Time{}
	m.mu.Unlock()
	// Tell the client the session id so it can resume after a drop.
	idMsg, _ := json.Marshal(map[string]string{"type": "session", "id": m.id})
	m.wmu.Lock()
	_ = ws.WriteMessage(websocket.TextMessage, idMsg)
	_ = ws.WriteMessage(websocket.BinaryMessage, m.ring.snapshot())
	m.wmu.Unlock()
}

// detach unbinds the current WebSocket and starts the resume grace timer.
func (m *managedSession) detach(ws *websocket.Conn) {
	m.mu.Lock()
	if m.ws == ws {
		m.ws = nil
		m.detachedAt = time.Now()
	}
	m.mu.Unlock()
}

// runInput pumps browser input into the shell until the WebSocket closes.
func (m *managedSession) runInput(ws *websocket.Conn) {
	recIn := m.rec.TeeInput(m.stdin)
	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if mt == websocket.TextMessage && len(data) > 0 && data[0] == '{' {
			var msg resizeMsg
			if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" {
				_ = m.session.WindowChange(msg.Rows, msg.Cols)
				continue
			}
		}
		if _, err := recIn.Write(data); err != nil {
			return
		}
	}
}

// isEnded reports whether the shell has terminated.
func (m *managedSession) isEnded() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ended
}

// end terminates the SSH shell, finalizes the recording, and deregisters.
func (m *managedSession) end() {
	m.endOnce.Do(func() {
		m.mu.Lock()
		m.ended = true
		ws := m.ws
		m.mu.Unlock()

		_ = m.session.Close()
		_ = m.client.Close()
		m.proxy.endSession(m.id, m.rec) // audits session_end + flushes recording
		if m.proxy.Hub != nil {
			m.proxy.Hub.Unregister(m.id)
		}
		m.proxy.notifySessionEnd(m.id, m.serverName, m.userID, m.rec)
		m.proxy.store.remove(m.id)
		if ws != nil {
			closeWS(ws, closeTerminated, "session ended")
		}
	})
}

// sessionStore tracks resumable sessions.
type sessionStore struct {
	mu sync.Mutex
	m  map[string]*managedSession
}

func newSessionStore() *sessionStore { return &sessionStore{m: make(map[string]*managedSession)} }

func (s *sessionStore) add(ms *managedSession) {
	s.mu.Lock()
	s.m[ms.id] = ms
	s.mu.Unlock()
}

func (s *sessionStore) get(id string) *managedSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[id]
}

func (s *sessionStore) remove(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// reap ends sessions that have been detached longer than the grace period.
func (s *sessionStore) reap() {
	for range time.Tick(30 * time.Second) {
		now := time.Now()
		var expired []*managedSession
		s.mu.Lock()
		for _, ms := range s.m {
			ms.mu.Lock()
			detached := !ms.detachedAt.IsZero() && now.Sub(ms.detachedAt) > resumeGrace
			ms.mu.Unlock()
			if detached {
				expired = append(expired, ms)
			}
		}
		s.mu.Unlock()
		for _, ms := range expired {
			ms.end()
		}
	}
}
