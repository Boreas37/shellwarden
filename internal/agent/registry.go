package agent

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Frame types for the multiplexed agent protocol. Every WebSocket binary
// message between gateway and agent is: [1 byte type][16 byte streamID][payload].
const (
	FrameOpen      byte = 0x01 // gateway -> agent: open a new bridged connection to local sshd
	FrameData      byte = 0x02 // bidirectional: stream payload
	FrameClose     byte = 0x03 // either side: stream finished
	FrameLog       byte = 0x04 // agent -> gateway: host exec events, JSON payload
	FrameTelemetry byte = 0x05 // agent -> gateway: host metrics snapshot, JSON payload
	FrameScan      byte = 0x06 // agent -> gateway: vulnerability scan result, JSON payload
)

const frameHeaderLen = 1 + 16 // type + uuid

// ErrAgentNotConnected is returned when no agent is registered for a server.
var ErrAgentNotConnected = errors.New("agent not connected for server")

// EncodeFrame builds a wire frame from its parts.
func EncodeFrame(typ byte, streamID uuid.UUID, payload []byte) []byte {
	buf := make([]byte, frameHeaderLen+len(payload))
	buf[0] = typ
	copy(buf[1:17], streamID[:])
	copy(buf[17:], payload)
	return buf
}

// DecodeFrame splits a wire frame into its parts. The returned payload aliases
// the input slice.
func DecodeFrame(b []byte) (typ byte, streamID uuid.UUID, payload []byte, err error) {
	if len(b) < frameHeaderLen {
		return 0, uuid.Nil, nil, errors.New("short frame")
	}
	typ = b[0]
	copy(streamID[:], b[1:17])
	payload = b[frameHeaderLen:]
	return typ, streamID, payload, nil
}

var _ = binary.BigEndian // reserved for future length-prefixed extensions

// Registry is a thread-safe map of server_id -> live agent connection.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]*AgentConn
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{agents: make(map[string]*AgentConn)}
}

// Register stores (and replaces any existing) agent connection for a server.
func (r *Registry) Register(serverID string, ac *AgentConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old := r.agents[serverID]; old != nil {
		old.Close()
	}
	r.agents[serverID] = ac
}

// Unregister removes the agent connection if it is still the current one.
func (r *Registry) Unregister(serverID string, ac *AgentConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.agents[serverID] == ac {
		delete(r.agents, serverID)
	}
}

// Get returns the live agent connection for a server, if any.
func (r *Registry) Get(serverID string) (*AgentConn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ac, ok := r.agents[serverID]
	return ac, ok
}

// Dial opens a new multiplexed stream to the target server's local sshd via its
// agent. The returned net.Conn bridges bytes over the agent WebSocket.
func (r *Registry) Dial(serverID string) (net.Conn, error) {
	ac, ok := r.Get(serverID)
	if !ok {
		return nil, ErrAgentNotConnected
	}
	return ac.openStream()
}

// AgentConn represents a single connected agent's reverse WebSocket plus all
// active multiplexed streams.
type AgentConn struct {
	ServerID string

	ws      *websocket.Conn
	writeMu sync.Mutex

	mu      sync.Mutex
	streams map[uuid.UUID]*stream
	closed  bool

	// OnLog / OnTelemetry / OnScan, if set (gateway side), handle inbound frames.
	OnLog       func(payload []byte)
	OnTelemetry func(payload []byte)
	OnScan      func(payload []byte)
}

// NewAgentConn wraps a WebSocket connection and starts nothing; the caller runs
// ReadLoop.
func NewAgentConn(serverID string, ws *websocket.Conn) *AgentConn {
	return &AgentConn{
		ServerID: serverID,
		ws:       ws,
		streams:  make(map[uuid.UUID]*stream),
	}
}

// writeFrame serializes a single frame onto the WebSocket (writes must be
// serialized — gorilla/websocket does not allow concurrent writers).
func (ac *AgentConn) writeFrame(typ byte, id uuid.UUID, payload []byte) error {
	ac.writeMu.Lock()
	defer ac.writeMu.Unlock()
	return ac.ws.WriteMessage(websocket.BinaryMessage, EncodeFrame(typ, id, payload))
}

// SendLog sends a host exec-event frame (agent -> gateway). The stream ID is
// unused (uuid.Nil) since these frames are not tied to a connection.
func (ac *AgentConn) SendLog(payload []byte) error {
	return ac.writeFrame(FrameLog, uuid.Nil, payload)
}

// SendTelemetry sends a host metrics snapshot frame (agent -> gateway).
func (ac *AgentConn) SendTelemetry(payload []byte) error {
	return ac.writeFrame(FrameTelemetry, uuid.Nil, payload)
}

// SendScan sends a vulnerability scan result frame (agent -> gateway).
func (ac *AgentConn) SendScan(payload []byte) error {
	return ac.writeFrame(FrameScan, uuid.Nil, payload)
}

// openStream allocates a stream ID, tells the agent to open, and returns the
// gateway-side net.Conn.
func (ac *AgentConn) openStream() (*stream, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	s := newStream(ac, id)

	ac.mu.Lock()
	if ac.closed {
		ac.mu.Unlock()
		return nil, ErrAgentNotConnected
	}
	ac.streams[id] = s
	ac.mu.Unlock()

	if err := ac.writeFrame(FrameOpen, id, nil); err != nil {
		ac.removeStream(id)
		return nil, err
	}
	return s, nil
}

func (ac *AgentConn) removeStream(id uuid.UUID) {
	ac.mu.Lock()
	delete(ac.streams, id)
	ac.mu.Unlock()
}

// ReadLoop reads frames off the WebSocket and dispatches them to streams. It
// runs until the connection closes, then tears down all streams. The onOpen
// callback (may be nil on the gateway side) is invoked for FrameOpen so the
// agent binary can dial local sshd.
func (ac *AgentConn) ReadLoop(onOpen func(id uuid.UUID, conn net.Conn)) error {
	defer ac.Close()
	for {
		mt, data, err := ac.ws.ReadMessage()
		if err != nil {
			return err
		}
		if mt != websocket.BinaryMessage {
			continue // ignore control/ping text frames here
		}
		typ, id, payload, err := DecodeFrame(data)
		if err != nil {
			continue
		}
		switch typ {
		case FrameOpen:
			if onOpen == nil {
				continue // gateway never receives Open
			}
			s := newStream(ac, id)
			ac.mu.Lock()
			ac.streams[id] = s
			ac.mu.Unlock()
			onOpen(id, s)
		case FrameData:
			ac.mu.Lock()
			s := ac.streams[id]
			ac.mu.Unlock()
			if s != nil {
				// Copy payload: it aliases the read buffer reused next iteration.
				cp := make([]byte, len(payload))
				copy(cp, payload)
				s.deliver(cp)
			}
		case FrameClose:
			ac.mu.Lock()
			s := ac.streams[id]
			delete(ac.streams, id)
			ac.mu.Unlock()
			if s != nil {
				s.closeRemote()
			}
		case FrameLog:
			if ac.OnLog != nil {
				cp := make([]byte, len(payload))
				copy(cp, payload)
				ac.OnLog(cp)
			}
		case FrameTelemetry:
			if ac.OnTelemetry != nil {
				cp := make([]byte, len(payload))
				copy(cp, payload)
				ac.OnTelemetry(cp)
			}
		case FrameScan:
			if ac.OnScan != nil {
				cp := make([]byte, len(payload))
				copy(cp, payload)
				ac.OnScan(cp)
			}
		}
	}
}

// Close tears down the WebSocket and all streams.
func (ac *AgentConn) Close() {
	ac.mu.Lock()
	if ac.closed {
		ac.mu.Unlock()
		return
	}
	ac.closed = true
	streams := ac.streams
	ac.streams = make(map[uuid.UUID]*stream)
	ac.mu.Unlock()

	for _, s := range streams {
		s.closeRemote()
	}
	_ = ac.ws.Close()
}

// stream is one multiplexed connection. It implements net.Conn.
type stream struct {
	ac *AgentConn
	id uuid.UUID

	pr *io.PipeReader
	pw *io.PipeWriter

	closeOnce sync.Once
}

func newStream(ac *AgentConn, id uuid.UUID) *stream {
	pr, pw := io.Pipe()
	return &stream{ac: ac, id: id, pr: pr, pw: pw}
}

// deliver pushes inbound bytes to the local reader side.
func (s *stream) deliver(b []byte) { _, _ = s.pw.Write(b) }

// closeRemote signals EOF to local readers without sending a Close frame.
func (s *stream) closeRemote() { _ = s.pw.Close() }

func (s *stream) Read(p []byte) (int, error) { return s.pr.Read(p) }

func (s *stream) Write(p []byte) (int, error) {
	if err := s.ac.writeFrame(FrameData, s.id, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close sends a Close frame and tears down the local pipe.
func (s *stream) Close() error {
	s.closeOnce.Do(func() {
		_ = s.ac.writeFrame(FrameClose, s.id, nil)
		s.ac.removeStream(s.id)
		_ = s.pw.Close()
		_ = s.pr.Close()
	})
	return nil
}

// net.Conn boilerplate — addresses/deadlines are not meaningful for the
// multiplexed virtual connection.
type fakeAddr struct{ s string }

func (a fakeAddr) Network() string { return "agent-tunnel" }
func (a fakeAddr) String() string  { return a.s }

func (s *stream) LocalAddr() net.Addr                { return fakeAddr{"gateway"} }
func (s *stream) RemoteAddr() net.Addr               { return fakeAddr{s.ac.ServerID} }
func (s *stream) SetDeadline(t time.Time) error      { return nil }
func (s *stream) SetReadDeadline(t time.Time) error  { return nil }
func (s *stream) SetWriteDeadline(t time.Time) error { return nil }
