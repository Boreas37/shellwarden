package proxy

import (
	"sync"
	"time"
)

// LiveSession represents an in-progress SSH session that can be shadowed
// (watched read-only) and terminated by an admin.
type LiveSession struct {
	ID       string
	UserID   string
	ServerID string
	Started  time.Time

	kill func()

	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

// Hub tracks all active sessions for shadowing and termination.
type Hub struct {
	mu       sync.RWMutex
	sessions map[string]*LiveSession
}

// NewHub creates an empty hub.
func NewHub() *Hub {
	return &Hub{sessions: make(map[string]*LiveSession)}
}

// Register adds a live session. kill is invoked to forcibly end it.
func (h *Hub) Register(id, userID, serverID string, kill func()) *LiveSession {
	ls := &LiveSession{
		ID:       id,
		UserID:   userID,
		ServerID: serverID,
		Started:  time.Now(),
		kill:     kill,
		subs:     make(map[chan []byte]struct{}),
	}
	h.mu.Lock()
	h.sessions[id] = ls
	h.mu.Unlock()
	return ls
}

// Unregister removes a session and closes all watcher channels.
func (h *Hub) Unregister(id string) {
	h.mu.Lock()
	ls := h.sessions[id]
	delete(h.sessions, id)
	h.mu.Unlock()
	if ls == nil {
		return
	}
	ls.mu.Lock()
	for ch := range ls.subs {
		close(ch)
	}
	ls.subs = map[chan []byte]struct{}{}
	ls.mu.Unlock()
}

// Publish fans an output chunk out to all watchers of a session.
func (h *Hub) Publish(id string, data []byte) {
	h.mu.RLock()
	ls := h.sessions[id]
	h.mu.RUnlock()
	if ls == nil {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	ls.mu.Lock()
	for ch := range ls.subs {
		select {
		case ch <- cp:
		default: // slow watcher — drop rather than block the live session
		}
	}
	ls.mu.Unlock()
}

// Subscribe returns a channel of output chunks for a session and an unsubscribe
// func. Returns (nil, nil) if the session is not live.
func (h *Hub) Subscribe(id string) (<-chan []byte, func()) {
	h.mu.RLock()
	ls := h.sessions[id]
	h.mu.RUnlock()
	if ls == nil {
		return nil, nil
	}
	ch := make(chan []byte, 256)
	ls.mu.Lock()
	ls.subs[ch] = struct{}{}
	ls.mu.Unlock()
	return ch, func() {
		ls.mu.Lock()
		if _, ok := ls.subs[ch]; ok {
			delete(ls.subs, ch)
			close(ch)
		}
		ls.mu.Unlock()
	}
}

// Kill forcibly terminates a live session. Returns false if not found.
func (h *Hub) Kill(id string) bool {
	h.mu.RLock()
	ls := h.sessions[id]
	h.mu.RUnlock()
	if ls == nil {
		return false
	}
	if ls.kill != nil {
		ls.kill()
	}
	return true
}

// Active returns the IDs of all live sessions.
func (h *Hub) Active() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	ids := make([]string, 0, len(h.sessions))
	for id := range h.sessions {
		ids = append(ids, id)
	}
	return ids
}
