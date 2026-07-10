// Package notify delivers structured events to external sinks (SIEM, Slack,
// generic webhooks) for alerting and compliance streaming. Delivery is async
// and best-effort so it never blocks a session.
package notify

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// Event is a structured notification.
type Event struct {
	Type      string                 `json:"type"`
	Severity  string                 `json:"severity"`
	Timestamp string                 `json:"timestamp"`
	User      string                 `json:"user,omitempty"`
	Server    string                 `json:"server,omitempty"`
	Session   string                 `json:"session,omitempty"`
	Message   string                 `json:"message,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// Notifier fans events out to one or more webhook URLs.
type Notifier struct {
	webhooks []string
	ch       chan Event
	client   *http.Client
}

// New builds a notifier for the given webhook URLs (empty ones are ignored).
// Returns a no-op notifier (Send drops) if no URLs are configured.
func New(urls ...string) *Notifier {
	var hooks []string
	for _, u := range urls {
		if u != "" {
			hooks = append(hooks, u)
		}
	}
	n := &Notifier{
		webhooks: hooks,
		ch:       make(chan Event, 512),
		client:   &http.Client{Timeout: 5 * time.Second},
	}
	if len(hooks) > 0 {
		go n.worker()
		log.Printf("notifications enabled (%d webhook sink(s))", len(hooks))
	}
	return n
}

// Enabled reports whether any sink is configured.
func (n *Notifier) Enabled() bool { return len(n.webhooks) > 0 }

// Send enqueues an event (non-blocking; drops if the queue is full).
func (n *Notifier) Send(e Event) {
	if !n.Enabled() {
		return
	}
	if e.Timestamp == "" {
		// Caller may set a precise time; default is filled by the worker.
	}
	select {
	case n.ch <- e:
	default: // queue full — drop rather than block
	}
}

func (n *Notifier) worker() {
	for e := range n.ch {
		body, err := json.Marshal(e)
		if err != nil {
			continue
		}
		for _, url := range n.webhooks {
			req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := n.client.Do(req)
			if err != nil {
				log.Printf("notify webhook %s failed: %v", url, err)
				continue
			}
			resp.Body.Close()
		}
	}
}
