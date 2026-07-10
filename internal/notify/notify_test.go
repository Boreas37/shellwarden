package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebhookDelivery(t *testing.T) {
	got := make(chan Event, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var e Event
		_ = json.Unmarshal(body, &e)
		got <- e
		w.WriteHeader(200)
	}))
	defer srv.Close()

	n := New(srv.URL)
	if !n.Enabled() {
		t.Fatal("notifier should be enabled")
	}
	n.Send(Event{Type: "session_start", User: "alice", Server: "web-01", Message: "hi"})

	select {
	case e := <-got:
		if e.Type != "session_start" || e.User != "alice" || e.Server != "web-01" {
			t.Fatalf("event mismatch: %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook not delivered within 2s")
	}
}

func TestDisabledNotifierIsNoop(t *testing.T) {
	n := New("")
	if n.Enabled() {
		t.Fatal("notifier with no URLs should be disabled")
	}
	n.Send(Event{Type: "x"}) // must not panic / block
}
