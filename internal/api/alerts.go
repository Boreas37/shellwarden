package api

import (
	"sync"
	"time"

	"github.com/shellwarden/shellwarden/internal/auditlog"
	"github.com/shellwarden/shellwarden/internal/notify"
)

// bruteForce tracks failed logins per username and raises a high-severity alert
// when too many occur in a short window — basic credential-stuffing detection.
type bruteForce struct {
	mu        sync.Mutex
	fails     map[string][]int64 // username -> unix-second timestamps
	window    time.Duration
	threshold int
}

func newBruteForce() *bruteForce {
	return &bruteForce{
		fails:     make(map[string][]int64),
		window:    5 * time.Minute,
		threshold: 5,
	}
}

// record adds a failed-login timestamp and reports whether the threshold was
// crossed within the window (deduplicated to one alert per breach).
func (b *bruteForce) record(username string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := now.Add(-b.window).Unix()
	kept := b.fails[username][:0]
	for _, ts := range b.fails[username] {
		if ts >= cutoff {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now.Unix())
	b.fails[username] = kept

	if len(kept) == b.threshold {
		return true // exactly at threshold — fire once
	}
	return false
}

// onLoginFailure records a failure (audit + alert) and raises a brute-force
// alert if the threshold is crossed.
func (a *API) onLoginFailure(username string, now time.Time) {
	_ = auditlog.Append(a.DB, "", "", "", "login_failed", username)
	a.emit(notify.Event{Type: "auth.login_failed", Severity: "warning", User: username, Message: "bad credentials"})
	if a.brute != nil && a.brute.record(username, now) {
		_ = auditlog.Append(a.DB, "", "", "", "bruteforce", username)
		a.emit(notify.Event{
			Type: "auth.bruteforce", Severity: "critical", User: username,
			Message: "5+ failed logins within 5 minutes — possible credential stuffing",
		})
	}
}
