package api

import (
	"net/http"
	"time"
)

// DashboardData is the live operations overview payload.
type DashboardData struct {
	Stats    DashStats       `json:"stats"`
	Active   []ActiveSession `json:"active_sessions"`
	Events   []DashEvent     `json:"recent_events"`
	Activity []HourBucket    `json:"activity_24h"`
}

type DashStats struct {
	HostsTotal      int `json:"hosts_total"`
	HostsOnline     int `json:"hosts_online"`
	Agents          int `json:"agents"`
	ActiveSessions  int `json:"active_sessions"`
	Sessions24h     int `json:"sessions_24h"`
	FailedLogins24h int `json:"failed_logins_24h"`
}

type ActiveSession struct {
	ID        string `json:"id"`
	User      string `json:"user"`
	Server    string `json:"server"`
	Protocol  string `json:"protocol"`
	StartedAt string `json:"started_at"`
}

type DashEvent struct {
	TS        string `json:"ts"`
	EventType string `json:"event_type"`
	User      string `json:"user,omitempty"`
	Server    string `json:"server,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

type HourBucket struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// Dashboard returns the live operations overview (all roles may view).
func (a *API) Dashboard(w http.ResponseWriter, _ *http.Request) {
	var d DashboardData

	_ = a.DB.QueryRow(`
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE status='online'),
		       COUNT(*) FILTER (WHERE connection_mode='agent')
		FROM servers`).Scan(&d.Stats.HostsTotal, &d.Stats.HostsOnline, &d.Stats.Agents)

	_ = a.DB.QueryRow(`SELECT COUNT(*) FROM sessions WHERE started_at > NOW() - INTERVAL '24 hours'`).
		Scan(&d.Stats.Sessions24h)
	_ = a.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE event_type='login_failed' AND ts > NOW() - INTERVAL '24 hours'`).
		Scan(&d.Stats.FailedLogins24h)

	// Active (not-yet-ended) sessions with resolved names.
	d.Active = []ActiveSession{}
	if rows, err := a.DB.Query(`
		SELECT se.id, COALESCE(u.username,''), COALESCE(sv.name,''), se.protocol, se.started_at
		FROM sessions se
		LEFT JOIN users u ON u.id = se.user_id
		LEFT JOIN servers sv ON sv.id = se.server_id
		WHERE se.ended_at IS NULL
		ORDER BY se.started_at DESC LIMIT 100`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var s ActiveSession
			var started time.Time
			if rows.Scan(&s.ID, &s.User, &s.Server, &s.Protocol, &started) == nil {
				s.StartedAt = started.Format(time.RFC3339)
				d.Active = append(d.Active, s)
			}
		}
	}
	d.Stats.ActiveSessions = len(d.Active)

	// Recent security/operational events.
	d.Events = []DashEvent{}
	if rows, err := a.DB.Query(`
		SELECT al.ts, al.event_type, COALESCE(u.username,''), COALESCE(sv.name,''), COALESCE(al.data,'')
		FROM audit_logs al
		LEFT JOIN users u ON u.id = al.user_id
		LEFT JOIN servers sv ON sv.id = al.server_id
		WHERE al.event_type IN ('session_start','session_end','login_failed','bruteforce','host_exec')
		ORDER BY al.id DESC LIMIT 30`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var e DashEvent
			var ts time.Time
			if rows.Scan(&ts, &e.EventType, &e.User, &e.Server, &e.Detail) == nil {
				e.TS = ts.Format(time.RFC3339)
				if len(e.Detail) > 120 {
					e.Detail = e.Detail[:120]
				}
				d.Events = append(d.Events, e)
			}
		}
	}

	// Sessions per hour over the last 24h.
	d.Activity = []HourBucket{}
	if rows, err := a.DB.Query(`
		SELECT to_char(date_trunc('hour', started_at), 'YYYY-MM-DD"T"HH24:00'), COUNT(*)
		FROM sessions WHERE started_at > NOW() - INTERVAL '24 hours'
		GROUP BY 1 ORDER BY 1`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var b HourBucket
			if rows.Scan(&b.Hour, &b.Count) == nil {
				d.Activity = append(d.Activity, b)
			}
		}
	}

	writeJSON(w, http.StatusOK, d)
}
