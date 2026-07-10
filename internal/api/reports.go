package api

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"
)

// AccessReviewRow summarizes a user's access posture for periodic reviews
// (SOC2 / ISO 27001 access certification).
type AccessReviewRow struct {
	Username      string `json:"username"`
	Role          string `json:"role"`
	MFAEnabled    bool   `json:"mfa_enabled"`
	Sessions30d   int    `json:"sessions_30d"`
	ActiveGrants  int    `json:"active_grants"`
	LastSeen      string `json:"last_seen,omitempty"`
	DistinctHosts int    `json:"distinct_hosts_30d"`
}

// AccessReview returns one row per user with access metrics (admin only).
func (a *API) AccessReview(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.DB.Query(`
		SELECT u.username, u.role, u.mfa_enabled,
		       COALESCE(s.cnt, 0)      AS sessions_30d,
		       COALESCE(s.hosts, 0)    AS distinct_hosts,
		       COALESCE(g.cnt, 0)      AS active_grants,
		       to_char(s.last_seen, 'YYYY-MM-DD"T"HH24:MI:SSZ') AS last_seen
		FROM users u
		LEFT JOIN (
		    SELECT user_id, COUNT(*) cnt, COUNT(DISTINCT server_id) hosts, MAX(started_at) last_seen
		    FROM sessions WHERE started_at > NOW() - INTERVAL '30 days' GROUP BY user_id
		) s ON s.user_id = u.id
		LEFT JOIN (
		    SELECT user_id, COUNT(*) cnt FROM access_requests
		    WHERE status='approved' AND (expires_at IS NULL OR expires_at > NOW()) GROUP BY user_id
		) g ON g.user_id = u.id
		ORDER BY u.username`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error: "+err.Error())
		return
	}
	defer rows.Close()

	out := []AccessReviewRow{}
	for rows.Next() {
		var r AccessReviewRow
		var lastSeen *string
		if err := rows.Scan(&r.Username, &r.Role, &r.MFAEnabled, &r.Sessions30d,
			&r.DistinctHosts, &r.ActiveGrants, &lastSeen); err != nil {
			writeErr(w, http.StatusInternalServerError, "scan error")
			return
		}
		if lastSeen != nil {
			r.LastSeen = *lastSeen
		}
		out = append(out, r)
	}
	writeJSON(w, http.StatusOK, out)
}

// SessionReportCSV exports a session-by-session access report (admin only).
func (a *API) SessionReportCSV(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Query(`
		SELECT se.id, se.started_at, se.ended_at, COALESCE(u.username,''), COALESCE(sv.name,''),
		       se.protocol, COALESCE(se.reason,''), se.bytes_read, se.bytes_written
		FROM sessions se
		LEFT JOIN users u ON u.id = se.user_id
		LEFT JOIN servers sv ON sv.id = se.server_id
		ORDER BY se.started_at DESC LIMIT 100000`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="shellwarden-sessions.csv"`)
	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"session_id", "started", "ended", "duration_sec", "user", "host", "protocol", "reason", "bytes_read", "bytes_written"})

	for rows.Next() {
		var id, user, host, proto, reason string
		var started time.Time
		var ended *time.Time
		var br, bw int64
		if err := rows.Scan(&id, &started, &ended, &user, &host, &proto, &reason, &br, &bw); err != nil {
			return
		}
		dur := ""
		endStr := ""
		if ended != nil {
			dur = strconv.Itoa(int(ended.Sub(started).Seconds()))
			endStr = ended.Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			id, started.Format(time.RFC3339), endStr, dur, user, host, proto, reason,
			strconv.FormatInt(br, 10), strconv.FormatInt(bw, 10),
		})
	}
}
