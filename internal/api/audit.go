package api

import (
	"encoding/csv"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/shellwarden/shellwarden/internal/auditlog"
	"github.com/shellwarden/shellwarden/internal/models"
)

// VerifyAudit walks the hash chain and reports whether the audit log is intact.
func (a *API) VerifyAudit(w http.ResponseWriter, _ *http.Request) {
	res, err := auditlog.Verify(a.DB)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "verify failed")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// buildAuditQuery assembles the WHERE clause from supported filters:
// session_id, user_id, server_id, event_type, from, to (RFC3339), q (substring).
func buildAuditQuery(q url.Values, limit int) (string, []interface{}) {
	var where []string
	var args []interface{}
	add := func(clause string, val interface{}) {
		args = append(args, val)
		where = append(where, clause+" $"+strconv.Itoa(len(args)))
	}

	if v := q.Get("session_id"); v != "" {
		add("session_id =", v)
	}
	if v := q.Get("user_id"); v != "" {
		add("user_id =", v)
	}
	if v := q.Get("server_id"); v != "" {
		add("server_id =", v)
	}
	if v := q.Get("event_type"); v != "" {
		add("event_type =", v)
	}
	if v := q.Get("from"); v != "" {
		add("ts >=", v)
	}
	if v := q.Get("to"); v != "" {
		add("ts <=", v)
	}
	if v := q.Get("q"); v != "" {
		add("data ILIKE", "%"+v+"%")
	}
	// Human view: hide raw per-keystroke input/output noise.
	if q.Get("human") == "1" {
		where = append(where, "event_type NOT IN ('output','input')")
	}

	sql := `SELECT id, session_id, server_id, user_id, event_type, data, ts FROM audit_logs`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY ts DESC LIMIT " + strconv.Itoa(limit)
	return sql, args
}

// QueryAudit returns filtered audit rows as JSON.
func (a *API) QueryAudit(w http.ResponseWriter, r *http.Request) {
	sql, args := buildAuditQuery(r.URL.Query(), 1000)
	rows, err := a.DB.Query(sql, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	logs := []models.AuditLog{}
	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(&l.ID, &l.SessionID, &l.ServerID, &l.UserID, &l.EventType, &l.Data, &l.TS); err != nil {
			writeErr(w, http.StatusInternalServerError, "scan error")
			return
		}
		logs = append(logs, l)
	}
	writeJSON(w, http.StatusOK, logs)
}

// ExportAudit streams filtered audit rows as a CSV download.
func (a *API) ExportAudit(w http.ResponseWriter, r *http.Request) {
	sql, args := buildAuditQuery(r.URL.Query(), 100000)
	rows, err := a.DB.Query(sql, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", `attachment; filename="shellwarden-audit.csv"`)

	cw := csv.NewWriter(w)
	defer cw.Flush()
	_ = cw.Write([]string{"id", "ts", "event_type", "session_id", "server_id", "user_id", "data"})

	for rows.Next() {
		var l models.AuditLog
		if err := rows.Scan(&l.ID, &l.SessionID, &l.ServerID, &l.UserID, &l.EventType, &l.Data, &l.TS); err != nil {
			return
		}
		_ = cw.Write([]string{
			strconv.FormatInt(l.ID, 10),
			l.TS.Format("2006-01-02T15:04:05Z07:00"),
			l.EventType,
			deref(l.SessionID),
			deref(l.ServerID),
			deref(l.UserID),
			deref(l.Data),
		})
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
