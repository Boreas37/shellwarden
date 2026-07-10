package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// CommandEntry is one reconstructed command line in a session.
type CommandEntry struct {
	OffsetSec float64 `json:"offset_sec"` // seconds from session start (for replay seek)
	TS        string  `json:"ts"`
	Command   string  `json:"command"`
}

// SessionCommands reconstructs the command timeline from recorded keystrokes so
// auditors can scan a session and jump the replay to any command.
func (a *API) SessionCommands(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var started time.Time
	if err := a.DB.QueryRow(`SELECT started_at FROM sessions WHERE id = $1`, id).Scan(&started); err != nil {
		writeErr(w, http.StatusNotFound, "session not found")
		return
	}

	rows, err := a.DB.Query(
		`SELECT COALESCE(data,''), ts FROM audit_logs
		 WHERE session_id = $1 AND event_type = 'input' ORDER BY id ASC`, id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	out := []CommandEntry{}
	var buf []rune
	skippingANSI := false

	for rows.Next() {
		var data string
		var ts time.Time
		if rows.Scan(&data, &ts) != nil {
			continue
		}
		for _, b := range []byte(data) {
			switch {
			case skippingANSI:
				// CSI/escape sequence ends on a final byte in @..~ range.
				if (b >= 0x40 && b <= 0x7e) || b == 'm' {
					skippingANSI = false
				}
			case b == 0x1b: // ESC — start of an escape sequence (arrows, etc.)
				skippingANSI = true
			case b == '\r' || b == '\n':
				cmd := strings.TrimSpace(string(buf))
				buf = buf[:0]
				if cmd != "" {
					out = append(out, CommandEntry{
						OffsetSec: ts.Sub(started).Seconds(),
						TS:        ts.Format(time.RFC3339),
						Command:   cmd,
					})
				}
			case b == 0x7f || b == 0x08: // backspace / delete
				if len(buf) > 0 {
					buf = buf[:len(buf)-1]
				}
			case b == '\t':
				// tab completion — best-effort; keep a marker space
				buf = append(buf, ' ')
			case b >= 0x20:
				buf = append(buf, rune(b))
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// CommandSearch finds sessions whose recorded activity matches a term (searches
// the echoed output stream so multi-character commands are found).
func (a *API) CommandSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}
	rows, err := a.DB.Query(`
		SELECT DISTINCT ON (al.session_id) al.session_id, al.ts,
		       COALESCE(sv.name,''), COALESCE(u.username,'')
		FROM audit_logs al
		LEFT JOIN sessions se ON se.id = al.session_id
		LEFT JOIN servers sv ON sv.id = se.server_id
		LEFT JOIN users u ON u.id = se.user_id
		WHERE al.event_type='output' AND al.session_id IS NOT NULL AND al.data ILIKE $1
		ORDER BY al.session_id, al.ts DESC LIMIT 100`, "%"+q+"%")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	type hit struct {
		SessionID string `json:"session_id"`
		TS        string `json:"ts"`
		Server    string `json:"server"`
		User      string `json:"user"`
	}
	out := []hit{}
	for rows.Next() {
		var h hit
		var ts time.Time
		if rows.Scan(&h.SessionID, &ts, &h.Server, &h.User) == nil {
			h.TS = ts.Format(time.RFC3339)
			out = append(out, h)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
