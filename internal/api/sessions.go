package api

import (
	"database/sql"
	"net/http"
	"path/filepath"

	"github.com/gorilla/mux"

	"github.com/shellwarden/shellwarden/internal/models"
)

const sessionCols = `id, server_id, user_id, protocol, started_at, ended_at,
	recording_path, reason, bytes_read, bytes_written`

func scanSession(row interface{ Scan(...interface{}) error }) (*models.Session, error) {
	s := &models.Session{}
	err := row.Scan(
		&s.ID, &s.ServerID, &s.UserID, &s.Protocol, &s.StartedAt, &s.EndedAt,
		&s.RecordingPath, &s.Reason, &s.BytesRead, &s.BytesWritten,
	)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ListSessions returns recent sessions, newest first.
func (a *API) ListSessions(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.DB.Query(`SELECT ` + sessionCols + ` FROM sessions ORDER BY started_at DESC LIMIT 500`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	sessions := []models.Session{}
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "scan error")
			return
		}
		sessions = append(sessions, *s)
	}
	writeJSON(w, http.StatusOK, sessions)
}

// GetSession returns one session by id.
func (a *API) GetSession(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s, err := scanSession(a.DB.QueryRow(`SELECT `+sessionCols+` FROM sessions WHERE id = $1`, id))
	if err == sql.ErrNoRows {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// TerminateSession forcibly ends a live session (admin action).
func (a *API) TerminateSession(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if a.SSHProxy == nil || a.SSHProxy.Hub == nil || !a.SSHProxy.Hub.Kill(id) {
		writeErr(w, http.StatusNotFound, "session not live")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "terminated"})
}

// GetSessionCast streams the asciinema v2 recording for a session so the SPA's
// player can replay it. Path is derived from RECORDING_PATH + session id (the
// id is a UUID from the route, so no traversal risk).
func (a *API) GetSessionCast(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	path := filepath.Join(a.Cfg.RecordingPath, id+".cast")
	w.Header().Set("Content-Type", "application/x-asciicast")
	http.ServeFile(w, r, path)
}
