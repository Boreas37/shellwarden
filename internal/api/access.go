package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/shellwarden/shellwarden/internal/auth"
	"github.com/shellwarden/shellwarden/internal/notify"
)

// AccessRequest is a JIT access request row.
type AccessRequest struct {
	ID          string  `json:"id"`
	UserID      *string `json:"user_id,omitempty"`
	Username    string  `json:"username,omitempty"`
	ServerID    string  `json:"server_id"`
	ServerName  string  `json:"server_name,omitempty"`
	Reason      *string `json:"reason,omitempty"`
	Status      string  `json:"status"`
	RequestedAt string  `json:"requested_at"`
	ExpiresAt   *string `json:"expires_at,omitempty"`
}

type accessReqBody struct {
	ServerID string `json:"server_id"`
	Reason   string `json:"reason"`
}

// RequestAccess creates a pending JIT access request for the caller.
func (a *API) RequestAccess(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFrom(r.Context())
	var body accessReqBody
	if err := decodeJSON(r, &body); err != nil || body.ServerID == "" {
		writeErr(w, http.StatusBadRequest, "server_id required")
		return
	}
	var id string
	var reason interface{}
	if body.Reason != "" {
		reason = body.Reason
	}
	err := a.DB.QueryRow(
		`INSERT INTO access_requests (user_id, server_id, reason) VALUES ($1, $2, $3) RETURNING id`,
		claims.UserID, body.ServerID, reason,
	).Scan(&id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not create request")
		return
	}
	a.emit(notify.Event{
		Type: "access.requested", Severity: "info", User: claims.Username,
		Server: body.ServerID, Message: body.Reason,
		Data: map[string]interface{}{"request_id": id},
	})
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "pending"})
}

// ListAccessRequests lists requests. Admins see all; others see their own.
func (a *API) ListAccessRequests(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFrom(r.Context())

	q := `SELECT ar.id, ar.user_id, COALESCE(u.username,''), ar.server_id, COALESCE(s.name,''),
	             ar.reason, ar.status, ar.requested_at, ar.expires_at
	      FROM access_requests ar
	      LEFT JOIN users u ON u.id = ar.user_id
	      LEFT JOIN servers s ON s.id = ar.server_id`
	args := []interface{}{}
	if claims.Role != RoleAdmin {
		q += ` WHERE ar.user_id = $1`
		args = append(args, claims.UserID)
	}
	q += ` ORDER BY ar.requested_at DESC LIMIT 200`

	rows, err := a.DB.Query(q, args...)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	out := []AccessRequest{}
	for rows.Next() {
		var ar AccessRequest
		var requested, expires sql.NullTime
		if err := rows.Scan(&ar.ID, &ar.UserID, &ar.Username, &ar.ServerID, &ar.ServerName,
			&ar.Reason, &ar.Status, &requested, &expires); err != nil {
			writeErr(w, http.StatusInternalServerError, "scan error")
			return
		}
		if requested.Valid {
			ar.RequestedAt = requested.Time.Format(time.RFC3339)
		}
		if expires.Valid {
			e := expires.Time.Format(time.RFC3339)
			ar.ExpiresAt = &e
		}
		out = append(out, ar)
	}
	writeJSON(w, http.StatusOK, out)
}

type approveBody struct {
	Minutes int `json:"minutes"`
}

// ApproveAccess grants a request for N minutes (admin only).
func (a *API) ApproveAccess(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFrom(r.Context())
	id := mux.Vars(r)["id"]
	var body approveBody
	_ = decodeJSON(r, &body)
	if body.Minutes <= 0 {
		body.Minutes = 60
	}
	res, err := a.DB.Exec(
		`UPDATE access_requests
		 SET status='approved', decided_by=$1, decided_at=NOW(), expires_at=NOW() + ($2 || ' minutes')::interval
		 WHERE id=$3 AND status='pending'`,
		claims.UserID, body.Minutes, id,
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "request not pending")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"status": "approved", "minutes": body.Minutes})
}

// DenyAccess denies a pending request (admin only).
func (a *API) DenyAccess(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFrom(r.Context())
	id := mux.Vars(r)["id"]
	res, err := a.DB.Exec(
		`UPDATE access_requests SET status='denied', decided_by=$1, decided_at=NOW()
		 WHERE id=$2 AND status='pending'`,
		claims.UserID, id,
	)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, http.StatusNotFound, "request not pending")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
}
