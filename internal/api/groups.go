package api

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/shellwarden/shellwarden/internal/models"
)

// ListGroups returns all groups with their member server ids.
func (a *API) ListGroups(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.DB.Query(`SELECT id, name, description, created_at FROM server_groups ORDER BY name`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	groups := []models.ServerGroup{}
	for rows.Next() {
		var g models.ServerGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "scan error")
			return
		}
		g.Members = a.groupMembers(g.ID)
		groups = append(groups, g)
	}
	writeJSON(w, http.StatusOK, groups)
}

func (a *API) groupMembers(groupID string) []string {
	rows, err := a.DB.Query(`SELECT server_id FROM group_members WHERE group_id = $1`, groupID)
	if err != nil {
		return []string{}
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			out = append(out, id)
		}
	}
	return out
}

type groupReq struct {
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

// CreateGroup creates a new server group.
func (a *API) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var req groupReq
	if err := decodeJSON(r, &req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name required")
		return
	}
	var g models.ServerGroup
	err := a.DB.QueryRow(
		`INSERT INTO server_groups (name, description) VALUES ($1, $2)
		 RETURNING id, name, description, created_at`,
		req.Name, req.Description,
	).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not create group (duplicate?)")
		return
	}
	g.Members = []string{}
	writeJSON(w, http.StatusCreated, g)
}

// UpdateGroup renames or re-describes a group.
func (a *API) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req groupReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	var g models.ServerGroup
	err := a.DB.QueryRow(
		`UPDATE server_groups SET name=$1, description=$2 WHERE id=$3
		 RETURNING id, name, description, created_at`,
		req.Name, req.Description, id,
	).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt)
	if err == sql.ErrNoRows {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusBadRequest, "could not update group")
		return
	}
	g.Members = a.groupMembers(g.ID)
	writeJSON(w, http.StatusOK, g)
}

// DeleteGroup removes a group (cascades membership rows).
func (a *API) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := a.DB.Exec(`DELETE FROM server_groups WHERE id = $1`, id); err != nil {
		writeErr(w, http.StatusBadRequest, "could not delete group")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type memberReq struct {
	ServerID string `json:"server_id"`
}

// AddMember adds a server to a group.
func (a *API) AddMember(w http.ResponseWriter, r *http.Request) {
	groupID := mux.Vars(r)["id"]
	var req memberReq
	if err := decodeJSON(r, &req); err != nil || req.ServerID == "" {
		writeErr(w, http.StatusBadRequest, "server_id required")
		return
	}
	_, err := a.DB.Exec(
		`INSERT INTO group_members (group_id, server_id) VALUES ($1, $2)
		 ON CONFLICT DO NOTHING`,
		groupID, req.ServerID,
	)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not add member")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// RemoveMember removes a server from a group.
func (a *API) RemoveMember(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	_, err := a.DB.Exec(
		`DELETE FROM group_members WHERE group_id = $1 AND server_id = $2`,
		vars["id"], vars["server_id"],
	)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not remove member")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
