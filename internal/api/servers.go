package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/ssh"

	"github.com/shellwarden/shellwarden/internal/models"
)

// validatePrivateKey returns an error if a non-empty key cannot be parsed.
// An empty/nil key is allowed (means "no key" / "leave unchanged").
func validatePrivateKey(key *string) error {
	if key == nil || *key == "" {
		return nil
	}
	_, err := ssh.ParsePrivateKey([]byte(*key))
	return err
}

const serverCols = `id, name, host, port, protocol, connection_mode, agent_token,
	agent_connected_at, status, os_info, ssh_user, ssh_key, ssh_password, ssh_host_key,
	created_at, metrics, metrics_at, use_ssh_ca, vuln_count, vuln_critical, vuln_scanned_at`

func scanServer(row interface{ Scan(...interface{}) error }) (*models.Server, error) {
	s := &models.Server{}
	err := row.Scan(
		&s.ID, &s.Name, &s.Host, &s.Port, &s.Protocol, &s.ConnectionMode, &s.AgentToken,
		&s.AgentConnectedAt, &s.Status, &s.OSInfo, &s.SSHUser, &s.SSHKey, &s.SSHPassword, &s.SSHHostKey,
		&s.CreatedAt, &s.Metrics, &s.MetricsAt, &s.UseSSHCA, &s.VulnCount, &s.VulnCritical, &s.VulnScannedAt,
	)
	if err != nil {
		return nil, err
	}
	s.HasSSHKey = s.SSHKey != nil && *s.SSHKey != ""
	s.HasSSHPassword = s.SSHPassword != nil && *s.SSHPassword != ""
	return s, nil
}

// ListServers returns all registered servers.
func (a *API) ListServers(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.DB.Query(`SELECT ` + serverCols + ` FROM servers ORDER BY created_at DESC`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	servers := []models.Server{}
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "scan error")
			return
		}
		servers = append(servers, *s)
	}
	writeJSON(w, http.StatusOK, servers)
}

// GetServer returns a single server by id.
func (a *API) GetServer(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s, err := scanServer(a.DB.QueryRow(`SELECT `+serverCols+` FROM servers WHERE id = $1`, id))
	if err == sql.ErrNoRows {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

type serverReq struct {
	Name           string  `json:"name"`
	Host           string  `json:"host"`
	Port           int     `json:"port"`
	Protocol       string  `json:"protocol"`
	ConnectionMode string  `json:"connection_mode"`
	OSInfo         *string `json:"os_info"`
	SSHUser        *string `json:"ssh_user"`
	SSHKey         *string `json:"ssh_key"`
	SSHPassword    *string `json:"ssh_password"`
	UseSSHCA       bool    `json:"use_ssh_ca"`
}

// CreateServer registers a new server. An agent_token is always minted so the
// host can be switched to agent mode later without a second call.
func (a *API) CreateServer(w http.ResponseWriter, r *http.Request) {
	var req serverReq
	if err := decodeJSON(r, &req); err != nil || req.Name == "" || req.Host == "" {
		writeErr(w, http.StatusBadRequest, "name and host required")
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.Protocol == "" {
		req.Protocol = "ssh"
	}
	if req.ConnectionMode == "" {
		req.ConnectionMode = models.ModeDirect
	}
	if err := validatePrivateKey(req.SSHKey); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid SSH private key: "+err.Error())
		return
	}

	token := newToken()
	s, err := scanServer(a.DB.QueryRow(
		`INSERT INTO servers (name, host, port, protocol, connection_mode, agent_token, os_info, ssh_user, ssh_key, ssh_password, use_ssh_ca)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING `+serverCols,
		req.Name, req.Host, req.Port, req.Protocol, req.ConnectionMode, token, req.OSInfo, req.SSHUser,
		a.Cipher.EncryptPtr(req.SSHKey), a.Cipher.EncryptPtr(req.SSHPassword), req.UseSSHCA,
	))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not create server")
		return
	}
	writeJSON(w, http.StatusCreated, s)
}

// UpdateServer updates mutable fields of a server.
func (a *API) UpdateServer(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req serverReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if err := validatePrivateKey(req.SSHKey); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid SSH private key: "+err.Error())
		return
	}

	s, err := scanServer(a.DB.QueryRow(
		`UPDATE servers SET name=$1, host=$2, port=$3, protocol=$4, connection_mode=$5,
		        os_info=$6, ssh_user=$7, ssh_key=COALESCE($8, ssh_key),
		        ssh_password=COALESCE($9, ssh_password), use_ssh_ca=$10
		 WHERE id=$11 RETURNING `+serverCols,
		req.Name, req.Host, req.Port, req.Protocol, req.ConnectionMode, req.OSInfo, req.SSHUser,
		a.Cipher.EncryptPtr(req.SSHKey), a.Cipher.EncryptPtr(req.SSHPassword), req.UseSSHCA, id,
	))
	if err == sql.ErrNoRows {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusBadRequest, "could not update server")
		return
	}
	writeJSON(w, http.StatusOK, s)
}

// DeleteServer removes a server.
func (a *API) DeleteServer(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := a.DB.Exec(`DELETE FROM servers WHERE id = $1`, id); err != nil {
		writeErr(w, http.StatusBadRequest, "could not delete (in use?)")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RotateToken issues a fresh agent token for a server.
func (a *API) RotateToken(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	token := newToken()
	var out string
	err := a.DB.QueryRow(
		`UPDATE servers SET agent_token = $1 WHERE id = $2 RETURNING agent_token`,
		token, id,
	).Scan(&out)
	if err == sql.ErrNoRows {
		writeErr(w, http.StatusNotFound, "not found")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"agent_token": out})
}

// newToken generates a 32-byte random hex token.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
