package api

import (
	"database/sql"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/shellwarden/shellwarden/internal/auth"
	"github.com/shellwarden/shellwarden/internal/models"
)

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Code     string `json:"code"` // TOTP, required when MFA is enabled
}

type loginResp struct {
	Token string      `json:"token"`
	User  models.User `json:"user"`
}

// Login authenticates a user (password + optional TOTP) and returns a JWT.
func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := decodeJSON(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}

	var u models.User
	var totp sql.NullString
	err := a.DB.QueryRow(
		`SELECT id, username, password_hash, role, mfa_enabled, COALESCE(totp_secret,''), created_at
		 FROM users WHERE username = $1`,
		req.Username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.MFAEnabled, &totp, &u.CreatedAt)
	if err == sql.ErrNoRows {
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	} else if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		a.onLoginFailure(req.Username, time.Now())
		writeErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Second factor.
	if u.MFAEnabled {
		if req.Code == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "mfa_required"})
			return
		}
		if !auth.ValidateTOTP(totp.String, req.Code) {
			writeErr(w, http.StatusUnauthorized, "invalid mfa code")
			return
		}
	}

	token, err := a.JWT.Issue(u.ID, u.Username, u.Role)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token error")
		return
	}
	writeJSON(w, http.StatusOK, loginResp{Token: token, User: u})
}

// MFASetup generates (but does not enable) a new TOTP secret for the caller and
// returns the secret + otpauth URL for QR enrollment.
func (a *API) MFASetup(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFrom(r.Context())
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "secret error")
		return
	}
	if _, err := a.DB.Exec(`UPDATE users SET totp_secret = $1 WHERE id = $2`, secret, claims.UserID); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":  secret,
		"otpauth": auth.OTPAuthURL("ShellWarden", claims.Username, secret),
	})
}

type codeReq struct {
	Code string `json:"code"`
}

// MFAEnable verifies a code against the staged secret and turns MFA on.
func (a *API) MFAEnable(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFrom(r.Context())
	var req codeReq
	_ = decodeJSON(r, &req)

	var secret sql.NullString
	if err := a.DB.QueryRow(`SELECT totp_secret FROM users WHERE id = $1`, claims.UserID).Scan(&secret); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if !secret.Valid || !auth.ValidateTOTP(secret.String, req.Code) {
		writeErr(w, http.StatusBadRequest, "invalid code")
		return
	}
	if _, err := a.DB.Exec(`UPDATE users SET mfa_enabled = TRUE WHERE id = $1`, claims.UserID); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "enabled"})
}

// MFADisable turns MFA off after verifying a current code.
func (a *API) MFADisable(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.ClaimsFrom(r.Context())
	var req codeReq
	_ = decodeJSON(r, &req)

	var secret sql.NullString
	if err := a.DB.QueryRow(`SELECT totp_secret FROM users WHERE id = $1`, claims.UserID).Scan(&secret); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if !secret.Valid || !auth.ValidateTOTP(secret.String, req.Code) {
		writeErr(w, http.StatusBadRequest, "invalid code")
		return
	}
	if _, err := a.DB.Exec(`UPDATE users SET mfa_enabled = FALSE, totp_secret = NULL WHERE id = $1`, claims.UserID); err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

// Logout is a no-op for stateless JWTs (client discards the token).
// TODO: add a server-side token denylist if logout-before-expiry is required.
func (a *API) Logout(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ListUsers returns all users (without password hashes).
func (a *API) ListUsers(w http.ResponseWriter, _ *http.Request) {
	rows, err := a.DB.Query(`SELECT id, username, role, created_at FROM users ORDER BY created_at`)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	defer rows.Close()

	users := []models.User{}
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			writeErr(w, http.StatusInternalServerError, "scan error")
			return
		}
		users = append(users, u)
	}
	writeJSON(w, http.StatusOK, users)
}

type createUserReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// CreateUser creates a new operator/admin user.
func (a *API) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserReq
	if err := decodeJSON(r, &req); err != nil || req.Username == "" || req.Password == "" {
		writeErr(w, http.StatusBadRequest, "username and password required")
		return
	}
	if req.Role == "" {
		req.Role = "operator"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "hash error")
		return
	}

	var u models.User
	err = a.DB.QueryRow(
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3)
		 RETURNING id, username, role, created_at`,
		req.Username, string(hash), req.Role,
	).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "could not create user (duplicate?)")
		return
	}
	writeJSON(w, http.StatusCreated, u)
}
