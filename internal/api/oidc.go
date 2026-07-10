package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/shellwarden/shellwarden/internal/notify"
)

// OIDC implements the authorization-code SSO flow against any OpenID Connect
// provider (Okta, Azure AD, Google, Keycloak…). Enabled when the issuer +
// client id are configured.
type OIDC struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	enabled  bool
}

// initOIDC builds the OIDC client if configured. Safe to call when disabled.
func (a *API) initOIDC() {
	a.oidc = &OIDC{}
	if a.Cfg.OIDCIssuer == "" || a.Cfg.OIDCClientID == "" {
		return
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, a.Cfg.OIDCIssuer)
	if err != nil {
		log.Printf("OIDC disabled — discovery failed: %v", err)
		return
	}
	a.oidc = &OIDC{
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: a.Cfg.OIDCClientID}),
		oauth: &oauth2.Config{
			ClientID:     a.Cfg.OIDCClientID,
			ClientSecret: a.Cfg.OIDCClientSecret,
			RedirectURL:  a.Cfg.OIDCRedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		enabled: true,
	}
	log.Println("OIDC SSO enabled")
}

// AuthMethods reports which login methods are available (consumed by the SPA).
func (a *API) AuthMethods(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"password": true,
		"oidc":     a.oidc != nil && a.oidc.enabled,
	})
}

// OIDCLogin redirects the browser to the IdP, carrying a signed state cookie.
func (a *API) OIDCLogin(w http.ResponseWriter, r *http.Request) {
	if a.oidc == nil || !a.oidc.enabled {
		writeErr(w, http.StatusNotFound, "oidc not configured")
		return
	}
	state := randToken()
	http.SetCookie(w, &http.Cookie{
		Name: "sw_oidc_state", Value: state, Path: "/", MaxAge: 300,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, a.oidc.oauth.AuthCodeURL(state), http.StatusFound)
}

// OIDCCallback exchanges the code, verifies the ID token, maps to a user, and
// redirects to the SPA with a ShellWarden JWT in the URL fragment.
func (a *API) OIDCCallback(w http.ResponseWriter, r *http.Request) {
	if a.oidc == nil || !a.oidc.enabled {
		writeErr(w, http.StatusNotFound, "oidc not configured")
		return
	}
	ctx := r.Context()

	cookie, err := r.Cookie("sw_oidc_state")
	if err != nil || cookie.Value != r.URL.Query().Get("state") {
		writeErr(w, http.StatusBadRequest, "invalid state")
		return
	}
	oauth2Token, err := a.oidc.oauth.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "code exchange failed")
		return
	}
	rawID, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "no id_token")
		return
	}
	idToken, err := a.oidc.verifier.Verify(ctx, rawID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "id_token verification failed")
		return
	}
	var claims struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Subject  string `json:"sub"`
		Username string `json:"preferred_username"`
	}
	_ = idToken.Claims(&claims)

	username := claims.Email
	if username == "" {
		username = claims.Username
	}
	if username == "" {
		username = claims.Subject
	}

	user, err := a.upsertSSOUser(username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "user provisioning failed")
		return
	}
	token, err := a.JWT.Issue(user.ID, user.Username, user.Role)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "token error")
		return
	}
	a.emit(notify.Event{Type: "auth.sso_login", Severity: "info", User: user.Username})

	// Hand the token to the SPA via fragment (not sent to servers/logs).
	http.Redirect(w, r, "/login#token="+token+"&role="+user.Role, http.StatusFound)
}

// upsertSSOUser finds or creates a user provisioned via SSO (default role:
// operator). Just-in-time provisioning; promote to admin manually.
func (a *API) upsertSSOUser(username string) (*ssoUser, error) {
	var u ssoUser
	err := a.DB.QueryRow(`SELECT id, username, role FROM users WHERE username = $1`, username).
		Scan(&u.ID, &u.Username, &u.Role)
	if err == nil {
		return &u, nil
	}
	// Create with a random unusable password (SSO-only account).
	err = a.DB.QueryRow(
		`INSERT INTO users (username, password_hash, role) VALUES ($1, $2, 'operator')
		 RETURNING id, username, role`,
		username, "!sso-"+randToken(),
	).Scan(&u.ID, &u.Username, &u.Role)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

type ssoUser struct {
	ID       string
	Username string
	Role     string
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

var _ = time.Now // reserved for future token-expiry checks
