package auth

import (
	"context"
	"net/http"
	"strings"
)

type ctxKey string

// claimsKey is the context key under which authenticated claims are stored.
const claimsKey ctxKey = "claims"

// Middleware returns an http.Handler wrapper that requires a valid Bearer JWT.
// On success it injects the parsed claims into the request context.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			http.Error(w, "missing authorization", http.StatusUnauthorized)
			return
		}
		claims, err := m.Parse(token)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// extractToken pulls a JWT from the Authorization header or, as a fallback for
// WebSocket connections that cannot set headers easily, a ?token= query param.
func extractToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return r.URL.Query().Get("token")
}

// ClaimsFrom retrieves the authenticated claims from a request context.
func ClaimsFrom(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*Claims)
	return c, ok
}
