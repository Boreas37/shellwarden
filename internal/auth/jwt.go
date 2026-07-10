package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// tokenTTL is how long an issued JWT remains valid.
const tokenTTL = 12 * time.Hour

// Claims is the JWT payload carried by an authenticated session.
type Claims struct {
	UserID   string `json:"uid"`
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Manager issues and validates JWTs using a shared HMAC secret.
type Manager struct {
	secret []byte
}

// NewManager builds a JWT manager from the configured secret.
func NewManager(secret string) *Manager {
	return &Manager{secret: []byte(secret)}
}

// Issue creates a signed JWT for the given user.
func (m *Manager) Issue(userID, username, role string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

// Parse validates a token string and returns its claims.
func (m *Manager) Parse(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return m.secret, nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}
