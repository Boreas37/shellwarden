package models

import "time"

// User is an operator or admin of the ShellWarden gateway.
type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	MFAEnabled   bool      `json:"mfa_enabled"`
	TOTPSecret   string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}
