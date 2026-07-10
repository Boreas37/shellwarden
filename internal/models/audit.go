package models

import "time"

// Audit event types.
const (
	EventSessionStart = "session_start"
	EventSessionEnd   = "session_end"
	EventOutput       = "output"
	EventInput        = "input"
)

// AuditLog is a single recorded event within a session (real-time stream).
type AuditLog struct {
	ID        int64     `json:"id"`
	SessionID *string   `json:"session_id,omitempty"`
	ServerID  *string   `json:"server_id,omitempty"`
	UserID    *string   `json:"user_id,omitempty"`
	EventType string    `json:"event_type"`
	Data      *string   `json:"data,omitempty"`
	TS        time.Time `json:"ts"`
}
