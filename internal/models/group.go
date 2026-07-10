package models

import "time"

// ServerGroup is a named collection of servers for bulk operations.
type ServerGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	// Members is optionally populated by handlers that join group_members.
	Members []string `json:"members,omitempty"`
}

// BulkJob is a fan-out command execution across a group of servers.
type BulkJob struct {
	ID        string    `json:"id"`
	UserID    *string   `json:"user_id,omitempty"`
	GroupID   *string   `json:"group_id,omitempty"`
	Command   string    `json:"command"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

// BulkResult is the outcome of running a bulk job's command on one server.
type BulkResult struct {
	ID         int64     `json:"id"`
	JobID      string    `json:"job_id"`
	ServerID   string    `json:"server_id"`
	ServerName string    `json:"server_name,omitempty"`
	Status     string    `json:"status"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	ExitCode   int       `json:"exit_code"`
	DurationMS int       `json:"duration_ms"`
	CreatedAt  time.Time `json:"created_at"`
}

// Bulk result statuses.
const (
	BulkStatusOK          = "ok"
	BulkStatusError       = "error"
	BulkStatusUnreachable = "unreachable"
	BulkStatusTimeout     = "timeout"
)
