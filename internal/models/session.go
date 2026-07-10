package models

import "time"

// Session is a single interactive SSH or RDP connection by a user to a server.
type Session struct {
	ID            string     `json:"id"`
	ServerID      string     `json:"server_id"`
	UserID        string     `json:"user_id"`
	Protocol      string     `json:"protocol"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	RecordingPath *string    `json:"recording_path,omitempty"`
	Reason        *string    `json:"reason,omitempty"`
	BytesRead     int64      `json:"bytes_read"`
	BytesWritten  int64      `json:"bytes_written"`
}
