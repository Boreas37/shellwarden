package models

import "time"

// Connection modes (see CLAUDE.md "Connection Modes").
const (
	ModeAgent  = "agent"
	ModeDirect = "direct"
)

// Server statuses.
const (
	StatusOnline  = "online"
	StatusOffline = "offline"
	StatusUnknown = "unknown"
)

// Server is a managed target host reachable over SSH or RDP.
type Server struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Host             string     `json:"host"`
	Port             int        `json:"port"`
	Protocol         string     `json:"protocol"`
	ConnectionMode   string     `json:"connection_mode"`
	AgentToken       *string    `json:"agent_token,omitempty"`
	AgentConnectedAt *time.Time `json:"agent_connected_at,omitempty"`
	Status           string     `json:"status"`
	OSInfo           *string    `json:"os_info,omitempty"`
	SSHUser          *string    `json:"ssh_user,omitempty"`
	SSHKey           *string    `json:"-"` // private key material, never serialized (encrypted at rest)
	SSHPassword      *string    `json:"-"` // password, never serialized out (encrypted at rest)
	SSHHostKey       *string    `json:"-"` // pinned host key (TOFU), not a secret
	// HasSSHKey / HasSSHPassword expose whether credentials are stored without
	// leaking the secrets themselves.
	HasSSHKey      bool       `json:"has_ssh_key"`
	HasSSHPassword bool       `json:"has_ssh_password"`
	Metrics        *string    `json:"metrics,omitempty"` // latest host telemetry (JSON)
	MetricsAt      *time.Time `json:"metrics_at,omitempty"`
	UseSSHCA       bool       `json:"use_ssh_ca"`
	VulnCount      int        `json:"vuln_count"`
	VulnCritical   int        `json:"vuln_critical"`
	VulnScannedAt  *time.Time `json:"vuln_scanned_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}
