-- Gateway key/value settings (used to persist the auto-generated SSH CA key).
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- When true, the gateway authenticates to this host using a short-lived,
-- CA-signed certificate instead of stored credentials.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS use_ssh_ca BOOLEAN NOT NULL DEFAULT FALSE;
