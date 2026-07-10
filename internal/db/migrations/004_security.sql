-- Host-key pinning (TOFU): the learned/expected SSH host key per server.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS ssh_host_key TEXT;

-- Reason/ticket attached to an interactive session (compliance).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS reason TEXT;
