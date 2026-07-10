-- Append-only, tamper-evident audit chain.
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS hash TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS prev_hash TEXT;

-- Latest agent-reported host telemetry (load/mem/disk/uptime as JSON).
ALTER TABLE servers ADD COLUMN IF NOT EXISTS metrics TEXT;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS metrics_at TIMESTAMPTZ;
