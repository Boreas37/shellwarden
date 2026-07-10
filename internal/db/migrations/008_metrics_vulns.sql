-- Time-series host metrics for the resource dashboard.
CREATE TABLE IF NOT EXISTS server_metrics (
    id BIGSERIAL PRIMARY KEY,
    server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cpu_pct DOUBLE PRECISION,
    mem_used_pct DOUBLE PRECISION,
    disk_used_pct DOUBLE PRECISION,
    net_rx_kbs DOUBLE PRECISION,
    net_tx_kbs DOUBLE PRECISION,
    load1 DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS idx_server_metrics_lookup ON server_metrics(server_id, ts DESC);

-- Latest vulnerability scan results per host.
ALTER TABLE servers ADD COLUMN IF NOT EXISTS vuln_scan TEXT;          -- full JSON
ALTER TABLE servers ADD COLUMN IF NOT EXISTS vuln_scanned_at TIMESTAMPTZ;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS vuln_count INT NOT NULL DEFAULT 0;
ALTER TABLE servers ADD COLUMN IF NOT EXISTS vuln_critical INT NOT NULL DEFAULT 0;
