import { useEffect, useState } from "react";
import Modal from "../../components/Modal";
import Chart from "../../components/Chart";
import { api, MetricPoint, VulnScan, Server } from "../../api/client";

type Tab = "metrics" | "vulns";

function sevBadge(s: string) {
  const cls =
    s === "critical" || s === "high" ? "error" : s === "medium" ? "running" : s === "low" ? "ok" : "poll";
  return <span className={`badge ${cls}`}>{s}</span>;
}

export default function ServerDetailModal({ server, onClose }: { server: Server; onClose: () => void }) {
  const [tab, setTab] = useState<Tab>("metrics");
  const [metrics, setMetrics] = useState<MetricPoint[]>([]);
  const [vulns, setVulns] = useState<VulnScan | null>(null);
  const [scanned, setScanned] = useState<boolean | null>(null);
  const [q, setQ] = useState("");

  useEffect(() => {
    const load = () => api.serverMetrics(server.id, 60).then(setMetrics).catch(() => {});
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [server.id]);

  useEffect(() => {
    api.serverVulns(server.id).then((r) => {
      setScanned(r.scanned);
      setVulns(r.scan ?? null);
    });
  }, [server.id]);

  const sev: Record<string, number> = {};
  (vulns?.findings ?? []).forEach((f) => (sev[f.severity] = (sev[f.severity] ?? 0) + 1));
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
  const findings = (vulns?.findings ?? [])
    .filter(
      (f) => !q || f.id.toLowerCase().includes(q.toLowerCase()) || f.package.toLowerCase().includes(q.toLowerCase())
    )
    .sort((a, b) => (rank[a.severity] ?? 4) - (rank[b.severity] ?? 4));

  return (
    <Modal kicker="host" title={server.name} onClose={onClose} wide>
      <div className="toolbar" style={{ marginBottom: 16 }}>
        <button className={tab === "metrics" ? "btn" : "btn ghost"} onClick={() => setTab("metrics")}>
          Resources
        </button>
        <button className={tab === "vulns" ? "btn" : "btn ghost"} onClick={() => setTab("vulns")}>
          Vulnerabilities{server.vuln_count ? ` (${server.vuln_count})` : ""}
        </button>
      </div>

      {tab === "metrics" && (
        <>
          {metrics.length === 0 && <p className="ops-empty">No metrics yet (agent reports every 30s).</p>}
          {metrics.length > 0 && (
            <div className="metric-grid">
              <Chart label="CPU" unit="%" max={100} color="#ffb000" values={metrics.map((m) => m.cpu_pct)} />
              <Chart label="Memory used" unit="%" max={100} color="#38c6d9" values={metrics.map((m) => m.mem_used_pct)} />
              <Chart label="Disk used" unit="%" max={100} color="#38d39f" values={metrics.map((m) => m.disk_used_pct)} />
              <Chart label="Load (1m)" color="#ffc14d" values={metrics.map((m) => m.load1)} />
              <Chart label="Net in" unit=" KB/s" color="#4f9cff" values={metrics.map((m) => m.net_rx_kbs)} />
              <Chart label="Net out" unit=" KB/s" color="#c08cff" values={metrics.map((m) => m.net_tx_kbs)} />
            </div>
          )}
        </>
      )}

      {tab === "vulns" && (
        <>
          {scanned === false && (
            <p className="ops-empty">
              Not scanned yet. The agent runs a distro-native scan shortly after connecting (and every 6h).
            </p>
          )}
          {vulns && (
            <>
              <div className="vuln-summary">
                <span>
                  <b>{vulns.findings.length}</b> known CVEs
                </span>
                <span>
                  <b>{vulns.security_updates}</b> security updates
                </span>
                <span>
                  <b>{vulns.upgradable}</b> upgradable
                </span>
                <span className="vuln-tool">via {vulns.tool}</span>
                {Object.entries(sev).map(([k, v]) => (
                  <span key={k}>
                    {sevBadge(k)} {v}
                  </span>
                ))}
              </div>
              {vulns.note && <p style={{ color: "var(--fg-faint)", fontSize: 12 }}>{vulns.note}</p>}

              <input
                placeholder="Filter CVE / package…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                style={{ width: "100%", margin: "8px 0 12px" }}
              />
              <div style={{ maxHeight: "48vh", overflowY: "auto" }}>
                <table>
                  <thead>
                    <tr>
                      <th>CVE</th>
                      <th>Package</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f, i) => (
                      <tr key={i}>
                        <td className="mono">
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${f.id}`}
                            target="_blank"
                            rel="noreferrer"
                          >
                            {f.id}
                          </a>
                        </td>
                        <td>{f.package}</td>
                        <td>{sevBadge(f.severity)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </Modal>
  );
}
