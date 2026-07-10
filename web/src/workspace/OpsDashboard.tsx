import { useEffect, useState } from "react";
import { api, DashboardData, isAdmin } from "../api/client";
import { IconActivity, IconShield } from "../components/icons";
import { eventMeta, describeEvent } from "../lib/events";

function dur(from: string): string {
  const s = Math.max(0, Math.floor((Date.now() - +new Date(from)) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function toneClass(tone: string): string {
  return tone === "bad" ? "ev-bad" : tone === "ok" ? "ev-ok" : tone === "info" ? "ev-info" : "ev-dim";
}

export default function OpsDashboard({ onWatch }: { onWatch: (id: string) => void }) {
  const [d, setD] = useState<DashboardData | null>(null);
  const [error, setError] = useState("");

  async function load() {
    try {
      setD(await api.dashboard());
      setError("");
    } catch (e) {
      setError(String(e));
    }
  }
  useEffect(() => {
    load();
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, []);

  async function terminate(id: string) {
    if (!confirm("Terminate this live session?")) return;
    await api.terminateSession(id).catch(() => {});
    load();
  }

  if (!d) {
    return (
      <div className="welcome">
        <IconShield className="glyph" />
        <h3>{error ? "dashboard error" : "loading operations…"}</h3>
      </div>
    );
  }

  const maxAct = Math.max(1, ...d.activity_24h.map((a) => a.count));
  const s = d.stats;

  return (
    <div className="ops">
      <div className="ops-head">
        <h2>
          <IconActivity /> Operations
        </h2>
        <span className="ops-live">● live</span>
      </div>

      <div className="ops-stats">
        <Stat label="Hosts online" value={`${s.hosts_online}/${s.hosts_total}`} />
        <Stat label="Agents" value={s.agents} />
        <Stat label="Active sessions" value={s.active_sessions} accent={s.active_sessions > 0} />
        <Stat label="Sessions 24h" value={s.sessions_24h} />
        <Stat label="Failed logins 24h" value={s.failed_logins_24h} danger={s.failed_logins_24h > 0} />
      </div>

      <div className="ops-grid">
        <div className="ops-card">
          <h3>Active sessions</h3>
          {d.active_sessions.length === 0 && <p className="ops-empty">No active sessions.</p>}
          {d.active_sessions.map((a) => (
            <div className="ops-row" key={a.id}>
              <span className="dot online" />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div className="ops-row-main">
                  {a.user || "—"} <span className="ops-arrow">→</span> {a.server}
                </div>
                <div className="ops-row-sub">
                  {a.protocol} · {dur(a.started_at)}
                </div>
              </div>
              <button className="btn ghost sm" onClick={() => onWatch(a.id)}>
                Watch
              </button>
              {isAdmin() && (
                <button className="btn danger sm" onClick={() => terminate(a.id)}>
                  Kill
                </button>
              )}
            </div>
          ))}
        </div>

        <div className="ops-card">
          <h3>Activity (24h)</h3>
          <div className="ops-bars">
            {d.activity_24h.length === 0 && <p className="ops-empty">No sessions in the last 24h.</p>}
            {d.activity_24h.map((a) => (
              <div className="ops-bar" key={a.hour} title={`${a.hour}: ${a.count}`}>
                <div className="ops-bar-fill" style={{ height: `${(a.count / maxAct) * 100}%` }} />
                <span className="ops-bar-x">{a.hour.slice(11, 13)}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="ops-card ops-feed">
          <h3>Recent events</h3>
          {d.recent_events.map((e, i) => {
            const m = eventMeta(e.event_type);
            return (
              <div className={`ops-event ${toneClass(m.tone)}`} key={i}>
                <span className="ops-event-t">{new Date(e.ts).toLocaleTimeString()}</span>
                <span className="ops-event-type">{m.label}</span>
                <span className="ops-event-d">{describeEvent(e.event_type, e.detail, e.user, e.server)}</span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  accent,
  danger,
}: {
  label: string;
  value: string | number;
  accent?: boolean;
  danger?: boolean;
}) {
  return (
    <div className={`ops-stat ${accent ? "accent" : ""} ${danger ? "danger" : ""}`}>
      <div className="ops-stat-v">{value}</div>
      <div className="ops-stat-l">{label}</div>
    </div>
  );
}
