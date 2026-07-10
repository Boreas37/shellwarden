import { useEffect, useState } from "react";
import Modal from "../../components/Modal";
import { api, AuditLog, getToken } from "../../api/client";
import { IconDownload } from "../../components/icons";
import { eventMeta, describeEvent, Tone } from "../../lib/events";

const toneColor: Record<Tone, string> = {
  ok: "var(--green)",
  bad: "var(--red)",
  info: "var(--cyan)",
  dim: "var(--fg-dim)",
};

export default function AuditModal({ onClose }: { onClose: () => void }) {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [q, setQ] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [onlyExec, setOnlyExec] = useState(false);
  const [raw, setRaw] = useState(false); // include per-keystroke noise (forensics)
  const [error, setError] = useState("");
  const [verify, setVerify] = useState("");

  async function verifyChain() {
    setVerify("checking…");
    try {
      const r = await api.verifyAudit();
      setVerify(
        r.ok
          ? `✓ chain intact (${r.checked} rows)`
          : `✗ TAMPERED at id ${r.break_at_id}: ${r.break_error}`
      );
    } catch (e) {
      setVerify(String(e));
    }
  }

  function params(): Record<string, string> {
    const p: Record<string, string> = {};
    if (q) p.q = q;
    if (from) p.from = new Date(from).toISOString();
    if (to) p.to = new Date(to).toISOString();
    if (onlyExec) p.event_type = "host_exec";
    else if (!raw) p.human = "1"; // hide raw keystroke output/input by default
    return p;
  }

  async function load() {
    setError("");
    try {
      setLogs(await api.queryAudit(params()));
    } catch (e) {
      setError(String(e));
    }
  }

  function exportCsv() {
    const qs = new URLSearchParams({ ...params(), token: getToken() ?? "" }).toString();
    window.open(`/api/audit/export?${qs}`, "_blank");
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [raw, onlyExec]);

  return (
    <Modal kicker="audit" title="Audit log" onClose={onClose} wide>
      {error && <p className="error-text">{error}</p>}

      <div style={{ display: "flex", gap: 8, marginBottom: 10, alignItems: "center", flexWrap: "wrap" }}>
        <input
          style={{ flex: 1, minWidth: 180 }}
          placeholder="Search commands / output…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && load()}
        />
        <button className="btn" onClick={load}>
          Search
        </button>
        <button className="btn ghost" onClick={exportCsv} title="Export filtered rows as CSV">
          <IconDownload /> CSV
        </button>
        <button className="btn ghost" onClick={verifyChain} title="Verify the tamper-evident hash chain">
          Verify
        </button>
      </div>
      {verify && (
        <p className="mono" style={{ margin: "0 0 10px", color: verify.startsWith("✓") ? "var(--green)" : "var(--red)" }}>
          {verify}
        </p>
      )}
      <div style={{ display: "flex", gap: 8, marginBottom: 14, alignItems: "center", flexWrap: "wrap" }}>
        <label style={{ color: "var(--fg-faint)" }}>from</label>
        <input type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
        <label style={{ color: "var(--fg-faint)" }}>to</label>
        <input type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
        <label className={`chip ${onlyExec ? "on" : ""}`} onClick={() => setOnlyExec((v) => !v)}>
          host commands only
        </label>
        <label className={`chip ${raw ? "on" : ""}`} onClick={() => setRaw((v) => !v)} title="Show raw keystrokes & terminal output (forensics)">
          raw keystrokes
        </label>
      </div>

      <table>
        <thead>
          <tr>
            <th style={{ width: 90 }}>Time</th>
            <th style={{ width: 130 }}>Event</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((l) => {
            const m = eventMeta(l.event_type);
            const isRaw = l.event_type === "output" || l.event_type === "input";
            return (
              <tr key={l.id}>
                <td className="mono" style={{ whiteSpace: "nowrap" }}>
                  {new Date(l.ts).toLocaleTimeString()}
                </td>
                <td>
                  <span style={{ color: toneColor[m.tone], fontSize: 13, fontWeight: 500 }}>{m.label}</span>
                </td>
                <td style={isRaw ? { fontFamily: "var(--mono)", fontSize: 12, color: "var(--fg-faint)" } : undefined}>
                  {isRaw
                    ? (l.data ?? "").replace(/\[[0-9;?]*[A-Za-z]/g, "").slice(0, 200)
                    : describeEvent(l.event_type, l.data, undefined, undefined)}
                </td>
              </tr>
            );
          })}
          {logs.length === 0 && (
            <tr>
              <td colSpan={3} style={{ color: "var(--fg-faint)", textAlign: "center", padding: 24 }}>
                No events.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Modal>
  );
}
