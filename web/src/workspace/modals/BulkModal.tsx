import { useEffect, useRef, useState } from "react";
import Modal from "../../components/Modal";
import { api, BulkResult, getToken } from "../../api/client";
import { useServers } from "../../data/ServersContext";

type Mode = "command" | "script";

// Ready-made scripts. The inline recon needs no internet; linpeas/LinEnum fetch.
const PRESETS: { label: string; body: string }[] = [
  {
    label: "linpeas",
    body: "curl -fsSL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh",
  },
  {
    label: "LinEnum",
    body: "curl -fsSL https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash",
  },
  {
    label: "quick recon (offline)",
    body: `#!/bin/bash
echo "== whoami =="; id
echo "== os =="; uname -a; cat /etc/os-release 2>/dev/null | head -1
echo "== sudo rights =="; sudo -n -l 2>/dev/null || echo "no passwordless sudo"
echo "== listening ports =="; ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
echo "== top processes =="; ps aux --sort=-%mem 2>/dev/null | head -8
echo "== SUID binaries =="; find / -perm -4000 -type f 2>/dev/null | head -20
echo "== world-writable dirs =="; find / -path /proc -prune -o -perm -0002 -type d -print 2>/dev/null | head -10`,
  },
];

export default function BulkModal({ onClose }: { onClose: () => void }) {
  const { groups } = useServers();
  const [groupId, setGroupId] = useState("");
  const [mode, setMode] = useState<Mode>("command");
  const [command, setCommand] = useState("");
  const [script, setScript] = useState("");
  const [results, setResults] = useState<BulkResult[]>([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => () => esRef.current?.close(), []);

  async function run() {
    const payload = mode === "script" ? script : command;
    if (!groupId || !payload.trim()) return;
    setError("");
    setResults([]);
    setRunning(true);
    try {
      const { job_id } = await api.createBulk(groupId, payload, mode === "script");
      const token = getToken() ?? "";
      const es = new EventSource(`/api/bulk/${job_id}/stream?token=${encodeURIComponent(token)}`);
      esRef.current = es;
      es.onmessage = (ev) => {
        try {
          setResults((prev) => [...prev, JSON.parse(ev.data) as BulkResult]);
        } catch {
          /* ignore */
        }
      };
      es.addEventListener("done", () => {
        es.close();
        setRunning(false);
      });
      es.onerror = () => {
        es.close();
        setRunning(false);
      };
    } catch (e) {
      setError(String(e));
      setRunning(false);
    }
  }

  return (
    <Modal kicker="fan-out" title="Bulk execution" onClose={onClose} wide>
      {error && <p className="error-text">{error}</p>}

      <div style={{ display: "flex", gap: 8, marginBottom: 12, alignItems: "center" }}>
        <select value={groupId} onChange={(e) => setGroupId(e.target.value)} style={{ width: 220 }}>
          <option value="">Select group…</option>
          {groups.map((g) => (
            <option key={g.id} value={g.id}>
              {g.name} ({g.members?.length ?? 0})
            </option>
          ))}
        </select>
        <button className={mode === "command" ? "btn" : "btn ghost"} onClick={() => setMode("command")}>
          Command
        </button>
        <button className={mode === "script" ? "btn" : "btn ghost"} onClick={() => setMode("script")}>
          Script
        </button>
        <div style={{ flex: 1 }} />
        <button className="btn" onClick={run} disabled={running || !groupId}>
          {running ? "Running…" : `Run on group`}
        </button>
      </div>

      {mode === "command" ? (
        <input
          className="mono"
          style={{ width: "100%", marginBottom: 16 }}
          placeholder="command, e.g. uptime"
          value={command}
          onChange={(e) => setCommand(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && run()}
        />
      ) : (
        <div style={{ marginBottom: 16 }}>
          <div style={{ display: "flex", gap: 6, marginBottom: 8, alignItems: "center" }}>
            <span style={{ color: "var(--fg-faint)", fontSize: 12 }}>presets:</span>
            {PRESETS.map((p) => (
              <button key={p.label} className="chip" onClick={() => setScript(p.body)}>
                {p.label}
              </button>
            ))}
          </div>
          <textarea
            className="mono"
            rows={8}
            style={{ width: "100%", fontSize: 12 }}
            placeholder="Paste a script (run on every host via bash -s). Pick a preset above, or paste linpeas, a recon script, etc."
            value={script}
            onChange={(e) => setScript(e.target.value)}
          />
          <p style={{ color: "var(--fg-faint)", fontSize: 11, margin: "4px 0 0" }}>
            Runs piped to <code>bash -s</code> on each host · 10-min per-host timeout · output recorded.
          </p>
        </div>
      )}

      {results.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Status</th>
              <th>Exit</th>
              <th>ms</th>
              <th>Output</th>
            </tr>
          </thead>
          <tbody>
            {results.map((r) => {
              const out = r.stdout || r.stderr || "";
              const open = expanded === r.server_id;
              return (
                <tr key={r.server_id} onClick={() => setExpanded(open ? null : r.server_id)} style={{ cursor: out ? "pointer" : "default" }}>
                  <td>{r.server_name || r.server_id}</td>
                  <td>
                    <span className={`badge ${r.status}`}>{r.status}</span>
                  </td>
                  <td className="mono">{r.exit_code}</td>
                  <td className="mono">{r.duration_ms}</td>
                  <td className="mono" style={{ maxWidth: 480 }}>
                    {open ? (
                      <pre style={{ whiteSpace: "pre-wrap", maxHeight: "40vh", overflow: "auto", margin: 0 }}>{out}</pre>
                    ) : (
                      <span style={{ color: "var(--fg-dim)" }}>
                        {out.split("\n")[0]?.slice(0, 80)}
                        {out.length > 80 ? " … (click to expand)" : ""}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </Modal>
  );
}
