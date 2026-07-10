import { useEffect, useRef, useState } from "react";
import * as AsciinemaPlayer from "asciinema-player";
import "asciinema-player/dist/bundle/asciinema-player.css";
import Modal from "../../components/Modal";
import WatchTerminal from "../../components/Terminal/WatchTerminal";
import { IconTerminal, IconActivity, IconSearch } from "../../components/icons";
import { api, castURL, Session, CommandEntry, CommandHit, isAdmin } from "../../api/client";
import { useServers } from "../../data/ServersContext";

function Player({ sessionId, startAt }: { sessionId: string; startAt: number }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!ref.current) return;
    const player = AsciinemaPlayer.create(castURL(sessionId), ref.current, {
      fit: "width",
      autoPlay: true,
      theme: "asciinema",
      idleTimeLimit: 2,
      startAt,
    });
    return () => player.dispose();
  }, [sessionId, startAt]);
  return <div ref={ref} />;
}

export default function SessionsModal({ onClose }: { onClose: () => void }) {
  const { servers } = useServers();
  const [sessions, setSessions] = useState<Session[]>([]);
  const [error, setError] = useState("");
  const [replay, setReplay] = useState<string | null>(null);
  const [watch, setWatch] = useState<string | null>(null);
  const [cmds, setCmds] = useState<CommandEntry[]>([]);
  const [startAt, setStartAt] = useState(0);
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<CommandHit[] | null>(null);

  const hostName = (id: string) => servers.find((s) => s.id === id)?.name ?? id.slice(0, 8);

  async function load() {
    try {
      setSessions(await api.listSessions());
    } catch (e) {
      setError(String(e));
    }
  }
  useEffect(() => {
    load();
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, []);

  // Load the command timeline when entering replay.
  useEffect(() => {
    if (replay) {
      setStartAt(0);
      api.sessionCommands(replay).then(setCmds).catch(() => setCmds([]));
    }
  }, [replay]);

  async function terminate(id: string) {
    if (!confirm("Forcibly terminate this live session?")) return;
    await api.terminateSession(id).catch((e) => setError(String(e)));
    load();
  }

  async function search() {
    if (!q.trim()) {
      setHits(null);
      return;
    }
    setHits(await api.commandSearch(q).catch(() => []));
  }

  if (watch) {
    return (
      <Modal kicker="shadow" title="Live session — read only" onClose={() => setWatch(null)} wide>
        <WatchTerminal sessionId={watch} />
        <div style={{ marginTop: 12, textAlign: "right" }}>
          <button className="btn ghost" onClick={() => setWatch(null)}>
            Back
          </button>
        </div>
      </Modal>
    );
  }

  if (replay) {
    return (
      <Modal kicker="replay" title="Session playback" onClose={() => setReplay(null)} wide>
        <div className="replay-split">
          <div className="replay-player">
            <Player sessionId={replay} startAt={startAt} />
          </div>
          <div className="cmd-timeline">
            <div className="cmd-timeline-h">Command timeline</div>
            {cmds.length === 0 && <p className="ops-empty">No commands reconstructed.</p>}
            {cmds.map((c, i) => (
              <div key={i} className="cmd-item" onClick={() => setStartAt(c.offset_sec)} title="Jump to this command">
                <span className="cmd-off">+{c.offset_sec.toFixed(1)}s</span>
                <span className="cmd-text">{c.command}</span>
              </div>
            ))}
          </div>
        </div>
        <div style={{ marginTop: 12, textAlign: "right" }}>
          <button className="btn ghost" onClick={() => setReplay(null)}>
            Back to list
          </button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal kicker="sessions" title="Recorded sessions" onClose={onClose} wide>
      {error && <p className="error-text">{error}</p>}

      <div className="search" style={{ marginBottom: 14 }}>
        <IconSearch />
        <input
          placeholder="Search across all sessions (commands & output)…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && search()}
        />
      </div>

      {hits !== null && (
        <div style={{ marginBottom: 16 }}>
          <h4 style={{ margin: "0 0 8px", color: "var(--fg-dim)" }}>
            {hits.length} session(s) match “{q}”
          </h4>
          {hits.map((h) => (
            <div key={h.session_id} className="ops-row">
              <div style={{ flex: 1 }}>
                {h.user || "—"} <span className="ops-arrow">→</span> {h.server} ·{" "}
                <span className="mono" style={{ color: "var(--fg-faint)" }}>
                  {new Date(h.ts).toLocaleString()}
                </span>
              </div>
              <button className="btn ghost sm" onClick={() => setReplay(h.session_id)}>
                <IconTerminal /> Replay
              </button>
            </div>
          ))}
        </div>
      )}

      <table>
        <thead>
          <tr>
            <th>Started</th>
            <th>Host</th>
            <th>Proto</th>
            <th>Duration</th>
            <th>Reason</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => {
            const live = !s.ended_at;
            const d = s.ended_at
              ? Math.round((+new Date(s.ended_at) - +new Date(s.started_at)) / 1000)
              : null;
            return (
              <tr key={s.id}>
                <td className="mono" style={{ whiteSpace: "nowrap" }}>
                  {new Date(s.started_at).toLocaleTimeString()}
                </td>
                <td>{hostName(s.server_id)}</td>
                <td className="mono">{s.protocol}</td>
                <td className="mono">{live ? <span className="badge online">live</span> : `${d}s`}</td>
                <td style={{ color: "var(--fg-dim)" }}>{s.reason || "—"}</td>
                <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                  {live && (
                    <button className="btn ghost sm" onClick={() => setWatch(s.id)}>
                      <IconActivity /> Watch
                    </button>
                  )}{" "}
                  {live && isAdmin() && (
                    <button className="btn danger sm" onClick={() => terminate(s.id)}>
                      Kill
                    </button>
                  )}{" "}
                  {s.recording_path && (
                    <button className="btn ghost sm" onClick={() => setReplay(s.id)}>
                      <IconTerminal /> Replay
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Modal>
  );
}
