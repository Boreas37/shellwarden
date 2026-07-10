import { useEffect } from "react";
import { useTerminals } from "../terminals/TerminalsContext";
import SshTerminal from "../components/Terminal/SshTerminal";
import RdpCanvas from "../components/Terminal/RdpCanvas";
import OpsDashboard from "./OpsDashboard";
import { IconTerminal, IconMonitor, IconClose, IconActivity, IconLayers } from "../components/icons";

export default function MainArea({ onWatch }: { onWatch: (id: string) => void }) {
  const t = useTerminals();
  const { sessions, activeKey, secondaryKey, broadcast, split, close, setActive } = t;

  // Refit xterm whenever the visible set changes.
  useEffect(() => {
    const id = setTimeout(() => window.dispatchEvent(new Event("resize")), 60);
    return () => clearTimeout(id);
  }, [activeKey, secondaryKey, split, sessions.length]);

  // Keyboard shortcuts (Ctrl+Alt+… to avoid clobbering terminal/browser keys).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey && e.altKey)) return;
      switch (e.key) {
        case "ArrowRight": e.preventDefault(); t.nextTab(); break;
        case "ArrowLeft": e.preventDefault(); t.prevTab(); break;
        case "w": e.preventDefault(); t.closeActive(); break;
        case "b": e.preventDefault(); t.setBroadcast(!broadcast); break;
        case "s": e.preventDefault(); t.setSplit(!split); break;
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [t, broadcast, split]);

  const showSplit = split && secondaryKey && secondaryKey !== activeKey && sessions.some((s) => s.key === secondaryKey);
  const visible = new Set<string>([activeKey ?? "", ...(showSplit ? [secondaryKey!] : [])]);

  return (
    <div className="main">
      <div className="tabstrip">
        {sessions.map((s) => (
          <div
            key={s.key}
            className={`tab ${s.key === activeKey ? "active" : ""}`}
            onClick={() => setActive(s.key)}
            title={`${s.protocol.toUpperCase()} · ${s.serverName}`}
          >
            {s.protocol === "rdp" ? <IconMonitor className="proto" /> : <IconTerminal className="proto" />}
            {s.serverName}
            <span className="tab-close" onClick={(e) => { e.stopPropagation(); close(s.key); }}>
              <IconClose width={12} height={12} />
            </span>
          </div>
        ))}

        {sessions.length > 0 && (
          <div style={{ marginLeft: "auto", display: "flex", gap: 6, alignItems: "center", paddingRight: 10 }}>
            <span
              className={`chip ${broadcast ? "on" : ""}`}
              onClick={() => t.setBroadcast(!broadcast)}
              title="Broadcast input to all terminals (Ctrl+Alt+B)"
            >
              <IconActivity width={13} height={13} /> Broadcast
            </span>
            <span
              className={`chip ${split ? "on" : ""}`}
              onClick={() => t.setSplit(!split)}
              title="Split view: show two sessions side by side (Ctrl+Alt+S)"
            >
              <IconLayers width={13} height={13} /> Split
            </span>
          </div>
        )}
      </div>

      {broadcast && sessions.length > 0 && (
        <div className="broadcast-banner">
          ⚡ Broadcast mode — keystrokes are sent to all {sessions.length} terminals
        </div>
      )}

      <div className={`panes ${showSplit ? "split" : ""}`}>
        {sessions.length === 0 && (
          <div className="pane" style={{ overflow: "auto" }}>
            <OpsDashboard onWatch={onWatch} />
          </div>
        )}

        {sessions.map((s) => (
          <div key={s.key} className="pane" style={{ display: visible.has(s.key) ? "block" : "none" }}>
            {s.protocol === "rdp" ? (
              <RdpCanvas serverId={s.serverId} />
            ) : (
              <SshTerminal serverId={s.serverId} reason={s.reason} sessionKey={s.key} />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
