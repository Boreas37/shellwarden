import { useEffect, useState } from "react";
import { useServers } from "../data/ServersContext";
import { useTerminals } from "../terminals/TerminalsContext";

export default function StatusBar() {
  const { servers, loading, error } = useServers();
  const { sessions } = useTerminals();
  const [clock, setClock] = useState(() => new Date().toLocaleTimeString());

  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(t);
  }, []);

  const online = servers.filter((s) => s.status === "online").length;
  const agents = servers.filter((s) => s.connection_mode === "agent").length;

  return (
    <footer className="statusbar">
      <span className="seg" style={{ color: error ? "var(--red)" : "var(--green)" }}>
        ● {error ? "gateway error" : loading ? "syncing…" : "gateway connected"}
      </span>
      <span className="seg">{online} online</span>
      <span className="seg">{servers.length} hosts</span>
      <span className="seg">{agents} agents</span>
      <span className="seg">{sessions.length} sessions</span>
      <span className="spacer" />
      <span className="seg">ShellWarden · MVP</span>
      <span className="seg">{clock}</span>
    </footer>
  );
}
