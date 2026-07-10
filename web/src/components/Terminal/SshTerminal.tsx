import { useEffect, useRef } from "react";
import { Terminal } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import "xterm/css/xterm.css";
import { wsURL } from "../../api/client";
import { useTerminals } from "../../terminals/TerminalsContext";

// Close codes the gateway uses to tell us NOT to reconnect.
const NO_RECONNECT = new Set([4001, 4002, 1008]);

// SshTerminal opens a WebSocket to /ws/ssh/{serverId}, attaches an xterm.js
// terminal, and pipes bytes bidirectionally. On unexpected disconnects it
// auto-reconnects with backoff (a transient agent/network blip no longer kills
// the terminal). Broadcast-mode input is fanned out to other terminals.
export default function SshTerminal({
  serverId,
  reason,
  sessionKey,
}: {
  serverId: string;
  reason?: string;
  sessionKey: string;
}) {
  const hostRef = useRef<HTMLDivElement>(null);
  const terminals = useTerminals();
  const bcastRef = useRef(terminals.broadcast);
  bcastRef.current = terminals.broadcast;

  useEffect(() => {
    if (!hostRef.current) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: '"IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize: 13,
      theme: { background: "#000000" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(hostRef.current);
    fit.fit();

    let ws: WebSocket | null = null;
    let attempts = 0;
    let unmounting = false;
    let reconnectTimer: number | undefined;
    let resumeId = ""; // server-assigned session id, used to resume after a drop

    const sendResize = () => {
      fit.fit();
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "resize", cols: term.cols, rows: term.rows }));
      }
    };

    const connect = () => {
      let url = wsURL(`/ws/ssh/${serverId}`);
      if (reason) url += `&reason=${encodeURIComponent(reason)}`;
      if (resumeId) url += `&resume=${encodeURIComponent(resumeId)}`;
      ws = new WebSocket(url);
      ws.binaryType = "arraybuffer";

      ws.onopen = () => {
        if (attempts > 0) term.write("\r\n\x1b[32m[shellwarden] reconnected\x1b[0m\r\n");
        attempts = 0;
        sendResize();
      };
      ws.onmessage = (ev) => {
        if (ev.data instanceof ArrayBuffer) {
          term.write(new Uint8Array(ev.data));
          return;
        }
        const s = ev.data as string;
        if (s.startsWith('{"type":"session"')) {
          try {
            resumeId = JSON.parse(s).id || "";
          } catch {
            /* ignore */
          }
          return; // control frame — don't print
        }
        term.write(s);
      };
      ws.onerror = () => {};
      ws.onclose = (ev) => {
        if (unmounting || NO_RECONNECT.has(ev.code)) {
          if (ev.code === 4001) term.write("\r\n\x1b[31m[shellwarden] session terminated by admin\x1b[0m\r\n");
          else if (ev.code === 4002) term.write("\r\n\x1b[33m[shellwarden] session ended (timeout)\x1b[0m\r\n");
          return;
        }
        attempts += 1;
        if (attempts > 8) {
          term.write("\r\n\x1b[31m[shellwarden] connection lost — giving up after 8 attempts\x1b[0m\r\n");
          return;
        }
        const delay = Math.min(1000 * 2 ** (attempts - 1), 10000);
        term.write(`\r\n\x1b[33m[shellwarden] disconnected — reconnecting in ${delay / 1000}s (try ${attempts})\x1b[0m\r\n`);
        reconnectTimer = window.setTimeout(connect, delay);
      };

      // Keep the broadcast sender pointing at the current socket.
      terminals.registerSender(sessionKey, (data) => {
        if (ws && ws.readyState === WebSocket.OPEN) ws.send(data);
      });
    };

    connect();

    const dataDisp = term.onData((data) => {
      if (ws && ws.readyState === WebSocket.OPEN) ws.send(data);
      if (bcastRef.current) terminals.fanout(sessionKey, data);
    });

    const onWindowResize = () => sendResize();
    window.addEventListener("resize", onWindowResize);

    return () => {
      unmounting = true;
      window.clearTimeout(reconnectTimer);
      window.removeEventListener("resize", onWindowResize);
      terminals.unregisterSender(sessionKey);
      dataDisp.dispose();
      ws?.close();
      term.dispose();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [serverId, reason, sessionKey]);

  return <div className="terminal-host" ref={hostRef} />;
}
