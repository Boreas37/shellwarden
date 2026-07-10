import { useEffect, useRef } from "react";
import Guacamole from "guacamole-common-js";
import { getToken } from "../../api/client";

// RdpCanvas connects to /ws/rdp/{serverId} via the Guacamole client, mounts the
// display element, and forwards mouse + keyboard events.
export default function RdpCanvas({ serverId }: { serverId: string }) {
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!hostRef.current) return;
    const host = hostRef.current;

    const token = getToken() ?? "";
    // The guac WebSocketTunnel appends its own query string, so pass auth via a
    // query param it will carry through.
    const tunnelURL = `ws/rdp/${serverId}?token=${encodeURIComponent(token)}`;
    const tunnel = new Guacamole.WebSocketTunnel(tunnelURL);
    const client = new Guacamole.Client(tunnel);

    const display = client.getDisplay().getElement();
    host.appendChild(display);

    client.onerror = (err: unknown) => {
      console.error("guacamole error", err);
    };

    client.connect(`width=${host.clientWidth}&height=${host.clientHeight}`);

    // Mouse forwarding.
    const mouse = new Guacamole.Mouse(display);
    mouse.onmousedown = mouse.onmouseup = mouse.onmousemove = (state: unknown) => {
      client.sendMouseState(state);
    };

    // Keyboard forwarding.
    const keyboard = new Guacamole.Keyboard(document);
    keyboard.onkeydown = (keysym: number) => client.sendKeyEvent(1, keysym);
    keyboard.onkeyup = (keysym: number) => client.sendKeyEvent(0, keysym);

    return () => {
      client.disconnect();
      keyboard.onkeydown = null;
      keyboard.onkeyup = null;
      if (display.parentNode === host) host.removeChild(display);
    };
  }, [serverId]);

  return <div className="rdp-host" ref={hostRef} />;
}
