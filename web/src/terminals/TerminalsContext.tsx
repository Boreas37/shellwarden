import { createContext, useContext, useRef, useState, ReactNode } from "react";

export interface TermSession {
  key: string; // unique per window (allows multiple windows to the same server)
  serverId: string;
  serverName: string;
  protocol: string;
  reason?: string;
}

interface TerminalsCtx {
  sessions: TermSession[];
  activeKey: string | null;
  secondaryKey: string | null; // for split-pane (previously active)
  broadcast: boolean;
  split: boolean;
  open: (server: { id: string; name: string; protocol: string }, reason?: string) => void;
  close: (key: string) => void;
  setActive: (key: string) => void;
  setBroadcast: (b: boolean) => void;
  setSplit: (b: boolean) => void;
  nextTab: () => void;
  prevTab: () => void;
  closeActive: () => void;
  // input fan-out
  registerSender: (key: string, send: (data: string) => void) => void;
  unregisterSender: (key: string) => void;
  fanout: (fromKey: string, data: string) => void;
}

const Ctx = createContext<TerminalsCtx | null>(null);

let counter = 0;

export function TerminalsProvider({ children }: { children: ReactNode }) {
  const [sessions, setSessions] = useState<TermSession[]>([]);
  const [activeKey, setActiveKeyState] = useState<string | null>(null);
  const [secondaryKey, setSecondaryKey] = useState<string | null>(null);
  const [broadcast, setBroadcast] = useState(false);
  const [split, setSplit] = useState(false);
  const senders = useRef<Map<string, (data: string) => void>>(new Map());

  function setActive(key: string) {
    setActiveKeyState((cur) => {
      if (cur && cur !== key) setSecondaryKey(cur);
      return key;
    });
  }

  function open(server: { id: string; name: string; protocol: string }, reason?: string) {
    counter += 1;
    const key = `${server.id}-${counter}`;
    setSessions((prev) => [
      ...prev,
      { key, serverId: server.id, serverName: server.name, protocol: server.protocol, reason },
    ]);
    setActive(key);
  }

  function close(key: string) {
    setSessions((prev) => {
      const next = prev.filter((s) => s.key !== key);
      setActiveKeyState((cur) => (cur !== key ? cur : next.length ? next[next.length - 1].key : null));
      setSecondaryKey((cur) => (cur === key ? null : cur));
      return next;
    });
    senders.current.delete(key);
  }

  function shiftTab(dir: number) {
    setSessions((prev) => {
      if (prev.length === 0) return prev;
      setActiveKeyState((cur) => {
        const idx = prev.findIndex((s) => s.key === cur);
        const ni = ((idx === -1 ? 0 : idx) + dir + prev.length) % prev.length;
        const nk = prev[ni].key;
        if (cur && cur !== nk) setSecondaryKey(cur);
        return nk;
      });
      return prev;
    });
  }

  const value: TerminalsCtx = {
    sessions,
    activeKey,
    secondaryKey,
    broadcast,
    split,
    open,
    close,
    setActive,
    setBroadcast,
    setSplit,
    nextTab: () => shiftTab(1),
    prevTab: () => shiftTab(-1),
    closeActive: () => activeKey && close(activeKey),
    registerSender: (key, send) => senders.current.set(key, send),
    unregisterSender: (key) => senders.current.delete(key),
    fanout: (fromKey, data) => {
      senders.current.forEach((send, key) => {
        if (key !== fromKey) send(data);
      });
    },
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useTerminals(): TerminalsCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useTerminals must be used within TerminalsProvider");
  return ctx;
}
