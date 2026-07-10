import { createContext, useContext, useEffect, useState, useCallback, ReactNode } from "react";
import { api, Server, ServerGroup } from "../api/client";

interface ServersCtx {
  servers: Server[];
  groups: ServerGroup[];
  loading: boolean;
  error: string;
  refresh: () => Promise<void>;
}

const Ctx = createContext<ServersCtx | null>(null);

export function ServersProvider({ children }: { children: ReactNode }) {
  const [servers, setServers] = useState<Server[]>([]);
  const [groups, setGroups] = useState<ServerGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    try {
      const [s, g] = await Promise.all([api.listServers(), api.listGroups()]);
      setServers(s);
      setGroups(g);
      setError("");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    // Live console: poll so status flips and newly enrolled hosts appear.
    const t = setInterval(refresh, 5000);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <Ctx.Provider value={{ servers, groups, loading, error, refresh }}>{children}</Ctx.Provider>
  );
}

export function useServers(): ServersCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useServers must be used within ServersProvider");
  return ctx;
}
