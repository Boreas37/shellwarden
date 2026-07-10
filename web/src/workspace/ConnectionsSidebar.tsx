import { useMemo, useState } from "react";
import { useServers } from "../data/ServersContext";
import { useTerminals } from "../terminals/TerminalsContext";
import { api, Server, HostMetrics, canWrite } from "../api/client";
import {
  IconSearch,
  IconPlus,
  IconDownload,
  IconLayers,
  IconChevron,
  IconTerminal,
  IconMonitor,
  IconEdit,
  IconTrash,
  IconKey,
  IconScroll,
  IconCopy,
  IconActivity,
} from "../components/icons";

interface Props {
  onAdd: () => void;
  onEnroll: () => void;
  onGroups: () => void;
  onEdit: (s: Server) => void;
  onConnectReason: (s: Server) => void;
  onSftp: (s: Server) => void;
  onRequestAccess: (s: Server) => void;
  onDetail: (s: Server) => void;
}

// metricsSummary builds a human tooltip + short load label from telemetry JSON.
function parseMetrics(s: Server): HostMetrics | null {
  if (!s.metrics) return null;
  try {
    return JSON.parse(s.metrics) as HostMetrics;
  } catch {
    return null;
  }
}

function metricsTooltip(s: Server, m: HostMetrics | null): string {
  if (!m) return `${s.host}:${s.port} · ${s.connection_mode}`;
  const up = m.uptime_sec ? `${Math.floor(m.uptime_sec / 3600)}h` : "?";
  const mem =
    m.mem_total_mb && m.mem_avail_mb
      ? `${Math.round(((m.mem_total_mb - m.mem_avail_mb) / m.mem_total_mb) * 100)}% used`
      : "?";
  return [
    m.os || "",
    m.kernel ? `kernel ${m.kernel}` : "",
    `load ${m.load1 ?? "?"} / ${m.load5 ?? "?"} / ${m.load15 ?? "?"}`,
    `mem ${mem}`,
    m.disk_total_gb ? `disk ${m.disk_free_gb}/${m.disk_total_gb} GB free` : "",
    `uptime ${up}`,
  ]
    .filter(Boolean)
    .join("  ·  ");
}

const ProtoIcon = ({ p }: { p: string }) =>
  p === "rdp" ? <IconMonitor className="proto" /> : <IconTerminal className="proto" />;

export default function ConnectionsSidebar({
  onAdd,
  onEnroll,
  onGroups,
  onEdit,
  onConnectReason,
  onSftp,
  onRequestAccess,
  onDetail,
}: Props) {
  const { servers, groups, refresh } = useServers();
  const { open } = useTerminals();
  const [query, setQuery] = useState("");
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());

  const q = query.trim().toLowerCase();
  const match = (s: Server) =>
    !q || s.name.toLowerCase().includes(q) || s.host.toLowerCase().includes(q);

  const { sections, online } = useMemo(() => {
    const grouped = new Set<string>();
    const secs = groups.map((g) => {
      const members = servers.filter((s) => (g.members ?? []).includes(s.id) && match(s));
      (g.members ?? []).forEach((id) => grouped.add(id));
      return { id: g.id, name: g.name, servers: members };
    });
    const ungrouped = servers.filter((s) => !grouped.has(s.id) && match(s));
    if (ungrouped.length || secs.length === 0) {
      secs.push({ id: "__ungrouped__", name: "Ungrouped", servers: ungrouped });
    }
    return { sections: secs, online: servers.filter((s) => s.status === "online").length };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [servers, groups, q]);

  function toggle(id: string) {
    setCollapsed((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  async function remove(s: Server) {
    if (!confirm(`Delete "${s.name}"?`)) return;
    await api.deleteServer(s.id);
    await refresh();
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-head">
        <div className="sidebar-title">
          <h2>Connections</h2>
        </div>
        <div className="search">
          <IconSearch />
          <input
            placeholder="Filter hosts…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        {canWrite() && (
          <div className="sidebar-tools">
            <button className="btn sm" onClick={onAdd}>
              <IconPlus /> Add
            </button>
            <button className="btn ghost sm" onClick={onEnroll}>
              <IconDownload /> Enroll
            </button>
            <button className="btn ghost sm" onClick={onGroups}>
              <IconLayers /> Groups
            </button>
          </div>
        )}
      </div>

      <div className="tree">
        {servers.length === 0 && (
          <div className="tree-empty">
            No hosts yet.
            <br />
            Use <strong>Add</strong> or <strong>Enroll</strong> to register one.
          </div>
        )}

        {sections.map((sec) => {
          const isCollapsed = collapsed.has(sec.id);
          return (
            <div className="tree-group" key={sec.id}>
              <div
                className={`tree-group-head ${isCollapsed ? "collapsed" : ""}`}
                onClick={() => toggle(sec.id)}
              >
                <IconChevron className="chev" />
                <span className="tree-group-name">{sec.name}</span>
                <span className="tree-count">{sec.servers.length}</span>
              </div>

              {!isCollapsed &&
                sec.servers.map((s) => {
                  const m = parseMetrics(s);
                  const conn = { id: s.id, name: s.name, protocol: s.protocol };
                  const connect = () => canWrite() && open(conn);
                  return (
                    <div
                      key={s.id}
                      className="node"
                      title={metricsTooltip(s, m)}
                      onDoubleClick={connect}
                    >
                      <span className={`dot ${s.status}`} />
                      <ProtoIcon p={s.protocol} />
                      <div className="node-main" onClick={connect}>
                        <div className="node-name">{s.name}</div>
                        <div className="node-host">
                          {m && m.load1 !== undefined ? (
                            <>load {m.load1}</>
                          ) : (
                            <>
                              {s.host}:{s.port} · {s.connection_mode}
                            </>
                          )}
                        </div>
                      </div>

                      <div className="node-stamp">
                        {!!s.vuln_count && (
                          <span
                            className={`vuln-chip ${s.vuln_critical ? "crit" : ""}`}
                            title={`${s.vuln_count} known CVEs`}
                          >
                            {s.vuln_count}
                          </span>
                        )}
                        {(s.has_ssh_key || s.has_ssh_password) && (
                          <IconKey className="cred-key" width={13} height={13} />
                        )}
                      </div>

                      <div className="node-actions">
                        <button
                          className="iconbtn"
                          title="Resources & vulnerabilities"
                          onClick={(e) => {
                            e.stopPropagation();
                            onDetail(s);
                          }}
                        >
                          <IconActivity />
                        </button>
                        {canWrite() && (
                          <>
                          <button
                            className="iconbtn"
                            title="Connect with reason"
                            onClick={(e) => {
                              e.stopPropagation();
                              onConnectReason(s);
                            }}
                          >
                            <IconScroll />
                          </button>
                          <button
                            className="iconbtn"
                            title="Files (SFTP)"
                            onClick={(e) => {
                              e.stopPropagation();
                              onSftp(s);
                            }}
                          >
                            <IconCopy />
                          </button>
                          <button
                            className="iconbtn"
                            title="Request JIT access"
                            onClick={async (e) => {
                              e.stopPropagation();
                              try {
                                await api.requestAccess(s.id, "");
                              } catch {
                                /* ignore */
                              }
                              onRequestAccess(s);
                            }}
                          >
                            <IconKey />
                          </button>
                          <button className="iconbtn" title="Edit" onClick={(e) => { e.stopPropagation(); onEdit(s); }}>
                            <IconEdit />
                          </button>
                          <button className="iconbtn" title="Delete" onClick={(e) => { e.stopPropagation(); remove(s); }}>
                            <IconTrash />
                          </button>
                          </>
                        )}
                      </div>
                    </div>
                  );
                })}
            </div>
          );
        })}
      </div>

      <div className="sidebar-foot">
        <span className="stat">
          <span className="dot online" /> {online} online
        </span>
        <span className="stat">{servers.length} hosts</span>
      </div>
    </aside>
  );
}
