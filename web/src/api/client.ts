// Typed fetch wrapper for the ShellWarden gateway API.

export interface User {
  id: string;
  username: string;
  role: string;
  created_at: string;
}

export interface Server {
  id: string;
  name: string;
  host: string;
  port: number;
  protocol: string;
  connection_mode: string;
  agent_token?: string;
  agent_connected_at?: string;
  status: string;
  os_info?: string;
  ssh_user?: string;
  has_ssh_key?: boolean;
  has_ssh_password?: boolean;
  metrics?: string;
  metrics_at?: string;
  use_ssh_ca?: boolean;
  vuln_count?: number;
  vuln_critical?: number;
  vuln_scanned_at?: string;
  created_at: string;
}

export interface MetricPoint {
  ts: string;
  cpu_pct: number;
  mem_used_pct: number;
  disk_used_pct: number;
  net_rx_kbs: number;
  net_tx_kbs: number;
  load1: number;
}

export interface VulnFinding {
  id: string;
  package: string;
  severity: string;
}

export interface VulnScan {
  tool: string;
  distro: string;
  upgradable: number;
  security_updates: number;
  findings: VulnFinding[];
  scanned_at: string;
  note?: string;
}

export interface HostMetrics {
  hostname?: string;
  os?: string;
  kernel?: string;
  uptime_sec?: number;
  load1?: number;
  load5?: number;
  load15?: number;
  mem_total_mb?: number;
  mem_avail_mb?: number;
  disk_total_gb?: number;
  disk_free_gb?: number;
  ts?: string;
}

// ServerInput is the payload accepted by create/update (includes write-only
// secret fields that are never returned by the API).
export interface ServerInput {
  name?: string;
  host?: string;
  port?: number;
  protocol?: string;
  connection_mode?: string;
  os_info?: string;
  ssh_user?: string;
  ssh_key?: string;
  ssh_password?: string;
  use_ssh_ca?: boolean;
}

export interface AccessReviewRow {
  username: string;
  role: string;
  mfa_enabled: boolean;
  sessions_30d: number;
  active_grants: number;
  distinct_hosts_30d: number;
  last_seen?: string;
}

export interface ServerGroup {
  id: string;
  name: string;
  description?: string;
  created_at: string;
  members?: string[];
}

export interface Session {
  id: string;
  server_id: string;
  user_id: string;
  protocol: string;
  started_at: string;
  ended_at?: string;
  recording_path?: string;
  reason?: string;
  bytes_read: number;
  bytes_written: number;
}

export interface AuditLog {
  id: number;
  session_id?: string;
  server_id?: string;
  user_id?: string;
  event_type: string;
  data?: string;
  ts: string;
}

export interface BulkResult {
  id: number;
  job_id: string;
  server_id: string;
  server_name: string;
  status: string;
  stdout: string;
  stderr: string;
  exit_code: number;
  duration_ms: number;
  created_at: string;
}

export interface FileEntry {
  name: string;
  size: number;
  mode: string;
  is_dir: boolean;
  mod_time: string;
}

export interface AccessRequest {
  id: string;
  username?: string;
  server_id: string;
  server_name?: string;
  reason?: string;
  status: string;
  requested_at: string;
  expires_at?: string;
}

export interface DashboardData {
  stats: {
    hosts_total: number;
    hosts_online: number;
    agents: number;
    active_sessions: number;
    sessions_24h: number;
    failed_logins_24h: number;
  };
  active_sessions: { id: string; user: string; server: string; protocol: string; started_at: string }[];
  recent_events: { ts: string; event_type: string; user?: string; server?: string; detail?: string }[];
  activity_24h: { hour: string; count: number }[];
}

export interface CommandEntry {
  offset_sec: number;
  ts: string;
  command: string;
}

export interface CommandHit {
  session_id: string;
  ts: string;
  server: string;
  user: string;
}

const TOKEN_KEY = "shellwarden_token";
const ROLE_KEY = "shellwarden_role";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function setRole(role: string) {
  localStorage.setItem(ROLE_KEY, role);
}

export function getRole(): string {
  return localStorage.getItem(ROLE_KEY) || "operator";
}

export function canWrite(): boolean {
  return getRole() === "admin" || getRole() === "operator";
}

export function isAdmin(): boolean {
  return getRole() === "admin";
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ROLE_KEY);
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const res = await fetch(`/api${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) {
    clearToken();
    throw new Error("unauthorized");
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `request failed: ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  login: (username: string, password: string, code?: string) =>
    request<{ token: string; user: User }>("POST", "/auth/login", { username, password, code }),
  authMethods: () => request<{ password: boolean; oidc: boolean }>("GET", "/auth/methods"),
  logout: () => request<{ status: string }>("POST", "/auth/logout"),

  listServers: () => request<Server[]>("GET", "/servers"),
  getServer: (id: string) => request<Server>("GET", `/servers/${id}`),
  serverMetrics: (id: string, minutes = 60) =>
    request<MetricPoint[]>("GET", `/servers/${id}/metrics?minutes=${minutes}`),
  serverVulns: (id: string) =>
    request<{ scanned: boolean; scan?: VulnScan }>("GET", `/servers/${id}/vulns`),
  createServer: (s: ServerInput) => request<Server>("POST", "/servers", s),
  updateServer: (id: string, s: ServerInput) => request<Server>("PUT", `/servers/${id}`, s),
  deleteServer: (id: string) => request<void>("DELETE", `/servers/${id}`),
  rotateToken: (id: string) => request<{ agent_token: string }>("POST", `/servers/${id}/token`),

  listGroups: () => request<ServerGroup[]>("GET", "/groups"),
  createGroup: (g: Partial<ServerGroup>) => request<ServerGroup>("POST", "/groups", g),
  updateGroup: (id: string, g: Partial<ServerGroup>) => request<ServerGroup>("PUT", `/groups/${id}`, g),
  deleteGroup: (id: string) => request<void>("DELETE", `/groups/${id}`),
  addMember: (groupId: string, serverId: string) =>
    request<{ status: string }>("POST", `/groups/${groupId}/members`, { server_id: serverId }),
  removeMember: (groupId: string, serverId: string) =>
    request<void>("DELETE", `/groups/${groupId}/members/${serverId}`),

  dashboard: () => request<DashboardData>("GET", "/dashboard"),

  listSessions: () => request<Session[]>("GET", "/sessions"),
  getSession: (id: string) => request<Session>("GET", `/sessions/${id}`),
  sessionCommands: (id: string) => request<CommandEntry[]>("GET", `/sessions/${id}/commands`),
  commandSearch: (q: string) =>
    request<CommandHit[]>("GET", `/commands/search?q=${encodeURIComponent(q)}`),
  terminateSession: (id: string) =>
    request<{ status: string }>("POST", `/sessions/${id}/terminate`),

  queryAudit: (params: Record<string, string>) => {
    const qs = new URLSearchParams(params).toString();
    return request<AuditLog[]>("GET", `/audit${qs ? `?${qs}` : ""}`);
  },
  verifyAudit: () =>
    request<{ ok: boolean; checked: number; break_at_id?: number; break_error?: string }>(
      "GET",
      "/audit/verify"
    ),

  accessReview: () => request<AccessReviewRow[]>("GET", "/reports/access-review"),
  sessionReportURL: () =>
    `/api/reports/sessions.csv?token=${encodeURIComponent(getToken() ?? "")}`,

  listUsers: () => request<User[]>("GET", "/users"),
  createUser: (u: { username: string; password: string; role?: string }) =>
    request<User>("POST", "/users", u),

  // MFA
  mfaSetup: () => request<{ secret: string; otpauth: string }>("POST", "/auth/mfa/setup"),
  mfaEnable: (code: string) => request<{ status: string }>("POST", "/auth/mfa/enable", { code }),
  mfaDisable: (code: string) => request<{ status: string }>("POST", "/auth/mfa/disable", { code }),

  // SFTP
  sftpList: (id: string, path: string) =>
    request<{ path: string; entries: FileEntry[] }>(
      "GET",
      `/servers/${id}/sftp?path=${encodeURIComponent(path)}`
    ),
  sftpDownloadURL: (id: string, path: string) =>
    `/api/servers/${id}/sftp/download?path=${encodeURIComponent(path)}&token=${encodeURIComponent(getToken() ?? "")}`,
  sftpUpload: async (id: string, path: string, file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`/api/servers/${id}/sftp/upload?path=${encodeURIComponent(path)}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${getToken() ?? ""}` },
      body: fd,
    });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  // JIT access
  requestAccess: (serverId: string, reason: string) =>
    request<{ id: string; status: string }>("POST", "/access/request", { server_id: serverId, reason }),
  listAccessRequests: () => request<AccessRequest[]>("GET", "/access/requests"),
  approveAccess: (id: string, minutes: number) =>
    request<{ status: string }>("POST", `/access/requests/${id}/approve`, { minutes }),
  denyAccess: (id: string) => request<{ status: string }>("POST", `/access/requests/${id}/deny`),

  createBulk: (groupId: string, command: string, script = false) =>
    request<{ job_id: string; status: string }>("POST", "/bulk", {
      group_id: groupId,
      command,
      script,
    }),
  getBulk: (jobId: string) =>
    request<{ job: unknown; results: BulkResult[] }>("GET", `/bulk/${jobId}`),
};

// castURL builds the asciinema recording URL for a session (token in query so
// the player can fetch it without custom headers).
export function castURL(sessionId: string): string {
  const token = getToken() ?? "";
  return `/api/sessions/${sessionId}/cast?token=${encodeURIComponent(token)}`;
}

// wsURL builds an absolute ws(s):// URL for a gateway WebSocket path, carrying
// the auth token as a query parameter (WebSocket clients can't set headers).
export function wsURL(path: string): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const token = getToken() ?? "";
  return `${proto}://${window.location.host}${path}?token=${encodeURIComponent(token)}`;
}
