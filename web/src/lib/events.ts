// Human-readable rendering for audit / dashboard events. Stored data stays raw
// (forensics / SIEM); this only affects display.

export type Tone = "ok" | "bad" | "info" | "dim";

const META: Record<string, { label: string; tone: Tone }> = {
  session_start: { label: "Session opened", tone: "ok" },
  session_end: { label: "Session closed", tone: "dim" },
  login_failed: { label: "Failed login", tone: "bad" },
  bruteforce: { label: "Brute force", tone: "bad" },
  host_exec: { label: "Command", tone: "info" },
  vuln_scan: { label: "Vuln scan", tone: "info" },
  output: { label: "Output", tone: "dim" },
  input: { label: "Keystroke", tone: "dim" },
};

export function eventMeta(type: string): { label: string; tone: Tone } {
  return META[type] ?? { label: type, tone: "dim" };
}

// prettyCmd turns noisy process names into readable phrases, but keeps real
// commands verbatim (that's the point of host command logging).
function prettyCmd(cmdline: string, comm: string): string {
  const c = (cmdline || comm || "").trim();
  if (c.startsWith("sshd: ") && c.includes("@")) return `SSH login (${c.split(":")[1].trim().split("@")[0]})`;
  if (c.startsWith("sshd:")) return "SSH session setup";
  if (c === "-bash" || c === "-sh" || c === "bash" || c === "sh") return "login shell";
  return c.length > 140 ? c.slice(0, 140) + "…" : c;
}

// describe builds a one-line human description for an event.
export function describeEvent(
  type: string,
  detail: string | undefined,
  user?: string,
  server?: string
): string {
  const d = detail ?? "";
  switch (type) {
    case "host_exec": {
      try {
        const j = JSON.parse(d);
        const who = j.user || (j.uid !== undefined ? `uid ${j.uid}` : "someone");
        const where = server ? ` on ${server}` : "";
        return `${who}${where}: ${prettyCmd(j.cmdline, j.comm)}`;
      } catch {
        return d;
      }
    }
    case "session_start":
      return `${user || "user"}${server ? ` → ${server}` : ""}${d ? ` · reason: ${d}` : ""}`;
    case "session_end":
      return `${user || "user"}${server ? ` → ${server}` : ""}`;
    case "login_failed":
      return `username: ${d || "?"}`;
    case "bruteforce":
      return d || "repeated failed logins";
    case "vuln_scan":
      return d;
    default:
      return d;
  }
}
