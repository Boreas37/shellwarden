import { useState } from "react";
import Modal from "../../components/Modal";
import { IconCopy } from "../../components/icons";
import { api } from "../../api/client";

type Distro = "debian" | "rhel" | "arch";

const DISTROS: { key: Distro; label: string; prereq: string }[] = [
  { key: "debian", label: "Debian / Ubuntu", prereq: "sudo apt-get update && sudo apt-get install -y curl" },
  { key: "rhel", label: "RHEL / CentOS / Fedora", prereq: "sudo yum install -y curl" },
  { key: "arch", label: "Arch", prereq: "sudo pacman -Sy --noconfirm curl" },
];

export default function EnrollModal({ onClose, onSaved }: { onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState("");
  const [sshUser, setSshUser] = useState("root");
  const [sshPassword, setSshPassword] = useState("");
  const [distro, setDistro] = useState<Distro>("debian");
  const [enrolled, setEnrolled] = useState<{ id: string; token: string } | null>(null);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  const httpBase = window.location.origin;
  const wsProto = window.location.protocol === "https:" ? "wss" : "ws";
  const wsBase = `${wsProto}://${window.location.host}`;
  const selected = DISTROS.find((d) => d.key === distro)!;

  async function generate() {
    setError("");
    setCopied(false);
    try {
      const srv = await api.createServer({
        name,
        host: "127.0.0.1",
        port: 22,
        protocol: "ssh",
        connection_mode: "agent",
        ssh_user: sshUser || undefined,
        ssh_password: sshPassword || undefined,
      });
      setEnrolled({ id: srv.id, token: srv.agent_token ?? "" });
      onSaved();
    } catch (e) {
      setError(String(e));
    }
  }

  const script = enrolled
    ? `# 1) ensure curl is present\n${selected.prereq}\n\n` +
      `# 2) install & start the ShellWarden agent (as root)\n` +
      `curl -fsSL ${httpBase}/install.sh | sudo bash -s -- \\\n` +
      `  --gateway ${wsBase} \\\n` +
      `  --token   ${enrolled.token} \\\n` +
      `  --id      ${enrolled.id}`
    : "";

  async function copy() {
    try {
      await navigator.clipboard.writeText(script);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setError("clipboard unavailable");
    }
  }

  return (
    <Modal
      kicker="enroll"
      title="Enroll a host via agent"
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            Done
          </button>
          {!enrolled && (
            <button className="btn" onClick={generate} disabled={!name}>
              Generate command
            </button>
          )}
        </>
      }
    >
      {error && <p className="error-text">{error}</p>}
      <p style={{ marginTop: 0, color: "var(--fg-dim)", fontSize: 13, lineHeight: 1.6 }}>
        Name the host and pick its distro. Run the generated one-liner on the target as root — the
        agent installs itself, opens a reverse tunnel, and the host appears in your tree
        automatically.
      </p>

      <div className="grid2">
        <div className="field">
          <label>Host name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="web-01" />
        </div>
        <div className="field">
          <label>SSH user</label>
          <input value={sshUser} onChange={(e) => setSshUser(e.target.value)} />
        </div>
        <div className="field">
          <label>SSH password (for sessions)</label>
          <input
            type="password"
            value={sshPassword}
            onChange={(e) => setSshPassword(e.target.value)}
            placeholder="••••••••"
          />
        </div>
        <div className="field">
          <label>Distro</label>
          <select value={distro} onChange={(e) => setDistro(e.target.value as Distro)}>
            {DISTROS.map((d) => (
              <option key={d.key} value={d.key}>
                {d.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {enrolled && (
        <div className="field">
          <div className="field-row">
            <label>{selected.label} — run on target</label>
            <button className="btn ghost sm" onClick={copy}>
              <IconCopy /> {copied ? "Copied" : "Copy"}
            </button>
          </div>
          <div className="code-block">{script}</div>
          <p style={{ color: "var(--fg-faint)", fontSize: 12, marginBottom: 0 }}>
            Host created with status <span className="badge unknown">unknown</span> — it flips to{" "}
            <span className="badge online">online</span> once the agent connects.
          </p>
        </div>
      )}
    </Modal>
  );
}
