import { useState } from "react";
import Modal from "../../components/Modal";
import { api, Server, ServerInput } from "../../api/client";

interface Props {
  server?: Server; // present => edit mode
  onClose: () => void;
  onSaved: () => void;
}

export default function ServerFormModal({ server, onClose, onSaved }: Props) {
  const editing = !!server;
  const [form, setForm] = useState<ServerInput>({
    name: server?.name ?? "",
    host: server?.host ?? "",
    port: server?.port ?? 22,
    protocol: server?.protocol ?? "ssh",
    connection_mode: server?.connection_mode ?? "direct",
    ssh_user: server?.ssh_user ?? "",
    ssh_password: "",
    ssh_key: "",
    use_ssh_ca: server?.use_ssh_ca ?? false,
  });
  const [clearPw, setClearPw] = useState(false);
  const [clearKey, setClearKey] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  function set<K extends keyof ServerInput>(k: K, v: ServerInput[K]) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  async function save() {
    setError("");
    setBusy(true);
    try {
      const payload: ServerInput = {
        ...form,
        port: Number(form.port) || 22,
        ssh_user: form.ssh_user || undefined,
        ssh_password: clearPw ? "" : form.ssh_password || undefined,
        ssh_key: clearKey ? "" : form.ssh_key || undefined,
        use_ssh_ca: form.use_ssh_ca,
      };
      if (editing) await api.updateServer(server!.id, payload);
      else await api.createServer(payload);
      onSaved();
      onClose();
    } catch (e) {
      setError(String(e).replace("Error:", "").trim());
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      kicker={editing ? "edit host" : "new host"}
      title={editing ? form.name || "Edit host" : "Register a host"}
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn" onClick={save} disabled={busy || !form.name || !form.host}>
            {busy ? "Saving…" : editing ? "Save changes" : "Create"}
          </button>
        </>
      }
    >
      {error && <p className="error-text">{error}</p>}

      <div className="grid2">
        <div className="field">
          <label>Name</label>
          <input value={form.name} onChange={(e) => set("name", e.target.value)} autoFocus />
        </div>
        <div className="field">
          <label>Host / IP</label>
          <input value={form.host} onChange={(e) => set("host", e.target.value)} />
        </div>
        <div className="field">
          <label>Port</label>
          <input
            type="number"
            value={form.port}
            onChange={(e) => set("port", Number(e.target.value))}
          />
        </div>
        <div className="field">
          <label>SSH user</label>
          <input value={form.ssh_user} onChange={(e) => set("ssh_user", e.target.value)} />
        </div>
        <div className="field">
          <label>Protocol</label>
          <select value={form.protocol} onChange={(e) => set("protocol", e.target.value)}>
            <option value="ssh">SSH</option>
            <option value="rdp">RDP</option>
          </select>
        </div>
        <div className="field">
          <label>Connection mode</label>
          <select
            value={form.connection_mode}
            onChange={(e) => set("connection_mode", e.target.value)}
          >
            <option value="direct">direct (gateway dials out)</option>
            <option value="agent">agent (reverse tunnel)</option>
          </select>
        </div>
      </div>

      <label className="checkline" style={{ marginBottom: 14 }}>
        <input
          type="checkbox"
          checked={form.use_ssh_ca}
          onChange={(e) => set("use_ssh_ca", e.target.checked)}
        />
        Credential-less access — gateway signs a short-lived SSH certificate (target must trust the CA)
      </label>

      <div className="field">
        <div className="field-row">
          <label>SSH password {editing && <span>(blank = keep)</span>}</label>
          {editing && (
            <label className="checkline">
              <input type="checkbox" checked={clearPw} onChange={(e) => setClearPw(e.target.checked)} />
              clear
            </label>
          )}
        </div>
        <input
          type="password"
          placeholder={clearPw ? "(will be cleared)" : "••••••••"}
          disabled={clearPw}
          value={form.ssh_password}
          onChange={(e) => set("ssh_password", e.target.value)}
        />
      </div>

      <div className="field">
        <div className="field-row">
          <label>SSH private key {editing && <span>(blank = keep)</span>}</label>
          {editing && (
            <label className="checkline">
              <input type="checkbox" checked={clearKey} onChange={(e) => setClearKey(e.target.checked)} />
              clear
            </label>
          )}
        </div>
        <textarea
          rows={4}
          className="mono"
          placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          disabled={clearKey}
          value={form.ssh_key}
          onChange={(e) => set("ssh_key", e.target.value)}
        />
      </div>
    </Modal>
  );
}
