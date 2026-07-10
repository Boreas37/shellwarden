import { useEffect, useRef, useState } from "react";
import Modal from "../../components/Modal";
import { IconDownload, IconPlus, IconChevron } from "../../components/icons";
import { api, FileEntry, Server } from "../../api/client";

export default function SftpModal({ server, onClose }: { server: Server; onClose: () => void }) {
  const [path, setPath] = useState(".");
  const [entries, setEntries] = useState<FileEntry[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  async function load(p: string) {
    setBusy(true);
    setError("");
    try {
      const res = await api.sftpList(server.id, p);
      setEntries(res.entries.sort((a, b) => Number(b.is_dir) - Number(a.is_dir) || a.name.localeCompare(b.name)));
      setPath(res.path);
    } catch (e) {
      setError(String(e).replace("Error:", "").trim());
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    load("/");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function join(p: string, name: string) {
    if (p === "/" || p === ".") return "/" + name;
    return p.replace(/\/$/, "") + "/" + name;
  }
  function parent(p: string) {
    if (p === "/" || p === "." || !p.includes("/")) return "/";
    const up = p.replace(/\/$/, "").replace(/\/[^/]+$/, "");
    return up === "" ? "/" : up;
  }

  async function upload(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (!f) return;
    setBusy(true);
    try {
      await api.sftpUpload(server.id, path, f);
      await load(path);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  return (
    <Modal kicker="sftp" title={`Files — ${server.name}`} onClose={onClose} wide>
      {error && <p className="error-text">{error}</p>}

      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12 }}>
        <button className="btn ghost sm" onClick={() => load(parent(path))} disabled={path === "/"}>
          <IconChevron style={{ transform: "rotate(90deg)" }} /> Up
        </button>
        <code className="mono" style={{ flex: 1, color: "var(--amber)" }}>
          {path}
        </code>
        <button className="btn sm" onClick={() => fileRef.current?.click()} disabled={busy}>
          <IconPlus /> Upload
        </button>
        <input ref={fileRef} type="file" hidden onChange={upload} />
      </div>

      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th style={{ width: 110 }}>Size</th>
            <th style={{ width: 130 }}>Mode</th>
            <th style={{ width: 60 }}></th>
          </tr>
        </thead>
        <tbody>
          {entries.map((f) => (
            <tr key={f.name}>
              <td>
                {f.is_dir ? (
                  <a style={{ cursor: "pointer" }} onClick={() => load(join(path, f.name))}>
                    📁 {f.name}/
                  </a>
                ) : (
                  <span>{f.name}</span>
                )}
              </td>
              <td className="mono">{f.is_dir ? "—" : `${f.size}`}</td>
              <td className="mono" style={{ color: "var(--fg-dim)" }}>{f.mode}</td>
              <td style={{ textAlign: "right" }}>
                {!f.is_dir && (
                  <a className="iconbtn" title="Download" href={api.sftpDownloadURL(server.id, join(path, f.name))}>
                    <IconDownload />
                  </a>
                )}
              </td>
            </tr>
          ))}
          {entries.length === 0 && !busy && (
            <tr>
              <td colSpan={4} style={{ color: "var(--fg-faint)", textAlign: "center", padding: 20 }}>
                Empty directory.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Modal>
  );
}
