import { useEffect, useState } from "react";
import Modal from "../../components/Modal";
import { api, AccessRequest, isAdmin } from "../../api/client";

export default function AccessModal({ onClose }: { onClose: () => void }) {
  const [reqs, setReqs] = useState<AccessRequest[]>([]);
  const [error, setError] = useState("");

  async function load() {
    try {
      setReqs(await api.listAccessRequests());
    } catch (e) {
      setError(String(e));
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function decide(id: string, approve: boolean) {
    try {
      if (approve) await api.approveAccess(id, 60);
      else await api.denyAccess(id);
      await load();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <Modal kicker="access" title="JIT access requests" onClose={onClose} wide>
      {error && <p className="error-text">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Requested</th>
            {isAdmin() && <th>User</th>}
            <th>Host</th>
            <th>Reason</th>
            <th>Status</th>
            {isAdmin() && <th></th>}
          </tr>
        </thead>
        <tbody>
          {reqs.map((r) => (
            <tr key={r.id}>
              <td className="mono" style={{ whiteSpace: "nowrap" }}>
                {new Date(r.requested_at).toLocaleString()}
              </td>
              {isAdmin() && <td>{r.username}</td>}
              <td>{r.server_name || r.server_id.slice(0, 8)}</td>
              <td style={{ color: "var(--fg-dim)" }}>{r.reason || "—"}</td>
              <td>
                <span className={`badge ${r.status === "approved" ? "ok" : r.status === "denied" ? "error" : "running"}`}>
                  {r.status}
                </span>
                {r.expires_at && r.status === "approved" && (
                  <div style={{ fontSize: 11, color: "var(--fg-faint)" }}>
                    until {new Date(r.expires_at).toLocaleTimeString()}
                  </div>
                )}
              </td>
              {isAdmin() && (
                <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                  {r.status === "pending" && (
                    <>
                      <button className="btn sm" onClick={() => decide(r.id, true)}>
                        Approve 1h
                      </button>{" "}
                      <button className="btn danger sm" onClick={() => decide(r.id, false)}>
                        Deny
                      </button>
                    </>
                  )}
                </td>
              )}
            </tr>
          ))}
          {reqs.length === 0 && (
            <tr>
              <td colSpan={isAdmin() ? 6 : 4} style={{ color: "var(--fg-faint)", textAlign: "center", padding: 20 }}>
                No access requests.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Modal>
  );
}
