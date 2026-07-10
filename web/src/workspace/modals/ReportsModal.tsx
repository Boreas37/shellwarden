import { useEffect, useState } from "react";
import Modal from "../../components/Modal";
import { IconDownload } from "../../components/icons";
import { api, AccessReviewRow } from "../../api/client";

export default function ReportsModal({ onClose }: { onClose: () => void }) {
  const [rows, setRows] = useState<AccessReviewRow[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.accessReview().then(setRows).catch((e) => setError(String(e)));
  }, []);

  return (
    <Modal kicker="compliance" title="Access review" onClose={onClose} wide>
      {error && <p className="error-text">{error}</p>}

      <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 12 }}>
        <a className="btn ghost sm" href={api.sessionReportURL()} target="_blank" rel="noreferrer">
          <IconDownload /> Session report (CSV)
        </a>
      </div>

      <table>
        <thead>
          <tr>
            <th>User</th>
            <th>Role</th>
            <th>MFA</th>
            <th>Sessions (30d)</th>
            <th>Hosts (30d)</th>
            <th>Active grants</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.username}>
              <td>{r.username}</td>
              <td>
                <span className={`role-pill ${r.role}`}>{r.role}</span>
              </td>
              <td>
                {r.mfa_enabled ? (
                  <span className="badge ok">on</span>
                ) : (
                  <span className="badge unknown">off</span>
                )}
              </td>
              <td className="mono">{r.sessions_30d}</td>
              <td className="mono">{r.distinct_hosts_30d}</td>
              <td className="mono">{r.active_grants}</td>
              <td className="mono" style={{ color: "var(--fg-dim)" }}>
                {r.last_seen ? new Date(r.last_seen).toLocaleString() : "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </Modal>
  );
}
