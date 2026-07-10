import { api, clearToken, canWrite, getRole, isAdmin } from "../api/client";
import { IconScroll, IconBolt, IconLogout, IconHistory, IconShield, IconKey, IconActivity } from "../components/icons";

interface Props {
  onAudit: () => void;
  onBulk: () => void;
  onSessions: () => void;
  onAccess: () => void;
  onSecurity: () => void;
  onReports: () => void;
}

export default function TopBar({ onAudit, onBulk, onSessions, onAccess, onSecurity, onReports }: Props) {
  async function logout() {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    clearToken();
    window.location.href = "/login";
  }

  return (
    <header className="topbar">
      <div className="wordmark">
        <span className="beacon" />
        ShellWarden
      </div>
      <div className="topbar-spacer" />
      <button className="topbar-tab" onClick={onSessions}>
        <IconHistory /> Sessions
      </button>
      {canWrite() && (
        <button className="topbar-tab" onClick={onBulk}>
          <IconBolt /> Bulk Exec
        </button>
      )}
      <button className="topbar-tab" onClick={onAccess}>
        <IconKey /> Access
      </button>
      <button className="topbar-tab" onClick={onAudit}>
        <IconScroll /> Audit Log
      </button>
      {isAdmin() && (
        <button className="topbar-tab" onClick={onReports}>
          <IconActivity /> Reports
        </button>
      )}
      <div className="topbar-user">
        <button className="iconbtn" title="Two-factor auth" onClick={onSecurity}>
          <IconShield />
        </button>
        <span className={`role-pill ${getRole()}`}>{getRole()}</span>
        <button className="iconbtn" title="Sign out" onClick={logout}>
          <IconLogout />
        </button>
      </div>
    </header>
  );
}
