import { useState } from "react";
import Modal from "../../components/Modal";
import { Server } from "../../api/client";
import { useTerminals } from "../../terminals/TerminalsContext";

// Captures a compliance reason/ticket, then opens the session with it attached
// (recorded against the session and the audit log).
export default function ReasonModal({ server, onClose }: { server: Server; onClose: () => void }) {
  const { open } = useTerminals();
  const [reason, setReason] = useState("");

  function connect() {
    open({ id: server.id, name: server.name, protocol: server.protocol }, reason || undefined);
    onClose();
  }

  return (
    <Modal
      kicker="connect"
      title={`Connect to ${server.name}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn ghost" onClick={onClose}>
            Cancel
          </button>
          <button className="btn" onClick={connect}>
            Open session
          </button>
        </>
      }
    >
      <div className="field">
        <label>Reason / ticket (recorded for audit)</label>
        <input
          autoFocus
          placeholder="e.g. INC-4821 — investigate disk alert"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && connect()}
        />
      </div>
      <p style={{ color: "var(--fg-faint)", fontSize: 12, margin: 0 }}>
        Attached to the session record and written to the audit log on connect.
      </p>
    </Modal>
  );
}
