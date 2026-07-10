import { useState } from "react";
import { ServersProvider, useServers } from "../data/ServersContext";
import { TerminalsProvider } from "../terminals/TerminalsContext";
import { Server } from "../api/client";
import TopBar from "./TopBar";
import StatusBar from "./StatusBar";
import ConnectionsSidebar from "./ConnectionsSidebar";
import MainArea from "./MainArea";
import ServerFormModal from "./modals/ServerFormModal";
import EnrollModal from "./modals/EnrollModal";
import GroupsModal from "./modals/GroupsModal";
import BulkModal from "./modals/BulkModal";
import AuditModal from "./modals/AuditModal";
import SessionsModal from "./modals/SessionsModal";
import ReasonModal from "./modals/ReasonModal";
import SftpModal from "./modals/SftpModal";
import AccessModal from "./modals/AccessModal";
import SecurityModal from "./modals/SecurityModal";
import ReportsModal from "./modals/ReportsModal";
import ServerDetailModal from "./modals/ServerDetailModal";
import Modal from "../components/Modal";
import WatchTerminal from "../components/Terminal/WatchTerminal";

type ModalState =
  | { kind: "none" }
  | { kind: "add" }
  | { kind: "edit"; server: Server }
  | { kind: "enroll" }
  | { kind: "groups" }
  | { kind: "bulk" }
  | { kind: "audit" }
  | { kind: "sessions" }
  | { kind: "reason"; server: Server }
  | { kind: "sftp"; server: Server }
  | { kind: "access" }
  | { kind: "security" }
  | { kind: "reports" }
  | { kind: "watch"; sessionId: string }
  | { kind: "detail"; server: Server };

function Shell() {
  const { refresh } = useServers();
  const [modal, setModal] = useState<ModalState>({ kind: "none" });
  const close = () => setModal({ kind: "none" });

  return (
    <div className="shell">
      <TopBar
        onAudit={() => setModal({ kind: "audit" })}
        onBulk={() => setModal({ kind: "bulk" })}
        onSessions={() => setModal({ kind: "sessions" })}
        onAccess={() => setModal({ kind: "access" })}
        onSecurity={() => setModal({ kind: "security" })}
        onReports={() => setModal({ kind: "reports" })}
      />
      <div className="middle">
        <ConnectionsSidebar
          onAdd={() => setModal({ kind: "add" })}
          onEnroll={() => setModal({ kind: "enroll" })}
          onGroups={() => setModal({ kind: "groups" })}
          onEdit={(s) => setModal({ kind: "edit", server: s })}
          onConnectReason={(s) => setModal({ kind: "reason", server: s })}
          onSftp={(s) => setModal({ kind: "sftp", server: s })}
          onRequestAccess={(s) => setModal({ kind: "access" })}
          onDetail={(s) => setModal({ kind: "detail", server: s })}
        />
        <MainArea onWatch={(id) => setModal({ kind: "watch", sessionId: id })} />
      </div>
      <StatusBar />

      {modal.kind === "add" && <ServerFormModal onClose={close} onSaved={refresh} />}
      {modal.kind === "edit" && (
        <ServerFormModal server={modal.server} onClose={close} onSaved={refresh} />
      )}
      {modal.kind === "enroll" && <EnrollModal onClose={close} onSaved={refresh} />}
      {modal.kind === "groups" && <GroupsModal onClose={close} />}
      {modal.kind === "bulk" && <BulkModal onClose={close} />}
      {modal.kind === "audit" && <AuditModal onClose={close} />}
      {modal.kind === "sessions" && <SessionsModal onClose={close} />}
      {modal.kind === "reason" && <ReasonModal server={modal.server} onClose={close} />}
      {modal.kind === "sftp" && <SftpModal server={modal.server} onClose={close} />}
      {modal.kind === "access" && <AccessModal onClose={close} />}
      {modal.kind === "security" && <SecurityModal onClose={close} />}
      {modal.kind === "reports" && <ReportsModal onClose={close} />}
      {modal.kind === "detail" && <ServerDetailModal server={modal.server} onClose={close} />}
      {modal.kind === "watch" && (
        <Modal kicker="shadow" title="Live session — read only" onClose={close} wide>
          <WatchTerminal sessionId={modal.sessionId} />
        </Modal>
      )}
    </div>
  );
}

export default function AppShell() {
  return (
    <ServersProvider>
      <TerminalsProvider>
        <Shell />
      </TerminalsProvider>
    </ServersProvider>
  );
}
