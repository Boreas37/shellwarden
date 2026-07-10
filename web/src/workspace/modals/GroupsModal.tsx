import { useState } from "react";
import Modal from "../../components/Modal";
import { IconTrash } from "../../components/icons";
import { api } from "../../api/client";
import { useServers } from "../../data/ServersContext";

export default function GroupsModal({ onClose }: { onClose: () => void }) {
  const { servers, groups, refresh } = useServers();
  const [name, setName] = useState("");
  const [error, setError] = useState("");

  const serverName = (id: string) => servers.find((s) => s.id === id)?.name ?? id;

  async function run(fn: () => Promise<unknown>) {
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <Modal kicker="groups" title="Server groups" onClose={onClose} wide>
      {error && <p className="error-text">{error}</p>}

      <div style={{ display: "flex", gap: 8, marginBottom: 18 }}>
        <input
          style={{ flex: 1 }}
          placeholder="New group name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button
          className="btn"
          disabled={!name}
          onClick={() => run(async () => { await api.createGroup({ name }); setName(""); })}
        >
          Create group
        </button>
      </div>

      {groups.length === 0 && <p style={{ color: "var(--fg-faint)" }}>No groups yet.</p>}

      {groups.map((g) => {
        const members = g.members ?? [];
        return (
          <div
            key={g.id}
            style={{ border: "1px solid var(--line)", borderRadius: "var(--r-sm)", padding: 14, marginBottom: 12 }}
          >
            <div style={{ display: "flex", alignItems: "center", marginBottom: 10 }}>
              <strong style={{ flex: 1 }}>{g.name}</strong>
              <span style={{ color: "var(--fg-faint)", fontFamily: "var(--mono)", fontSize: 12, marginRight: 10 }}>
                {members.length} member{members.length === 1 ? "" : "s"}
              </span>
              <button
                className="btn danger sm"
                onClick={() => confirm(`Delete group "${g.name}"?`) && run(() => api.deleteGroup(g.id))}
              >
                <IconTrash /> Delete
              </button>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 7 }}>
              {servers.map((s) => {
                const inGroup = members.includes(s.id);
                return (
                  <button
                    key={s.id}
                    className={`chip ${inGroup ? "on" : ""}`}
                    onClick={() =>
                      run(() =>
                        inGroup ? api.removeMember(g.id, s.id) : api.addMember(g.id, s.id)
                      )
                    }
                  >
                    {inGroup ? "✓" : "+"} {s.name}
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </Modal>
  );
}
