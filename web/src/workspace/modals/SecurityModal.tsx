import { useState } from "react";
import Modal from "../../components/Modal";
import { api } from "../../api/client";

// Self-service MFA (TOTP) enrollment.
export default function SecurityModal({ onClose }: { onClose: () => void }) {
  const [secret, setSecret] = useState("");
  const [otpauth, setOtpauth] = useState("");
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");

  async function setup() {
    setError("");
    try {
      const r = await api.mfaSetup();
      setSecret(r.secret);
      setOtpauth(r.otpauth);
      setMsg("");
    } catch (e) {
      setError(String(e));
    }
  }
  async function enable() {
    setError("");
    try {
      await api.mfaEnable(code);
      setMsg("✓ MFA enabled. You'll be asked for a code at next login.");
      setSecret("");
      setOtpauth("");
    } catch {
      setError("Invalid code — check your authenticator and try again.");
    }
  }
  async function disable() {
    setError("");
    try {
      await api.mfaDisable(code);
      setMsg("MFA disabled.");
    } catch {
      setError("Invalid code.");
    }
  }

  return (
    <Modal kicker="security" title="Two-factor authentication" onClose={onClose}>
      {error && <p className="error-text">{error}</p>}
      {msg && <p style={{ color: "var(--green)" }}>{msg}</p>}

      <p style={{ color: "var(--fg-dim)", fontSize: 13, marginTop: 0 }}>
        Add a TOTP authenticator (Google Authenticator, 1Password, Authy…).
      </p>

      {!secret && (
        <button className="btn" onClick={setup}>
          Begin enrollment
        </button>
      )}

      {secret && (
        <>
          <div className="field">
            <label>1. Add this secret to your authenticator</label>
            <div className="code-block" style={{ whiteSpace: "pre-wrap" }}>
              {secret}
              {"\n\n"}
              {otpauth}
            </div>
          </div>
          <div className="field">
            <label>2. Enter the current 6-digit code to confirm</label>
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="123456"
              className="mono"
              maxLength={6}
            />
          </div>
          <button className="btn" onClick={enable} disabled={code.length !== 6}>
            Enable MFA
          </button>
        </>
      )}

      <hr style={{ border: "none", borderTop: "1px solid var(--line)", margin: "20px 0" }} />
      <div className="field">
        <label>Disable MFA (enter a current code)</label>
        <input value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" className="mono" maxLength={6} />
      </div>
      <button className="btn ghost" onClick={disable} disabled={code.length !== 6}>
        Disable MFA
      </button>
    </Modal>
  );
}
