import { useState, useEffect, FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, setToken, setRole } from "../api/client";

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [mfaStep, setMfaStep] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [ssoEnabled, setSsoEnabled] = useState(false);

  // Handle SSO callback: token arrives in the URL fragment.
  useEffect(() => {
    const hash = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const t = hash.get("token");
    if (t) {
      setToken(t);
      setRole(hash.get("role") || "operator");
      window.location.hash = "";
      navigate("/");
      return;
    }
    api.authMethods().then((m) => setSsoEnabled(!!m.oidc)).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const { token, user } = await api.login(username, password, mfaStep ? code : undefined);
      setToken(token);
      setRole(user.role);
      navigate("/");
    } catch (err) {
      const msg = String(err);
      if (msg.includes("mfa_required")) {
        setMfaStep(true);
        setError("Enter your authenticator code");
      } else {
        setError(mfaStep ? "Invalid code" : "Invalid username or password");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={onSubmit}>
        <div className="wordmark">
          <span className="beacon" />
          ShellWarden
        </div>
        <p className="login-sub">// privileged access console</p>

        {!mfaStep ? (
          <>
            <div className="field">
              <label>Username</label>
              <input value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
            </div>
            <div className="field">
              <label>Password</label>
              <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
          </>
        ) : (
          <div className="field">
            <label>Authenticator code</label>
            <input
              className="mono"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="123456"
              maxLength={6}
              autoFocus
            />
          </div>
        )}

        {error && <p className="error-text">{error}</p>}
        <button type="submit" className="btn" disabled={busy} style={{ width: "100%", justifyContent: "center" }}>
          {busy ? "Authenticating…" : mfaStep ? "Verify" : "Sign in"}
        </button>

        {ssoEnabled && !mfaStep && (
          <button
            type="button"
            className="btn ghost"
            style={{ width: "100%", justifyContent: "center", marginTop: 10 }}
            onClick={() => (window.location.href = "/api/auth/oidc/login")}
          >
            Sign in with SSO
          </button>
        )}
      </form>
    </div>
  );
}
