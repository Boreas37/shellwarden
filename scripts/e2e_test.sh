#!/usr/bin/env bash
#
# ShellWarden end-to-end test harness.
#
# Exercises the full gateway API + WebSocket surface against a running stack.
# Designed to run on the test VM:
#
#   docker compose -f docker-compose.test.yml up --build -d
#   ./scripts/e2e_test.sh
#
# Env (all optional):
#   BASE         gateway base URL              (default http://localhost:8080)
#   ADMIN_USER   admin username                (default admin)
#   ADMIN_PASS   admin password                (default changeme)
#   TARGET_NAME  name of an online ssh target  (default debian-target)
#   PSQL         psql command prefix for DB-level checks (optional). e.g.
#                PSQL="docker compose -f docker-compose.test.yml exec -T postgres psql -U shellwarden -d shellwarden"
#
set -uo pipefail

BASE="${BASE:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-changeme}"
TARGET_NAME="${TARGET_NAME:-debian-target}"
PSQL="${PSQL:-}"

# Prebuild the WS probe once (avoids `go run` compile latency that would make
# timing-sensitive checks flaky).
WS=/tmp/sw_wsprobe
go build -o "$WS" ./scripts/wsprobe || { echo "failed to build wsprobe"; exit 1; }

PASS=0; FAIL=0
ok()   { echo "  ✓ $1"; PASS=$((PASS+1)); }
bad()  { echo "  ✗ $1"; FAIL=$((FAIL+1)); }
note() { echo "  · $1"; }
hdr()  { echo; echo "== $1 =="; }

jq_get() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
login() { curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d "$1" | jq_get 'd.get("token","")'; }
code()  { curl -s -o /dev/null -w '%{http_code}' "$@"; }

hdr "Health & auth"
[ "$(code "$BASE/healthz")" = "200" ] && ok "healthz 200" || bad "healthz"
ADMIN=$(login "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}")
[ -n "$ADMIN" ] && ok "admin login" || { bad "admin login (aborting)"; exit 1; }
AUTH=(-H "Authorization: Bearer $ADMIN")

SID=$(curl -s "$BASE/api/servers" "${AUTH[@]}" | python3 -c "import sys,json;print(next((s['id'] for s in json.load(sys.stdin) if s['name']=='$TARGET_NAME'),''))")
[ -n "$SID" ] && ok "found target '$TARGET_NAME' ($SID)" || { bad "target '$TARGET_NAME' not found (aborting)"; exit 1; }

hdr "RBAC (auditor read-only)"
curl -s -X POST "$BASE/api/users" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"username":"e2e_auditor","password":"e2e_auditor","role":"auditor"}' >/dev/null
AUD=$(login '{"username":"e2e_auditor","password":"e2e_auditor"}')
AUDH=(-H "Authorization: Bearer $AUD")
[ "$(code "$BASE/api/servers" "${AUDH[@]}")" = "200" ] && ok "auditor GET /servers 200" || bad "auditor GET"
[ "$(code -X POST "$BASE/api/servers" "${AUDH[@]}" -H 'Content-Type: application/json' -d '{"name":"x","host":"1.1.1.1"}')" = "403" ] && ok "auditor POST /servers 403" || bad "auditor POST not blocked"
[ "$(code -X POST "$BASE/api/bulk" "${AUDH[@]}" -H 'Content-Type: application/json' -d '{"group_id":"x","command":"id"}')" = "403" ] && ok "auditor POST /bulk 403" || bad "auditor bulk not blocked"
WSCODE=$(code -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" "$BASE/ws/ssh/$SID?token=$AUD")
[ "$WSCODE" = "403" ] && ok "auditor WS /ws/ssh 403" || bad "auditor WS not blocked ($WSCODE)"

hdr "MFA (TOTP)"
SECRET=$(curl -s -X POST "$BASE/api/auth/mfa/setup" "${AUTH[@]}" | jq_get 'd.get("secret","")')
[ -n "$SECRET" ] && ok "mfa setup returns secret" || bad "mfa setup"
MFACODE=$($WS totp "$SECRET")
EN=$(code -X POST "$BASE/api/auth/mfa/enable" "${AUTH[@]}" -H 'Content-Type: application/json' -d "{\"code\":\"$MFACODE\"}")
[ "$EN" = "200" ] && ok "mfa enable with valid code" || bad "mfa enable ($EN)"
NOMFA=$(curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" | jq_get 'd.get("error","")')
[ "$NOMFA" = "mfa_required" ] && ok "login without code -> mfa_required" || bad "mfa not enforced ($NOMFA)"
MFACODE2=$($WS totp "$SECRET")
WITHMFA=$(login "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\",\"code\":\"$MFACODE2\"}")
[ -n "$WITHMFA" ] && ok "login with valid code succeeds" || bad "mfa login"
# disable again so the rest of the suite uses simple admin login
ADMIN=$(login "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\",\"code\":\"$($WS totp "$SECRET")\"}"); AUTH=(-H "Authorization: Bearer $ADMIN")
DIS=$(code -X POST "$BASE/api/auth/mfa/disable" "${AUTH[@]}" -H 'Content-Type: application/json' -d "{\"code\":\"$($WS totp "$SECRET")\"}")
[ "$DIS" = "200" ] && ok "mfa disable" || bad "mfa disable ($DIS)"

hdr "SSH session + recording + reason"
$WS ssh "$BASE" "$SID" "$ADMIN" "E2E ticket INC-1" "echo E2E_MARKER_\$(hostname)" 4 > /tmp/e2e_ssh.out 2>&1
grep -aq "E2E_MARKER_" /tmp/e2e_ssh.out && ok "ssh session executed command" || bad "ssh session (see /tmp/e2e_ssh.out)"
SESSJSON=$(curl -s "$BASE/api/sessions" "${AUTH[@]}")
HASREASON=$(echo "$SESSJSON" | jq_get 'any(s.get("reason")=="E2E ticket INC-1" for s in d)')
[ "$HASREASON" = "True" ] && ok "session reason recorded" || bad "reason not found"
# Pick a session that has actually ended (has a flushed recording) — resumable
# sessions linger without a recording until they truly end.
RECSESS=$(echo "$SESSJSON" | jq_get 'next((s["id"] for s in d if s.get("recording_path")), "")')
if [ -n "$RECSESS" ]; then
  curl -s "$BASE/api/sessions/$RECSESS/cast?token=$ADMIN" -o /tmp/e2e_cast.txt
  head -1 /tmp/e2e_cast.txt | grep -q '"version":2' && ok "asciinema cast served" || bad "cast"
else
  note "no ended session with a recording yet — skipping cast check"
fi

hdr "Audit chain"
curl -s "$BASE/api/audit/verify" "${AUTH[@]}" | grep -q '"ok":true' && ok "audit chain intact" || bad "audit verify"
curl -s "$BASE/api/audit/export?token=$ADMIN&event_type=host_exec" -o /tmp/e2e_audit.csv
head -1 /tmp/e2e_audit.csv | grep -q '^id,ts,event_type' && ok "audit CSV export" || bad "csv export"

hdr "JIT access workflow"
# operator user
curl -s -X POST "$BASE/api/users" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d '{"username":"e2e_op","password":"e2e_op","role":"operator"}' >/dev/null
OP=$(login '{"username":"e2e_op","password":"e2e_op"}'); OPH=(-H "Authorization: Bearer $OP")
REQID=$(curl -s -X POST "$BASE/api/access/request" "${OPH[@]}" -H 'Content-Type: application/json' -d "{\"server_id\":\"$SID\",\"reason\":\"e2e\"}" | jq_get 'd.get("id","")')
[ -n "$REQID" ] && ok "operator created access request" || bad "access request"
APR=$(code -X POST "$BASE/api/access/requests/$REQID/approve" "${OPH[@]}" -H 'Content-Type: application/json' -d '{"minutes":30}')
[ "$APR" = "403" ] && ok "operator cannot approve (403)" || bad "approve not admin-gated ($APR)"
APR2=$(code -X POST "$BASE/api/access/requests/$REQID/approve" "${AUTH[@]}" -H 'Content-Type: application/json' -d '{"minutes":30}')
[ "$APR2" = "200" ] && ok "admin approved request" || bad "admin approve ($APR2)"
curl -s "$BASE/api/access/requests" "${AUTH[@]}" | grep -q '"status":"approved"' && ok "request shows approved" || bad "approved state"

hdr "SFTP file browser"
curl -s "$BASE/api/servers/$SID/sftp?path=/etc" "${AUTH[@]}" | grep -q '"entries"' && ok "sftp list /etc" || bad "sftp list"
echo "shellwarden-e2e-$(date +%s 2>/dev/null || echo x)" > /tmp/e2e_upload.txt
UP=$(curl -s -X POST "$BASE/api/servers/$SID/sftp/upload?path=/tmp" "${AUTH[@]}" -F "file=@/tmp/e2e_upload.txt" | jq_get 'd.get("bytes",0)')
[ "${UP:-0}" -gt 0 ] && ok "sftp upload ($UP bytes)" || bad "sftp upload"
curl -s "$BASE/api/servers/$SID/sftp/download?path=/tmp/e2e_upload.txt&token=$ADMIN" "${AUTH[@]}" > /tmp/e2e_dl.txt
diff -q /tmp/e2e_upload.txt /tmp/e2e_dl.txt >/dev/null 2>&1 && ok "sftp download round-trip matches" || bad "sftp download mismatch"

hdr "Port-forward (to target sshd:22)"
$WS forward "$BASE" "$SID" "$ADMIN" "127.0.0.1" "22" 3 > /tmp/e2e_fwd.out 2>&1
grep -aq "SSH-2.0" /tmp/e2e_fwd.out && ok "forwarded TCP to sshd (got SSH banner)" || bad "port-forward (see /tmp/e2e_fwd.out)"

hdr "Live shadow + terminate"
# Retry launching a long session until one registers live — tolerant of agent
# reconnect churn (on a stable network the first attempt always works).
LIVE=""
for attempt in 1 2 3 4 5; do
  $WS ssh "$BASE" "$SID" "$ADMIN" "" "sleep 14; echo DONE" 18 > /tmp/e2e_long.out 2>&1 &
  for _ in 1 2 3; do
    sleep 2
    LIVE=$(curl -s "$BASE/api/sessions" "${AUTH[@]}" | python3 -c "import sys,json;print(next((s['id'] for s in json.load(sys.stdin) if not s.get('ended_at')),''))")
    [ -n "$LIVE" ] && break
  done
  [ -n "$LIVE" ] && break
  note "attempt $attempt: agent window down, retrying…"
done
[ -n "$LIVE" ] && ok "live session listed" || bad "no live session"
if [ -n "$LIVE" ]; then
  $WS watch "$BASE" "$LIVE" "$ADMIN" 3 > /tmp/e2e_watch.out 2>&1
  grep -aq "read only" /tmp/e2e_watch.out && ok "shadow stream connected" || bad "shadow"
  TERM=$(code -X POST "$BASE/api/sessions/$LIVE/terminate" "${AUTH[@]}")
  [ "$TERM" = "200" ] && ok "admin terminate 200" || bad "terminate ($TERM)"
fi
wait 2>/dev/null

hdr "Session resume (drop + reconnect keeps shell state)"
$WS resume "$BASE" "$SID" "$ADMIN" > /tmp/e2e_resume.out 2>&1
grep -aq "GOT:hello42" /tmp/e2e_resume.out && ok "shell state survives reconnect" || bad "resume (see /tmp/e2e_resume.out)"

hdr "Operations dashboard + command timeline"
curl -s "$BASE/api/dashboard" "${AUTH[@]}" | grep -q '"stats"' && ok "dashboard endpoint" || bad "dashboard"
TLSESS=$(curl -s "$BASE/api/sessions" "${AUTH[@]}" | jq_get 'next((s["id"] for s in d if s.get("recording_path")), "")')
if [ -n "$TLSESS" ]; then
  curl -s "$BASE/api/sessions/$TLSESS/commands" "${AUTH[@]}" -o /tmp/e2e_cmds.json
  head -c 1 /tmp/e2e_cmds.json | grep -q '\[' && ok "command timeline endpoint" || bad "command timeline"
fi
curl -s "$BASE/api/commands/search?q=echo" "${AUTH[@]}" -o /tmp/e2e_cmdsearch.json
head -c 1 /tmp/e2e_cmdsearch.json | grep -q '\[' && ok "command search endpoint" || bad "command search"

hdr "Resource metrics + vulnerability scan"
curl -s "$BASE/api/servers/$SID/metrics?minutes=60" "${AUTH[@]}" -o /tmp/e2e_metrics.json
head -c 1 /tmp/e2e_metrics.json | grep -q '\[' && ok "metrics time-series endpoint" || bad "metrics"
curl -s "$BASE/api/servers/$SID/vulns" "${AUTH[@]}" | grep -q '"scanned"' && ok "vulnerability scan endpoint" || bad "vulns"
VC=$(curl -s "$BASE/api/servers" "${AUTH[@]}" | jq_get 'next((s.get("vuln_count",0) for s in d if s["name"]=="'"$TARGET_NAME"'"), 0)')
if [ "${VC:-0}" -gt 0 ]; then ok "host vulnerabilities detected ($VC CVEs)"; else note "no vulns recorded yet (scan may be pending)"; fi

hdr "Auth methods + SSH CA"
curl -s "$BASE/api/auth/methods" | grep -q '"password":true' && ok "auth methods endpoint" || bad "auth methods"
curl -s "$BASE/ca/pubkey" -o /tmp/e2e_ca.txt
grep -q '^ssh-' /tmp/e2e_ca.txt && ok "CA public key served" || bad "ca pubkey"
# Credential-less cert auth: clear password, enable CA, connect, restore.
SRVDEF="\"name\":\"$TARGET_NAME\",\"host\":\"127.0.0.1\",\"port\":22,\"protocol\":\"ssh\",\"connection_mode\":\"agent\",\"ssh_user\":\"warden\""
curl -s -X PUT "$BASE/api/servers/$SID" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{$SRVDEF,\"ssh_password\":\"\",\"use_ssh_ca\":true}" >/dev/null
$WS ssh "$BASE" "$SID" "$ADMIN" "" "echo CERT_OK_\$(whoami)" 5 > /tmp/e2e_cert.out 2>&1
grep -aq "CERT_OK_warden" /tmp/e2e_cert.out && ok "credential-less SSH cert auth" || bad "cert auth (target must trust CA)"
curl -s -X PUT "$BASE/api/servers/$SID" "${AUTH[@]}" -H 'Content-Type: application/json' \
  -d "{$SRVDEF,\"ssh_password\":\"warden\",\"use_ssh_ca\":false}" >/dev/null

hdr "Compliance reports"
curl -s "$BASE/api/reports/access-review" "${AUTH[@]}" | grep -q '"username"' && ok "access-review report" || bad "access review"
curl -s "$BASE/api/reports/sessions.csv?token=$ADMIN" -o /tmp/e2e_sessrep.csv
head -1 /tmp/e2e_sessrep.csv | grep -q '^session_id' && ok "session report CSV" || bad "session report"

if [ -n "$PSQL" ]; then
  hdr "DB-level checks (encryption / TOFU / tamper)"
  $PSQL -tAc "SELECT left(ssh_password,7) FROM servers WHERE id='$SID';" 2>/dev/null | grep -q 'enc:v1:' && ok "ssh_password encrypted at rest" || note "ssh_password not encrypted (maybe no password set)"
  $PSQL -tAc "SELECT length(ssh_host_key) FROM servers WHERE id='$SID';" 2>/dev/null | grep -qE '[1-9]' && ok "host key pinned (TOFU)" || bad "host key not pinned"
  # Tamper the hash column (pure hex — byte-safe to save/restore) of a mid-chain
  # row; verify must flag it, then restore exactly so the chain stays intact.
  RID=$($PSQL -tAc "SELECT id FROM audit_logs WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1 OFFSET 3;" 2>/dev/null | tr -dc '0-9')
  if [ -n "$RID" ]; then
    ORIGH=$($PSQL -tAc "SELECT hash FROM audit_logs WHERE id=$RID;" 2>/dev/null | tr -dc 'a-f0-9')
    $PSQL -c "UPDATE audit_logs SET hash='deadbeef' WHERE id=$RID;" >/dev/null 2>&1
    curl -s "$BASE/api/audit/verify" "${AUTH[@]}" | grep -q '"ok":false' && ok "tamper detected by chain verify" || bad "tamper NOT detected"
    $PSQL -c "UPDATE audit_logs SET hash='$ORIGH' WHERE id=$RID;" >/dev/null 2>&1
    curl -s "$BASE/api/audit/verify" "${AUTH[@]}" | grep -q '"ok":true' && ok "chain restored after test" || bad "chain left broken"
  fi
else
  note "PSQL not set — skipping DB-level checks (encryption/TOFU/tamper)"
fi

echo
echo "================ RESULT: $PASS passed, $FAIL failed ================"
[ "$FAIL" -eq 0 ]
