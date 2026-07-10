#!/bin/sh
# Configure SSH (incl. trusting the gateway CA), start sshd, optionally
# self-enroll with the gateway, then run the ShellWarden agent.
set -e

ssh-keygen -A >/dev/null 2>&1 || true
mkdir -p /run/sshd

: "${GATEWAY_HTTP:=http://gateway:8080}"
: "${ADMIN_USER:=admin}"
: "${ADMIN_PASS:=changeme}"
: "${TARGET_NAME:=debian-target}"

# Wait for the gateway (needed for CA trust + enrollment).
if [ "${BOOTSTRAP:-0}" = "1" ]; then
  echo "[target] waiting for gateway at ${GATEWAY_HTTP} ..."
  i=0
  until curl -fsS "${GATEWAY_HTTP}/healthz" >/dev/null 2>&1; do
    i=$((i+1)); [ "$i" -gt 60 ] && echo "[target] gateway not ready" && exit 1
    sleep 2
  done
fi

# Trust the gateway's SSH certificate authority (credential-less access).
CAPUB=$(curl -fsS "${GATEWAY_HTTP}/ca/pubkey" 2>/dev/null || true)
if [ -n "$CAPUB" ]; then
  echo "$CAPUB" > /etc/ssh/shellwarden_ca.pub
  if ! grep -q "TrustedUserCAKeys /etc/ssh/shellwarden_ca.pub" /etc/ssh/sshd_config; then
    echo "TrustedUserCAKeys /etc/ssh/shellwarden_ca.pub" >> /etc/ssh/sshd_config
  fi
  echo "[target] trusting gateway SSH CA"
fi

/usr/sbin/sshd

# Self-enroll with the gateway over the API.
if [ "${BOOTSTRAP:-0}" = "1" ] && [ -z "${AGENT_TOKEN:-}" ]; then
  TOKEN=$(curl -s -X POST "${GATEWAY_HTTP}/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" | jq -r .token)

  ID=$(curl -s "${GATEWAY_HTTP}/api/servers" -H "Authorization: Bearer ${TOKEN}" \
    | jq -r ".[] | select(.name==\"${TARGET_NAME}\") | .id" | head -1)

  if [ -z "$ID" ] || [ "$ID" = "null" ]; then
    RESP=$(curl -s -X POST "${GATEWAY_HTTP}/api/servers" -H "Authorization: Bearer ${TOKEN}" \
      -H 'Content-Type: application/json' \
      -d "{\"name\":\"${TARGET_NAME}\",\"host\":\"127.0.0.1\",\"port\":22,\"protocol\":\"ssh\",\"connection_mode\":\"agent\",\"ssh_user\":\"warden\",\"ssh_password\":\"warden\"}")
    ID=$(echo "$RESP" | jq -r .id)
    AGENT_TOKEN=$(echo "$RESP" | jq -r .agent_token)
  else
    AGENT_TOKEN=$(curl -s "${GATEWAY_HTTP}/api/servers/${ID}" -H "Authorization: Bearer ${TOKEN}" | jq -r .agent_token)
  fi
  export SERVER_ID="$ID" AGENT_TOKEN
  echo "[target] enrolled as ${TARGET_NAME} (${SERVER_ID})"
fi

echo "[target] launching shellwarden-agent (server ${SERVER_ID})"
exec /usr/local/bin/shellwarden-agent
