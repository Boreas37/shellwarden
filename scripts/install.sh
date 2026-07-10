#!/usr/bin/env bash
#
# ShellWarden agent installer. Run on the target server as root:
#
#   curl -fsSL https://gateway.internal/install.sh | \
#     bash -s -- \
#       --gateway wss://gateway.internal:8080 \
#       --token   <agent_token> \
#       --id      <server_uuid>
#
set -euo pipefail

GATEWAY_URL=""
AGENT_TOKEN=""
SERVER_ID=""

# --- parse args ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --gateway) GATEWAY_URL="$2"; shift 2 ;;
    --token)   AGENT_TOKEN="$2"; shift 2 ;;
    --id)      SERVER_ID="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$GATEWAY_URL" || -z "$AGENT_TOKEN" || -z "$SERVER_ID" ]]; then
  echo "usage: install.sh --gateway <url> --token <token> --id <uuid>" >&2
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "this installer must run as root" >&2
  exit 1
fi

# --- 1. detect OS ---
OS="unknown"
if [[ -f /etc/debian_version ]]; then
  OS="debian"
elif [[ -f /etc/redhat-release ]]; then
  OS="rhel"
elif [[ -f /etc/arch-release ]]; then
  OS="arch"
fi
echo "[shellwarden] detected OS family: ${OS}"

# --- detect arch ---
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

# Derive the HTTPS base URL for downloads from the (ws/wss) gateway URL.
HTTP_BASE="$(echo "$GATEWAY_URL" | sed -e 's#^wss://#https://#' -e 's#^ws://#http://#')"

# --- 2. download agent binary ---
echo "[shellwarden] downloading agent binary..."
install -d /usr/local/bin
curl -fsSL "${HTTP_BASE}/downloads/agent/${OS}/${ARCH}" -o /usr/local/bin/shellwarden-agent
chmod +x /usr/local/bin/shellwarden-agent

# --- 3. write config ---
echo "[shellwarden] writing /etc/shellwarden/agent.conf"
install -d -m 0750 /etc/shellwarden
cat > /etc/shellwarden/agent.conf <<EOF
GATEWAY_URL=${GATEWAY_URL}
AGENT_TOKEN=${AGENT_TOKEN}
SERVER_ID=${SERVER_ID}
EOF
chmod 0600 /etc/shellwarden/agent.conf

# --- 4. systemd unit ---
echo "[shellwarden] creating systemd unit"
cat > /etc/systemd/system/shellwarden-agent.service <<'EOF'
[Unit]
Description=ShellWarden Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/shellwarden/agent.conf
ExecStart=/usr/local/bin/shellwarden-agent
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

# --- 5. enable + start ---
systemctl daemon-reload
systemctl enable shellwarden-agent.service
systemctl restart shellwarden-agent.service

# --- 6. success ---
echo ""
echo "[shellwarden] agent installed and started."
echo "[shellwarden] server UUID: ${SERVER_ID}"
echo "[shellwarden] check status with: systemctl status shellwarden-agent"
