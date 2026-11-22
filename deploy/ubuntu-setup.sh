#!/usr/bin/env bash
set -euo pipefail

# SimVault Ubuntu 22.04 / 24.04 LTS Production Setup Script
# Usage:
#   sudo bash deploy/ubuntu-setup.sh
#   sudo bash deploy/ubuntu-setup.sh sms.yourdomain.com owner@yourdomain.com

DOMAIN="${1:-_}"
SSL_EMAIL="${2:-}"
APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE_USER="simvault"
APP_PORT="${PORT:-3000}"

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (example: sudo bash deploy/ubuntu-setup.sh [domain] [email])"
  exit 1
fi

echo "==> [1/7] Installing system packages (curl, openssl, nginx, ufw)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg openssl nginx ufw

echo "==> [2/7] Checking Node.js >= 22.5 (required for built-in node:sqlite)..."
NEED_NODE=1
if command -v node >/dev/null 2>&1; then
  NODE_VER="$(node -v | sed 's/^v//')"
  NODE_MAJOR="${NODE_VER%%.*}"
  if [[ "$NODE_MAJOR" -ge 22 ]]; then
    NEED_NODE=0
    echo "Node.js v$NODE_VER already installed."
  fi
fi

if [[ "$NEED_NODE" -eq 1 ]]; then
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/nodesource.gpg
  echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list
  apt-get update -y
  apt-get install -y nodejs
  echo "Installed Node.js $(node -v)"
fi

echo "==> [3/7] Creating service user & persistent data directory..."
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi
mkdir -p "$APP_DIR/data"

echo "==> [4/7] Preparing production .env with 256-bit cryptographic secrets..."
if [[ ! -f "$APP_DIR/.env" ]]; then
  SCHEME="http"
  if [[ "$DOMAIN" != "_" ]]; then
    SCHEME="https"
    BASE_URL="${SCHEME}://${DOMAIN}"
  else
    VPS_IP="$(hostname -I | awk '{print $1}')"
    BASE_URL="http://${VPS_IP:-localhost}"
  fi
  if [[ -z "${SSL_EMAIL:-}" ]]; then
    echo "Error: provide an owner email as the second argument." >&2
    echo "Usage: sudo bash deploy/ubuntu-setup.sh sms.yourdomain.com owner@example.com" >&2
    exit 1
  fi
  ADMIN_PASSWORD="$(openssl rand -hex 24)"

  cat > "$APP_DIR/.env" <<EOF
NODE_ENV=production
HOST=127.0.0.1
PORT=${APP_PORT}
APP_BASE_URL=${BASE_URL}
API_BASE_URL=${BASE_URL}
SIMVAULT_DB_PATH=${APP_DIR}/data/simvault.db
SIMVAULT_KEYS_PATH=${APP_DIR}/data/.simvault.keys
JWT_PRIVATE_KEY=$(openssl rand -hex 32)
API_KEY_PEPPER=$(openssl rand -hex 32)
OTP_PEPPER=$(openssl rand -hex 32)
FIELD_ENCRYPTION_KEY=$(openssl rand -hex 32)
SIMVAULT_ADMIN_EMAIL=${SSL_EMAIL}
SIMVAULT_ADMIN_PASSWORD=${ADMIN_PASSWORD}
LOG_LEVEL=info
EOF
  echo "Created $APP_DIR/.env."
  echo "Owner email: ${SSL_EMAIL}"
  echo "Generated owner password: ${ADMIN_PASSWORD}"
  echo "Save this password now; it is stored in $APP_DIR/.env with mode 600."
else
  echo "Existing $APP_DIR/.env preserved."
fi

if grep -q '^SIMVAULT_ADMIN_PASSWORD=SimVault!2026$' "$APP_DIR/.env"; then
  ROTATED_ADMIN_PASSWORD="$(openssl rand -hex 24)"
  sed -i "s|^SIMVAULT_ADMIN_PASSWORD=.*$|SIMVAULT_ADMIN_PASSWORD=${ROTATED_ADMIN_PASSWORD}|" "$APP_DIR/.env"
  echo "Rotated a previously used default owner password."
  echo "Generated owner password: ${ROTATED_ADMIN_PASSWORD}"
  echo "Save this password now; it is stored in $APP_DIR/.env with mode 600."
fi
chmod 600 "$APP_DIR/.env"

echo "==> [5/7] Installing Node dependencies and building Vite frontend..."
cd "$APP_DIR"
npm ci
npm run build
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
chmod 700 "$APP_DIR/data"

echo "==> [6/7] Installing systemd service & Nginx reverse proxy..."
sed \
  -e "s|__APP_DIR__|${APP_DIR}|g" \
  -e "s|__SERVICE_USER__|${SERVICE_USER}|g" \
  "$APP_DIR/deploy/simvault.service" > /etc/systemd/system/simvault.service

systemctl daemon-reload
systemctl enable simvault
systemctl restart simvault

sed \
  -e "s|__SERVER_NAME__|${DOMAIN}|g" \
  -e "s|__APP_PORT__|${APP_PORT}|g" \
  "$APP_DIR/deploy/nginx-simvault.conf" > /etc/nginx/sites-available/simvault

ln -sf /etc/nginx/sites-available/simvault /etc/nginx/sites-enabled/simvault
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl restart nginx

echo "==> [7/7] Configuring UFW firewall & health check..."
ufw allow OpenSSH >/dev/null 2>&1 || true
ufw allow 'Nginx Full' >/dev/null 2>&1 || true
if ufw status | grep -q "Status: active"; then
  ufw reload >/dev/null 2>&1 || true
fi

if [[ "$DOMAIN" != "_" && -n "$SSL_EMAIL" ]]; then
  echo "==> Provisioning free Let's Encrypt HTTPS certificate for ${DOMAIN}..."
  apt-get install -y certbot python3-certbot-nginx
  certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos -m "$SSL_EMAIL" --redirect || \
    echo "Certbot skipped/failed (ensure DNS A record points to this VPS IP, then run: sudo certbot --nginx -d ${DOMAIN})"
fi

sleep 2
echo "==> Verifying local health endpoint..."
curl -fsS "http://127.0.0.1:${APP_PORT}/health"
echo ""
echo "SimVault is live on Ubuntu VPS!"
echo "Check logs: sudo journalctl -u simvault -f"
