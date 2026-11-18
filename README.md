# SimVault — Personal SIM SMS & OTP Platform

Self-hosted personal SIM SMS & OTP gateway platform. Connect your own Android phone with an active SIM card to send transactional SMS and OTP verification codes from your own apps over a secure REST API, backed by an Ubuntu VPS control plane (Node.js 22 + built-in SQLite) and an owner web dashboard.

> **Pure Native Ubuntu VPS Architecture (No Docker Required)**  
> SimVault runs directly on Ubuntu 22.04 / 24.04 LTS using **Node.js 22 LTS** (built-in `node:sqlite`), **systemd** (or PM2), **Nginx**, and **Let's Encrypt SSL**. No external database server (PostgreSQL/MySQL) or Redis is required.

---

## What SimVault Does

1. **Application REST API (`/v1/*`)**: Your backend services call `POST /v1/sms` or `POST /v1/otp/challenges` using scoped API keys (`sv_live_...` / `sv_test_...`) and `Idempotency-Key` protection.
2. **Android SIM Gateway (`android-gateway/`)**: A native Kotlin + Jetpack Compose Android app runs on your paired phone, polls queued jobs over HTTPS, sends SMS through your chosen physical SIM slot via `SmsManager`, and reports carrier handoff / delivery receipts back to the server.
3. **OTP Verification Engine**: Generates 6-digit OTP codes, stores only salted HMAC-SHA256 hashes (never plaintext), enforces resend cooldowns, expiry TTLs, and max-attempt lockouts via `POST /v1/otp/challenges/:id/verify`.
4. **Owner Control Console (React + Vite)**: Real-time dashboard to pair phones, generate/rotate/revoke API keys, manage approved templates, configure destination allowlists, inspect message lifecycle & audit logs, reconcile SIM plan quotas, and trigger a **Global Emergency Kill Switch**.
5. **Security & Privacy Controls**:
   - AES-256-GCM encryption at rest for phone numbers and outbound message payloads (`FIELD_ENCRYPTION_KEY`).
   - Masked E.164 phone numbers and redacted metadata in UI & audit logs.
   - HTTP-only session cookies, CSRF header protection, login rate limiting, and optional TOTP 2FA.
   - SSRF-protected HTTPS webhook deliveries signed with HMAC-SHA256.

---

## Project Structure

```text
.
├── server.ts                  # Express server, security headers, /health, static SPA & graceful shutdown
├── server/
│   ├── crypto.ts              # AES-256-GCM, scrypt passwords, HMAC API keys/OTPs, TOTP 2FA
│   ├── db.ts                  # SQLite schema migrations, WAL mode, initial owner seed
│   ├── services.ts            # Queue leasing, OTP lifecycle, rate limits, SSRF check, background sweeper
│   └── routes/
│       ├── v1.ts              # Public App API (/v1/sms, /v1/otp/*) & Gateway API (/v1/gateway/*)
│       └── admin.ts           # Authenticated Owner Console API (/api/admin/*)
├── src/                       # React + TypeScript + Tailwind CSS Owner Console
├── android-gateway/           # Native Kotlin + Jetpack Compose Android Studio project
├── deploy/
│   ├── ubuntu-setup.sh        # Automated Ubuntu 22.04/24.04 VPS setup (Node 22 + systemd + Nginx + SSL)
│   ├── simvault.service       # Hardened systemd service unit
│   ├── nginx-simvault.conf    # Nginx reverse proxy configuration
│   └── ecosystem.config.cjs   # Optional PM2 configuration
├── tests/                     # Unit & API integration tests (node:test + tsx)
├── .env.example               # Production environment template
└── package.json
```

---

## Ubuntu VPS Requirements

* **OS**: Ubuntu 22.04 LTS or Ubuntu 24.04 LTS (1 GB RAM+, 10 GB disk)
* **Node.js**: **v22.5.0 or higher** (Node.js 22 LTS recommended — required for built-in `node:sqlite`)
* **Web Server / SSL**: `nginx`, `certbot`, `python3-certbot-nginx`
* **Utilities**: `git`, `curl`, `openssl`, `ufw`
* *(No Docker, PostgreSQL, or Redis required — SQLite stores everything in `./data/simvault.db`)*

---

## Hosting on Ubuntu VPS

### Option 1: One-Command Automated Setup (Recommended)

Upload or clone the repository onto your Ubuntu VPS (for example in `/opt/simvault`), then run:

```bash
sudo mkdir -p /opt/simvault
cd /opt/simvault
# (Clone or extract project files here)

# With a domain + free Let's Encrypt HTTPS (recommended for Android Gateway):
sudo bash deploy/ubuntu-setup.sh sms.yourdomain.com owner@yourdomain.com
```

*(If testing on VPS IP without a domain, run `sudo bash deploy/ubuntu-setup.sh`)*

**What `deploy/ubuntu-setup.sh` automatically does:**
1. Installs `nginx`, `openssl`, `ufw`, and **Node.js 22 LTS** via NodeSource.
2. Creates a dedicated system user (`simvault`) and persistent `data/` folder.
3. Generates `.env` with strong 256-bit random secrets (`openssl rand -hex 32`) and sets `chmod 600 .env`.
4. Runs `npm ci` and `npm run build` to compile the frontend into `dist/`.
5. Installs & enables the `simvault.service` `systemd` unit.
6. Configures Nginx reverse proxy on ports `80`/`443` and enables UFW firewall rules (`OpenSSH`, `Nginx Full`).
7. Provisions a free Let's Encrypt HTTPS certificate with Certbot (when domain & email are passed).

---

### Option 2: Manual Step-by-Step Setup on Ubuntu VPS

If you prefer installing everything manually:

#### 1. Install System Packages & Node.js 22 LTS
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git unzip openssl nginx ufw certbot python3-certbot-nginx ca-certificates gnupg

# Install Node.js 22 LTS (required for node:sqlite)
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
node -v   # Confirm v22.x.x
```

#### 2. Setup `.env` File (With Auto-Generated Security Keys)
Run these commands inside your project directory (`/opt/simvault`):

```bash
# 1. Enter project directory and create persistent data folder
cd /opt/simvault
mkdir -p data

# 2. Optional: copy example template for reference
cp .env.example .env

# 3. Generate .env with 4 random 256-bit cryptographic secrets (openssl rand -hex 32)
cat > .env <<EOF
# Run in production mode on Ubuntu VPS
NODE_ENV="production"
HOST="127.0.0.1"
PORT="3000"

# Set your public VPS domain (or http://YOUR_VPS_IP)
APP_BASE_URL="https://sms.yourdomain.com"
API_BASE_URL="https://sms.yourdomain.com"

# Persistent SQLite database & fallback runtime keys path (works in any folder)
SIMVAULT_DB_PATH="./data/simvault.db"
SIMVAULT_KEYS_PATH="./data/.simvault.keys"

# 256-bit cryptographic secrets (auto-generated by openssl below)
JWT_PRIVATE_KEY="$(openssl rand -hex 32)"
API_KEY_PEPPER="$(openssl rand -hex 32)"
OTP_PEPPER="$(openssl rand -hex 32)"
FIELD_ENCRYPTION_KEY="$(openssl rand -hex 32)"

# Owner Login credentials (changing these in .env updates login on next server restart)
SIMVAULT_ADMIN_EMAIL="owner@yourdomain.com"
SIMVAULT_ADMIN_PASSWORD="ChangeThisStrongPassword!2026"

LOG_LEVEL="info"
EOF

# 4. Open .env to set your real domain, admin email, and password (Ctrl+O Enter, Ctrl+X exit)
nano .env

# 5. Lock file permissions so only the owner can read secrets
chmod 600 .env
chmod 700 data

# 6. Verify .env exists and key fields are populated
ls -la .env && grep -E '^(NODE_ENV|PORT|APP_BASE_URL|SIMVAULT_ADMIN_EMAIL)=' .env
```

#### 3. Install Dependencies & Build Frontend
```bash
npm ci
npm run build
```

#### 4. Start with `systemd` (or PM2)

**Using `systemd`:**
```bash
sudo sed -e "s|__APP_DIR__|/opt/simvault|g" -e "s|__SERVICE_USER__|root|g" deploy/simvault.service | sudo tee /etc/systemd/system/simvault.service
sudo systemctl daemon-reload
sudo systemctl enable --now simvault
```
*(For best security, create a dedicated `simvault` user and run `chown -R simvault:simvault /opt/simvault` as `ubuntu-setup.sh` does.)*

**Or using PM2:**
```bash
sudo npm install -g pm2
pm2 start deploy/ecosystem.config.cjs
pm2 save
pm2 startup
```

#### 5. Configure Nginx, Firewall & SSL
```bash
sudo sed -e "s|__SERVER_NAME__|sms.yourdomain.com|g" -e "s|__APP_PORT__|3000|g" deploy/nginx-simvault.conf | sudo tee /etc/nginx/sites-available/simvault
sudo ln -sf /etc/nginx/sites-available/simvault /etc/nginx/sites-enabled/simvault
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable

# Enable free HTTPS
sudo certbot --nginx -d sms.yourdomain.com -m owner@yourdomain.com --agree-tos --redirect
```

Verify health:
```bash
curl -fsS https://sms.yourdomain.com/health
```

---

## First Login & Security Checklist

* **Default Login** (when `SIMVAULT_ADMIN_EMAIL` / `SIMVAULT_ADMIN_PASSWORD` are not set in `.env` prior to first boot):
  * **Email:** `owner@simvault.local`
  * **Password:** `SimVault!2026`
  * *(Seeded in `server/db.ts` only when the `users` table is empty.)*
* **Immediately after first sign-in**:
  1. Go to **Governance → Security & Limits** and change the owner password.
  2. Enable **TOTP 2FA** (Google Authenticator / Authy).
  3. Keep `data/.simvault.keys` and `.env` backed up safely — losing `FIELD_ENCRYPTION_KEY` will make encrypted records unreadable.

---

## Pairing the Android Gateway Phone

1. Open the `android-gateway/` folder in **Android Studio** (JDK 17, Android 10+ / API 29+ device).
2. Build and install the APK onto your dedicated Android SIM phone (`Build > Build APK(s)`).
3. Grant `SEND_SMS` and `READ_PHONE_STATE` permissions and disable battery optimization for reliable background polling.
4. In the SimVault web console, open **Gateway Devices → Generate Enrollment Token**.
5. In the Android app, enter your VPS URL (`https://sms.yourdomain.com`) and the one-time `ENROLL-XXXX-XXXX-XXXX` token to pair.
6. Confirm **Live SIM Mode** is active and your SIM slot is selected.

---

## Quick API Usage

### Send Transactional SMS
```bash
curl -X POST https://sms.yourdomain.com/v1/sms \
  -H "Authorization: Bearer sv_live_YOUR_API_KEY" \
  -H "Idempotency-Key: order-1001" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "+919876543210",
    "template_id": "login_notice",
    "variables": { "name": "Aarav", "device_label": "Chrome Linux" },
    "purpose": "account_transactional"
  }'
```

### Create & Verify OTP Challenge
```bash
# 1. Create OTP challenge
curl -X POST https://sms.yourdomain.com/v1/otp/challenges \
  -H "Authorization: Bearer sv_live_YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "to": "+919876543210", "purpose": "login", "ttl_seconds": 300 }'

# 2. Verify code submitted by user
curl -X POST https://sms.yourdomain.com/v1/otp/challenges/otp_CHALLENGE_ID/verify \
  -H "Authorization: Bearer sv_live_YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "code": "123456" }'
```

---

## Useful VPS Operations & Backups

```bash
# Service status & live logs
sudo systemctl status simvault
sudo journalctl -u simvault -f

# Update code & rebuild
cd /opt/simvault
git pull
npm ci && npm run build
sudo systemctl restart simvault

# Backup SQLite DB + keys (cleanly stops service for WAL-safe copy)
mkdir -p ~/simvault-backups
sudo systemctl stop simvault
cp -a /opt/simvault/data /opt/simvault/.env ~/simvault-backups/backup-$(date +%F)/
sudo systemctl start simvault
```

---

## Local Development & Tests

```bash
npm install
npm run dev       # Start Express + Vite dev server on http://localhost:3000
npm test          # Run unit & integration test suite
npm run lint      # TypeScript typecheck
npm run build     # Build frontend production bundle into dist/
```
