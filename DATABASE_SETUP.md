# SimVault — Supabase + Vercel Database Setup Guide

Complete step-by-step guide to connect **SimVault** to **Supabase PostgreSQL**, create all database tables with SQL, and configure **`.env`** / **Vercel Environment Variables**.

---

## Step 1: Create Database Tables in Supabase (SQL Command)

1. Open your active project in **Supabase Dashboard** (ensure the project is **Active**, not paused).
2. Go to **SQL Editor → New Query**.
3. Copy and paste the SQL below (also saved in `infra/supabase_schema.sql`) and click **Run**:

```sql
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'owner',
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  mfa_secret TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  csrf_token TEXT NOT NULL,
  mfa_verified INTEGER NOT NULL DEFAULT 1,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS applications (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  environment TEXT NOT NULL CHECK(environment IN ('test', 'live')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'paused', 'disabled')),
  allowed_purposes_json TEXT NOT NULL,
  daily_limit INTEGER NOT NULL DEFAULT 200,
  allowlist_only INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  secret_hash TEXT NOT NULL UNIQUE,
  scopes_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'rotating', 'revoked')),
  last_used_at TEXT,
  expires_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway_devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  device_token_hash TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'offline' CHECK(status IN ('online', 'offline', 'paused', 'revoked')),
  app_version TEXT NOT NULL DEFAULT '1.0.0',
  android_version TEXT NOT NULL DEFAULT '14',
  permission_send_sms INTEGER NOT NULL DEFAULT 1,
  network_type TEXT NOT NULL DEFAULT '4G LTE',
  battery_pct INTEGER NOT NULL DEFAULT 92,
  sim_ready INTEGER NOT NULL DEFAULT 1,
  last_heartbeat_at TEXT,
  enrolled_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
  id TEXT PRIMARY KEY,
  device_name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sims (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES gateway_devices(id) ON DELETE CASCADE,
  carrier_label TEXT NOT NULL,
  masked_msisdn TEXT NOT NULL,
  slot_index INTEGER NOT NULL DEFAULT 0,
  plan_sms_limit INTEGER NOT NULL DEFAULT 3000,
  period_start TEXT NOT NULL,
  period_end TEXT NOT NULL,
  estimated_sms_sent INTEGER NOT NULL DEFAULT 0,
  estimated_sms_remaining INTEGER NOT NULL DEFAULT 3000,
  warning_threshold INTEGER NOT NULL DEFAULT 300,
  notes TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS message_templates (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  purpose TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'approved' CHECK(status IN ('approved', 'draft', 'archived')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS destination_allowlist (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  e164_masked TEXT NOT NULL,
  e164_hash TEXT NOT NULL,
  e164_encrypted TEXT NOT NULL,
  label TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  UNIQUE(application_id, e164_hash)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  device_id TEXT REFERENCES gateway_devices(id) ON DELETE SET NULL,
  destination_masked TEXT NOT NULL,
  destination_hash TEXT NOT NULL,
  destination_encrypted TEXT NOT NULL,
  template_id TEXT NOT NULL,
  body_encrypted TEXT NOT NULL,
  purpose TEXT NOT NULL,
  status TEXT NOT NULL,
  is_test INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT,
  ttl_expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  queued_at TEXT,
  leased_at TEXT,
  accepted_at TEXT,
  sent_at TEXT,
  delivered_at TEXT,
  failed_at TEXT,
  error_code TEXT
);

CREATE TABLE IF NOT EXISTS otp_challenges (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  destination_masked TEXT NOT NULL,
  destination_hash TEXT NOT NULL,
  destination_encrypted TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  purpose TEXT NOT NULL,
  status TEXT NOT NULL,
  is_test INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 5,
  consumed_at TEXT,
  message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway_job_leases (
  id TEXT PRIMARY KEY,
  message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES gateway_devices(id) ON DELETE CASCADE,
  lease_token_hash TEXT NOT NULL,
  leased_at TEXT NOT NULL,
  lease_expires_at TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS usage_events (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  device_id TEXT,
  message_id TEXT,
  event_type TEXT NOT NULL,
  units INTEGER NOT NULL DEFAULT 1,
  occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_endpoints (
  id TEXT PRIMARY KEY,
  application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  secret_encrypted TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  event_types_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload_redacted_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'delivered', 'failed')),
  attempt_count INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_http_status INTEGER,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  metadata_redacted_json TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_status_created ON messages(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_app_created ON messages(application_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_app_idempotency ON messages(application_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_otp_app_exp_status ON otp_challenges(application_id, expires_at, status);
CREATE INDEX IF NOT EXISTS idx_leases_device_exp ON gateway_job_leases(device_id, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_apikeys_prefix_status ON api_keys(key_prefix, status);
CREATE INDEX IF NOT EXISTS idx_usage_app_occurred ON usage_events(application_id, occurred_at);

INSERT INTO platform_settings (key, value, updated_at) VALUES
  ('global_paused', 'false', NOW()::text),
  ('live_mode', 'true', NOW()::text),
  ('migration_live_mode_v2', 'done', NOW()::text),
  ('otp_ttl_seconds', '300', NOW()::text),
  ('otp_max_attempts', '5', NOW()::text),
  ('otp_resend_cooldown_seconds', '45', NOW()::text),
  ('rate_limit_per_number_hourly', '6', NOW()::text),
  ('rate_limit_per_ip_minute', '30', NOW()::text),
  ('lease_timeout_seconds', '30', NOW()::text),
  ('max_send_retries', '3', NOW()::text),
  ('retention_days', '30', NOW()::text),
  ('global_daily_sim_cap', '300', NOW()::text)
ON CONFLICT (key) DO NOTHING;
```

> Note: On first server boot, SimVault automatically seeds the initial Owner user (`SIMVAULT_ADMIN_EMAIL` / `SIMVAULT_ADMIN_PASSWORD`), default live application (`app_portal_prod`), and default SMS/OTP templates.

---

## Step 2: Get Your Supabase Database Password & Pooler Details

1. In **Supabase Dashboard**, open **Project Settings → Database**.
   - If you forgot your database password, click **Reset database password** and save the new password.
   - *(This is your Supabase project's PostgreSQL password, NOT your Supabase account login password.)*
2. Click the **Connect** button at the top of the Supabase Dashboard.
3. Under **Connection String → URI**, select **Method: Transaction pooler** (port `6543`).
4. Note the exact URI shown there, for example:
   ```text
   postgresql://postgres.<PROJECT_REF>:[YOUR-PASSWORD]@aws-0-ap-south-1.pooler.supabase.com:6543/postgres
   ```
   Check the exact pooler prefix (`aws-0-...` vs `aws-1-...`) and region (`ap-south-1`, `us-east-1`, `ap-southeast-1`, etc.).

---

## Step 3: Configure `.env` (Local) or Vercel Environment Variables

For local development, copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
For production on Vercel, add these variables in **Vercel Dashboard → Project Settings → Environment Variables**.

### Choose EITHER Option A OR Option B for the Database

#### Option A (Recommended — Direct Transaction Pooler URI)
Paste the exact port `6543` URI from **Supabase → Connect → Transaction pooler**:
```env
SUPABASE_DB_URL=postgresql://postgres.<PROJECT_REF>:<URL_ENCODED_PASSWORD>@aws-0-<REGION>.pooler.supabase.com:6543/postgres
```
> **Important if your password has special characters:**  
> URL-encode special characters in Option A (for example `@` → `%40`, `#` → `%23`, `!` → `%21`, `$` → `%24`, `%` → `%25`).

#### Option B (Separate Fields — Auto-Encodes Password Special Characters)
Leave `SUPABASE_DB_URL` empty/unset and set these fields instead:
```env
SUPABASE_URL=https://<PROJECT_REF>.supabase.co
SUPABASE_DB_PASSWORD=your_raw_database_password
SUPABASE_DB_REGION=ap-south-1
# Optional: set if Supabase -> Connect shows aws-1-... or a custom pooler hostname
# SUPABASE_DB_POOLER_HOST=aws-1-ap-south-1.pooler.supabase.com
```
> Note: `SUPABASE_DB_REGION` must match your Supabase project's actual region. If `aws-0-<region>.pooler.supabase.com` returns `tenant not found`, SimVault automatically tries `aws-1-<region>.pooler.supabase.com`.

### Required Security, Owner Login & Cron Keys
Generate 4 separate 256-bit secrets using `openssl rand -hex 32`:
```env
API_KEY_PEPPER=<64-char-hex-secret-1>
JWT_PRIVATE_KEY=<64-char-hex-secret-2>
OTP_PEPPER=<64-char-hex-secret-3>
FIELD_ENCRYPTION_KEY=<64-char-hex-secret-4>

SIMVAULT_ADMIN_EMAIL=owner@yourdomain.com
SIMVAULT_ADMIN_PASSWORD=YourStrongPassword123!

# Generate via: openssl rand -hex 24
CRON_SECRET=<48-char-hex-secret>
```

> **Do NOT set `SIMVAULT_DB_PATH` on Vercel.** Vercel's filesystem (`/var/task`) is read-only.

---

## Step 4: Security Rules (Very Important)

1. **Never put real passwords or secret keys into `.env.example`** — `.env.example` is tracked in Git/GitHub.
2. Only put real secrets in your local **`.env`** (ignored by `.gitignore`) or **Vercel Environment Variables**.
3. If any DB password or secret key was ever committed or shared, rotate it immediately in Supabase (`Reset database password`) and Vercel.

---

## Step 5: Build, Push & Verify

```bash
npm install
npm run build
```
Push the changes to GitHub and trigger **Redeploy** in Vercel.

1. Open `https://<your-vercel-domain>/health` — verify it returns:
   ```json
   {
     "status": "ok",
     "database": "postgres"
   }
   ```
2. Sign in to the SimVault Owner Console using `SIMVAULT_ADMIN_EMAIL` and `SIMVAULT_ADMIN_PASSWORD`.

---

## Troubleshooting Common Errors

| Error Message | Cause | Fix |
| --- | --- | --- |
| `(ENOTFOUND) tenant/user postgres.<ref> not found` | Wrong `SUPABASE_DB_REGION`, wrong `aws-0`/`aws-1` pooler host, typo in project ref, or paused Supabase project | Confirm project is **Active** in Supabase; open **Connect → Transaction pooler**, copy the exact URI into `SUPABASE_DB_URL` (with URL-encoded password), or set the exact `SUPABASE_DB_REGION` + `SUPABASE_DB_POOLER_HOST`. |
| `SUPABASE_DB_URL/DATABASE_URL appears to be an https:// API URL` | `https://<ref>.supabase.co` was pasted into `SUPABASE_DB_URL` without `SUPABASE_DB_PASSWORD` | Either paste the `postgresql://...` URI into `SUPABASE_DB_URL`, or use Option B (`SUPABASE_URL` + `SUPABASE_DB_PASSWORD` + `SUPABASE_DB_REGION`). |
| `ENETUNREACH` on port `5432` | Direct `db.<ref>.supabase.co:5432` uses IPv6; Vercel serverless uses IPv4 | Always use the **Transaction Pooler (port `6543`)** URI or set `SUPABASE_DB_REGION`. |
| `Cannot write to SimVault database directory "/var/task/data"` | `SIMVAULT_DB_PATH` is still set in Vercel Environment Variables | Delete `SIMVAULT_DB_PATH` from Vercel Environment Variables and ensure Supabase DB env vars are set. |
