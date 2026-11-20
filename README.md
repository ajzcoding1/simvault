# SimVault — Personal SIM SMS & OTP Platform

Self-hosted personal SIM SMS & OTP gateway platform. Connect your own Android phone with an active SIM card to send transactional SMS and OTP verification codes from your apps over a secure REST API, deployed on **Vercel Serverless** with **Supabase PostgreSQL** (via `.env` / Vercel Environment Variables).

---

## Architecture Overview

1. **Frontend & API Control Plane (Vercel + Express + React/Vite)**:
   - Bundled Vercel serverless entrypoints (`api/index.mjs` and `api/cron/sweeper.mjs` compiled from `server/vercel/*.ts`).
   - React + Tailwind CSS Owner Console served as a static SPA from `dist/`.
2. **Database (Supabase PostgreSQL)**:
   - Schema defined in `infra/supabase_schema.sql` (17 tables + 7 indexes + default live-mode settings).
   - Connected via `.env` (locally) or Vercel Project Settings → Environment Variables (`SUPABASE_DB_URL`, `POSTGRES_URL`, or `SUPABASE_URL` + `SUPABASE_DB_PASSWORD` + `SUPABASE_DB_REGION`).
   - Local development & automated tests automatically fall back to in-memory/local `node:sqlite` if no Postgres URL is set.
3. **Android SIM Gateway (`android-gateway/`)**:
   - Native Kotlin + Jetpack Compose Android app that polls `/v1/gateway/jobs/next`, sends SMS via your chosen physical SIM slot (`SmsManager`), and reports carrier handoff & delivery receipts.

---

## Quick Setup: Supabase + Vercel + `.env`

### Step 1: Create Tables in Supabase (SQL Command)

1. Open **Supabase Dashboard → SQL Editor → New Query**.
2. Copy the entire contents of `infra/supabase_schema.sql` and click **Run**.
   *(All statements use `CREATE TABLE IF NOT EXISTS` / `ON CONFLICT DO NOTHING`, so running it multiple times is safe.)*

### Step 2: Configure `.env` (Local) or Vercel Environment Variables

Copy `.env.example` to `.env` for local runs with Supabase, OR add these exact variables in **Vercel Dashboard → Project Settings → Environment Variables**:

#### Option A (Recommended): Full Transaction Pooler URI
Get from **Supabase Dashboard → Connect → Connection String (URI) → Transaction Pooler (port 6543)**:
```env
SUPABASE_DB_URL="postgresql://postgres.<PROJECT_REF>:<URL_ENCODED_PASSWORD>@aws-0-<REGION>.pooler.supabase.com:6543/postgres"
```

#### Option B: Separate Supabase Fields (Auto-encodes special characters in password)
```env
SUPABASE_URL="https://<PROJECT_REF>.supabase.co"
SUPABASE_DB_PASSWORD="your-database-password"
SUPABASE_DB_REGION="ap-south-1"
# Optional if your pooler hostname uses aws-1-... instead of aws-0-...
# SUPABASE_DB_POOLER_HOST="aws-1-ap-south-1.pooler.supabase.com"
```
*(Do **not** put an `https://...supabase.co` URL into `SUPABASE_DB_URL`; put it into `SUPABASE_URL` if using Option B.)*

#### Required Security, Admin Login & Cron Variables
Generate 4 distinct 256-bit secrets (`openssl rand -hex 32`):
```env
API_KEY_PEPPER="your-64-hex-secret-1"
JWT_PRIVATE_KEY="your-64-hex-secret-2"
OTP_PEPPER="your-64-hex-secret-3"
FIELD_ENCRYPTION_KEY="your-64-hex-secret-4"

SIMVAULT_ADMIN_EMAIL="owner@yourdomain.com"
SIMVAULT_ADMIN_PASSWORD="ChangeThisStrongPassword!2026"

# Vercel Cron secret (`openssl rand -hex 24`)
CRON_SECRET="your-48-hex-cron-secret"
```

### Step 3: Build & Deploy on Vercel

```bash
npm install
npm run build   # Builds frontend (dist/) + Vercel API bundles (api/index.mjs, api/cron/sweeper.mjs)
```

Push the repo (including `api/*.mjs`) to GitHub and trigger a Vercel deployment.

---

## Local Development & Tests

```bash
npm install
npm run dev     # Starts Express + Vite on http://localhost:3000 (reads .env if present)
npm test        # Runs unit & API flow tests (isolated in-memory DB)
npm run lint    # TypeScript typecheck
npm run build   # Builds dist/ + api/index.mjs + api/cron/sweeper.mjs
```

---

## Project Structure

```text
.
├── infra/
│   └── supabase_schema.sql    # Authoritative PostgreSQL DDL + default settings
├── server/
│   ├── db.ts                  # Dual-dialect DB layer (Supabase PostgreSQL + local SQLite)
│   ├── crypto.ts              # AES-256-GCM, scrypt passwords, HMAC API keys/OTPs, TOTP 2FA
│   ├── services.ts            # Queue leasing, OTP lifecycle, rate limits, SSRF check, sweeper
│   ├── app.ts                 # Shared Express app (/health, /v1/*, /api/admin/*, /api/cron/sweeper)
│   ├── routes/
│   │   ├── v1.ts              # Application API (/v1/sms, /v1/otp/*) & Gateway API (/v1/gateway/*)
│   │   └── admin.ts           # Owner Console API (/api/admin/*)
│   └── vercel/
│       ├── index.ts           # Bundled into api/index.mjs
│       └── sweeper.ts         # Bundled into api/cron/sweeper.mjs
├── src/                       # React + TypeScript + Tailwind CSS Owner Console
├── android-gateway/           # Native Kotlin + Jetpack Compose Android Studio project
├── tests/                     # Unit & API integration tests
├── .env.example               # Supabase + Vercel environment template
├── vercel.json                # Vercel build, rewrites & cron config
└── package.json
```

---

## Quick API Usage

### Send Transactional SMS
```bash
curl -X POST https://your-vercel-app.vercel.app/v1/sms \
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
curl -X POST https://your-vercel-app.vercel.app/v1/otp/challenges \
  -H "Authorization: Bearer sv_live_YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "to": "+919876543210", "purpose": "login", "ttl_seconds": 300 }'

# 2. Verify code submitted by user
curl -X POST https://your-vercel-app.vercel.app/v1/otp/verify \
  -H "Authorization: Bearer sv_live_YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ "challenge_id": "otp_CHALLENGE_ID", "code": "123456" }'
```
