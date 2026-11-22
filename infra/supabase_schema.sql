-- ==============================================================================
-- SimVault — Supabase PostgreSQL Schema
-- Run this SQL in: Supabase Dashboard -> SQL Editor -> New Query -> Run
-- (All statements are idempotent via IF NOT EXISTS / ON CONFLICT DO NOTHING)
-- ==============================================================================

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

CREATE TABLE IF NOT EXISTS used_totp_codes (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (user_id, code_hash)
);

-- Indexes for queue polling, idempotency, OTP expiry, and usage reporting
CREATE INDEX IF NOT EXISTS idx_messages_status_created ON messages(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_app_created ON messages(application_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_app_idempotency ON messages(application_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_otp_app_exp_status ON otp_challenges(application_id, expires_at, status);
CREATE INDEX IF NOT EXISTS idx_leases_device_exp ON gateway_job_leases(device_id, lease_expires_at);
CREATE INDEX IF NOT EXISTS idx_apikeys_prefix_status ON api_keys(key_prefix, status);
CREATE INDEX IF NOT EXISTS idx_usage_app_occurred ON usage_events(application_id, occurred_at);

-- Default live-mode platform settings (owner account & default templates are seeded by app boot)
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
