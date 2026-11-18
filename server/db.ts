import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  generateTotpSecret,
  hashPassword,
} from './crypto';
import { redactSensitiveMetadata } from '../src/shared/smsRules';

let dbInstance: DatabaseSync | null = null;

export function getDb(dbPath?: string): DatabaseSync {
  if (dbInstance) return dbInstance;
  const targetPath = dbPath ?? process.env.SIMVAULT_DB_PATH ?? path.resolve(process.cwd(), 'data', 'simvault.db');
  if (targetPath !== ':memory:') {
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  }
  const db = new DatabaseSync(targetPath);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  migrateSchema(db);
  seedInitialData(db);
  dbInstance = db;
  return db;
}

export function closeDb(): void {
  if (!dbInstance) return;
  try {
    dbInstance.exec('PRAGMA wal_checkpoint(TRUNCATE);');
  } catch {
    // Ignore checkpoint errors on already-closed or in-memory DBs
  }
  try {
    dbInstance.close();
  } catch {
    // Ignore close errors
  }
  dbInstance = null;
}

export function createIsolatedTestDb(): DatabaseSync {
  const db = new DatabaseSync(':memory:');
  db.exec('PRAGMA foreign_keys = ON;');
  migrateSchema(db);
  seedInitialData(db);
  return db;
}

function migrateSchema(db: DatabaseSync): void {
  db.exec(`
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
  `);

  runLiveModeMigration(db);
}

function runLiveModeMigration(db: DatabaseSync): void {
  const alreadyMigrated = db
    .prepare("SELECT value FROM platform_settings WHERE key = 'migration_live_mode_v2'")
    .get() as { value: string } | undefined;
  if (alreadyMigrated?.value === 'done') return;

  const hasUsers = db.prepare('SELECT COUNT(*) as cnt FROM users').get() as { cnt: number };
  const nowIso = new Date().toISOString();

  if (hasUsers.cnt > 0) {
    db.exec('BEGIN IMMEDIATE;');
    try {
      // Remove legacy simulated / demo records while keeping real user-created data
      db.prepare("DELETE FROM webhook_deliveries WHERE endpoint_id = 'wh_portal_events'").run();
      db.prepare("DELETE FROM webhook_endpoints WHERE id = 'wh_portal_events' OR url LIKE '%.example%'").run();
      db.prepare("DELETE FROM otp_challenges WHERE id IN ('otp_c84a12', 'otp_c84a13')").run();
      db.prepare(
        "DELETE FROM usage_events WHERE message_id IN ('msg_91f0a1', 'msg_91f0a2', 'msg_91f0a3', 'msg_91f0a4', 'msg_91f0a5', 'msg_91f0a6')"
      ).run();
      db.prepare(
        "DELETE FROM messages WHERE id IN ('msg_91f0a1', 'msg_91f0a2', 'msg_91f0a3', 'msg_91f0a4', 'msg_91f0a5', 'msg_91f0a6')"
      ).run();
      db.prepare("DELETE FROM sims WHERE id = 'sim_primary_slot0' OR device_id = 'dev_pixel7_gateway'").run();
      db.prepare("DELETE FROM gateway_devices WHERE id = 'dev_pixel7_gateway'").run();
      db.prepare(
        "DELETE FROM destination_allowlist WHERE label IN ('Owner Primary Handset', 'QA Verification Phone', 'US Staging Test Number')"
      ).run();
      db.prepare("DELETE FROM api_keys WHERE id IN ('key_portal_primary', 'key_sandbox_ci')").run();
      db.prepare("DELETE FROM applications WHERE id = 'app_sandbox_test'").run();
      db.prepare("DELETE FROM audit_logs WHERE target_id IN ('dev_pixel7_gateway', 'sim_primary_slot0', 'key_portal_primary')").run();
      db.prepare("DELETE FROM platform_settings WHERE key = 'simulator_auto_process'").run();
      db.prepare("UPDATE applications SET environment = 'live', status = 'active', allowlist_only = 0 WHERE id = 'app_portal_prod'").run();

      db.prepare(
        `INSERT INTO platform_settings (key, value, updated_at) VALUES ('live_mode', 'true', ?)
         ON CONFLICT(key) DO UPDATE SET value = 'true', updated_at = excluded.updated_at`
      ).run(nowIso);
      db.prepare(
        `INSERT INTO platform_settings (key, value, updated_at) VALUES ('migration_live_mode_v2', 'done', ?)
         ON CONFLICT(key) DO UPDATE SET value = 'done', updated_at = excluded.updated_at`
      ).run(nowIso);
      db.exec('COMMIT;');
    } catch (err) {
      db.exec('ROLLBACK;');
      throw err;
    }
  }
}

export function writeAuditLog(
  db: DatabaseSync,
  entry: {
    actorType: 'owner' | 'application' | 'device' | 'system';
    actorId: string;
    action: string;
    targetType: string;
    targetId: string;
    metadata?: Record<string, unknown>;
    ipAddress?: string;
  }
): void {
  const redacted = redactSensitiveMetadata(entry.metadata ?? {});
  db.prepare(
    `INSERT INTO audit_logs (id, actor_type, actor_id, action, target_type, target_id, metadata_redacted_json, ip_address, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    crypto.randomUUID(),
    entry.actorType,
    entry.actorId,
    entry.action,
    entry.targetType,
    entry.targetId,
    JSON.stringify(redacted),
    entry.ipAddress ?? '127.0.0.1',
    new Date().toISOString()
  );
}

function seedInitialData(db: DatabaseSync): void {
  const existingUsers = db.prepare('SELECT COUNT(*) as cnt FROM users').get() as { cnt: number };
  if (existingUsers.cnt > 0) return;

  const now = new Date();
  const isoNow = now.toISOString();

  const ownerId = 'usr_owner_primary';
  const initialEmail = (process.env.SIMVAULT_ADMIN_EMAIL || 'owner@simvault.local').trim().toLowerCase();
  const initialPassword = process.env.SIMVAULT_ADMIN_PASSWORD || 'SimVault!2026';
  db.prepare(
    `INSERT INTO users (id, email, password_hash, role, mfa_enabled, mfa_secret, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(ownerId, initialEmail, hashPassword(initialPassword), 'owner', 0, generateTotpSecret(), isoNow, isoNow);

  // Live-mode platform defaults
  const settings: Array<[string, string]> = [
    ['global_paused', 'false'],
    ['live_mode', 'true'],
    ['migration_live_mode_v2', 'done'],
    ['otp_ttl_seconds', '300'],
    ['otp_max_attempts', '5'],
    ['otp_resend_cooldown_seconds', '45'],
    ['rate_limit_per_number_hourly', '6'],
    ['rate_limit_per_ip_minute', '30'],
    ['lease_timeout_seconds', '30'],
    ['max_send_retries', '3'],
    ['retention_days', '30'],
    ['global_daily_sim_cap', '300'],
  ];
  const insertSetting = db.prepare('INSERT INTO platform_settings (key, value, updated_at) VALUES (?, ?, ?)');
  for (const [k, v] of settings) {
    insertSetting.run(k, v, isoNow);
  }

  // Primary Live Application (owner generates keys & pairs real hardware device via dashboard)
  const appProdId = 'app_portal_prod';
  db.prepare(
    `INSERT INTO applications (id, owner_user_id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    appProdId,
    ownerId,
    'Customer Account Portal',
    'live',
    'active',
    JSON.stringify(['login', 'signup', 'mfa', 'password_reset', 'security_alert', 'account_transactional']),
    250,
    0,
    isoNow
  );

  // Approved Templates
  const templates = [
    {
      id: 'tpl_otp_login',
      code: 'otp_login',
      purpose: 'login',
      body: 'Your verification code for {{app_name}} is {{code}}. Valid for {{ttl_minutes}} minutes. Do not share this code.',
      status: 'approved',
    },
    {
      id: 'tpl_login_notice',
      code: 'login_notice',
      purpose: 'account_transactional',
      body: 'New sign-in detected for {{name}} on {{device_label}}. If this was not you, reset your credentials immediately.',
      status: 'approved',
    },
    {
      id: 'tpl_security_alert',
      code: 'security_alert',
      purpose: 'security_alert',
      body: 'Security notice: {{event_summary}} on your account. Review recent activity in your security settings.',
      status: 'approved',
    },
    {
      id: 'tpl_password_reset',
      code: 'otp_password_reset',
      purpose: 'password_reset',
      body: 'Password reset code for {{app_name}}: {{code}}. Expires in {{ttl_minutes}} minutes.',
      status: 'approved',
    },
  ];
  const insertTpl = db.prepare(
    `INSERT INTO message_templates (id, owner_user_id, code, purpose, body, status, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  for (const t of templates) {
    insertTpl.run(t.id, ownerId, t.code, t.purpose, t.body, t.status, isoNow, isoNow);
  }

  writeAuditLog(db, {
    actorType: 'system',
    actorId: 'bootstrap',
    action: 'platform.live_mode_initialized',
    targetType: 'platform_settings',
    targetId: 'live_mode',
    metadata: { live_mode: true },
    ipAddress: '127.0.0.1',
  });
}
