import type { DatabaseSync, SQLInputValue } from 'node:sqlite';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import pg, { type Pool, type PoolClient } from 'pg';
import { generateTotpSecret, hashPassword } from './crypto';
import { redactSensitiveMetadata } from '../src/shared/smsRules';

const { Pool: PgPool } = pg;

export interface RunResult {
  changes: number;
}

export interface DbExecutor {
  readonly dialect: 'sqlite' | 'postgres';
  get<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T | undefined>;
  all<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]>;
  run(sql: string, ...params: unknown[]): Promise<RunResult>;
  exec(sql: string): Promise<void>;
}

export interface DbClient extends DbExecutor {
  transaction<T>(fn: (tx: DbExecutor) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

export function convertPlaceholdersToPostgres(sql: string): string {
  let out = '';
  let idx = 1;
  let inSingle = false;
  let inDouble = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (inLineComment) {
      out += ch;
      if (ch === '\n') inLineComment = false;
      continue;
    }

    if (inBlockComment) {
      out += ch;
      if (ch === '*' && next === '/') {
        out += '/';
        i++;
        inBlockComment = false;
      }
      continue;
    }

    if (inSingle) {
      out += ch;
      if (ch === "'" && next === "'") {
        out += "'";
        i++;
      } else if (ch === "'") {
        inSingle = false;
      }
      continue;
    }

    if (inDouble) {
      out += ch;
      if (ch === '"' && next === '"') {
        out += '"';
        i++;
      } else if (ch === '"') {
        inDouble = false;
      }
      continue;
    }

    if (ch === '-' && next === '-') {
      out += '--';
      i++;
      inLineComment = true;
      continue;
    }

    if (ch === '/' && next === '*') {
      out += '/*';
      i++;
      inBlockComment = true;
      continue;
    }

    if (ch === "'") {
      out += ch;
      inSingle = true;
      continue;
    }

    if (ch === '"') {
      out += ch;
      inDouble = true;
      continue;
    }

    if (ch === '?') {
      out += `$${idx++}`;
      continue;
    }

    out += ch;
  }

  return out;
}

function normalizeSqliteParams(params: unknown[]): SQLInputValue[] {
  return params.map((p) => {
    if (p === undefined || p === null) return null;
    if (typeof p === 'boolean') return p ? 1 : 0;
    return p as SQLInputValue;
  });
}

function normalizePgParams(params: unknown[]): unknown[] {
  return params.map((p) => {
    if (p === undefined || p === null) return null;
    if (typeof p === 'boolean') return p ? 1 : 0;
    return p;
  });
}

class SqliteDbClient implements DbClient {
  readonly dialect = 'sqlite' as const;
  private readonly raw: DatabaseSync;
  private txTail: Promise<void> = Promise.resolve();

  constructor(raw: DatabaseSync) {
    this.raw = raw;
  }

  async get<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T | undefined> {
    return this.raw.prepare(sql).get(...normalizeSqliteParams(params)) as T | undefined;
  }

  async all<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]> {
    return this.raw.prepare(sql).all(...normalizeSqliteParams(params)) as T[];
  }

  async run(sql: string, ...params: unknown[]): Promise<RunResult> {
    const res = this.raw.prepare(sql).run(...normalizeSqliteParams(params));
    return { changes: Number(res.changes ?? 0) };
  }

  async exec(sql: string): Promise<void> {
    this.raw.exec(sql);
  }

  async transaction<T>(fn: (tx: DbExecutor) => Promise<T>): Promise<T> {
    let release!: () => void;
    const prev = this.txTail;
    this.txTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await prev;

    this.raw.exec('BEGIN IMMEDIATE;');
    try {
      const result = await fn(this);
      this.raw.exec('COMMIT;');
      return result;
    } catch (err) {
      try {
        this.raw.exec('ROLLBACK;');
      } catch {
        // Ignore rollback errors if transaction already aborted
      }
      throw err;
    } finally {
      release();
    }
  }

  async close(): Promise<void> {
    try {
      this.raw.exec('PRAGMA wal_checkpoint(TRUNCATE);');
    } catch {
      // Ignore checkpoint errors on already-closed or in-memory DBs
    }
    try {
      this.raw.close();
    } catch {
      // Ignore close errors
    }
  }
}

class PgExecutor implements DbExecutor {
  readonly dialect = 'postgres' as const;
  private readonly queryable: Pool | PoolClient;

  constructor(queryable: Pool | PoolClient) {
    this.queryable = queryable;
  }

  async get<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T | undefined> {
    const pgSql = convertPlaceholdersToPostgres(sql);
    const res = await this.queryable.query(pgSql, normalizePgParams(params));
    return res.rows[0] as T | undefined;
  }

  async all<T = Record<string, unknown>>(sql: string, ...params: unknown[]): Promise<T[]> {
    const pgSql = convertPlaceholdersToPostgres(sql);
    const res = await this.queryable.query(pgSql, normalizePgParams(params));
    return res.rows as T[];
  }

  async run(sql: string, ...params: unknown[]): Promise<RunResult> {
    const pgSql = convertPlaceholdersToPostgres(sql);
    const res = await this.queryable.query(pgSql, normalizePgParams(params));
    return { changes: Number(res.rowCount ?? 0) };
  }

  async exec(sql: string): Promise<void> {
    await this.queryable.query(sql);
  }
}

class PostgresDbClient extends PgExecutor implements DbClient {
  private readonly pool: Pool;

  constructor(pool: Pool) {
    super(pool);
    this.pool = pool;
  }

  async transaction<T>(fn: (tx: DbExecutor) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    const txExec = new PgExecutor(client);
    try {
      await client.query('BEGIN');
      const result = await fn(txExec);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        // Ignore rollback errors
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

const SCHEMA_SQL = `
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
`;

function stripOuterQuotes(value: string): string {
  const trimmed = value.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2)
  ) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}

export function resolvePostgresUrl(env: Record<string, string | undefined> = process.env): string | null {
  const raw =
    env.SUPABASE_DB_URL ||
    env.DATABASE_URL ||
    env.POSTGRES_URL ||
    env.POSTGRES_PRISMA_URL ||
    env.POSTGRES_URL_NON_POOLING ||
    '';
  const candidate = stripOuterQuotes(raw);
  if (candidate && /^postgres(ql)?:\/\//i.test(candidate)) {
    return candidate;
  }

  const supabaseUrl = stripOuterQuotes(env.SUPABASE_URL || '');
  const supabaseDbPassword = stripOuterQuotes(env.SUPABASE_DB_PASSWORD || '');
  if (supabaseUrl && supabaseDbPassword) {
    try {
      const parsed = new URL(supabaseUrl);
      const match = /^([a-z0-9-]+)\.supabase\.co$/i.exec(parsed.hostname);
      if (match) {
        const ref = match[1];
        const encodedPass = encodeURIComponent(supabaseDbPassword);
        const poolerHost = stripOuterQuotes(env.SUPABASE_DB_POOLER_HOST || '');
        const region = stripOuterQuotes(env.SUPABASE_DB_REGION || '');
        if (poolerHost) {
          return `postgresql://postgres.${ref}:${encodedPass}@${poolerHost}:6543/postgres`;
        }
        if (region) {
          return `postgresql://postgres.${ref}:${encodedPass}@aws-0-${region}.pooler.supabase.com:6543/postgres`;
        }
        return `postgresql://postgres:${encodedPass}@db.${ref}.supabase.co:5432/postgres`;
      }
    } catch {
      // Ignore malformed SUPABASE_URL
    }
  }

  return null;
}

export function resolveDbPath(dbPath?: string): string {
  const raw = (dbPath !== undefined ? dbPath : process.env.SIMVAULT_DB_PATH)?.trim() ?? '';
  if (raw === ':memory:') return ':memory:';
  if (!raw) return path.resolve(process.cwd(), 'data', 'simvault.db');

  let cleaned = raw;
  if (cleaned.startsWith('sqlite://')) cleaned = cleaned.slice('sqlite://'.length);
  else if (cleaned.startsWith('file://')) cleaned = cleaned.slice('file://'.length);

  if (cleaned === '~/') cleaned = os.homedir();
  else if (cleaned.startsWith('~/')) cleaned = path.join(os.homedir(), cleaned.slice(2));

  return path.resolve(process.cwd(), cleaned);
}

interface GlobalDbCache {
  client?: DbClient;
  initPromise?: Promise<DbClient>;
}

const globalForDb = globalThis as typeof globalThis & { __simvaultDbCache?: GlobalDbCache };
if (!globalForDb.__simvaultDbCache) {
  globalForDb.__simvaultDbCache = {};
}
const dbCache = globalForDb.__simvaultDbCache;

export async function getDb(dbPath?: string): Promise<DbClient> {
  if (dbCache.client) return dbCache.client;
  if (dbCache.initPromise) return dbCache.initPromise;

  dbCache.initPromise = (async () => {
    const rawPgCandidate = stripOuterQuotes(
      process.env.SUPABASE_DB_URL ||
        process.env.DATABASE_URL ||
        process.env.POSTGRES_URL ||
        process.env.POSTGRES_PRISMA_URL ||
        process.env.POSTGRES_URL_NON_POOLING ||
        ''
    );
    if (dbPath === undefined && rawPgCandidate && /^https?:\/\//i.test(rawPgCandidate)) {
      throw new Error(
        'SUPABASE_DB_URL/DATABASE_URL appears to be an https:// API URL. Either paste the postgresql:// Transaction Pooler URI from Supabase -> Connect, or use SUPABASE_URL + SUPABASE_DB_PASSWORD + SUPABASE_DB_REGION.'
      );
    }

    const pgUrl = dbPath === undefined ? resolvePostgresUrl() : null;

    let client: DbClient;
    if (pgUrl) {
      let useSsl: boolean | { rejectUnauthorized: boolean } = { rejectUnauthorized: false };
      try {
        const parsed = new URL(pgUrl);
        if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
          useSsl = false;
        }
      } catch {
        // Keep SSL enabled for non-URL connection strings
      }

      const pool = new PgPool({
        connectionString: pgUrl,
        ssl: useSsl,
        max: process.env.VERCEL ? 5 : 10,
        idleTimeoutMillis: 20_000,
        connectionTimeoutMillis: 10_000,
      });

      const pgClient = new PostgresDbClient(pool);
      try {
        await pgClient.transaction(async (tx) => {
          await tx.exec('SELECT pg_advisory_xact_lock(84729103);');
          await migrateSchema(tx);
          await seedInitialData(tx);
          await syncEnvAdminCredentials(tx);
        });
      } catch (err) {
        await pool.end().catch(() => undefined);
        const msg = err instanceof Error ? err.message : String(err);
        if (/ENETUNREACH|EAI_AGAIN|ECONNREFUSED/i.test(msg) && pgUrl.includes(':5432')) {
          throw new Error(
            `Cannot reach Supabase direct port 5432 from this IPv4 serverless environment (${msg}). Set SUPABASE_DB_REGION (e.g. ap-south-1) or paste the port 6543 Transaction Pooler URI into SUPABASE_DB_URL.`
          );
        }
        throw err;
      }
      client = pgClient;
    } else {
      const explicitDbPath = (dbPath !== undefined ? dbPath : process.env.SIMVAULT_DB_PATH)?.trim() ?? '';
      const allowEphemeralSqliteOnVercel = explicitDbPath === ':memory:' || explicitDbPath.startsWith('/tmp/');
      if (process.env.VERCEL && !allowEphemeralSqliteOnVercel) {
        throw new Error(
          'Missing Supabase PostgreSQL connection string for Vercel. Add SUPABASE_DB_URL, DATABASE_URL, or POSTGRES_URL (postgresql://...) in Vercel Project Settings -> Environment Variables, and remove SIMVAULT_DB_PATH.'
        );
      }

      const targetPath = resolveDbPath(dbPath);
      if (targetPath !== ':memory:') {
        const dir = path.dirname(targetPath);
        try {
          fs.mkdirSync(dir, { recursive: true });
          fs.accessSync(dir, fs.constants.W_OK);
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          throw new Error(
            `Cannot write to SimVault database directory "${dir}" (resolved from SIMVAULT_DB_PATH="${process.env.SIMVAULT_DB_PATH ?? ''}", cwd="${process.cwd()}"). Fix folder permissions or set SIMVAULT_DB_PATH="./data/simvault.db" in .env. Details: ${reason}`
          );
        }
      }

      let rawDb: DatabaseSync;
      try {
        const { DatabaseSync: SqliteDatabaseSync } = await import('node:sqlite');
        rawDb = new SqliteDatabaseSync(targetPath);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        throw new Error(
          `Unable to open SQLite database at "${targetPath}". Check file/folder permissions (if created with sudo, run "sudo chown -R $USER:$USER ${path.dirname(targetPath)}") or check SIMVAULT_DB_PATH in .env. Details: ${reason}`
        );
      }

      rawDb.exec('PRAGMA journal_mode = WAL;');
      rawDb.exec('PRAGMA foreign_keys = ON;');
      const sqliteClient = new SqliteDbClient(rawDb);
      await migrateSchema(sqliteClient);
      await seedInitialData(sqliteClient);
      await syncEnvAdminCredentials(sqliteClient);
      client = sqliteClient;
    }

    dbCache.client = client;
    return client;
  })();

  try {
    return await dbCache.initPromise;
  } catch (err) {
    dbCache.initPromise = undefined;
    throw err;
  }
}

export async function closeDb(): Promise<void> {
  const client = dbCache.client;
  dbCache.client = undefined;
  dbCache.initPromise = undefined;
  if (!client) return;
  await client.close();
}

export async function createIsolatedTestDb(): Promise<DbClient> {
  const { DatabaseSync: SqliteDatabaseSync } = await import('node:sqlite');
  const rawDb = new SqliteDatabaseSync(':memory:');
  rawDb.exec('PRAGMA foreign_keys = ON;');
  const client = new SqliteDbClient(rawDb);
  await migrateSchema(client);
  await seedInitialData(client);
  return client;
}

async function migrateSchema(db: DbExecutor): Promise<void> {
  await db.exec(SCHEMA_SQL);
  await runLiveModeMigration(db);
}

async function runLiveModeMigration(db: DbExecutor): Promise<void> {
  const alreadyMigrated = await db.get<{ value: string }>(
    "SELECT value FROM platform_settings WHERE key = 'migration_live_mode_v2'"
  );
  if (alreadyMigrated?.value === 'done') return;

  const hasUsers = await db.get<{ cnt: number | string }>('SELECT COUNT(*) as cnt FROM users');
  const userCount = Number(hasUsers?.cnt ?? 0);
  const nowIso = new Date().toISOString();

  if (userCount > 0) {
    await db.run("DELETE FROM webhook_deliveries WHERE endpoint_id = 'wh_portal_events'");
    await db.run("DELETE FROM webhook_endpoints WHERE id = 'wh_portal_events' OR url LIKE '%.example%'");
    await db.run("DELETE FROM otp_challenges WHERE id IN ('otp_c84a12', 'otp_c84a13')");
    await db.run(
      "DELETE FROM usage_events WHERE message_id IN ('msg_91f0a1', 'msg_91f0a2', 'msg_91f0a3', 'msg_91f0a4', 'msg_91f0a5', 'msg_91f0a6')"
    );
    await db.run(
      "DELETE FROM messages WHERE id IN ('msg_91f0a1', 'msg_91f0a2', 'msg_91f0a3', 'msg_91f0a4', 'msg_91f0a5', 'msg_91f0a6')"
    );
    await db.run("DELETE FROM sims WHERE id = 'sim_primary_slot0' OR device_id = 'dev_pixel7_gateway'");
    await db.run("DELETE FROM gateway_devices WHERE id = 'dev_pixel7_gateway'");
    await db.run(
      "DELETE FROM destination_allowlist WHERE label IN ('Owner Primary Handset', 'QA Verification Phone', 'US Staging Test Number')"
    );
    await db.run("DELETE FROM api_keys WHERE id IN ('key_portal_primary', 'key_sandbox_ci')");
    await db.run("DELETE FROM applications WHERE id = 'app_sandbox_test'");
    await db.run("DELETE FROM audit_logs WHERE target_id IN ('dev_pixel7_gateway', 'sim_primary_slot0', 'key_portal_primary')");
    await db.run("DELETE FROM platform_settings WHERE key = 'simulator_auto_process'");
    await db.run("UPDATE applications SET environment = 'live', status = 'active', allowlist_only = 0 WHERE id = 'app_portal_prod'");

    await db.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES ('live_mode', 'true', ?)
       ON CONFLICT(key) DO UPDATE SET value = 'true', updated_at = excluded.updated_at`,
      nowIso
    );
    await db.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES ('migration_live_mode_v2', 'done', ?)
       ON CONFLICT(key) DO UPDATE SET value = 'done', updated_at = excluded.updated_at`,
      nowIso
    );
  }
}

export async function writeAuditLog(
  db: DbExecutor,
  entry: {
    actorType: 'owner' | 'application' | 'device' | 'system';
    actorId: string;
    action: string;
    targetType: string;
    targetId: string;
    metadata?: Record<string, unknown>;
    ipAddress?: string;
  }
): Promise<void> {
  const redacted = redactSensitiveMetadata(entry.metadata ?? {});
  await db.run(
    `INSERT INTO audit_logs (id, actor_type, actor_id, action, target_type, target_id, metadata_redacted_json, ip_address, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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

async function seedInitialData(db: DbExecutor): Promise<void> {
  const existingUsers = await db.get<{ cnt: number | string }>('SELECT COUNT(*) as cnt FROM users');
  if (Number(existingUsers?.cnt ?? 0) > 0) return;

  const now = new Date();
  const isoNow = now.toISOString();

  const ownerId = 'usr_owner_primary';
  const initialEmail = (process.env.SIMVAULT_ADMIN_EMAIL || 'owner@simvault.local').trim().toLowerCase();
  const initialPassword = process.env.SIMVAULT_ADMIN_PASSWORD || 'SimVault!2026';
  await db.run(
    `INSERT INTO users (id, email, password_hash, role, mfa_enabled, mfa_secret, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ownerId,
    initialEmail,
    hashPassword(initialPassword),
    'owner',
    0,
    generateTotpSecret(),
    isoNow,
    isoNow
  );

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
  for (const [k, v] of settings) {
    await db.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO NOTHING`,
      k,
      v,
      isoNow
    );
  }

  // Primary Live Application (owner generates keys & pairs real hardware device via dashboard)
  const appProdId = 'app_portal_prod';
  await db.run(
    `INSERT INTO applications (id, owner_user_id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO NOTHING`,
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
  for (const t of templates) {
    await db.run(
      `INSERT INTO message_templates (id, owner_user_id, code, purpose, body, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO NOTHING`,
      t.id,
      ownerId,
      t.code,
      t.purpose,
      t.body,
      t.status,
      isoNow,
      isoNow
    );
  }

  if (process.env.SIMVAULT_ADMIN_EMAIL?.trim() || process.env.SIMVAULT_ADMIN_PASSWORD?.trim()) {
    const initialSig = crypto
      .createHash('sha256')
      .update(`${process.env.SIMVAULT_ADMIN_EMAIL?.trim().toLowerCase() ?? ''}:${process.env.SIMVAULT_ADMIN_PASSWORD?.trim() ?? ''}`)
      .digest('hex');
    await db.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      'env_admin_sync_sig',
      initialSig,
      isoNow
    );
  }

  await writeAuditLog(db, {
    actorType: 'system',
    actorId: 'bootstrap',
    action: 'platform.live_mode_initialized',
    targetType: 'platform_settings',
    targetId: 'live_mode',
    metadata: { live_mode: true },
    ipAddress: '127.0.0.1',
  });
}

export async function syncEnvAdminCredentials(
  db: DbExecutor,
  overrides?: { email?: string; password?: string }
): Promise<boolean> {
  const rawEmail = (overrides?.email !== undefined ? overrides.email : process.env.SIMVAULT_ADMIN_EMAIL)?.trim().toLowerCase() ?? '';
  const rawPassword = (overrides?.password !== undefined ? overrides.password : process.env.SIMVAULT_ADMIN_PASSWORD)?.trim() ?? '';
  if (!rawEmail && !rawPassword) return false;

  const sig = crypto.createHash('sha256').update(`${rawEmail}:${rawPassword}`).digest('hex');
  const existingSig = await db.get<{ value: string }>(
    "SELECT value FROM platform_settings WHERE key = 'env_admin_sync_sig'"
  );
  if (existingSig?.value === sig) return false;

  const owner = await db.get<{ id: string; email: string }>(
    "SELECT id, email FROM users WHERE role = 'owner' ORDER BY created_at ASC LIMIT 1"
  );
  if (!owner) return false;

  const nowIso = new Date().toISOString();
  const nextEmail = rawEmail || owner.email;

  const applySync = async (tx: DbExecutor) => {
    if (rawPassword) {
      await tx.run(
        'UPDATE users SET email = ?, password_hash = ?, updated_at = ? WHERE id = ?',
        nextEmail,
        hashPassword(rawPassword),
        nowIso,
        owner.id
      );
      await tx.run('DELETE FROM sessions WHERE user_id = ?', owner.id);
    } else {
      await tx.run('UPDATE users SET email = ?, updated_at = ? WHERE id = ?', nextEmail, nowIso, owner.id);
    }

    await tx.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES ('env_admin_sync_sig', ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      sig,
      nowIso
    );
  };

  if ('transaction' in db && typeof (db as DbClient).transaction === 'function') {
    await (db as DbClient).transaction(applySync);
  } else {
    await applySync(db);
  }

  await writeAuditLog(db, {
    actorType: 'system',
    actorId: 'env_sync',
    action: 'owner.env_credentials_synced',
    targetType: 'user',
    targetId: owner.id,
    metadata: { email: nextEmail, password_updated: Boolean(rawPassword) },
    ipAddress: '127.0.0.1',
  });
  return true;
}
