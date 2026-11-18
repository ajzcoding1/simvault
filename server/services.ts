import crypto from 'node:crypto';
import dns from 'node:dns';
import { DatabaseSync } from 'node:sqlite';
import {
  decryptField,
  encryptField,
  generateOtpCode,
  hashDestination,
  hashOtpCode,
  hashToken,
  signWebhookPayload,
  verifyOtpHashConstantTime,
} from './crypto';
import { writeAuditLog } from './db';
import {
  ApiKeyScope,
  isPrivateOrReservedIp,
  isValidE164,
  isValidMessageTransition,
  isValidWebhookUrl,
  maskE164,
  MessageStatus,
  normalizeE164,
  renderTemplate,
} from '../src/shared/smsRules';

export class AppError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export function getSettingsMap(db: DatabaseSync): Record<string, string> {
  const rows = db.prepare('SELECT key, value FROM platform_settings').all() as Array<{ key: string; value: string }>;
  const map: Record<string, string> = {};
  for (const r of rows) map[r.key] = r.value;
  return map;
}

export function updateSetting(db: DatabaseSync, key: string, value: string, actorId: string, ipAddress = '127.0.0.1'): void {
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO platform_settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
  ).run(key, value, now);
  writeAuditLog(db, {
    actorType: 'owner',
    actorId,
    action: 'settings.updated',
    targetType: 'platform_settings',
    targetId: key,
    metadata: { key, value },
    ipAddress,
  });
}

// Sliding window IP throttle
const ipWindow = new Map<string, number[]>();
const loginFailureWindow = new Map<string, number[]>();

export function checkIpRateLimit(ip: string, limitPerMinute: number): boolean {
  const now = Date.now();
  const windowStart = now - 60_000;
  const timestamps = (ipWindow.get(ip) ?? []).filter((t) => t > windowStart);
  if (timestamps.length >= limitPerMinute) {
    ipWindow.set(ip, timestamps);
    return false;
  }
  timestamps.push(now);
  ipWindow.set(ip, timestamps);
  return true;
}

export function checkLoginRateLimit(ip: string, maxFailures = 8, windowMs = 5 * 60_000): boolean {
  const now = Date.now();
  const cutoff = now - windowMs;
  const recent = (loginFailureWindow.get(ip) ?? []).filter((t) => t > cutoff);
  loginFailureWindow.set(ip, recent);
  return recent.length < maxFailures;
}

export function recordLoginFailure(ip: string): void {
  const now = Date.now();
  const cutoff = now - 5 * 60_000;
  const recent = (loginFailureWindow.get(ip) ?? []).filter((t) => t > cutoff);
  recent.push(now);
  loginFailureWindow.set(ip, recent);
}

export function clearLoginFailures(ip: string): void {
  loginFailureWindow.delete(ip);
}

export async function assertPublicWebhookHost(rawUrl: string): Promise<URL> {
  if (!isValidWebhookUrl(rawUrl)) {
    throw new AppError(422, 'INVALID_WEBHOOK_URL', 'Webhook URL must be a public HTTPS URL (localhost, private/reserved IPs, and .example/.local domains are blocked).');
  }
  const parsed = new URL(rawUrl.trim());
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  if (isPrivateOrReservedIp(hostname)) {
    throw new AppError(422, 'SSRF_BLOCKED', 'Webhook host resolves to a private or reserved IP address.');
  }
  try {
    const records = await dns.promises.lookup(hostname, { all: true });
    if (!records || records.length === 0) {
      throw new AppError(422, 'DNS_LOOKUP_FAILED', 'Webhook hostname could not be resolved.');
    }
    for (const rec of records) {
      if (isPrivateOrReservedIp(rec.address)) {
        throw new AppError(422, 'SSRF_BLOCKED', 'Webhook host resolves to a private or reserved IP address.');
      }
    }
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError(422, 'DNS_LOOKUP_FAILED', 'Webhook hostname could not be resolved via DNS.');
  }
  return parsed;
}

export interface AuthenticatedAppContext {
  applicationId: string;
  applicationName: string;
  environment: 'test' | 'live';
  status: string;
  allowedPurposes: string[];
  dailyLimit: number;
  allowlistOnly: boolean;
  keyId: string;
  keyPrefix: string;
  scopes: ApiKeyScope[];
}

export function authenticateApiKey(db: DatabaseSync, rawBearerToken: string, hashFn: (s: string) => string): AuthenticatedAppContext {
  const secretHash = hashFn(rawBearerToken);
  const row = db
    .prepare(
      `SELECT k.id as key_id, k.key_prefix, k.scopes_json, k.status as key_status, k.expires_at,
              a.id as app_id, a.name as app_name, a.environment, a.status as app_status,
              a.allowed_purposes_json, a.daily_limit, a.allowlist_only
       FROM api_keys k
       JOIN applications a ON a.id = k.application_id
       WHERE k.secret_hash = ?`
    )
    .get(secretHash) as
    | {
        key_id: string;
        key_prefix: string;
        scopes_json: string;
        key_status: string;
        expires_at: string | null;
        app_id: string;
        app_name: string;
        environment: 'test' | 'live';
        app_status: string;
        allowed_purposes_json: string;
        daily_limit: number;
        allowlist_only: number;
      }
    | undefined;

  if (!row) {
    throw new AppError(401, 'UNAUTHORIZED', 'Invalid API key.');
  }
  if (row.key_status === 'revoked') {
    throw new AppError(401, 'KEY_REVOKED', 'API key has been revoked.');
  }
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
    throw new AppError(401, 'KEY_EXPIRED', 'API key overlap window has expired.');
  }
  if (row.app_status !== 'active') {
    throw new AppError(403, 'APPLICATION_INACTIVE', 'Application is currently paused or disabled.');
  }

  db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(new Date().toISOString(), row.key_id);

  return {
    applicationId: row.app_id,
    applicationName: row.app_name,
    environment: row.environment,
    status: row.app_status,
    allowedPurposes: JSON.parse(row.allowed_purposes_json),
    dailyLimit: row.daily_limit,
    allowlistOnly: Boolean(row.allowlist_only),
    keyId: row.key_id,
    keyPrefix: row.key_prefix,
    scopes: JSON.parse(row.scopes_json),
  };
}

export function requireScope(ctx: AuthenticatedAppContext, scope: ApiKeyScope): void {
  if (!ctx.scopes.includes(scope)) {
    throw new AppError(403, 'INSUFFICIENT_SCOPE', `API key lacks required scope: ${scope}`);
  }
}

function checkQuotasAndDestination(
  db: DatabaseSync,
  app: { id: string; dailyLimit: number; allowlistOnly: boolean; environment: 'test' | 'live'; allowedPurposes: string[] },
  toE164: string,
  purpose: string,
  ipAddress: string
): void {
  const settings = getSettingsMap(db);
  if (settings.global_paused === 'true') {
    throw new AppError(503, 'GATEWAY_PAUSED', 'Global SMS kill switch is active. All outbound requests are paused.');
  }
  const ipLimit = Number(settings.rate_limit_per_ip_minute ?? 30);
  if (!checkIpRateLimit(ipAddress, ipLimit)) {
    throw new AppError(429, 'RATE_LIMITED', 'IP request limit exceeded.');
  }

  if (!app.allowedPurposes.includes(purpose)) {
    throw new AppError(403, 'PURPOSE_NOT_ALLOWED', `Purpose '${purpose}' is not enabled for this application.`);
  }

  const destHash = hashDestination(toE164);
  if (app.allowlistOnly && app.environment === 'live') {
    const allowed = db
      .prepare('SELECT id FROM destination_allowlist WHERE application_id = ? AND e164_hash = ?')
      .get(app.id, destHash);
    if (!allowed) {
      throw new AppError(403, 'DESTINATION_NOT_ALLOWLISTED', 'Destination number is not in the approved allowlist for this live application.');
    }
  }

  const dayStart = new Date();
  dayStart.setUTCHours(0, 0, 0, 0);
  const dayStartIso = dayStart.toISOString();

  const appToday = db
    .prepare('SELECT COUNT(*) as cnt FROM messages WHERE application_id = ? AND created_at >= ? AND is_test = 0')
    .get(app.id, dayStartIso) as { cnt: number };

  if (app.environment === 'live' && appToday.cnt >= app.dailyLimit) {
    throw new AppError(429, 'APP_DAILY_CAP_REACHED', 'Application daily message cap reached.');
  }

  const globalCap = Number(settings.global_daily_sim_cap ?? 300);
  const globalToday = db
    .prepare('SELECT COUNT(*) as cnt FROM messages WHERE created_at >= ? AND is_test = 0')
    .get(dayStartIso) as { cnt: number };
  if (app.environment === 'live' && globalToday.cnt >= globalCap) {
    throw new AppError(429, 'GLOBAL_SIM_CAP_REACHED', 'Global daily SIM safety cap reached.');
  }

  const hourAgo = new Date(Date.now() - 3600_000).toISOString();
  const perNumberHourlyLimit = Number(settings.rate_limit_per_number_hourly ?? 6);
  const numberHourCount = db
    .prepare('SELECT COUNT(*) as cnt FROM messages WHERE destination_hash = ? AND created_at >= ?')
    .get(destHash, hourAgo) as { cnt: number };
  if (numberHourCount.cnt >= perNumberHourlyLimit) {
    throw new AppError(429, 'DESTINATION_THROTTLED', 'Hourly per-number message limit exceeded.');
  }
}

export function enqueueWebhookEvent(
  db: DatabaseSync,
  applicationId: string,
  eventType: string,
  payload: Record<string, unknown>
): void {
  const endpoints = db
    .prepare('SELECT id, event_types_json FROM webhook_endpoints WHERE application_id = ? AND enabled = 1')
    .all(applicationId) as Array<{ id: string; event_types_json: string }>;

  const now = new Date().toISOString();
  const eventId = `evt_${crypto.randomBytes(8).toString('hex')}`;
  const redactedPayload = {
    event_id: eventId,
    event_type: eventType,
    occurred_at: now,
    data: payload,
  };

  const stmt = db.prepare(
    `INSERT INTO webhook_deliveries (id, endpoint_id, event_id, event_type, payload_redacted_json, status, attempt_count, next_attempt_at, last_http_status, created_at)
     VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, NULL, ?)`
  );

  for (const ep of endpoints) {
    const subscribed: string[] = JSON.parse(ep.event_types_json);
    if (subscribed.includes(eventType)) {
      stmt.run(crypto.randomUUID(), ep.id, eventId, eventType, JSON.stringify(redactedPayload), now, now);
    }
  }
}

export function createSmsRequest(
  db: DatabaseSync,
  input: {
    applicationId: string;
    to: string;
    templateCode: string;
    variables?: Record<string, string | number | boolean>;
    purpose: string;
    ttlSeconds?: number;
    idempotencyKey?: string;
    actorId: string;
    ipAddress?: string;
  }
): {
  message_id: string;
  status: MessageStatus;
  created_at: string;
  is_test: boolean;
  deduplicated: boolean;
} {
  const normalizedTo = normalizeE164(input.to);
  if (!isValidE164(normalizedTo)) {
    throw new AppError(422, 'INVALID_PHONE', 'Destination phone must be valid E.164 format (e.g. +919876543210).');
  }

  const appRow = db
    .prepare('SELECT id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only FROM applications WHERE id = ?')
    .get(input.applicationId) as
    | {
        id: string;
        name: string;
        environment: 'test' | 'live';
        status: string;
        allowed_purposes_json: string;
        daily_limit: number;
        allowlist_only: number;
      }
    | undefined;

  if (!appRow) {
    throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Application not found.');
  }
  if (appRow.status !== 'active') {
    throw new AppError(403, 'APPLICATION_INACTIVE', 'Application is paused or disabled.');
  }

  // Idempotency check BEFORE creating a duplicate job
  if (input.idempotencyKey) {
    const existing = db
      .prepare('SELECT id, status, created_at, is_test FROM messages WHERE application_id = ? AND idempotency_key = ?')
      .get(appRow.id, input.idempotencyKey) as
      | { id: string; status: MessageStatus; created_at: string; is_test: number }
      | undefined;
    if (existing) {
      return {
        message_id: existing.id,
        status: existing.status,
        created_at: existing.created_at,
        is_test: Boolean(existing.is_test),
        deduplicated: true,
      };
    }
  }

  checkQuotasAndDestination(
    db,
    {
      id: appRow.id,
      dailyLimit: appRow.daily_limit,
      allowlistOnly: Boolean(appRow.allowlist_only),
      environment: appRow.environment,
      allowedPurposes: JSON.parse(appRow.allowed_purposes_json),
    },
    normalizedTo,
    input.purpose,
    input.ipAddress ?? '127.0.0.1'
  );

  const template = db
    .prepare("SELECT id, code, purpose, body, status FROM message_templates WHERE code = ? AND status = 'approved'")
    .get(input.templateCode) as
    | { id: string; code: string; purpose: string; body: string; status: string }
    | undefined;
  if (!template) {
    throw new AppError(422, 'TEMPLATE_NOT_APPROVED', `Approved template '${input.templateCode}' not found.`);
  }

  const { rendered, missingVariables } = renderTemplate(template.body, input.variables ?? {});
  if (missingVariables.length > 0) {
    throw new AppError(422, 'MISSING_TEMPLATE_VARIABLES', `Missing template variables: ${missingVariables.join(', ')}`);
  }

  const now = new Date();
  const ttl = Math.min(Math.max(Number(input.ttlSeconds ?? 180), 30), 3600);
  const ttlExpiresAt = new Date(now.getTime() + ttl * 1000).toISOString();
  const createdAt = now.toISOString();
  const messageId = `msg_${crypto.randomBytes(6).toString('hex')}`;
  const isTest = appRow.environment === 'test' ? 1 : 0;

  db.prepare(
    `INSERT INTO messages (id, application_id, device_id, destination_masked, destination_hash, destination_encrypted, template_id, body_encrypted, purpose, status, is_test, idempotency_key, ttl_expires_at, created_at, queued_at)
     VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)`
  ).run(
    messageId,
    appRow.id,
    maskE164(normalizedTo),
    hashDestination(normalizedTo),
    encryptField(normalizedTo),
    template.code,
    encryptField(rendered),
    input.purpose,
    isTest,
    input.idempotencyKey ?? null,
    ttlExpiresAt,
    createdAt,
    createdAt
  );

  db.prepare(
    `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
     VALUES (?, ?, NULL, ?, 'message.requested', 1, ?)`
  ).run(crypto.randomUUID(), appRow.id, messageId, createdAt);

  writeAuditLog(db, {
    actorType: 'application',
    actorId: input.actorId,
    action: 'sms.queued',
    targetType: 'message',
    targetId: messageId,
    metadata: {
      application_id: appRow.id,
      template_id: template.code,
      purpose: input.purpose,
      destination_masked: maskE164(normalizedTo),
      is_test: Boolean(isTest),
    },
    ipAddress: input.ipAddress,
  });

  enqueueWebhookEvent(db, appRow.id, 'message.status', {
    message_id: messageId,
    status: 'queued',
    destination_masked: maskE164(normalizedTo),
    is_test: Boolean(isTest),
  });

  return {
    message_id: messageId,
    status: 'queued',
    created_at: createdAt,
    is_test: Boolean(isTest),
    deduplicated: false,
  };
}

export function createOtpChallenge(
  db: DatabaseSync,
  input: {
    applicationId: string;
    to: string;
    purpose: string;
    ttlSeconds?: number;
    actorId: string;
    ipAddress?: string;
    bypassCooldown?: boolean;
  }
): {
  challenge_id: string;
  message_id: string;
  status: 'queued';
  expires_at: string;
  is_test: boolean;
} {
  const normalizedTo = normalizeE164(input.to);
  if (!isValidE164(normalizedTo)) {
    throw new AppError(422, 'INVALID_PHONE', 'Destination phone must be valid E.164 format.');
  }

  const settings = getSettingsMap(db);
  const appRow = db
    .prepare('SELECT id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only FROM applications WHERE id = ?')
    .get(input.applicationId) as
    | {
        id: string;
        name: string;
        environment: 'test' | 'live';
        status: string;
        allowed_purposes_json: string;
        daily_limit: number;
        allowlist_only: number;
      }
    | undefined;

  if (!appRow) throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Application not found.');
  if (appRow.status !== 'active') throw new AppError(403, 'APPLICATION_INACTIVE', 'Application is paused or disabled.');

  const destHash = hashDestination(normalizedTo);
  const cooldownSeconds = Number(settings.otp_resend_cooldown_seconds ?? 45);
  if (!input.bypassCooldown && cooldownSeconds > 0) {
    const cooldownCutoff = new Date(Date.now() - cooldownSeconds * 1000).toISOString();
    const recent = db
      .prepare(
        `SELECT id FROM otp_challenges
         WHERE application_id = ? AND destination_hash = ? AND created_at > ? AND status IN ('queued', 'sent')`
      )
      .get(appRow.id, destHash, cooldownCutoff);
    if (recent) {
      throw new AppError(429, 'RESEND_COOLDOWN', `Please wait ${cooldownSeconds} seconds before requesting another verification code.`);
    }
  }

  checkQuotasAndDestination(
    db,
    {
      id: appRow.id,
      dailyLimit: appRow.daily_limit,
      allowlistOnly: Boolean(appRow.allowlist_only),
      environment: appRow.environment,
      allowedPurposes: JSON.parse(appRow.allowed_purposes_json),
    },
    normalizedTo,
    input.purpose,
    input.ipAddress ?? '127.0.0.1'
  );

  const defaultTtl = Number(settings.otp_ttl_seconds ?? 300);
  const ttlSeconds = Math.min(Math.max(Number(input.ttlSeconds ?? defaultTtl), 60), 600);
  const maxAttempts = Number(settings.otp_max_attempts ?? 5);

  const challengeId = `otp_${crypto.randomBytes(6).toString('hex')}`;
  const otpCode = generateOtpCode(6);
  const codeHash = hashOtpCode(challengeId, otpCode);

  const templateCode = input.purpose === 'password_reset' ? 'otp_password_reset' : 'otp_login';
  const template = db
    .prepare("SELECT code, body FROM message_templates WHERE code = ? AND status = 'approved'")
    .get(templateCode) as { code: string; body: string } | undefined;

  const fallbackTemplate = 'Your verification code for {{app_name}} is {{code}}. Valid for {{ttl_minutes}} minutes.';
  const { rendered } = renderTemplate(template?.body ?? fallbackTemplate, {
    app_name: appRow.name,
    code: otpCode,
    ttl_minutes: Math.max(1, Math.round(ttlSeconds / 60)),
  });

  const now = new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();
  const messageId = `msg_${crypto.randomBytes(6).toString('hex')}`;
  const isTest = appRow.environment === 'test' ? 1 : 0;

  // Persist message + challenge atomically; OTP plaintext is NEVER stored in DB or logs
  db.exec('BEGIN IMMEDIATE;');
  try {
    db.prepare(
      `INSERT INTO messages (id, application_id, device_id, destination_masked, destination_hash, destination_encrypted, template_id, body_encrypted, purpose, status, is_test, idempotency_key, ttl_expires_at, created_at, queued_at)
       VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 'queued', ?, NULL, ?, ?, ?)`
    ).run(
      messageId,
      appRow.id,
      maskE164(normalizedTo),
      destHash,
      encryptField(normalizedTo),
      template?.code ?? 'otp_login',
      encryptField(rendered),
      input.purpose,
      isTest,
      expiresAt,
      createdAt,
      createdAt
    );

    db.prepare(
      `INSERT INTO otp_challenges (id, application_id, destination_masked, destination_hash, destination_encrypted, code_hash, purpose, status, is_test, expires_at, attempts, max_attempts, consumed_at, message_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, 0, ?, NULL, ?, ?)`
    ).run(
      challengeId,
      appRow.id,
      maskE164(normalizedTo),
      destHash,
      encryptField(normalizedTo),
      codeHash,
      input.purpose,
      isTest,
      expiresAt,
      maxAttempts,
      messageId,
      createdAt
    );

    db.prepare(
      `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
       VALUES (?, ?, NULL, ?, 'otp.requested', 1, ?)`
    ).run(crypto.randomUUID(), appRow.id, messageId, createdAt);

    db.exec('COMMIT;');
  } catch (err) {
    db.exec('ROLLBACK;');
    throw err;
  }

  writeAuditLog(db, {
    actorType: 'application',
    actorId: input.actorId,
    action: 'otp.challenge_created',
    targetType: 'otp_challenge',
    targetId: challengeId,
    metadata: {
      application_id: appRow.id,
      purpose: input.purpose,
      destination_masked: maskE164(normalizedTo),
      expires_at: expiresAt,
      is_test: Boolean(isTest),
    },
    ipAddress: input.ipAddress,
  });

  // Never include OTP plaintext in response!
  return {
    challenge_id: challengeId,
    message_id: messageId,
    status: 'queued',
    expires_at: expiresAt,
    is_test: Boolean(isTest),
  };
}

export function verifyOtpChallenge(
  db: DatabaseSync,
  input: {
    applicationId?: string;
    challengeId: string;
    code: string;
    ipAddress?: string;
  }
): { verified: true; verified_at: string; challenge_id: string } {
  const cleanCode = input.code.trim();
  if (!/^\d{4,10}$/.test(cleanCode)) {
    throw new AppError(422, 'OTP_INVALID', 'Invalid or expired verification code.');
  }

  const nowIso = new Date().toISOString();
  db.exec('BEGIN IMMEDIATE;');
  let row:
    | {
        id: string;
        application_id: string;
        code_hash: string;
        status: string;
        expires_at: string;
        attempts: number;
        max_attempts: number;
      }
    | undefined;
  let isMatch = false;
  let nextAttempts = 0;
  let locked = false;
  let invalidReason: 'missing' | 'expired' | 'terminal' | 'mismatch' | null = null;

  try {
    row = db
      .prepare(
        `SELECT id, application_id, code_hash, status, expires_at, attempts, max_attempts
         FROM otp_challenges WHERE id = ?`
      )
      .get(input.challengeId) as typeof row;

    if (!row || (input.applicationId && row.application_id !== input.applicationId)) {
      invalidReason = 'missing';
    } else if (new Date(row.expires_at).getTime() <= Date.now()) {
      if (row.status === 'queued' || row.status === 'sent') {
        db.prepare("UPDATE otp_challenges SET status = 'expired' WHERE id = ? AND status IN ('queued', 'sent')").run(row.id);
      }
      invalidReason = 'expired';
    } else if (row.status !== 'queued' && row.status !== 'sent') {
      invalidReason = 'terminal';
    } else {
      nextAttempts = row.attempts + 1;
      isMatch = verifyOtpHashConstantTime(row.id, cleanCode, row.code_hash);
      if (!isMatch) {
        locked = nextAttempts >= row.max_attempts;
        db.prepare("UPDATE otp_challenges SET attempts = ?, status = ? WHERE id = ? AND status IN ('queued', 'sent')").run(
          nextAttempts,
          locked ? 'locked' : row.status,
          row.id
        );
        invalidReason = 'mismatch';
      } else {
        const updateRes = db
          .prepare("UPDATE otp_challenges SET status = 'verified', attempts = ?, consumed_at = ? WHERE id = ? AND status IN ('queued', 'sent')")
          .run(nextAttempts, nowIso, row.id);
        if (updateRes.changes === 0) {
          invalidReason = 'terminal';
        }
      }
    }
    db.exec('COMMIT;');
  } catch (err) {
    db.exec('ROLLBACK;');
    throw err;
  }

  if (invalidReason === 'missing' || invalidReason === 'expired' || invalidReason === 'terminal') {
    throw new AppError(422, 'OTP_INVALID', 'Invalid or expired verification code.');
  }

  if (invalidReason === 'mismatch' && row) {
    writeAuditLog(db, {
      actorType: 'application',
      actorId: row.application_id,
      action: locked ? 'otp.locked_max_attempts' : 'otp.verify_failed',
      targetType: 'otp_challenge',
      targetId: row.id,
      metadata: { attempts: nextAttempts, max_attempts: row.max_attempts },
      ipAddress: input.ipAddress,
    });
    if (locked) {
      enqueueWebhookEvent(db, row.application_id, 'otp.failed', {
        challenge_id: row.id,
        reason: 'MAX_ATTEMPTS_EXCEEDED',
      });
    }
    throw new AppError(422, 'OTP_INVALID', 'Invalid or expired verification code.');
  }

  writeAuditLog(db, {
    actorType: 'application',
    actorId: row!.application_id,
    action: 'otp.verified',
    targetType: 'otp_challenge',
    targetId: row!.id,
    metadata: { attempts: nextAttempts },
    ipAddress: input.ipAddress,
  });

  enqueueWebhookEvent(db, row!.application_id, 'otp.verified', {
    challenge_id: row!.id,
    verified_at: nowIso,
  });

  return { verified: true, verified_at: nowIso, challenge_id: row!.id };
}

export function authenticateGatewayDevice(
  db: DatabaseSync,
  rawToken: string
): {
  id: string;
  name: string;
  status: string;
  permissionSendSms: boolean;
  simReady: boolean;
} {
  const tokenHash = hashToken(rawToken);
  const dev = db
    .prepare(
      `SELECT id, name, status, permission_send_sms, sim_ready, revoked_at
       FROM gateway_devices WHERE device_token_hash = ?`
    )
    .get(tokenHash) as
    | {
        id: string;
        name: string;
        status: string;
        permission_send_sms: number;
        sim_ready: number;
        revoked_at: string | null;
      }
    | undefined;

  if (!dev || dev.status === 'revoked' || dev.revoked_at) {
    throw new AppError(401, 'DEVICE_UNAUTHORIZED', 'Invalid or revoked device credential.');
  }

  return {
    id: dev.id,
    name: dev.name,
    status: dev.status,
    permissionSendSms: Boolean(dev.permission_send_sms),
    simReady: Boolean(dev.sim_ready),
  };
}

export function leaseNextGatewayJob(
  db: DatabaseSync,
  deviceId: string
): {
  job_id: string;
  lease_token: string;
  to: string;
  body: string;
  sim_slot: number;
  is_test: boolean;
  expires_at: string;
} | null {
  const settings = getSettingsMap(db);
  if (settings.global_paused === 'true') {
    return null;
  }

  const dev = db
    .prepare('SELECT id, status, permission_send_sms, sim_ready FROM gateway_devices WHERE id = ?')
    .get(deviceId) as
    | { id: string; status: string; permission_send_sms: number; sim_ready: number }
    | undefined;

  if (!dev || dev.status !== 'online' || !dev.permission_send_sms || !dev.sim_ready) {
    return null;
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const leaseTimeoutSec = Number(settings.lease_timeout_seconds ?? 30);
  const leaseExpiresAt = new Date(now.getTime() + leaseTimeoutSec * 1000).toISOString();

  db.exec('BEGIN IMMEDIATE;');
  try {
    const candidate = db
      .prepare(
        `SELECT id, destination_encrypted, body_encrypted, is_test, ttl_expires_at
         FROM messages
         WHERE status = 'queued' AND ttl_expires_at > ?
         ORDER BY created_at ASC
         LIMIT 1`
      )
      .get(nowIso) as
      | {
          id: string;
          destination_encrypted: string;
          body_encrypted: string;
          is_test: number;
          ttl_expires_at: string;
        }
      | undefined;

    if (!candidate) {
      db.exec('COMMIT;');
      return null;
    }

    const existingAttempts = db
      .prepare('SELECT COUNT(*) as cnt FROM gateway_job_leases WHERE message_id = ?')
      .get(candidate.id) as { cnt: number };

    const leaseToken = `lease_${crypto.randomBytes(16).toString('hex')}`;
    db.prepare(
      `INSERT INTO gateway_job_leases (id, message_id, device_id, lease_token_hash, leased_at, lease_expires_at, attempt_count)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).run(
      crypto.randomUUID(),
      candidate.id,
      deviceId,
      hashToken(leaseToken),
      nowIso,
      leaseExpiresAt,
      existingAttempts.cnt + 1
    );

    db.prepare("UPDATE messages SET status = 'leased', device_id = ?, leased_at = ? WHERE id = ?").run(
      deviceId,
      nowIso,
      candidate.id
    );

    const sim = db.prepare('SELECT slot_index FROM sims WHERE device_id = ? ORDER BY slot_index ASC LIMIT 1').get(deviceId) as
      | { slot_index: number }
      | undefined;

    db.exec('COMMIT;');

    return {
      job_id: candidate.id,
      lease_token: leaseToken,
      to: decryptField(candidate.destination_encrypted),
      body: decryptField(candidate.body_encrypted),
      sim_slot: sim?.slot_index ?? 0,
      is_test: Boolean(candidate.is_test),
      expires_at: candidate.ttl_expires_at,
    };
  } catch (err) {
    db.exec('ROLLBACK;');
    throw err;
  }
}

export function markJobAcceptedByDevice(db: DatabaseSync, deviceId: string, jobId: string): { status: MessageStatus } {
  const msg = db
    .prepare('SELECT id, application_id, device_id, status, destination_masked FROM messages WHERE id = ?')
    .get(jobId) as
    | { id: string; application_id: string; device_id: string | null; status: MessageStatus; destination_masked: string }
    | undefined;

  if (!msg || msg.device_id !== deviceId) {
    throw new AppError(404, 'JOB_NOT_FOUND', 'Leased job not found for this device.');
  }
  if (!isValidMessageTransition(msg.status, 'accepted_by_device')) {
    throw new AppError(409, 'INVALID_TRANSITION', `Cannot transition from ${msg.status} to accepted_by_device.`);
  }

  const nowIso = new Date().toISOString();
  db.prepare("UPDATE messages SET status = 'accepted_by_device', accepted_at = ? WHERE id = ?").run(nowIso, jobId);
  enqueueWebhookEvent(db, msg.application_id, 'message.status', {
    message_id: msg.id,
    status: 'accepted_by_device',
    destination_masked: msg.destination_masked,
  });
  return { status: 'accepted_by_device' };
}

export function reportJobResult(
  db: DatabaseSync,
  deviceId: string,
  jobId: string,
  outcome: 'sent_to_network' | 'failed' | 'delivery_unknown',
  errorCode?: string
): { status: MessageStatus } {
  const msg = db
    .prepare('SELECT id, application_id, device_id, status, is_test, destination_masked FROM messages WHERE id = ?')
    .get(jobId) as
    | {
        id: string;
        application_id: string;
        device_id: string | null;
        status: MessageStatus;
        is_test: number;
        destination_masked: string;
      }
    | undefined;

  if (!msg || msg.device_id !== deviceId) {
    throw new AppError(404, 'JOB_NOT_FOUND', 'Job not found for this device.');
  }
  if (!isValidMessageTransition(msg.status, outcome)) {
    throw new AppError(409, 'INVALID_TRANSITION', `Cannot transition from ${msg.status} to ${outcome}.`);
  }

  const cleanErrorCode = errorCode ? String(errorCode).replace(/[^A-Z0-9_:-]/gi, '').slice(0, 48) : undefined;
  const nowIso = new Date().toISOString();
  db.exec('BEGIN IMMEDIATE;');
  try {
    if (outcome === 'sent_to_network') {
      db.prepare("UPDATE messages SET status = 'sent_to_network', sent_at = ?, error_code = NULL WHERE id = ?").run(nowIso, jobId);
      db.prepare("UPDATE otp_challenges SET status = 'sent' WHERE message_id = ? AND status = 'queued'").run(jobId);
      db.prepare(
        `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
         VALUES (?, ?, ?, ?, 'message.sent_to_network', 1, ?)`
      ).run(crypto.randomUUID(), msg.application_id, deviceId, jobId, nowIso);

      if (!msg.is_test) {
        db.prepare(
          `UPDATE sims
           SET estimated_sms_sent = estimated_sms_sent + 1,
               estimated_sms_remaining = MAX(0, estimated_sms_remaining - 1),
               updated_at = ?
           WHERE device_id = ?`
        ).run(nowIso, deviceId);
      }
    } else if (outcome === 'delivery_unknown') {
      db.prepare("UPDATE messages SET status = 'delivery_unknown', sent_at = COALESCE(sent_at, ?), error_code = ? WHERE id = ?").run(
        nowIso,
        cleanErrorCode || 'NO_CARRIER_RECEIPT',
        jobId
      );
    } else {
      db.prepare("UPDATE messages SET status = 'failed', failed_at = ?, error_code = ? WHERE id = ?").run(
        nowIso,
        cleanErrorCode || 'SEND_FAILED',
        jobId
      );
      db.prepare("UPDATE otp_challenges SET status = 'failed' WHERE message_id = ? AND status IN ('queued', 'sent')").run(jobId);
      db.prepare(
        `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
         VALUES (?, ?, ?, ?, 'message.failed', 1, ?)`
      ).run(crypto.randomUUID(), msg.application_id, deviceId, jobId, nowIso);
    }

    db.prepare('DELETE FROM gateway_job_leases WHERE message_id = ?').run(jobId);
    db.exec('COMMIT;');
  } catch (err) {
    db.exec('ROLLBACK;');
    throw err;
  }

  enqueueWebhookEvent(db, msg.application_id, 'message.status', {
    message_id: msg.id,
    status: outcome,
    error_code: errorCode ?? null,
    destination_masked: msg.destination_masked,
  });

  if (outcome === 'sent_to_network') {
    const otp = db.prepare('SELECT id FROM otp_challenges WHERE message_id = ?').get(jobId) as { id: string } | undefined;
    if (otp) {
      enqueueWebhookEvent(db, msg.application_id, 'otp.sent', { challenge_id: otp.id, message_id: jobId });
    }
  } else if (outcome === 'failed') {
    const otp = db.prepare('SELECT id FROM otp_challenges WHERE message_id = ?').get(jobId) as { id: string } | undefined;
    if (otp) {
      enqueueWebhookEvent(db, msg.application_id, 'otp.failed', {
        challenge_id: otp.id,
        message_id: jobId,
        error_code: errorCode ?? 'SEND_FAILED',
      });
    }
  }

  return { status: outcome };
}

export function reportDeliveryReceipt(db: DatabaseSync, deviceId: string, jobId: string): { status: MessageStatus } {
  const msg = db
    .prepare('SELECT id, application_id, device_id, status, destination_masked FROM messages WHERE id = ?')
    .get(jobId) as
    | { id: string; application_id: string; device_id: string | null; status: MessageStatus; destination_masked: string }
    | undefined;

  if (!msg || msg.device_id !== deviceId) {
    throw new AppError(404, 'JOB_NOT_FOUND', 'Job not found for this device.');
  }
  if (!isValidMessageTransition(msg.status, 'delivered')) {
    throw new AppError(409, 'INVALID_TRANSITION', `Cannot transition from ${msg.status} to delivered.`);
  }

  const nowIso = new Date().toISOString();
  db.prepare("UPDATE messages SET status = 'delivered', delivered_at = ?, error_code = NULL WHERE id = ?").run(nowIso, jobId);
  db.prepare(
    `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
     VALUES (?, ?, ?, ?, 'message.delivered', 1, ?)`
  ).run(crypto.randomUUID(), msg.application_id, deviceId, jobId, nowIso);

  enqueueWebhookEvent(db, msg.application_id, 'message.status', {
    message_id: msg.id,
    status: 'delivered',
    delivered_at: nowIso,
    destination_masked: msg.destination_masked,
  });

  return { status: 'delivered' };
}

export function runSweeperTick(db: DatabaseSync): {
  expiredMessages: number;
  requeuedLeases: number;
  failedMaxRetries: number;
  expiredOtps: number;
  processedWebhooks: number;
} {
  const now = new Date();
  const nowIso = now.toISOString();
  const settings = getSettingsMap(db);
  const maxRetries = Number(settings.max_send_retries ?? 3);

  // 1. Expire TTL-exceeded queued/leased messages
  const expiredRows = db
    .prepare(
      `SELECT id, application_id, destination_masked FROM messages
       WHERE status IN ('created', 'queued', 'leased', 'accepted_by_device') AND ttl_expires_at <= ?`
    )
    .all(nowIso) as Array<{ id: string; application_id: string; destination_masked: string }>;

  for (const row of expiredRows) {
    db.prepare("UPDATE messages SET status = 'expired', failed_at = ?, error_code = 'TTL_EXPIRED' WHERE id = ?").run(nowIso, row.id);
    db.prepare('DELETE FROM gateway_job_leases WHERE message_id = ?').run(row.id);
    enqueueWebhookEvent(db, row.application_id, 'message.status', {
      message_id: row.id,
      status: 'expired',
      error_code: 'TTL_EXPIRED',
      destination_masked: row.destination_masked,
    });
  }

  // 2. Expire OTP challenges past expires_at
  const expOtps = db
    .prepare("UPDATE otp_challenges SET status = 'expired' WHERE status IN ('queued', 'sent') AND expires_at <= ?")
    .run(nowIso);

  // 3. Requeue or dead-letter expired leases
  const staleLeases = db
    .prepare(
      `SELECT l.id as lease_id, l.message_id, l.attempt_count, m.application_id, m.destination_masked
       FROM gateway_job_leases l
       JOIN messages m ON m.id = l.message_id
       WHERE l.lease_expires_at <= ? AND m.status IN ('leased', 'accepted_by_device')`
    )
    .all(nowIso) as Array<{
    lease_id: string;
    message_id: string;
    attempt_count: number;
    application_id: string;
    destination_masked: string;
  }>;

  let requeuedLeases = 0;
  let failedMaxRetries = 0;
  for (const lease of staleLeases) {
    db.prepare('DELETE FROM gateway_job_leases WHERE id = ?').run(lease.lease_id);
    if (lease.attempt_count >= maxRetries) {
      db.prepare("UPDATE messages SET status = 'failed', failed_at = ?, error_code = 'LEASE_EXPIRED_MAX_RETRIES' WHERE id = ?").run(
        nowIso,
        lease.message_id
      );
      failedMaxRetries++;
      enqueueWebhookEvent(db, lease.application_id, 'message.status', {
        message_id: lease.message_id,
        status: 'failed',
        error_code: 'LEASE_EXPIRED_MAX_RETRIES',
        destination_masked: lease.destination_masked,
      });
    } else {
      db.prepare("UPDATE messages SET status = 'queued', device_id = NULL WHERE id = ?").run(lease.message_id);
      requeuedLeases++;
    }
  }

  // 4. Mark gateway devices offline if heartbeat stale (> 45s) — skip seeded primary if within 45s
  const staleHeartbeatCutoff = new Date(now.getTime() - 45_000).toISOString();
  db.prepare(
    `UPDATE gateway_devices
     SET status = 'offline'
     WHERE status = 'online' AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at < ?`
  ).run(staleHeartbeatCutoff);

  // 5. Process pending webhook deliveries with SSRF DNS check and redirect blocking
  const pendingHooks = db
    .prepare(
      `SELECT d.id, d.event_id, d.payload_redacted_json, d.attempt_count, e.url, e.secret_encrypted
       FROM webhook_deliveries d
       JOIN webhook_endpoints e ON e.id = d.endpoint_id
       WHERE d.status = 'pending' AND d.next_attempt_at <= ?
       LIMIT 10`
    )
    .all(nowIso) as Array<{
    id: string;
    event_id: string;
    payload_redacted_json: string;
    attempt_count: number;
    url: string;
    secret_encrypted: string;
  }>;

  let processedWebhooks = 0;
  for (const hook of pendingHooks) {
    processedWebhooks++;
    const ts = String(Math.floor(Date.now() / 1000));
    const secret = decryptField(hook.secret_encrypted);
    const sig = signWebhookPayload(secret, ts, hook.event_id, hook.payload_redacted_json);
    const nextAttempt = hook.attempt_count + 1;

    // Optimistically bump next_attempt_at so the sweeper doesn't double-fire while DNS/fetch is in flight
    db.prepare('UPDATE webhook_deliveries SET next_attempt_at = ? WHERE id = ?').run(
      new Date(Date.now() + 10_000).toISOString(),
      hook.id
    );

    void assertPublicWebhookHost(hook.url)
      .then(() =>
        fetch(hook.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-SimVault-Event-Id': hook.event_id,
            'X-SimVault-Timestamp': ts,
            'X-SimVault-Signature': `v1=${sig}`,
          },
          body: hook.payload_redacted_json,
          redirect: 'error',
          signal: AbortSignal.timeout(4000),
        })
      )
      .then((res) => {
        if (res.ok) {
          db.prepare(
            "UPDATE webhook_deliveries SET status = 'delivered', attempt_count = ?, last_http_status = ? WHERE id = ?"
          ).run(nextAttempt, res.status, hook.id);
        } else {
          const backoffMs = Math.min(60_000, Math.pow(2, nextAttempt) * 1000);
          db.prepare(
            "UPDATE webhook_deliveries SET status = ?, attempt_count = ?, next_attempt_at = ?, last_http_status = ? WHERE id = ?"
          ).run(nextAttempt >= 4 ? 'failed' : 'pending', nextAttempt, new Date(Date.now() + backoffMs).toISOString(), res.status, hook.id);
        }
      })
      .catch(() => {
        const backoffMs = Math.min(60_000, Math.pow(2, nextAttempt) * 1000);
        db.prepare(
          "UPDATE webhook_deliveries SET status = ?, attempt_count = ?, next_attempt_at = ?, last_http_status = 0 WHERE id = ?"
        ).run(nextAttempt >= 4 ? 'failed' : 'pending', nextAttempt, new Date(Date.now() + backoffMs).toISOString(), hook.id);
      });
  }

  return {
    expiredMessages: expiredRows.length,
    requeuedLeases,
    failedMaxRetries,
    expiredOtps: Number(expOtps.changes ?? 0),
    processedWebhooks,
  };
}
