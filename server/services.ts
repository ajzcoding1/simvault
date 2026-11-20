import crypto from 'node:crypto';
import dns from 'node:dns';
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
import { DbClient, DbExecutor, writeAuditLog } from './db';
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

export async function getSettingsMap(db: DbExecutor): Promise<Record<string, string>> {
  const rows = await db.all<{ key: string; value: string }>('SELECT key, value FROM platform_settings');
  const map: Record<string, string> = {};
  for (const r of rows) map[r.key] = r.value;
  return map;
}

export async function updateSetting(
  db: DbExecutor,
  key: string,
  value: string,
  actorId: string,
  ipAddress = '127.0.0.1'
): Promise<void> {
  const now = new Date().toISOString();
  await db.run(
    `INSERT INTO platform_settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    key,
    value,
    now
  );
  await writeAuditLog(db, {
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
    throw new AppError(
      422,
      'INVALID_WEBHOOK_URL',
      'Webhook URL must be a public HTTPS URL (localhost, private/reserved IPs, and .example/.local domains are blocked).'
    );
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

export async function authenticateApiKey(
  db: DbExecutor,
  rawBearerToken: string,
  hashFn: (s: string) => string
): Promise<AuthenticatedAppContext> {
  const secretHash = hashFn(rawBearerToken);
  const row = await db.get<{
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
  }>(
    `SELECT k.id as key_id, k.key_prefix, k.scopes_json, k.status as key_status, k.expires_at,
            a.id as app_id, a.name as app_name, a.environment, a.status as app_status,
            a.allowed_purposes_json, a.daily_limit, a.allowlist_only
     FROM api_keys k
     JOIN applications a ON a.id = k.application_id
     WHERE k.secret_hash = ?`,
    secretHash
  );

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

  await db.run('UPDATE api_keys SET last_used_at = ? WHERE id = ?', new Date().toISOString(), row.key_id);

  return {
    applicationId: row.app_id,
    applicationName: row.app_name,
    environment: row.environment,
    status: row.app_status,
    allowedPurposes: JSON.parse(row.allowed_purposes_json),
    dailyLimit: Number(row.daily_limit),
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

async function checkQuotasAndDestination(
  db: DbExecutor,
  app: { id: string; dailyLimit: number; allowlistOnly: boolean; environment: 'test' | 'live'; allowedPurposes: string[] },
  toE164: string,
  purpose: string,
  ipAddress: string
): Promise<void> {
  const settings = await getSettingsMap(db);
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
    const allowed = await db.get<{ id: string }>(
      'SELECT id FROM destination_allowlist WHERE application_id = ? AND e164_hash = ?',
      app.id,
      destHash
    );
    if (!allowed) {
      throw new AppError(
        403,
        'DESTINATION_NOT_ALLOWLISTED',
        'Destination number is not in the approved allowlist for this live application.'
      );
    }
  }

  const dayStart = new Date();
  dayStart.setUTCHours(0, 0, 0, 0);
  const dayStartIso = dayStart.toISOString();

  const appToday = await db.get<{ cnt: number | string }>(
    'SELECT COUNT(*) as cnt FROM messages WHERE application_id = ? AND created_at >= ? AND is_test = 0',
    app.id,
    dayStartIso
  );

  if (app.environment === 'live' && Number(appToday?.cnt ?? 0) >= app.dailyLimit) {
    throw new AppError(429, 'APP_DAILY_CAP_REACHED', 'Application daily message cap reached.');
  }

  const globalCap = Number(settings.global_daily_sim_cap ?? 300);
  const globalToday = await db.get<{ cnt: number | string }>(
    'SELECT COUNT(*) as cnt FROM messages WHERE created_at >= ? AND is_test = 0',
    dayStartIso
  );
  if (app.environment === 'live' && Number(globalToday?.cnt ?? 0) >= globalCap) {
    throw new AppError(429, 'GLOBAL_SIM_CAP_REACHED', 'Global daily SIM safety cap reached.');
  }

  const hourAgo = new Date(Date.now() - 3600_000).toISOString();
  const perNumberHourlyLimit = Number(settings.rate_limit_per_number_hourly ?? 6);
  const numberHourCount = await db.get<{ cnt: number | string }>(
    'SELECT COUNT(*) as cnt FROM messages WHERE destination_hash = ? AND created_at >= ?',
    destHash,
    hourAgo
  );
  if (Number(numberHourCount?.cnt ?? 0) >= perNumberHourlyLimit) {
    throw new AppError(429, 'DESTINATION_THROTTLED', 'Hourly per-number message limit exceeded.');
  }
}

export async function enqueueWebhookEvent(
  db: DbExecutor,
  applicationId: string,
  eventType: string,
  payload: Record<string, unknown>
): Promise<void> {
  const endpoints = await db.all<{ id: string; event_types_json: string }>(
    'SELECT id, event_types_json FROM webhook_endpoints WHERE application_id = ? AND enabled = 1',
    applicationId
  );

  const now = new Date().toISOString();
  const eventId = `evt_${crypto.randomBytes(8).toString('hex')}`;
  const redactedPayload = {
    event_id: eventId,
    event_type: eventType,
    occurred_at: now,
    data: payload,
  };

  for (const ep of endpoints) {
    const subscribed: string[] = JSON.parse(ep.event_types_json);
    if (subscribed.includes(eventType)) {
      await db.run(
        `INSERT INTO webhook_deliveries (id, endpoint_id, event_id, event_type, payload_redacted_json, status, attempt_count, next_attempt_at, last_http_status, created_at)
         VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, NULL, ?)`,
        crypto.randomUUID(),
        ep.id,
        eventId,
        eventType,
        JSON.stringify(redactedPayload),
        now,
        now
      );
    }
  }
}

export async function createSmsRequest(
  db: DbClient,
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
): Promise<{
  message_id: string;
  status: MessageStatus;
  created_at: string;
  is_test: boolean;
  deduplicated: boolean;
}> {
  const normalizedTo = normalizeE164(input.to);
  if (!isValidE164(normalizedTo)) {
    throw new AppError(422, 'INVALID_PHONE', 'Destination phone must be valid E.164 format (e.g. +919876543210).');
  }

  const appRow = await db.get<{
    id: string;
    name: string;
    environment: 'test' | 'live';
    status: string;
    allowed_purposes_json: string;
    daily_limit: number;
    allowlist_only: number;
  }>(
    'SELECT id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only FROM applications WHERE id = ?',
    input.applicationId
  );

  if (!appRow) {
    throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Application not found.');
  }
  if (appRow.status !== 'active') {
    throw new AppError(403, 'APPLICATION_INACTIVE', 'Application is paused or disabled.');
  }

  // Idempotency check BEFORE creating a duplicate job
  if (input.idempotencyKey) {
    const existing = await db.get<{ id: string; status: MessageStatus; created_at: string; is_test: number }>(
      'SELECT id, status, created_at, is_test FROM messages WHERE application_id = ? AND idempotency_key = ?',
      appRow.id,
      input.idempotencyKey
    );
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

  await checkQuotasAndDestination(
    db,
    {
      id: appRow.id,
      dailyLimit: Number(appRow.daily_limit),
      allowlistOnly: Boolean(appRow.allowlist_only),
      environment: appRow.environment,
      allowedPurposes: JSON.parse(appRow.allowed_purposes_json),
    },
    normalizedTo,
    input.purpose,
    input.ipAddress ?? '127.0.0.1'
  );

  const template = await db.get<{ id: string; code: string; purpose: string; body: string; status: string }>(
    "SELECT id, code, purpose, body, status FROM message_templates WHERE code = ? AND status = 'approved'",
    input.templateCode
  );
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

  await db.run(
    `INSERT INTO messages (id, application_id, device_id, destination_masked, destination_hash, destination_encrypted, template_id, body_encrypted, purpose, status, is_test, idempotency_key, ttl_expires_at, created_at, queued_at)
     VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)`,
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

  await db.run(
    `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
     VALUES (?, ?, NULL, ?, 'message.requested', 1, ?)`,
    crypto.randomUUID(),
    appRow.id,
    messageId,
    createdAt
  );

  await writeAuditLog(db, {
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

  await enqueueWebhookEvent(db, appRow.id, 'message.status', {
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

export async function createOtpChallenge(
  db: DbClient,
  input: {
    applicationId: string;
    to: string;
    purpose: string;
    ttlSeconds?: number;
    actorId: string;
    ipAddress?: string;
    bypassCooldown?: boolean;
  }
): Promise<{
  challenge_id: string;
  message_id: string;
  status: 'queued';
  expires_at: string;
  is_test: boolean;
}> {
  const normalizedTo = normalizeE164(input.to);
  if (!isValidE164(normalizedTo)) {
    throw new AppError(422, 'INVALID_PHONE', 'Destination phone must be valid E.164 format.');
  }

  const settings = await getSettingsMap(db);
  const appRow = await db.get<{
    id: string;
    name: string;
    environment: 'test' | 'live';
    status: string;
    allowed_purposes_json: string;
    daily_limit: number;
    allowlist_only: number;
  }>(
    'SELECT id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only FROM applications WHERE id = ?',
    input.applicationId
  );

  if (!appRow) throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Application not found.');
  if (appRow.status !== 'active') throw new AppError(403, 'APPLICATION_INACTIVE', 'Application is paused or disabled.');

  const destHash = hashDestination(normalizedTo);
  const cooldownSeconds = Number(settings.otp_resend_cooldown_seconds ?? 45);
  if (!input.bypassCooldown && cooldownSeconds > 0) {
    const cooldownCutoff = new Date(Date.now() - cooldownSeconds * 1000).toISOString();
    const recent = await db.get<{ id: string }>(
      `SELECT id FROM otp_challenges
       WHERE application_id = ? AND destination_hash = ? AND created_at > ? AND status IN ('queued', 'sent')`,
      appRow.id,
      destHash,
      cooldownCutoff
    );
    if (recent) {
      throw new AppError(
        429,
        'RESEND_COOLDOWN',
        `Please wait ${cooldownSeconds} seconds before requesting another verification code.`
      );
    }
  }

  await checkQuotasAndDestination(
    db,
    {
      id: appRow.id,
      dailyLimit: Number(appRow.daily_limit),
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
  const template = await db.get<{ code: string; body: string }>(
    "SELECT code, body FROM message_templates WHERE code = ? AND status = 'approved'",
    templateCode
  );

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
  await db.transaction(async (tx) => {
    await tx.run(
      `INSERT INTO messages (id, application_id, device_id, destination_masked, destination_hash, destination_encrypted, template_id, body_encrypted, purpose, status, is_test, idempotency_key, ttl_expires_at, created_at, queued_at)
       VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 'queued', ?, NULL, ?, ?, ?)`,
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

    await tx.run(
      `INSERT INTO otp_challenges (id, application_id, destination_masked, destination_hash, destination_encrypted, code_hash, purpose, status, is_test, expires_at, attempts, max_attempts, consumed_at, message_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, 0, ?, NULL, ?, ?)`,
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

    await tx.run(
      `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
       VALUES (?, ?, NULL, ?, 'otp.requested', 1, ?)`,
      crypto.randomUUID(),
      appRow.id,
      messageId,
      createdAt
    );
  });

  await writeAuditLog(db, {
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

export async function verifyOtpChallenge(
  db: DbClient,
  input: {
    applicationId?: string;
    challengeId: string;
    code: string;
    ipAddress?: string;
  }
): Promise<{ verified: true; verified_at: string; challenge_id: string }> {
  const cleanCode = input.code.trim();
  if (!/^\d{4,10}$/.test(cleanCode)) {
    throw new AppError(422, 'OTP_INVALID', 'Invalid or expired verification code.');
  }

  const nowIso = new Date().toISOString();

  const txOutcome = await db.transaction(async (tx) => {
    const selectSql =
      tx.dialect === 'postgres'
        ? `SELECT id, application_id, code_hash, status, expires_at, attempts, max_attempts
           FROM otp_challenges WHERE id = ? FOR UPDATE`
        : `SELECT id, application_id, code_hash, status, expires_at, attempts, max_attempts
           FROM otp_challenges WHERE id = ?`;

    const row = await tx.get<{
      id: string;
      application_id: string;
      code_hash: string;
      status: string;
      expires_at: string;
      attempts: number;
      max_attempts: number;
    }>(selectSql, input.challengeId);

    let nextAttempts = 0;
    let locked = false;
    let invalidReason: 'missing' | 'expired' | 'terminal' | 'mismatch' | null = null;

    if (!row || (input.applicationId && row.application_id !== input.applicationId)) {
      invalidReason = 'missing';
    } else if (new Date(row.expires_at).getTime() <= Date.now()) {
      if (row.status === 'queued' || row.status === 'sent') {
        await tx.run("UPDATE otp_challenges SET status = 'expired' WHERE id = ? AND status IN ('queued', 'sent')", row.id);
      }
      invalidReason = 'expired';
    } else if (row.status !== 'queued' && row.status !== 'sent') {
      invalidReason = 'terminal';
    } else {
      nextAttempts = Number(row.attempts) + 1;
      const isMatch = verifyOtpHashConstantTime(row.id, cleanCode, row.code_hash);
      if (!isMatch) {
        locked = nextAttempts >= Number(row.max_attempts);
        await tx.run(
          "UPDATE otp_challenges SET attempts = ?, status = ? WHERE id = ? AND status IN ('queued', 'sent')",
          nextAttempts,
          locked ? 'locked' : row.status,
          row.id
        );
        invalidReason = 'mismatch';
      } else {
        const updateRes = await tx.run(
          "UPDATE otp_challenges SET status = 'verified', attempts = ?, consumed_at = ? WHERE id = ? AND status IN ('queued', 'sent')",
          nextAttempts,
          nowIso,
          row.id
        );
        if (updateRes.changes === 0) {
          invalidReason = 'terminal';
        }
      }
    }

    return { row, nextAttempts, locked, invalidReason };
  });

  if (
    txOutcome.invalidReason === 'missing' ||
    txOutcome.invalidReason === 'expired' ||
    txOutcome.invalidReason === 'terminal'
  ) {
    throw new AppError(422, 'OTP_INVALID', 'Invalid or expired verification code.');
  }

  if (txOutcome.invalidReason === 'mismatch' && txOutcome.row) {
    await writeAuditLog(db, {
      actorType: 'application',
      actorId: txOutcome.row.application_id,
      action: txOutcome.locked ? 'otp.locked_max_attempts' : 'otp.verify_failed',
      targetType: 'otp_challenge',
      targetId: txOutcome.row.id,
      metadata: { attempts: txOutcome.nextAttempts, max_attempts: Number(txOutcome.row.max_attempts) },
      ipAddress: input.ipAddress,
    });
    if (txOutcome.locked) {
      await enqueueWebhookEvent(db, txOutcome.row.application_id, 'otp.failed', {
        challenge_id: txOutcome.row.id,
        reason: 'MAX_ATTEMPTS_EXCEEDED',
      });
    }
    throw new AppError(422, 'OTP_INVALID', 'Invalid or expired verification code.');
  }

  const verifiedRow = txOutcome.row!;
  await writeAuditLog(db, {
    actorType: 'application',
    actorId: verifiedRow.application_id,
    action: 'otp.verified',
    targetType: 'otp_challenge',
    targetId: verifiedRow.id,
    metadata: { attempts: txOutcome.nextAttempts },
    ipAddress: input.ipAddress,
  });

  await enqueueWebhookEvent(db, verifiedRow.application_id, 'otp.verified', {
    challenge_id: verifiedRow.id,
    verified_at: nowIso,
  });

  return { verified: true, verified_at: nowIso, challenge_id: verifiedRow.id };
}

export async function authenticateGatewayDevice(
  db: DbExecutor,
  rawToken: string
): Promise<{
  id: string;
  name: string;
  status: string;
  permissionSendSms: boolean;
  simReady: boolean;
}> {
  const tokenHash = hashToken(rawToken);
  const dev = await db.get<{
    id: string;
    name: string;
    status: string;
    permission_send_sms: number;
    sim_ready: number;
    revoked_at: string | null;
  }>(
    `SELECT id, name, status, permission_send_sms, sim_ready, revoked_at
     FROM gateway_devices WHERE device_token_hash = ?`,
    tokenHash
  );

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

export async function leaseNextGatewayJob(
  db: DbClient,
  deviceId: string
): Promise<{
  job_id: string;
  lease_token: string;
  to: string;
  body: string;
  sim_slot: number;
  is_test: boolean;
  expires_at: string;
} | null> {
  await maybeRunOpportunisticSweep(db);

  const settings = await getSettingsMap(db);
  if (settings.global_paused === 'true') {
    return null;
  }

  const dev = await db.get<{ id: string; status: string; permission_send_sms: number; sim_ready: number }>(
    'SELECT id, status, permission_send_sms, sim_ready FROM gateway_devices WHERE id = ?',
    deviceId
  );

  if (!dev || dev.status !== 'online' || !dev.permission_send_sms || !dev.sim_ready) {
    return null;
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const leaseTimeoutSec = Number(settings.lease_timeout_seconds ?? 30);
  const leaseExpiresAt = new Date(now.getTime() + leaseTimeoutSec * 1000).toISOString();

  return db.transaction(async (tx) => {
    const candidateSql =
      tx.dialect === 'postgres'
        ? `SELECT id, destination_encrypted, body_encrypted, is_test, ttl_expires_at
           FROM messages
           WHERE status = 'queued' AND ttl_expires_at > ?
           ORDER BY created_at ASC
           FOR UPDATE SKIP LOCKED
           LIMIT 1`
        : `SELECT id, destination_encrypted, body_encrypted, is_test, ttl_expires_at
           FROM messages
           WHERE status = 'queued' AND ttl_expires_at > ?
           ORDER BY created_at ASC
           LIMIT 1`;

    const candidate = await tx.get<{
      id: string;
      destination_encrypted: string;
      body_encrypted: string;
      is_test: number;
      ttl_expires_at: string;
    }>(candidateSql, nowIso);

    if (!candidate) {
      return null;
    }

    const existingAttempts = await tx.get<{ cnt: number | string }>(
      'SELECT COUNT(*) as cnt FROM gateway_job_leases WHERE message_id = ?',
      candidate.id
    );

    const leaseToken = `lease_${crypto.randomBytes(16).toString('hex')}`;
    await tx.run(
      `INSERT INTO gateway_job_leases (id, message_id, device_id, lease_token_hash, leased_at, lease_expires_at, attempt_count)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      crypto.randomUUID(),
      candidate.id,
      deviceId,
      hashToken(leaseToken),
      nowIso,
      leaseExpiresAt,
      Number(existingAttempts?.cnt ?? 0) + 1
    );

    await tx.run("UPDATE messages SET status = 'leased', device_id = ?, leased_at = ? WHERE id = ?", deviceId, nowIso, candidate.id);

    const sim = await tx.get<{ slot_index: number }>(
      'SELECT slot_index FROM sims WHERE device_id = ? ORDER BY slot_index ASC LIMIT 1',
      deviceId
    );

    return {
      job_id: candidate.id,
      lease_token: leaseToken,
      to: decryptField(candidate.destination_encrypted),
      body: decryptField(candidate.body_encrypted),
      sim_slot: sim?.slot_index ?? 0,
      is_test: Boolean(candidate.is_test),
      expires_at: candidate.ttl_expires_at,
    };
  });
}

export async function markJobAcceptedByDevice(
  db: DbExecutor,
  deviceId: string,
  jobId: string
): Promise<{ status: MessageStatus }> {
  const msg = await db.get<{
    id: string;
    application_id: string;
    device_id: string | null;
    status: MessageStatus;
    destination_masked: string;
  }>('SELECT id, application_id, device_id, status, destination_masked FROM messages WHERE id = ?', jobId);

  if (!msg || msg.device_id !== deviceId) {
    throw new AppError(404, 'JOB_NOT_FOUND', 'Leased job not found for this device.');
  }
  if (!isValidMessageTransition(msg.status, 'accepted_by_device')) {
    throw new AppError(409, 'INVALID_TRANSITION', `Cannot transition from ${msg.status} to accepted_by_device.`);
  }

  const nowIso = new Date().toISOString();
  await db.run("UPDATE messages SET status = 'accepted_by_device', accepted_at = ? WHERE id = ?", nowIso, jobId);
  await enqueueWebhookEvent(db, msg.application_id, 'message.status', {
    message_id: msg.id,
    status: 'accepted_by_device',
    destination_masked: msg.destination_masked,
  });
  return { status: 'accepted_by_device' };
}

export async function reportJobResult(
  db: DbClient,
  deviceId: string,
  jobId: string,
  outcome: 'sent_to_network' | 'failed' | 'delivery_unknown',
  errorCode?: string
): Promise<{ status: MessageStatus }> {
  const msg = await db.get<{
    id: string;
    application_id: string;
    device_id: string | null;
    status: MessageStatus;
    is_test: number;
    destination_masked: string;
  }>('SELECT id, application_id, device_id, status, is_test, destination_masked FROM messages WHERE id = ?', jobId);

  if (!msg || msg.device_id !== deviceId) {
    throw new AppError(404, 'JOB_NOT_FOUND', 'Job not found for this device.');
  }
  if (!isValidMessageTransition(msg.status, outcome)) {
    throw new AppError(409, 'INVALID_TRANSITION', `Cannot transition from ${msg.status} to ${outcome}.`);
  }

  const cleanErrorCode = errorCode ? String(errorCode).replace(/[^A-Z0-9_:-]/gi, '').slice(0, 48) : undefined;
  const nowIso = new Date().toISOString();

  await db.transaction(async (tx) => {
    if (outcome === 'sent_to_network') {
      await tx.run("UPDATE messages SET status = 'sent_to_network', sent_at = ?, error_code = NULL WHERE id = ?", nowIso, jobId);
      await tx.run("UPDATE otp_challenges SET status = 'sent' WHERE message_id = ? AND status = 'queued'", jobId);
      await tx.run(
        `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
         VALUES (?, ?, ?, ?, 'message.sent_to_network', 1, ?)`,
        crypto.randomUUID(),
        msg.application_id,
        deviceId,
        jobId,
        nowIso
      );

      if (!msg.is_test) {
        await tx.run(
          `UPDATE sims
           SET estimated_sms_sent = estimated_sms_sent + 1,
               estimated_sms_remaining = CASE WHEN estimated_sms_remaining > 0 THEN estimated_sms_remaining - 1 ELSE 0 END,
               updated_at = ?
           WHERE device_id = ?`,
          nowIso,
          deviceId
        );
      }
    } else if (outcome === 'delivery_unknown') {
      await tx.run(
        "UPDATE messages SET status = 'delivery_unknown', sent_at = COALESCE(sent_at, ?), error_code = ? WHERE id = ?",
        nowIso,
        cleanErrorCode || 'NO_CARRIER_RECEIPT',
        jobId
      );
    } else {
      await tx.run(
        "UPDATE messages SET status = 'failed', failed_at = ?, error_code = ? WHERE id = ?",
        nowIso,
        cleanErrorCode || 'SEND_FAILED',
        jobId
      );
      await tx.run(
        "UPDATE otp_challenges SET status = 'failed' WHERE message_id = ? AND status IN ('queued', 'sent')",
        jobId
      );
      await tx.run(
        `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
         VALUES (?, ?, ?, ?, 'message.failed', 1, ?)`,
        crypto.randomUUID(),
        msg.application_id,
        deviceId,
        jobId,
        nowIso
      );
    }

    await tx.run('DELETE FROM gateway_job_leases WHERE message_id = ?', jobId);
  });

  await enqueueWebhookEvent(db, msg.application_id, 'message.status', {
    message_id: msg.id,
    status: outcome,
    error_code: errorCode ?? null,
    destination_masked: msg.destination_masked,
  });

  if (outcome === 'sent_to_network') {
    const otp = await db.get<{ id: string }>('SELECT id FROM otp_challenges WHERE message_id = ?', jobId);
    if (otp) {
      await enqueueWebhookEvent(db, msg.application_id, 'otp.sent', { challenge_id: otp.id, message_id: jobId });
    }
  } else if (outcome === 'failed') {
    const otp = await db.get<{ id: string }>('SELECT id FROM otp_challenges WHERE message_id = ?', jobId);
    if (otp) {
      await enqueueWebhookEvent(db, msg.application_id, 'otp.failed', {
        challenge_id: otp.id,
        message_id: jobId,
        error_code: errorCode ?? 'SEND_FAILED',
      });
    }
  }

  return { status: outcome };
}

export async function reportDeliveryReceipt(
  db: DbExecutor,
  deviceId: string,
  jobId: string
): Promise<{ status: MessageStatus }> {
  const msg = await db.get<{
    id: string;
    application_id: string;
    device_id: string | null;
    status: MessageStatus;
    destination_masked: string;
  }>('SELECT id, application_id, device_id, status, destination_masked FROM messages WHERE id = ?', jobId);

  if (!msg || msg.device_id !== deviceId) {
    throw new AppError(404, 'JOB_NOT_FOUND', 'Job not found for this device.');
  }
  if (!isValidMessageTransition(msg.status, 'delivered')) {
    throw new AppError(409, 'INVALID_TRANSITION', `Cannot transition from ${msg.status} to delivered.`);
  }

  const nowIso = new Date().toISOString();
  await db.run("UPDATE messages SET status = 'delivered', delivered_at = ?, error_code = NULL WHERE id = ?", nowIso, jobId);
  await db.run(
    `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
     VALUES (?, ?, ?, ?, 'message.delivered', 1, ?)`,
    crypto.randomUUID(),
    msg.application_id,
    deviceId,
    jobId,
    nowIso
  );

  await enqueueWebhookEvent(db, msg.application_id, 'message.status', {
    message_id: msg.id,
    status: 'delivered',
    delivered_at: nowIso,
    destination_masked: msg.destination_masked,
  });

  return { status: 'delivered' };
}

export async function runSweeperTick(db: DbExecutor): Promise<{
  expiredMessages: number;
  requeuedLeases: number;
  failedMaxRetries: number;
  expiredOtps: number;
  processedWebhooks: number;
}> {
  const now = new Date();
  const nowIso = now.toISOString();
  const settings = await getSettingsMap(db);
  const maxRetries = Number(settings.max_send_retries ?? 3);

  // 1. Expire TTL-exceeded queued/leased messages
  const expiredRows = await db.all<{ id: string; application_id: string; destination_masked: string }>(
    `SELECT id, application_id, destination_masked FROM messages
     WHERE status IN ('created', 'queued', 'leased', 'accepted_by_device') AND ttl_expires_at <= ?`,
    nowIso
  );

  for (const row of expiredRows) {
    await db.run("UPDATE messages SET status = 'expired', failed_at = ?, error_code = 'TTL_EXPIRED' WHERE id = ?", nowIso, row.id);
    await db.run('DELETE FROM gateway_job_leases WHERE message_id = ?', row.id);
    await enqueueWebhookEvent(db, row.application_id, 'message.status', {
      message_id: row.id,
      status: 'expired',
      error_code: 'TTL_EXPIRED',
      destination_masked: row.destination_masked,
    });
  }

  // 2. Expire OTP challenges past expires_at
  const expOtps = await db.run(
    "UPDATE otp_challenges SET status = 'expired' WHERE status IN ('queued', 'sent') AND expires_at <= ?",
    nowIso
  );

  // 3. Requeue or dead-letter expired leases
  const staleLeases = await db.all<{
    lease_id: string;
    message_id: string;
    attempt_count: number;
    application_id: string;
    destination_masked: string;
  }>(
    `SELECT l.id as lease_id, l.message_id, l.attempt_count, m.application_id, m.destination_masked
     FROM gateway_job_leases l
     JOIN messages m ON m.id = l.message_id
     WHERE l.lease_expires_at <= ? AND m.status IN ('leased', 'accepted_by_device')`,
    nowIso
  );

  let requeuedLeases = 0;
  let failedMaxRetries = 0;
  for (const lease of staleLeases) {
    await db.run('DELETE FROM gateway_job_leases WHERE id = ?', lease.lease_id);
    if (Number(lease.attempt_count) >= maxRetries) {
      await db.run(
        "UPDATE messages SET status = 'failed', failed_at = ?, error_code = 'LEASE_EXPIRED_MAX_RETRIES' WHERE id = ?",
        nowIso,
        lease.message_id
      );
      failedMaxRetries++;
      await enqueueWebhookEvent(db, lease.application_id, 'message.status', {
        message_id: lease.message_id,
        status: 'failed',
        error_code: 'LEASE_EXPIRED_MAX_RETRIES',
        destination_masked: lease.destination_masked,
      });
    } else {
      await db.run("UPDATE messages SET status = 'queued', device_id = NULL WHERE id = ?", lease.message_id);
      requeuedLeases++;
    }
  }

  // 4. Mark gateway devices offline if heartbeat stale (> 45s)
  const staleHeartbeatCutoff = new Date(now.getTime() - 45_000).toISOString();
  await db.run(
    `UPDATE gateway_devices
     SET status = 'offline'
     WHERE status = 'online' AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at < ?`,
    staleHeartbeatCutoff
  );

  // 5. Process pending webhook deliveries with SSRF DNS check and redirect blocking
  const pendingHooks = await db.all<{
    id: string;
    event_id: string;
    payload_redacted_json: string;
    attempt_count: number;
    url: string;
    secret_encrypted: string;
  }>(
    `SELECT d.id, d.event_id, d.payload_redacted_json, d.attempt_count, e.url, e.secret_encrypted
     FROM webhook_deliveries d
     JOIN webhook_endpoints e ON e.id = d.endpoint_id
     WHERE d.status = 'pending' AND d.next_attempt_at <= ?
     LIMIT 10`,
    nowIso
  );

  let processedWebhooks = 0;
  const webhookPromises: Array<Promise<void>> = [];

  for (const hook of pendingHooks) {
    processedWebhooks++;
    const ts = String(Math.floor(Date.now() / 1000));
    const secret = decryptField(hook.secret_encrypted);
    const sig = signWebhookPayload(secret, ts, hook.event_id, hook.payload_redacted_json);
    const nextAttempt = Number(hook.attempt_count) + 1;

    // Optimistically bump next_attempt_at so the sweeper doesn't double-fire while DNS/fetch is in flight
    await db.run(
      'UPDATE webhook_deliveries SET next_attempt_at = ? WHERE id = ?',
      new Date(Date.now() + 10_000).toISOString(),
      hook.id
    );

    const deliveryTask = assertPublicWebhookHost(hook.url)
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
      .then(async (res) => {
        if (res.ok) {
          await db.run(
            "UPDATE webhook_deliveries SET status = 'delivered', attempt_count = ?, last_http_status = ? WHERE id = ?",
            nextAttempt,
            res.status,
            hook.id
          );
        } else {
          const backoffMs = Math.min(60_000, Math.pow(2, nextAttempt) * 1000);
          await db.run(
            'UPDATE webhook_deliveries SET status = ?, attempt_count = ?, next_attempt_at = ?, last_http_status = ? WHERE id = ?',
            nextAttempt >= 4 ? 'failed' : 'pending',
            nextAttempt,
            new Date(Date.now() + backoffMs).toISOString(),
            res.status,
            hook.id
          );
        }
      })
      .catch(async () => {
        const backoffMs = Math.min(60_000, Math.pow(2, nextAttempt) * 1000);
        await db.run(
          'UPDATE webhook_deliveries SET status = ?, attempt_count = ?, next_attempt_at = ?, last_http_status = 0 WHERE id = ?',
          nextAttempt >= 4 ? 'failed' : 'pending',
          nextAttempt,
          new Date(Date.now() + backoffMs).toISOString(),
          hook.id
        );
      });

    webhookPromises.push(deliveryTask);
  }

  if (webhookPromises.length > 0) {
    await Promise.allSettled(webhookPromises);
  }

  return {
    expiredMessages: expiredRows.length,
    requeuedLeases,
    failedMaxRetries,
    expiredOtps: Number(expOtps.changes ?? 0),
    processedWebhooks,
  };
}

const lastSweepAtByDb = new WeakMap<DbExecutor, number>();
const inFlightSweepByDb = new WeakMap<DbExecutor, Promise<void>>();

export async function maybeRunOpportunisticSweep(db: DbExecutor, minIntervalMs = 5000): Promise<void> {
  const now = Date.now();
  const lastAt = lastSweepAtByDb.get(db) ?? 0;
  if (now - lastAt < minIntervalMs) return;

  const active = inFlightSweepByDb.get(db);
  if (active) {
    await active;
    return;
  }

  lastSweepAtByDb.set(db, now);
  const promise = runSweeperTick(db)
    .then(() => undefined)
    .catch(() => undefined)
    .finally(() => {
      inFlightSweepByDb.delete(db);
    });
  inFlightSweepByDb.set(db, promise);
  await promise;
}
