import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Router, Request, Response, NextFunction } from 'express';
import { DatabaseSync } from 'node:sqlite';
import {
  decryptField,
  encryptField,
  generateApiKey,
  generateEnrollmentToken,
  generateTotpSecret,
  hashDestination,
  hashPassword,
  hashToken,
  verifyPassword,
  verifyTotpCode,
} from '../crypto';
import { writeAuditLog } from '../db';
import {
  AppError,
  assertPublicWebhookHost,
  checkLoginRateLimit,
  clearLoginFailures,
  createOtpChallenge,
  createSmsRequest,
  getSettingsMap,
  recordLoginFailure,
  runSweeperTick,
  updateSetting,
  verifyOtpChallenge,
} from '../services';
import {
  ALL_API_SCOPES,
  calculateSimRemainingEstimate,
  isValidE164,
  maskE164,
  normalizeE164,
  VALID_MESSAGE_PURPOSES,
} from '../../src/shared/smsRules';

function sendAdminError(res: Response, err: unknown): void {
  if (err instanceof AppError) {
    res.status(err.status).json({ error: { code: err.code, message: err.message } });
    return;
  }
  const message = err instanceof Error ? err.message : 'Unexpected server error';
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message } });
}

function isHttpsRequest(req: Request): boolean {
  const xfProto = req.headers['x-forwarded-proto'];
  return req.secure || (typeof xfProto === 'string' && xfProto.split(',')[0].trim() === 'https');
}

export function createAdminRouter(db: DatabaseSync): Router {
  const router = Router();

  // Strict owner session authentication & CSRF validation
  router.use((req: Request, res: Response, next: NextFunction) => {
    const cookieHeader = req.headers.cookie ?? '';
    const match = /simvault_session=([^;]+)/.exec(cookieHeader);
    let user: { id: string; email: string; role: string; mfa_enabled: number } | undefined;
    let sessionCsrf: string | null = null;
    let currentTokenHash: string | null = null;

    if (match) {
      const tokHash = hashToken(decodeURIComponent(match[1]));
      const sess = db
        .prepare(
          `SELECT s.csrf_token, s.expires_at, s.mfa_verified, u.id, u.email, u.role, u.mfa_enabled
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ?`
        )
        .get(tokHash) as
        | {
            csrf_token: string;
            expires_at: string;
            mfa_verified: number;
            id: string;
            email: string;
            role: string;
            mfa_enabled: number;
          }
        | undefined;
      if (sess && new Date(sess.expires_at).getTime() > Date.now() && sess.mfa_verified) {
        user = { id: sess.id, email: sess.email, role: sess.role, mfa_enabled: sess.mfa_enabled };
        sessionCsrf = sess.csrf_token;
        currentTokenHash = tokHash;
      }
    }

    (req as Request & { ownerUser?: typeof user; csrfToken?: string | null; currentTokenHash?: string | null }).ownerUser = user;
    (req as Request & { csrfToken?: string | null }).csrfToken = sessionCsrf;
    (req as Request & { currentTokenHash?: string | null }).currentTokenHash = currentTokenHash;

    const isAuthRoute = req.path.startsWith('/auth/');
    if (!user && !isAuthRoute) {
      res.status(401).json({ error: { code: 'AUTH_REQUIRED', message: 'Owner authentication required.' } });
      return;
    }
    if (!isAuthRoute && ['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method)) {
      const providedCsrf = req.headers['x-csrf-token'];
      if (!sessionCsrf || typeof providedCsrf !== 'string' || providedCsrf !== sessionCsrf) {
        res.status(403).json({ error: { code: 'CSRF_INVALID', message: 'Invalid or missing CSRF token.' } });
        return;
      }
    }
    next();
  });

  const getOwner = (req: Request) =>
    (req as Request & { ownerUser?: { id: string; email: string; role: string; mfa_enabled: number } }).ownerUser!;

  // --- Auth & MFA ---
  router.get('/auth/session', (req: Request, res: Response) => {
    const owner = (req as Request & { ownerUser?: { id: string; email: string; role: string; mfa_enabled: number } }).ownerUser;
    const csrf = (req as Request & { csrfToken?: string | null }).csrfToken;
    if (!owner) {
      res.json({ authenticated: false, mfa_required: false });
      return;
    }
    res.json({
      authenticated: true,
      user: {
        id: owner.id,
        email: owner.email,
        role: owner.role,
        mfa_enabled: Boolean(owner.mfa_enabled),
      },
      csrf_token: csrf ?? null,
    });
  });

  router.post('/auth/login', (req: Request, res: Response) => {
    try {
      const clientIp = req.ip || '127.0.0.1';
      if (!checkLoginRateLimit(clientIp)) {
        throw new AppError(429, 'LOGIN_RATE_LIMITED', 'Too many failed sign-in attempts. Please wait 5 minutes before trying again.');
      }

      const { email, password, totp_code } = req.body ?? {};
      const cleanEmail = String(email ?? '').trim().toLowerCase();
      const user = db.prepare('SELECT id, email, password_hash, role, mfa_enabled, mfa_secret FROM users WHERE email = ?').get(
        cleanEmail
      ) as
        | {
            id: string;
            email: string;
            password_hash: string;
            role: string;
            mfa_enabled: number;
            mfa_secret: string | null;
          }
        | undefined;

      if (!user || !verifyPassword(String(password ?? ''), user.password_hash)) {
        recordLoginFailure(clientIp);
        writeAuditLog(db, {
          actorType: 'system',
          actorId: 'auth_guard',
          action: 'owner.login_failed',
          targetType: 'user',
          targetId: cleanEmail || 'unknown',
          metadata: { reason: 'invalid_credentials' },
          ipAddress: clientIp,
        });
        throw new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password.');
      }

      if (user.mfa_enabled && user.mfa_secret) {
        if (!totp_code) {
          res.status(200).json({ authenticated: false, mfa_required: true });
          return;
        }
        if (!verifyTotpCode(user.mfa_secret, String(totp_code))) {
          recordLoginFailure(clientIp);
          writeAuditLog(db, {
            actorType: 'owner',
            actorId: user.id,
            action: 'owner.login_failed',
            targetType: 'user',
            targetId: user.id,
            metadata: { reason: 'invalid_totp' },
            ipAddress: clientIp,
          });
          throw new AppError(401, 'INVALID_MFA', 'Invalid authenticator code.');
        }
      }

      clearLoginFailures(clientIp);
      const rawToken = crypto.randomBytes(32).toString('base64url');
      const csrfToken = crypto.randomBytes(24).toString('base64url');
      const nowIso = new Date().toISOString();
      const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();

      db.prepare(
        `INSERT INTO sessions (id, user_id, token_hash, csrf_token, mfa_verified, expires_at, created_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`
      ).run(crypto.randomUUID(), user.id, hashToken(rawToken), csrfToken, expiresAt, nowIso);

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: user.id,
        action: 'owner.login',
        targetType: 'session',
        targetId: user.id,
        metadata: { mfa_used: Boolean(user.mfa_enabled) },
        ipAddress: clientIp,
      });

      const secureFlag = isHttpsRequest(req) ? '; Secure' : '';
      res.setHeader('Set-Cookie', [
        `simvault_session=${encodeURIComponent(rawToken)}; Path=/; HttpOnly; SameSite=Lax${secureFlag}`,
        `simvault_locked=; Path=/; Max-Age=0; SameSite=Lax${secureFlag}`,
      ]);
      res.json({
        authenticated: true,
        user: { id: user.id, email: user.email, role: user.role, mfa_enabled: Boolean(user.mfa_enabled) },
        csrf_token: csrfToken,
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/auth/logout', (req: Request, res: Response) => {
    const cookieHeader = req.headers.cookie ?? '';
    const match = /simvault_session=([^;]+)/.exec(cookieHeader);
    if (match) {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(hashToken(decodeURIComponent(match[1])));
    }
    const secureFlag = isHttpsRequest(req) ? '; Secure' : '';
    res.setHeader('Set-Cookie', [
      `simvault_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secureFlag}`,
      `simvault_locked=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secureFlag}`,
    ]);
    res.json({ ok: true });
  });

  router.post('/security/password', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const currentTokenHash = (req as Request & { currentTokenHash?: string | null }).currentTokenHash;
      const { current_password, new_password } = req.body ?? {};
      const nextPass = String(new_password ?? '');
      if (nextPass.length < 10) {
        throw new AppError(422, 'WEAK_PASSWORD', 'New password must be at least 10 characters long.');
      }

      const userRow = db.prepare('SELECT id, password_hash FROM users WHERE id = ?').get(owner.id) as
        | { id: string; password_hash: string }
        | undefined;
      if (!userRow || !verifyPassword(String(current_password ?? ''), userRow.password_hash)) {
        throw new AppError(401, 'INVALID_CURRENT_PASSWORD', 'Current password is incorrect.');
      }

      const nowIso = new Date().toISOString();
      db.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').run(hashPassword(nextPass), nowIso, owner.id);
      if (currentTokenHash) {
        db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?').run(owner.id, currentTokenHash);
      }

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'owner.password_changed',
        targetType: 'user',
        targetId: owner.id,
        ipAddress: req.ip,
      });

      res.json({ updated: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.get('/security/mfa', (req: Request, res: Response) => {
    const owner = getOwner(req);
    const user = db.prepare('SELECT email, mfa_enabled, mfa_secret FROM users WHERE id = ?').get(owner.id) as {
      email: string;
      mfa_enabled: number;
      mfa_secret: string | null;
    };
    const secret = user.mfa_secret || generateTotpSecret();
    if (!user.mfa_secret) {
      db.prepare('UPDATE users SET mfa_secret = ? WHERE id = ?').run(secret, owner.id);
    }
    const otpauthUri = `otpauth://totp/SimVault:${encodeURIComponent(user.email)}?secret=${secret}&issuer=SimVault`;
    res.json({
      mfa_enabled: Boolean(user.mfa_enabled),
      secret_preview: user.mfa_enabled ? 'Configured' : secret,
      otpauth_uri: user.mfa_enabled ? null : otpauthUri,
    });
  });

  router.post('/security/mfa/enable', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { code } = req.body ?? {};
      const user = db.prepare('SELECT mfa_secret FROM users WHERE id = ?').get(owner.id) as { mfa_secret: string | null };
      if (!user?.mfa_secret || !verifyTotpCode(user.mfa_secret, String(code ?? ''))) {
        throw new AppError(422, 'INVALID_TOTP', 'Verification code did not match.');
      }
      db.prepare('UPDATE users SET mfa_enabled = 1, updated_at = ? WHERE id = ?').run(new Date().toISOString(), owner.id);
      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'owner.mfa_enabled',
        targetType: 'user',
        targetId: owner.id,
        ipAddress: req.ip,
      });
      res.json({ mfa_enabled: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/security/mfa/disable', (req: Request, res: Response) => {
    const owner = getOwner(req);
    db.prepare('UPDATE users SET mfa_enabled = 0, updated_at = ? WHERE id = ?').run(new Date().toISOString(), owner.id);
    writeAuditLog(db, {
      actorType: 'owner',
      actorId: owner.id,
      action: 'owner.mfa_disabled',
      targetType: 'user',
      targetId: owner.id,
      ipAddress: req.ip,
    });
    res.json({ mfa_enabled: false });
  });

  // --- Overview & Dashboard Summary ---
  router.get('/overview', (_req: Request, res: Response) => {
    const settings = getSettingsMap(db);
    const dayStart = new Date();
    dayStart.setUTCHours(0, 0, 0, 0);
    const dayIso = dayStart.toISOString();

    const statusCounts = db
      .prepare('SELECT status, COUNT(*) as count FROM messages GROUP BY status')
      .all() as Array<{ status: string; count: number }>;

    const todayRequests = db
      .prepare('SELECT COUNT(*) as count FROM messages WHERE created_at >= ?')
      .get(dayIso) as { count: number };

    const todaySent = db
      .prepare("SELECT COUNT(*) as count FROM messages WHERE sent_at >= ? AND status IN ('sent_to_network', 'delivered', 'delivery_unknown')")
      .get(dayIso) as { count: number };

    const queueDepth = db
      .prepare("SELECT COUNT(*) as count FROM messages WHERE status IN ('created', 'queued', 'leased', 'accepted_by_device')")
      .get() as { count: number };

    const devices = db
      .prepare(
        `SELECT id, name, status, app_version, android_version, permission_send_sms, network_type, battery_pct, sim_ready, last_heartbeat_at
         FROM gateway_devices WHERE status != 'revoked' ORDER BY enrolled_at ASC`
      )
      .all();

    const sims = db.prepare('SELECT * FROM sims ORDER BY updated_at DESC').all();

    const recentMessages = db
      .prepare(
        `SELECT m.id, m.application_id, a.name as application_name, m.device_id, m.destination_masked, m.template_id,
                m.purpose, m.status, m.is_test, m.created_at, m.sent_at, m.delivered_at, m.failed_at, m.error_code
         FROM messages m
         JOIN applications a ON a.id = m.application_id
         ORDER BY m.created_at DESC
         LIMIT 12`
      )
      .all();

    const recentAudit = db
      .prepare('SELECT id, actor_type, actor_id, action, target_type, target_id, metadata_redacted_json, ip_address, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 8')
      .all();

    const activeOtpCount = db
      .prepare("SELECT COUNT(*) as count FROM otp_challenges WHERE status IN ('queued', 'sent')")
      .get() as { count: number };

    res.json({
      global_paused: settings.global_paused === 'true',
      settings,
      kpis: {
        requests_today: todayRequests.count,
        sent_to_network_today: todaySent.count,
        queue_depth: queueDepth.count,
        active_otps: activeOtpCount.count,
        status_breakdown: statusCounts,
      },
      devices,
      sims,
      recent_messages: recentMessages,
      recent_audit: recentAudit,
    });
  });

  // --- Applications ---
  router.get('/applications', (_req: Request, res: Response) => {
    const apps = db
      .prepare(
        `SELECT a.*,
                (SELECT COUNT(*) FROM api_keys k WHERE k.application_id = a.id AND k.status != 'revoked') as active_keys_count,
                (SELECT COUNT(*) FROM messages m WHERE m.application_id = a.id) as total_messages_count
         FROM applications a ORDER BY a.created_at DESC`
      )
      .all();
    res.json({ applications: apps, valid_purposes: VALID_MESSAGE_PURPOSES });
  });

  router.post('/applications', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { name, environment, daily_limit, allowlist_only, allowed_purposes } = req.body ?? {};
      if (!name || String(name).trim().length < 2) {
        throw new AppError(400, 'BAD_REQUEST', 'Application name is required (min 2 chars).');
      }
      const env = environment === 'test' ? 'test' : 'live';
      const parsedLimit = Number(daily_limit ?? 200);
      if (!Number.isFinite(parsedLimit) || parsedLimit < 1 || parsedLimit > 100000) {
        throw new AppError(422, 'INVALID_LIMIT', 'Daily limit must be between 1 and 100000.');
      }
      const id = `app_${crypto.randomBytes(5).toString('hex')}`;
      const nowIso = new Date().toISOString();
      const rawPurposes = Array.isArray(allowed_purposes)
        ? allowed_purposes.filter((p): p is string => typeof p === 'string' && (VALID_MESSAGE_PURPOSES as readonly string[]).includes(p))
        : [];
      const purposes = rawPurposes.length > 0 ? rawPurposes : ['login', 'mfa', 'account_transactional'];

      db.prepare(
        `INSERT INTO applications (id, owner_user_id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only, created_at)
         VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)`
      ).run(
        id,
        owner.id,
        String(name).trim().slice(0, 80),
        env,
        JSON.stringify(purposes),
        Math.trunc(parsedLimit),
        allowlist_only === true ? 1 : 0,
        nowIso
      );

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'application.created',
        targetType: 'application',
        targetId: id,
        metadata: { name: String(name).trim(), environment: env },
        ipAddress: req.ip,
      });

      const created = db.prepare('SELECT * FROM applications WHERE id = ?').get(id);
      res.status(201).json({ application: created });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.patch('/applications/:id', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { status, daily_limit, allowlist_only, allowed_purposes } = req.body ?? {};
      const existing = db.prepare('SELECT id FROM applications WHERE id = ?').get(req.params.id);
      if (!existing) throw new AppError(404, 'NOT_FOUND', 'Application not found.');

      if (status !== undefined && !['active', 'paused', 'disabled'].includes(String(status))) {
        throw new AppError(422, 'INVALID_STATUS', 'Status must be active, paused, or disabled.');
      }
      if (daily_limit !== undefined && (!Number.isFinite(Number(daily_limit)) || Number(daily_limit) < 1 || Number(daily_limit) > 100000)) {
        throw new AppError(422, 'INVALID_LIMIT', 'Daily limit must be between 1 and 100000.');
      }
      const nextPurposes = Array.isArray(allowed_purposes)
        ? allowed_purposes.filter((p): p is string => typeof p === 'string' && (VALID_MESSAGE_PURPOSES as readonly string[]).includes(p))
        : null;

      db.prepare(
        `UPDATE applications
         SET status = COALESCE(?, status),
             daily_limit = COALESCE(?, daily_limit),
             allowlist_only = COALESCE(?, allowlist_only),
             allowed_purposes_json = COALESCE(?, allowed_purposes_json)
         WHERE id = ?`
      ).run(
        status !== undefined ? String(status) : null,
        daily_limit !== undefined ? Math.trunc(Number(daily_limit)) : null,
        typeof allowlist_only === 'boolean' ? (allowlist_only ? 1 : 0) : null,
        nextPurposes && nextPurposes.length > 0 ? JSON.stringify(nextPurposes) : null,
        req.params.id
      );

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'application.updated',
        targetType: 'application',
        targetId: req.params.id,
        metadata: { status, daily_limit, allowlist_only },
        ipAddress: req.ip,
      });

      res.json({ application: db.prepare('SELECT * FROM applications WHERE id = ?').get(req.params.id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- API Keys (secret shown ONLY ONCE at creation/rotation) ---
  router.get('/api-keys', (_req: Request, res: Response) => {
    const keys = db
      .prepare(
        `SELECT k.id, k.application_id, a.name as application_name, a.environment,
                k.name, k.key_prefix, k.scopes_json, k.status, k.last_used_at, k.expires_at, k.revoked_at, k.created_at
         FROM api_keys k
         JOIN applications a ON a.id = k.application_id
         ORDER BY k.created_at DESC`
      )
      .all();
    res.json({ api_keys: keys, available_scopes: ALL_API_SCOPES });
  });

  router.post('/api-keys', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, name, scopes } = req.body ?? {};
      const app = db.prepare('SELECT id, environment FROM applications WHERE id = ?').get(application_id) as
        | { id: string; environment: 'test' | 'live' }
        | undefined;
      if (!app) throw new AppError(404, 'NOT_FOUND', 'Application not found.');
      if (!name || String(name).trim().length < 2) throw new AppError(400, 'BAD_REQUEST', 'Key label is required.');

      const validScopes = Array.isArray(scopes) && scopes.length > 0
        ? scopes.filter((s: string) => ALL_API_SCOPES.includes(s as (typeof ALL_API_SCOPES)[number]))
        : ['sms:send', 'otp:create', 'otp:verify', 'usage:read'];

      const { rawKey, keyPrefix, secretHash } = generateApiKey(app.environment);
      const id = `key_${crypto.randomBytes(5).toString('hex')}`;
      const nowIso = new Date().toISOString();

      db.prepare(
        `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`
      ).run(id, app.id, String(name).trim(), keyPrefix, secretHash, JSON.stringify(validScopes), nowIso);

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'api_key.created',
        targetType: 'api_key',
        targetId: id,
        metadata: { application_id: app.id, key_prefix: keyPrefix, scopes: validScopes },
        ipAddress: req.ip,
      });

      const created = db
        .prepare(
          `SELECT k.id, k.application_id, a.name as application_name, a.environment,
                  k.name, k.key_prefix, k.scopes_json, k.status, k.last_used_at, k.expires_at, k.revoked_at, k.created_at
           FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.id = ?`
        )
        .get(id);

      // Returned ONLY ONCE here — never persisted or returned again
      res.status(201).json({ api_key: created, secret_once: rawKey });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/api-keys/:id/rotate', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const existing = db
        .prepare(
          `SELECT k.id, k.application_id, k.name, k.scopes_json, k.status, a.environment
           FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.id = ?`
        )
        .get(req.params.id) as
        | {
            id: string;
            application_id: string;
            name: string;
            scopes_json: string;
            status: string;
            environment: 'test' | 'live';
          }
        | undefined;

      if (!existing || existing.status === 'revoked') {
        throw new AppError(404, 'NOT_FOUND', 'Active API key not found.');
      }

      const now = new Date();
      const nowIso = now.toISOString();
      const overlapExpires = new Date(now.getTime() + 15 * 60_000).toISOString();
      const { rawKey, keyPrefix, secretHash } = generateApiKey(existing.environment);
      const newId = `key_${crypto.randomBytes(5).toString('hex')}`;

      db.exec('BEGIN IMMEDIATE;');
      try {
        db.prepare("UPDATE api_keys SET status = 'rotating', expires_at = ? WHERE id = ?").run(overlapExpires, existing.id);
        db.prepare(
          `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`
        ).run(newId, existing.application_id, `${existing.name} (Rotated)`, keyPrefix, secretHash, existing.scopes_json, nowIso);
        db.exec('COMMIT;');
      } catch (e) {
        db.exec('ROLLBACK;');
        throw e;
      }

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'api_key.rotated',
        targetType: 'api_key',
        targetId: newId,
        metadata: { previous_key_id: existing.id, key_prefix: keyPrefix, overlap_expires_at: overlapExpires },
        ipAddress: req.ip,
      });

      const created = db
        .prepare(
          `SELECT k.id, k.application_id, a.name as application_name, a.environment,
                  k.name, k.key_prefix, k.scopes_json, k.status, k.last_used_at, k.expires_at, k.revoked_at, k.created_at
           FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.id = ?`
        )
        .get(newId);

      res.status(201).json({ api_key: created, secret_once: rawKey, overlap_expires_at: overlapExpires });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/api-keys/:id/revoke', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const nowIso = new Date().toISOString();
      const result = db
        .prepare("UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE id = ? AND status != 'revoked'")
        .run(nowIso, req.params.id);
      if (result.changes === 0) throw new AppError(404, 'NOT_FOUND', 'API key not found or already revoked.');

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'api_key.revoked',
        targetType: 'api_key',
        targetId: req.params.id,
        ipAddress: req.ip,
      });
      res.json({ revoked: true, revoked_at: nowIso });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Messages & Test Dispatch ---
  router.get('/messages', (req: Request, res: Response) => {
    const status = typeof req.query.status === 'string' && req.query.status !== 'all' ? req.query.status : null;
    const appId = typeof req.query.application_id === 'string' && req.query.application_id !== 'all' ? req.query.application_id : null;
    const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';

    let sql = `
      SELECT m.id, m.application_id, a.name as application_name, a.environment, m.device_id,
             m.destination_masked, m.template_id, m.purpose, m.status, m.is_test, m.idempotency_key,
             m.ttl_expires_at, m.created_at, m.queued_at, m.leased_at, m.accepted_at,
             m.sent_at, m.delivered_at, m.failed_at, m.error_code
      FROM messages m
      JOIN applications a ON a.id = m.application_id
      WHERE 1=1
    `;
    const params: string[] = [];
    if (status) {
      sql += ' AND m.status = ?';
      params.push(status);
    }
    if (appId) {
      sql += ' AND m.application_id = ?';
      params.push(appId);
    }
    if (q) {
      sql += ' AND (m.id LIKE ? OR m.destination_masked LIKE ? OR m.template_id LIKE ?)';
      params.push(`%${q}%`, `%${q}%`, `%${q}%`);
    }
    sql += ' ORDER BY m.created_at DESC LIMIT 100';

    const rows = db.prepare(sql).all(...params);
    res.json({ messages: rows });
  });

  const handleAdminSendSms = (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, to, template_id, variables, purpose, ttl_seconds, idempotency_key } = req.body ?? {};
      if (!application_id || !to || !template_id) {
        throw new AppError(400, 'BAD_REQUEST', 'application_id, to, and template_id are required.');
      }
      const result = createSmsRequest(db, {
        applicationId: String(application_id),
        to: String(to),
        templateCode: String(template_id),
        variables: variables && typeof variables === 'object' ? variables : {},
        purpose: String(purpose || 'account_transactional'),
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : 180,
        idempotencyKey: idempotency_key ? String(idempotency_key).trim() : undefined,
        actorId: owner.id,
        ipAddress: req.ip,
      });
      res.status(result.deduplicated ? 200 : 202).json(result);
    } catch (err) {
      sendAdminError(res, err);
    }
  };

  router.post('/messages/send', handleAdminSendSms);
  router.post('/messages/test-send', handleAdminSendSms);

  // --- OTP Challenges ---
  router.get('/otp-challenges', (_req: Request, res: Response) => {
    const challenges = db
      .prepare(
        `SELECT o.id, o.application_id, a.name as application_name, o.destination_masked,
                o.purpose, o.status, o.is_test, o.expires_at, o.attempts, o.max_attempts,
                o.consumed_at, o.message_id, o.created_at
         FROM otp_challenges o
         JOIN applications a ON a.id = o.application_id
         ORDER BY o.created_at DESC
         LIMIT 100`
      )
      .all();
    res.json({ challenges });
  });

  const handleAdminCreateOtp = (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, to, purpose, ttl_seconds, bypass_cooldown } = req.body ?? {};
      if (!application_id || !to) {
        throw new AppError(400, 'BAD_REQUEST', 'application_id and to are required.');
      }
      const result = createOtpChallenge(db, {
        applicationId: String(application_id),
        to: String(to),
        purpose: String(purpose || 'login'),
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : undefined,
        actorId: owner.id,
        ipAddress: req.ip,
        bypassCooldown: Boolean(bypass_cooldown),
      });
      res.status(202).json(result);
    } catch (err) {
      sendAdminError(res, err);
    }
  };

  router.post('/otp-challenges/create', handleAdminCreateOtp);
  router.post('/otp-challenges/test-create', handleAdminCreateOtp);

  const handleAdminVerifyOtp = (req: Request, res: Response) => {
    try {
      const { challenge_id, code } = req.body ?? {};
      const result = verifyOtpChallenge(db, {
        challengeId: String(challenge_id ?? ''),
        code: String(code ?? ''),
        ipAddress: req.ip,
      });
      res.json(result);
    } catch (err) {
      sendAdminError(res, err);
    }
  };

  router.post('/otp-challenges/verify', handleAdminVerifyOtp);
  router.post('/otp-challenges/test-verify', handleAdminVerifyOtp);

  // --- Gateway Devices (Live Hardware Control Only) ---
  router.get('/devices', (_req: Request, res: Response) => {
    const devices = db
      .prepare('SELECT id, name, status, app_version, android_version, permission_send_sms, network_type, battery_pct, sim_ready, last_heartbeat_at, enrolled_at, revoked_at FROM gateway_devices ORDER BY enrolled_at DESC')
      .all();
    const tokens = db
      .prepare('SELECT id, device_name, expires_at, used_at, created_at FROM enrollment_tokens ORDER BY created_at DESC LIMIT 10')
      .all();
    const sims = db.prepare('SELECT * FROM sims').all();
    const queuedCount = (db.prepare("SELECT COUNT(*) as c FROM messages WHERE status = 'queued'").get() as { c: number }).c;
    const leasedJobs = db
      .prepare(
        `SELECT m.id, m.destination_masked, m.template_id, m.purpose, m.status, m.is_test, m.leased_at, m.ttl_expires_at, l.lease_expires_at, l.attempt_count
         FROM messages m
         LEFT JOIN gateway_job_leases l ON l.message_id = m.id
         WHERE m.status IN ('queued', 'leased', 'accepted_by_device')
         ORDER BY m.created_at ASC
         LIMIT 20`
      )
      .all();

    res.json({ devices, enrollment_tokens: tokens, sims, queued_count: queuedCount, pending_jobs: leasedJobs });
  });

  router.post('/devices/enrollment-tokens', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { device_name, ttl_minutes } = req.body ?? {};
      if (!device_name || String(device_name).trim().length < 2) {
        throw new AppError(400, 'BAD_REQUEST', 'Device name is required.');
      }
      const { rawToken, tokenHash } = generateEnrollmentToken();
      const now = new Date();
      const ttlMins = Number(ttl_minutes ?? 15);
      const boundedTtl = Number.isFinite(ttlMins) ? Math.min(Math.max(ttlMins, 2), 60) : 15;
      const expiresAt = new Date(now.getTime() + boundedTtl * 60_000).toISOString();
      const id = `enr_${crypto.randomBytes(4).toString('hex')}`;

      db.prepare(
        `INSERT INTO enrollment_tokens (id, device_name, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?)`
      ).run(id, String(device_name).trim().slice(0, 80), tokenHash, expiresAt, now.toISOString());

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'gateway.enrollment_token_created',
        targetType: 'enrollment_token',
        targetId: id,
        metadata: { device_name: String(device_name).trim(), expires_at: expiresAt },
        ipAddress: req.ip,
      });

      res.status(201).json({ id, device_name: String(device_name).trim(), enrollment_token_once: rawToken, expires_at: expiresAt });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/devices/:id/action', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { action } = req.body ?? {};
      const devId = req.params.id;
      const dev = db.prepare('SELECT id, status FROM gateway_devices WHERE id = ?').get(devId) as { id: string; status: string } | undefined;
      if (!dev) throw new AppError(404, 'NOT_FOUND', 'Device not found.');

      const nowIso = new Date().toISOString();
      if (action === 'pause') {
        db.prepare("UPDATE gateway_devices SET status = 'paused' WHERE id = ? AND status != 'revoked'").run(devId);
      } else if (action === 'resume') {
        db.prepare("UPDATE gateway_devices SET status = CASE WHEN last_heartbeat_at IS NOT NULL THEN 'online' ELSE 'offline' END WHERE id = ? AND status != 'revoked'").run(devId);
      } else if (action === 'revoke') {
        db.prepare("UPDATE gateway_devices SET status = 'revoked', revoked_at = ? WHERE id = ?").run(nowIso, devId);
      } else {
        throw new AppError(400, 'BAD_REQUEST', 'Unsupported device action. Allowed: pause, resume, revoke.');
      }

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: `gateway.device_${action}`,
        targetType: 'gateway_device',
        targetId: devId,
        ipAddress: req.ip,
      });

      res.json({ device: db.prepare('SELECT * FROM gateway_devices WHERE id = ?').get(devId) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- SIM & Usage ---
  router.get('/sim-usage', (_req: Request, res: Response) => {
    const sims = db
      .prepare(
        `SELECT s.*, d.name as device_name, d.status as device_status
         FROM sims s JOIN gateway_devices d ON d.id = s.device_id`
      )
      .all();

    const usageByApp = db
      .prepare(
        `SELECT a.id as application_id, a.name as application_name, a.environment, a.daily_limit,
                COUNT(m.id) as total_messages,
                SUM(CASE WHEN m.status = 'sent_to_network' THEN 1 ELSE 0 END) as sent_to_network,
                SUM(CASE WHEN m.status = 'delivered' THEN 1 ELSE 0 END) as delivered,
                SUM(CASE WHEN m.status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN m.status = 'delivery_unknown' THEN 1 ELSE 0 END) as delivery_unknown
         FROM applications a
         LEFT JOIN messages m ON m.application_id = a.id
         GROUP BY a.id`
      )
      .all();

    res.json({ sims, usage_by_app: usageByApp });
  });

  router.patch('/sim-usage/:id/reconcile', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { plan_sms_limit, estimated_sms_sent, warning_threshold, carrier_label, period_start, period_end, notes } = req.body ?? {};
      const sim = db.prepare('SELECT * FROM sims WHERE id = ?').get(req.params.id) as
        | { id: string; plan_sms_limit: number; estimated_sms_sent: number }
        | undefined;
      if (!sim) throw new AppError(404, 'NOT_FOUND', 'SIM record not found.');

      const nextLimit = typeof plan_sms_limit === 'number' ? Math.max(0, plan_sms_limit) : sim.plan_sms_limit;
      const nextSent = typeof estimated_sms_sent === 'number' ? Math.max(0, estimated_sms_sent) : sim.estimated_sms_sent;
      const { remaining } = calculateSimRemainingEstimate(nextLimit, nextSent);
      const nowIso = new Date().toISOString();

      db.prepare(
        `UPDATE sims
         SET plan_sms_limit = ?,
             estimated_sms_sent = ?,
             estimated_sms_remaining = ?,
             warning_threshold = COALESCE(?, warning_threshold),
             carrier_label = COALESCE(?, carrier_label),
             period_start = COALESCE(?, period_start),
             period_end = COALESCE(?, period_end),
             notes = COALESCE(?, notes),
             updated_at = ?
         WHERE id = ?`
      ).run(
        nextLimit,
        nextSent,
        remaining,
        typeof warning_threshold === 'number' ? warning_threshold : null,
        carrier_label ?? null,
        period_start ?? null,
        period_end ?? null,
        notes ?? null,
        nowIso,
        req.params.id
      );

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'sim.manual_reconciliation',
        targetType: 'sim',
        targetId: req.params.id,
        metadata: { plan_sms_limit: nextLimit, estimated_sms_sent: nextSent, estimated_sms_remaining: remaining },
        ipAddress: req.ip,
      });

      res.json({ sim: db.prepare('SELECT * FROM sims WHERE id = ?').get(req.params.id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Templates ---
  router.get('/templates', (_req: Request, res: Response) => {
    const templates = db.prepare('SELECT * FROM message_templates ORDER BY created_at DESC').all();
    res.json({ templates, valid_purposes: VALID_MESSAGE_PURPOSES });
  });

  router.post('/templates', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { code, purpose, body, status } = req.body ?? {};
      const cleanCode = String(code ?? '').trim().toLowerCase().replace(/[^a-z0-9_]/g, '_');
      if (!cleanCode || cleanCode.length < 2 || !body || String(body).trim().length < 8) {
        throw new AppError(400, 'BAD_REQUEST', 'Template code and body (min 8 chars) are required.');
      }
      const cleanPurpose = String(purpose || 'account_transactional');
      if (!(VALID_MESSAGE_PURPOSES as readonly string[]).includes(cleanPurpose)) {
        throw new AppError(422, 'INVALID_PURPOSE', 'Invalid message purpose.');
      }
      const id = `tpl_${crypto.randomBytes(5).toString('hex')}`;
      const nowIso = new Date().toISOString();
      db.prepare(
        `INSERT INTO message_templates (id, owner_user_id, code, purpose, body, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(id, owner.id, cleanCode, cleanPurpose, String(body).trim(), status === 'draft' ? 'draft' : 'approved', nowIso, nowIso);

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'template.created',
        targetType: 'message_template',
        targetId: id,
        metadata: { code: cleanCode, purpose: cleanPurpose },
        ipAddress: req.ip,
      });
      res.status(201).json({ template: db.prepare('SELECT * FROM message_templates WHERE id = ?').get(id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.patch('/templates/:id', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { body, status, purpose } = req.body ?? {};
      if (status !== undefined && !['approved', 'draft', 'archived'].includes(String(status))) {
        throw new AppError(422, 'INVALID_STATUS', 'Status must be approved, draft, or archived.');
      }
      if (purpose !== undefined && !(VALID_MESSAGE_PURPOSES as readonly string[]).includes(String(purpose))) {
        throw new AppError(422, 'INVALID_PURPOSE', 'Invalid message purpose.');
      }
      const nowIso = new Date().toISOString();
      const result = db
        .prepare(
          `UPDATE message_templates
           SET body = COALESCE(?, body),
               status = COALESCE(?, status),
               purpose = COALESCE(?, purpose),
               updated_at = ?
           WHERE id = ?`
        )
        .run(body ?? null, status ?? null, purpose ?? null, nowIso, req.params.id);

      if (result.changes === 0) throw new AppError(404, 'NOT_FOUND', 'Template not found.');
      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'template.updated',
        targetType: 'message_template',
        targetId: req.params.id,
        metadata: { status, purpose },
        ipAddress: req.ip,
      });
      res.json({ template: db.prepare('SELECT * FROM message_templates WHERE id = ?').get(req.params.id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Destination Allowlist ---
  router.get('/allowlist', (_req: Request, res: Response) => {
    const entries = db
      .prepare(
        `SELECT d.id, d.application_id, a.name as application_name, d.e164_masked, d.label, d.created_at
         FROM destination_allowlist d JOIN applications a ON a.id = d.application_id
         ORDER BY d.created_at DESC`
      )
      .all();
    res.json({ entries });
  });

  router.post('/allowlist', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, phone, label } = req.body ?? {};
      const appExists = db.prepare('SELECT id FROM applications WHERE id = ?').get(String(application_id ?? ''));
      if (!appExists) {
        throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Application not found.');
      }
      const normalized = normalizeE164(String(phone ?? ''));
      if (!isValidE164(normalized)) {
        throw new AppError(422, 'INVALID_PHONE', 'Phone number must be valid E.164 format (e.g. +919876543210).');
      }
      const id = crypto.randomUUID();
      const masked = maskE164(normalized);
      const nowIso = new Date().toISOString();
      db.prepare(
        `INSERT INTO destination_allowlist (id, application_id, e164_masked, e164_hash, e164_encrypted, label, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(id, String(application_id), masked, hashDestination(normalized), encryptField(normalized), String(label || 'Approved Destination').slice(0, 80), nowIso);

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'allowlist.added',
        targetType: 'destination_allowlist',
        targetId: id,
        metadata: { application_id, e164_masked: masked, label },
        ipAddress: req.ip,
      });
      res.status(201).json({ entry: { id, application_id, e164_masked: masked, label, created_at: nowIso } });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.delete('/allowlist/:id', (req: Request, res: Response) => {
    const owner = getOwner(req);
    db.prepare('DELETE FROM destination_allowlist WHERE id = ?').run(req.params.id);
    writeAuditLog(db, {
      actorType: 'owner',
      actorId: owner.id,
      action: 'allowlist.removed',
      targetType: 'destination_allowlist',
      targetId: req.params.id,
      ipAddress: req.ip,
    });
    res.json({ deleted: true });
  });

  // --- Webhooks (SSRF-hardened HTTPS endpoints only) ---
  router.get('/webhooks', (_req: Request, res: Response) => {
    const endpoints = db
      .prepare(
        `SELECT w.id, w.application_id, a.name as application_name, w.url, w.enabled, w.event_types_json, w.created_at
         FROM webhook_endpoints w JOIN applications a ON a.id = w.application_id
         ORDER BY w.created_at DESC`
      )
      .all();
    const deliveries = db
      .prepare(
        `SELECT d.*, e.url
         FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id
         ORDER BY d.created_at DESC LIMIT 40`
      )
      .all();
    res.json({ endpoints, deliveries });
  });

  router.post('/webhooks', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, url, event_types } = req.body ?? {};
      const appExists = db.prepare('SELECT id FROM applications WHERE id = ?').get(String(application_id ?? ''));
      if (!appExists) {
        throw new AppError(404, 'APPLICATION_NOT_FOUND', 'Application not found.');
      }

      const validatedUrl = await assertPublicWebhookHost(String(url ?? ''));
      const cleanUrl = validatedUrl.toString();

      const id = `wh_${crypto.randomBytes(5).toString('hex')}`;
      const rawSecret = `whsec_${crypto.randomBytes(20).toString('hex')}`;
      const allowedEvents = new Set(['message.status', 'otp.sent', 'otp.verified', 'otp.failed']);
      const events =
        Array.isArray(event_types) && event_types.length > 0
          ? event_types.filter((e): e is string => typeof e === 'string' && allowedEvents.has(e))
          : ['message.status', 'otp.sent', 'otp.verified', 'otp.failed'];
      const nowIso = new Date().toISOString();

      db.prepare(
        `INSERT INTO webhook_endpoints (id, application_id, url, secret_encrypted, enabled, event_types_json, created_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`
      ).run(id, String(application_id), cleanUrl, encryptField(rawSecret), JSON.stringify(events), nowIso);

      writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'webhook.created',
        targetType: 'webhook_endpoint',
        targetId: id,
        metadata: { application_id, url: cleanUrl, events },
        ipAddress: req.ip,
      });

      res.status(201).json({
        endpoint: { id, application_id, url: cleanUrl, enabled: 1, event_types_json: JSON.stringify(events), created_at: nowIso },
        signing_secret_once: rawSecret,
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/webhooks/:id/test', (req: Request, res: Response) => {
    try {
      const ep = db.prepare('SELECT id, application_id, url, secret_encrypted FROM webhook_endpoints WHERE id = ?').get(req.params.id) as
        | { id: string; application_id: string; url: string; secret_encrypted: string }
        | undefined;
      if (!ep) throw new AppError(404, 'NOT_FOUND', 'Webhook endpoint not found.');
      const eventId = `evt_test_${crypto.randomBytes(4).toString('hex')}`;
      const nowIso = new Date().toISOString();
      const payload = JSON.stringify({ event_id: eventId, event_type: 'message.status', test: true, occurred_at: nowIso });
      db.prepare(
        `INSERT INTO webhook_deliveries (id, endpoint_id, event_id, event_type, payload_redacted_json, status, attempt_count, next_attempt_at, last_http_status, created_at)
         VALUES (?, ?, ?, 'message.status', ?, 'pending', 0, ?, NULL, ?)`
      ).run(crypto.randomUUID(), ep.id, eventId, payload, nowIso, nowIso);
      const tick = runSweeperTick(db);
      res.json({ queued: true, event_id: eventId, sweeper: tick });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.patch('/webhooks/:id/toggle', (req: Request, res: Response) => {
    const owner = getOwner(req);
    db.prepare('UPDATE webhook_endpoints SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?').run(req.params.id);
    writeAuditLog(db, {
      actorType: 'owner',
      actorId: owner.id,
      action: 'webhook.toggled',
      targetType: 'webhook_endpoint',
      targetId: req.params.id,
      ipAddress: req.ip,
    });
    res.json({ ok: true });
  });

  // --- Audit Logs ---
  router.get('/audit-logs', (req: Request, res: Response) => {
    const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
    let sql = 'SELECT * FROM audit_logs WHERE 1=1';
    const params: string[] = [];
    if (q) {
      sql += ' AND (action LIKE ? OR target_type LIKE ? OR target_id LIKE ? OR metadata_redacted_json LIKE ?)';
      params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
    }
    sql += ' ORDER BY created_at DESC LIMIT 120';
    res.json({ logs: db.prepare(sql).all(...params) });
  });

  // --- Settings & Kill Switch ---
  router.get('/settings', (_req: Request, res: Response) => {
    res.json({ settings: getSettingsMap(db) });
  });

  router.patch('/settings', (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const updates = req.body ?? {};
      const numericBounds: Record<string, [number, number]> = {
        otp_ttl_seconds: [60, 600],
        otp_max_attempts: [1, 10],
        otp_resend_cooldown_seconds: [0, 300],
        rate_limit_per_number_hourly: [1, 50],
        rate_limit_per_ip_minute: [5, 500],
        lease_timeout_seconds: [10, 300],
        max_send_retries: [1, 10],
        retention_days: [1, 365],
        global_daily_sim_cap: [1, 50000],
      };

      for (const [k, v] of Object.entries(updates)) {
        if (k === 'global_paused') {
          const val = String(v) === 'true' ? 'true' : 'false';
          updateSetting(db, k, val, owner.id, req.ip);
        } else if (k in numericBounds) {
          const num = Number(v);
          const [min, max] = numericBounds[k];
          if (!Number.isFinite(num) || num < min || num > max) {
            throw new AppError(422, 'INVALID_SETTING', `Setting ${k} must be between ${min} and ${max}.`);
          }
          updateSetting(db, k, String(Math.trunc(num)), owner.id, req.ip);
        }
      }
      res.json({ settings: getSettingsMap(db) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/sweeper/run', (_req: Request, res: Response) => {
    res.json(runSweeperTick(db));
  });

  // --- Deployment & Android Gateway Blueprint Snippets (matching Docs 05 & 09) ---
  router.get('/blueprints', (_req: Request, res: Response) => {
    res.json({
      kotlin_gateway_snippet: `// SimVault Android Gateway Worker (Kotlin / SmsManager)
class SmsDispatchWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
  override suspend fun doWork(): Result {
    if (ContextCompat.checkSelfPermission(applicationContext, Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED) {
      return Result.failure() // Never bypass Android runtime permissions
    }
    val job = gatewayApi.pollNextJob() ?: return Result.success()
    if (localJournal.hasProcessed(job.jobId)) return Result.success()
    localJournal.markReceived(job.jobId)
    gatewayApi.ackAccepted(job.jobId)

    val subManager = applicationContext.getSystemService(SubscriptionManager::class.java)
    val subInfo = subManager.activeSubscriptionInfoList?.firstOrNull { it.simSlotIndex == job.simSlot }
      ?: return reportFailure(job.jobId, "SIM_SLOT_UNAVAILABLE")

    val smsManager = applicationContext.getSystemService(SmsManager::class.java)
      .createForSubscriptionId(subInfo.subscriptionId)

    smsManager.sendTextMessage(job.to, null, job.body, sentPendingIntent, deliveryPendingIntent)
    return Result.success()
  }
}`,
      docker_compose_snippet: `services:
  nginx:
    image: nginx:1.27-alpine
    ports: ["80:80", "443:443"]
    depends_on: [web, api]
  api:
    build: ./apps/api
    env_file: .env
    depends_on: [postgres, redis]
  worker:
    build: ./apps/worker
    env_file: .env
    depends_on: [postgres, redis]
  web:
    build: ./apps/web
    env_file: .env
  postgres:
    image: postgres:16-alpine
    volumes: ["pgdata:/var/lib/postgresql/data"]
  redis:
    image: redis:7-alpine`,
    });
  });

  function collectAndroidProjectFiles(): Array<{ path: string; data: Buffer }> {
    const rootDir = path.resolve(process.cwd(), 'android-gateway');
    const files: Array<{ path: string; data: Buffer }> = [];

    function walk(dir: string) {
      if (!fs.existsSync(dir)) return;
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else {
          files.push({
            path: path.relative(rootDir, full).replace(/\\/g, '/'),
            data: fs.readFileSync(full),
          });
        }
      }
    }

    walk(rootDir);
    files.sort((a, b) => a.path.localeCompare(b.path));
    return files;
  }

  function crc32(buf: Buffer): number {
    let crc = 0xffffffff;
    for (let i = 0; i < buf.length; i++) {
      crc ^= buf[i];
      for (let j = 0; j < 8; j++) {
        crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
      }
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  function buildZipStoreArchive(entries: Array<{ path: string; data: Buffer }>): Buffer {
    const localChunks: Buffer[] = [];
    const centralChunks: Buffer[] = [];
    let offset = 0;

    for (const entry of entries) {
      const nameBuf = Buffer.from(`android-gateway/${entry.path}`, 'utf8');
      const crc = crc32(entry.data);
      const size = entry.data.length;

      const localHeader = Buffer.alloc(30);
      localHeader.writeUInt32LE(0x04034b50, 0);
      localHeader.writeUInt16LE(20, 4); // version needed
      localHeader.writeUInt16LE(0x0800, 6); // UTF-8 filename flag
      localHeader.writeUInt16LE(0, 8); // compression method: STORE
      localHeader.writeUInt16LE(0, 10); // mod time
      localHeader.writeUInt16LE(0x5421, 12); // mod date
      localHeader.writeUInt32LE(crc, 14);
      localHeader.writeUInt32LE(size, 18);
      localHeader.writeUInt32LE(size, 22);
      localHeader.writeUInt16LE(nameBuf.length, 26);
      localHeader.writeUInt16LE(0, 28);

      localChunks.push(localHeader, nameBuf, entry.data);

      const centralHeader = Buffer.alloc(46);
      centralHeader.writeUInt32LE(0x02014b50, 0);
      centralHeader.writeUInt16LE(20, 4);
      centralHeader.writeUInt16LE(20, 6);
      centralHeader.writeUInt16LE(0x0800, 8);
      centralHeader.writeUInt16LE(0, 10);
      centralHeader.writeUInt16LE(0, 12);
      centralHeader.writeUInt16LE(0x5421, 14);
      centralHeader.writeUInt32LE(crc, 16);
      centralHeader.writeUInt32LE(size, 20);
      centralHeader.writeUInt32LE(size, 24);
      centralHeader.writeUInt16LE(nameBuf.length, 28);
      centralHeader.writeUInt16LE(0, 30);
      centralHeader.writeUInt16LE(0, 32);
      centralHeader.writeUInt16LE(0, 34);
      centralHeader.writeUInt16LE(0, 36);
      centralHeader.writeUInt32LE(0, 38);
      centralHeader.writeUInt32LE(offset, 42);

      centralChunks.push(centralHeader, nameBuf);
      offset += localHeader.length + nameBuf.length + entry.data.length;
    }

    const centralDir = Buffer.concat(centralChunks);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(0x06054b50, 0);
    eocd.writeUInt16LE(0, 4);
    eocd.writeUInt16LE(0, 6);
    eocd.writeUInt16LE(entries.length, 8);
    eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(centralDir.length, 12);
    eocd.writeUInt32LE(offset, 16);
    eocd.writeUInt16LE(0, 20);

    return Buffer.concat([...localChunks, centralDir, eocd]);
  }

  router.get('/android-project', (_req: Request, res: Response) => {
    const files = collectAndroidProjectFiles().map((f) => ({
      path: f.path,
      content: f.data.toString('utf8'),
    }));
    res.json({ root: 'android-gateway', files });
  });

  router.get('/android-project.zip', (_req: Request, res: Response) => {
    const archive = buildZipStoreArchive(collectAndroidProjectFiles());
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="simvault-android-gateway.zip"');
    res.send(archive);
  });

  return router;
}
