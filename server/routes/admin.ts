import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Router, Request, Response, NextFunction } from 'express';
import {
  constantTimeEquals,
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
import { DbClient, writeAuditLog } from '../db';
import {
  AppError,
  assertPublicWebhookHost,
  checkLoginRateLimit,
  clearLoginFailures,
  consumeTotpCode,
  createBulkSmsRequests,
  createOtpChallenge,
  createPersonalSmsRequest,
  createSmsRequest,
  getSettingsMap,
  maybeRunOpportunisticSweep,
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

function escapeLikePattern(raw: string): string {
  return raw.replace(/[!%_]/g, '!$&');
}

function sendAdminError(res: Response, err: unknown): void {
  if (err instanceof AppError) {
    res.status(err.status).json({ error: { code: err.code, message: err.message } });
    return;
  }
  console.error('[SimVault admin]', err);
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected server error occurred.' } });
}

function isHttpsRequest(req: Request): boolean {
  const xfProto = req.headers['x-forwarded-proto'];
  return req.secure || (typeof xfProto === 'string' && xfProto.split(',')[0].trim() === 'https');
}

export function createAdminRouter(db: DbClient): Router {
  const router = Router();

  // Strict owner session authentication & CSRF validation
  router.use(async (req: Request, res: Response, next: NextFunction) => {
    try {
      const cookieHeader = req.headers.cookie ?? '';
      const match = /simvault_session=([^;]+)/.exec(cookieHeader);
      let user: { id: string; email: string; role: string; mfa_enabled: number } | undefined;
      let sessionCsrf: string | null = null;
      let currentTokenHash: string | null = null;

      if (match) {
        const tokHash = hashToken(decodeURIComponent(match[1]));
        const sess = await db.get<{
          csrf_token: string;
          expires_at: string;
          mfa_verified: number;
          id: string;
          email: string;
          role: string;
          mfa_enabled: number;
        }>(
          `SELECT s.csrf_token, s.expires_at, s.mfa_verified, u.id, u.email, u.role, u.mfa_enabled
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ?`,
          tokHash
        );
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
        if (!sessionCsrf || typeof providedCsrf !== 'string' || !constantTimeEquals(providedCsrf, sessionCsrf)) {
          res.status(403).json({ error: { code: 'CSRF_INVALID', message: 'Invalid or missing CSRF token.' } });
          return;
        }
      }
      next();
    } catch (err) {
      sendAdminError(res, err);
    }
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

  router.post('/auth/login', async (req: Request, res: Response) => {
    try {
      const clientIp = req.ip || '127.0.0.1';
      const { email, password, totp_code } = req.body ?? {};
      const cleanEmail = typeof email === 'string' ? email.trim().toLowerCase() : '';
      const accountKey = cleanEmail ? `acct:${cleanEmail}` : '';

      if (!checkLoginRateLimit(clientIp) || (accountKey && !checkLoginRateLimit(accountKey))) {
        throw new AppError(429, 'LOGIN_RATE_LIMITED', 'Too many failed sign-in attempts. Please wait 5 minutes before trying again.');
      }

      if (typeof email !== 'string' || typeof password !== 'string' || !cleanEmail || !password) {
        recordLoginFailure(clientIp);
        if (accountKey) recordLoginFailure(accountKey);
        throw new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password.');
      }

      const user = await db.get<{
        id: string;
        email: string;
        password_hash: string;
        role: string;
        mfa_enabled: number;
        mfa_secret: string | null;
      }>('SELECT id, email, password_hash, role, mfa_enabled, mfa_secret FROM users WHERE email = ?', cleanEmail);

      if (!user || !verifyPassword(password, user.password_hash)) {
        recordLoginFailure(clientIp);
        if (accountKey) recordLoginFailure(accountKey);
        await writeAuditLog(db, {
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
        if (totp_code === undefined || totp_code === null || totp_code === '') {
          res.status(200).json({ authenticated: false, mfa_required: true });
          return;
        }
        const cleanTotp = typeof totp_code === 'string' ? totp_code.trim() : '';
        if (!cleanTotp || !verifyTotpCode(user.mfa_secret, cleanTotp) || !consumeTotpCode(user.id, cleanTotp)) {
          recordLoginFailure(clientIp);
          if (accountKey) recordLoginFailure(accountKey);
          await writeAuditLog(db, {
            actorType: 'owner',
            actorId: user.id,
            action: 'owner.login_failed',
            targetType: 'user',
            targetId: user.id,
            metadata: { reason: 'invalid_totp' },
            ipAddress: clientIp,
          });
          throw new AppError(401, 'INVALID_MFA', 'Invalid or already-used authenticator code.');
        }
      }

      clearLoginFailures(clientIp);
      if (accountKey) clearLoginFailures(accountKey);
      const rawToken = crypto.randomBytes(32).toString('base64url');
      const csrfToken = crypto.randomBytes(24).toString('base64url');
      const nowIso = new Date().toISOString();
      const expiresAt = new Date(Date.now() + 24 * 3600_000).toISOString();

      await db.run('DELETE FROM sessions WHERE expires_at <= ?', nowIso);
      await db.run(
        `INSERT INTO sessions (id, user_id, token_hash, csrf_token, mfa_verified, expires_at, created_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`,
        crypto.randomUUID(),
        user.id,
        hashToken(rawToken),
        csrfToken,
        expiresAt,
        nowIso
      );

      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: user.id,
        action: 'owner.login',
        targetType: 'session',
        targetId: user.id,
        metadata: { mfa_used: Boolean(user.mfa_enabled) },
        ipAddress: clientIp,
      });

      const isHttps = isHttpsRequest(req);
      const cookiePolicy = isHttps ? 'SameSite=None; Secure; Partitioned' : 'SameSite=Lax';
      res.setHeader('Set-Cookie', [
        `simvault_session=${encodeURIComponent(rawToken)}; Path=/; HttpOnly; ${cookiePolicy}`,
        `simvault_locked=; Path=/; Max-Age=0; ${cookiePolicy}`,
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

  router.post('/auth/logout', async (req: Request, res: Response) => {
    try {
      const cookieHeader = req.headers.cookie ?? '';
      const match = /simvault_session=([^;]+)/.exec(cookieHeader);
      if (match) {
        await db.run('DELETE FROM sessions WHERE token_hash = ?', hashToken(decodeURIComponent(match[1])));
      }
      const isHttps = isHttpsRequest(req);
      const cookiePolicy = isHttps ? 'SameSite=None; Secure; Partitioned' : 'SameSite=Lax';
      res.setHeader('Set-Cookie', [
        `simvault_session=; Path=/; Max-Age=0; HttpOnly; ${cookiePolicy}`,
        `simvault_locked=; Path=/; Max-Age=0; HttpOnly; ${cookiePolicy}`,
      ]);
      res.json({ ok: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/security/password', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const currentTokenHash = (req as Request & { currentTokenHash?: string | null }).currentTokenHash;
      const { current_password, new_password } = req.body ?? {};
      const nextPass = String(new_password ?? '');
      if (nextPass.length < 10) {
        throw new AppError(422, 'WEAK_PASSWORD', 'New password must be at least 10 characters long.');
      }

      const userRow = await db.get<{ id: string; password_hash: string }>(
        'SELECT id, password_hash FROM users WHERE id = ?',
        owner.id
      );
      if (!userRow || !verifyPassword(String(current_password ?? ''), userRow.password_hash)) {
        throw new AppError(401, 'INVALID_CURRENT_PASSWORD', 'Current password is incorrect.');
      }

      const nowIso = new Date().toISOString();
      await db.run('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', hashPassword(nextPass), nowIso, owner.id);
      if (currentTokenHash) {
        await db.run('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', owner.id, currentTokenHash);
      }

      await writeAuditLog(db, {
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

  router.get('/security/mfa', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const user = await db.get<{ email: string; mfa_enabled: number; mfa_secret: string | null }>(
        'SELECT email, mfa_enabled, mfa_secret FROM users WHERE id = ?',
        owner.id
      );
      if (!user) throw new AppError(404, 'NOT_FOUND', 'Owner account not found.');
      const secret = user.mfa_secret || generateTotpSecret();
      if (!user.mfa_secret) {
        await db.run('UPDATE users SET mfa_secret = ? WHERE id = ?', secret, owner.id);
      }
      const otpauthUri = `otpauth://totp/SimVault:${encodeURIComponent(user.email)}?secret=${secret}&issuer=SimVault`;
      res.json({
        mfa_enabled: Boolean(user.mfa_enabled),
        secret_preview: user.mfa_enabled ? 'Configured' : secret,
        otpauth_uri: user.mfa_enabled ? null : otpauthUri,
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/security/mfa/enable', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { code } = req.body ?? {};
      const cleanCode = typeof code === 'string' ? code.trim() : '';
      const user = await db.get<{ mfa_secret: string | null }>('SELECT mfa_secret FROM users WHERE id = ?', owner.id);
      if (!user?.mfa_secret || !cleanCode || !verifyTotpCode(user.mfa_secret, cleanCode) || !consumeTotpCode(owner.id, cleanCode)) {
        throw new AppError(422, 'INVALID_TOTP', 'Verification code did not match or was already used.');
      }
      await db.run('UPDATE users SET mfa_enabled = 1, updated_at = ? WHERE id = ?', new Date().toISOString(), owner.id);
      await writeAuditLog(db, {
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

  router.post('/security/mfa/disable', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { current_password, totp_code } = req.body ?? {};
      const user = await db.get<{ password_hash: string; mfa_enabled: number; mfa_secret: string | null }>(
        'SELECT password_hash, mfa_enabled, mfa_secret FROM users WHERE id = ?',
        owner.id
      );
      if (!user) throw new AppError(404, 'NOT_FOUND', 'Owner account not found.');

      if (user.mfa_enabled) {
        const validPassword =
          typeof current_password === 'string' &&
          current_password.length > 0 &&
          verifyPassword(current_password, user.password_hash);
        const cleanTotp = typeof totp_code === 'string' ? totp_code.trim() : '';
        const validTotp =
          Boolean(user.mfa_secret) &&
          cleanTotp.length > 0 &&
          verifyTotpCode(user.mfa_secret!, cleanTotp) &&
          consumeTotpCode(owner.id, cleanTotp);

        if (!validPassword && !validTotp) {
          throw new AppError(
            401,
            'AUTH_RECONFIRM_REQUIRED',
            'Enter your current password or a valid 6-digit authenticator code to disable MFA.'
          );
        }
      }

      await db.run('UPDATE users SET mfa_enabled = 0, updated_at = ? WHERE id = ?', new Date().toISOString(), owner.id);
      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'owner.mfa_disabled',
        targetType: 'user',
        targetId: owner.id,
        ipAddress: req.ip,
      });
      res.json({ mfa_enabled: false });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Overview & Dashboard Summary ---
  router.get('/overview', async (_req: Request, res: Response) => {
    try {
      await maybeRunOpportunisticSweep(db);
      const settings = await getSettingsMap(db);
      const dayStart = new Date();
      dayStart.setUTCHours(0, 0, 0, 0);
      const dayIso = dayStart.toISOString();

      const statusCounts = await db.all<{ status: string; count: number | string }>(
        'SELECT status, COUNT(*) as count FROM messages GROUP BY status'
      );

      const todayRequests = await db.get<{ count: number | string }>(
        'SELECT COUNT(*) as count FROM messages WHERE created_at >= ?',
        dayIso
      );

      const todaySent = await db.get<{ count: number | string }>(
        "SELECT COUNT(*) as count FROM messages WHERE sent_at >= ? AND status IN ('sent_to_network', 'delivered', 'delivery_unknown')",
        dayIso
      );

      const queueDepth = await db.get<{ count: number | string }>(
        "SELECT COUNT(*) as count FROM messages WHERE status IN ('created', 'queued', 'leased', 'accepted_by_device')"
      );

      const devices = await db.all(
        `SELECT id, name, status, app_version, android_version, permission_send_sms, network_type, battery_pct, sim_ready, last_heartbeat_at
         FROM gateway_devices WHERE status != 'revoked' ORDER BY enrolled_at ASC`
      );

      const sims = await db.all('SELECT * FROM sims ORDER BY updated_at DESC');

      const recentMessages = await db.all(
        `SELECT m.id, m.application_id, a.name as application_name, m.device_id, m.destination_masked, m.template_id,
                m.purpose, m.status, m.is_test, m.created_at, m.sent_at, m.delivered_at, m.failed_at, m.error_code
         FROM messages m
         JOIN applications a ON a.id = m.application_id
         ORDER BY m.created_at DESC
         LIMIT 12`
      );

      const recentAudit = await db.all(
        'SELECT id, actor_type, actor_id, action, target_type, target_id, metadata_redacted_json, ip_address, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 8'
      );

      const activeOtpCount = await db.get<{ count: number | string }>(
        "SELECT COUNT(*) as count FROM otp_challenges WHERE status IN ('queued', 'sent')"
      );

      res.json({
        global_paused: settings.global_paused === 'true',
        settings,
        kpis: {
          requests_today: Number(todayRequests?.count ?? 0),
          sent_to_network_today: Number(todaySent?.count ?? 0),
          queue_depth: Number(queueDepth?.count ?? 0),
          active_otps: Number(activeOtpCount?.count ?? 0),
          status_breakdown: statusCounts.map((r) => ({ status: r.status, count: Number(r.count ?? 0) })),
        },
        devices,
        sims,
        recent_messages: recentMessages,
        recent_audit: recentAudit,
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Applications ---
  router.get('/applications', async (_req: Request, res: Response) => {
    try {
      const apps = await db.all<{
        id: string;
        owner_user_id: string;
        name: string;
        environment: string;
        status: string;
        allowed_purposes_json: string;
        daily_limit: number | string;
        allowlist_only: number | string;
        created_at: string;
        active_keys_count: number | string;
        total_messages_count: number | string;
      }>(
        `SELECT a.*,
                (SELECT COUNT(*) FROM api_keys k WHERE k.application_id = a.id AND k.status != 'revoked') as active_keys_count,
                (SELECT COUNT(*) FROM messages m WHERE m.application_id = a.id) as total_messages_count
         FROM applications a ORDER BY a.created_at DESC`
      );
      res.json({
        applications: apps.map((a) => ({
          ...a,
          daily_limit: Number(a.daily_limit ?? 0),
          allowlist_only: Number(a.allowlist_only ?? 0),
          active_keys_count: Number(a.active_keys_count ?? 0),
          total_messages_count: Number(a.total_messages_count ?? 0),
        })),
        valid_purposes: VALID_MESSAGE_PURPOSES,
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/applications', async (req: Request, res: Response) => {
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
      const purposes =
        rawPurposes.length > 0
          ? rawPurposes
          : ['login', 'mfa', 'account_transactional', 'personal_message', 'bulk_broadcast'];

      await db.run(
        `INSERT INTO applications (id, owner_user_id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only, created_at)
         VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)`,
        id,
        owner.id,
        String(name).trim().slice(0, 80),
        env,
        JSON.stringify(purposes),
        Math.trunc(parsedLimit),
        allowlist_only === true ? 1 : 0,
        nowIso
      );

      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'application.created',
        targetType: 'application',
        targetId: id,
        metadata: { name: String(name).trim(), environment: env },
        ipAddress: req.ip,
      });

      const created = await db.get('SELECT * FROM applications WHERE id = ?', id);
      res.status(201).json({ application: created });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.patch('/applications/:id', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { status, daily_limit, allowlist_only, allowed_purposes } = req.body ?? {};
      const existing = await db.get('SELECT id FROM applications WHERE id = ?', req.params.id);
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

      await db.run(
        `UPDATE applications
         SET status = COALESCE(?, status),
             daily_limit = COALESCE(?, daily_limit),
             allowlist_only = COALESCE(?, allowlist_only),
             allowed_purposes_json = COALESCE(?, allowed_purposes_json)
         WHERE id = ?`,
        status !== undefined ? String(status) : null,
        daily_limit !== undefined ? Math.trunc(Number(daily_limit)) : null,
        typeof allowlist_only === 'boolean' ? (allowlist_only ? 1 : 0) : null,
        nextPurposes && nextPurposes.length > 0 ? JSON.stringify(nextPurposes) : null,
        req.params.id
      );

      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'application.updated',
        targetType: 'application',
        targetId: req.params.id,
        metadata: { status, daily_limit, allowlist_only },
        ipAddress: req.ip,
      });

      res.json({ application: await db.get('SELECT * FROM applications WHERE id = ?', req.params.id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- API Keys (secret shown ONLY ONCE at creation/rotation) ---
  router.get('/api-keys', async (_req: Request, res: Response) => {
    try {
      const keys = await db.all(
        `SELECT k.id, k.application_id, a.name as application_name, a.environment,
                k.name, k.key_prefix, k.scopes_json, k.status, k.last_used_at, k.expires_at, k.revoked_at, k.created_at
         FROM api_keys k
         JOIN applications a ON a.id = k.application_id
         ORDER BY k.created_at DESC`
      );
      res.json({ api_keys: keys, available_scopes: ALL_API_SCOPES });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/api-keys', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, name, scopes } = req.body ?? {};
      const app = await db.get<{ id: string; environment: 'test' | 'live' }>(
        'SELECT id, environment FROM applications WHERE id = ?',
        application_id
      );
      if (!app) throw new AppError(404, 'NOT_FOUND', 'Application not found.');
      if (!name || String(name).trim().length < 2) throw new AppError(400, 'BAD_REQUEST', 'Key label is required.');

      const validScopes =
        Array.isArray(scopes) && scopes.length > 0
          ? scopes.filter((s: string) => ALL_API_SCOPES.includes(s as (typeof ALL_API_SCOPES)[number]))
          : ['sms:send', 'otp:create', 'otp:verify', 'usage:read'];

      const { rawKey, keyPrefix, secretHash } = generateApiKey(app.environment);
      const id = `key_${crypto.randomBytes(5).toString('hex')}`;
      const nowIso = new Date().toISOString();

      await db.run(
        `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
        id,
        app.id,
        String(name).trim(),
        keyPrefix,
        secretHash,
        JSON.stringify(validScopes),
        nowIso
      );

      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'api_key.created',
        targetType: 'api_key',
        targetId: id,
        metadata: { application_id: app.id, key_prefix: keyPrefix, scopes: validScopes },
        ipAddress: req.ip,
      });

      const created = await db.get(
        `SELECT k.id, k.application_id, a.name as application_name, a.environment,
                k.name, k.key_prefix, k.scopes_json, k.status, k.last_used_at, k.expires_at, k.revoked_at, k.created_at
         FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.id = ?`,
        id
      );

      // Returned ONLY ONCE here — never persisted or returned again
      res.status(201).json({ api_key: created, secret_once: rawKey });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/api-keys/:id/rotate', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const existing = await db.get<{
        id: string;
        application_id: string;
        name: string;
        scopes_json: string;
        status: string;
        environment: 'test' | 'live';
      }>(
        `SELECT k.id, k.application_id, k.name, k.scopes_json, k.status, a.environment
         FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.id = ?`,
        req.params.id
      );

      if (!existing || existing.status === 'revoked') {
        throw new AppError(404, 'NOT_FOUND', 'Active API key not found.');
      }

      const now = new Date();
      const nowIso = now.toISOString();
      const overlapExpires = new Date(now.getTime() + 15 * 60_000).toISOString();
      const { rawKey, keyPrefix, secretHash } = generateApiKey(existing.environment);
      const newId = `key_${crypto.randomBytes(5).toString('hex')}`;

      await db.transaction(async (tx) => {
        await tx.run("UPDATE api_keys SET status = 'rotating', expires_at = ? WHERE id = ?", overlapExpires, existing.id);
        await tx.run(
          `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
          newId,
          existing.application_id,
          `${existing.name} (Rotated)`,
          keyPrefix,
          secretHash,
          existing.scopes_json,
          nowIso
        );
      });

      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'api_key.rotated',
        targetType: 'api_key',
        targetId: newId,
        metadata: { previous_key_id: existing.id, key_prefix: keyPrefix, overlap_expires_at: overlapExpires },
        ipAddress: req.ip,
      });

      const created = await db.get(
        `SELECT k.id, k.application_id, a.name as application_name, a.environment,
                k.name, k.key_prefix, k.scopes_json, k.status, k.last_used_at, k.expires_at, k.revoked_at, k.created_at
         FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.id = ?`,
        newId
      );

      res.status(201).json({ api_key: created, secret_once: rawKey, overlap_expires_at: overlapExpires });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/api-keys/:id/revoke', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const nowIso = new Date().toISOString();
      const result = await db.run(
        "UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE id = ? AND status != 'revoked'",
        nowIso,
        req.params.id
      );
      if (result.changes === 0) throw new AppError(404, 'NOT_FOUND', 'API key not found or already revoked.');

      await writeAuditLog(db, {
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
  router.get('/messages', async (req: Request, res: Response) => {
    try {
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
        const likeTerm = `%${escapeLikePattern(q)}%`;
        sql += " AND (LOWER(m.id) LIKE LOWER(?) ESCAPE '!' OR LOWER(m.destination_masked) LIKE LOWER(?) ESCAPE '!' OR LOWER(m.template_id) LIKE LOWER(?) ESCAPE '!')";
        params.push(likeTerm, likeTerm, likeTerm);
      }
      sql += ' ORDER BY m.created_at DESC LIMIT 100';

      const rows = await db.all(sql, ...params);
      res.json({ messages: rows });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  const handleAdminSendSms = async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, to, template_id, variables, purpose, ttl_seconds, idempotency_key } = req.body ?? {};
      if (typeof application_id !== 'string' || typeof to !== 'string' || typeof template_id !== 'string' || !application_id || !to || !template_id) {
        throw new AppError(400, 'BAD_REQUEST', 'application_id, to, and template_id must be non-empty strings.');
      }
      const result = await createSmsRequest(db, {
        applicationId: application_id,
        to,
        templateCode: template_id,
        variables: variables && typeof variables === 'object' && !Array.isArray(variables) ? variables : {},
        purpose: typeof purpose === 'string' && purpose ? purpose : 'account_transactional',
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : 180,
        idempotencyKey: typeof idempotency_key === 'string' && idempotency_key.trim() ? idempotency_key.trim() : undefined,
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

  router.post('/messages/personal', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, to, body, purpose, ttl_seconds, idempotency_key } = req.body ?? {};
      if (typeof application_id !== 'string' || typeof to !== 'string' || typeof body !== 'string' || !application_id || !to || !body) {
        throw new AppError(400, 'BAD_REQUEST', 'application_id, to, and body must be non-empty strings.');
      }
      const result = await createPersonalSmsRequest(db, {
        applicationId: application_id,
        to,
        body,
        purpose: typeof purpose === 'string' && purpose ? purpose : 'personal_message',
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : 300,
        idempotencyKey: typeof idempotency_key === 'string' && idempotency_key.trim() ? idempotency_key.trim() : undefined,
        actorType: 'owner',
        actorId: owner.id,
        ipAddress: req.ip,
      });
      res.status(result.deduplicated ? 200 : 202).json(result);
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/messages/bulk', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, recipients, body, template_id, variables, purpose, ttl_seconds, batch_label } = req.body ?? {};
      if (
        typeof application_id !== 'string' ||
        !application_id ||
        (!Array.isArray(recipients) && typeof recipients !== 'string') ||
        (typeof body !== 'string' && typeof template_id !== 'string')
      ) {
        throw new AppError(
          400,
          'BAD_REQUEST',
          'application_id, recipients, and either body or template_id are required.'
        );
      }
      const result = await createBulkSmsRequests(db, {
        applicationId: application_id,
        recipients: Array.isArray(recipients) ? recipients.filter((r): r is string => typeof r === 'string') : recipients,
        body: typeof body === 'string' ? body : undefined,
        templateCode: typeof template_id === 'string' ? template_id : undefined,
        variables: variables && typeof variables === 'object' && !Array.isArray(variables) ? variables : {},
        purpose: typeof purpose === 'string' ? purpose : undefined,
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : 600,
        batchLabel: typeof batch_label === 'string' ? batch_label : undefined,
        actorType: 'owner',
        actorId: owner.id,
        ipAddress: req.ip,
      });
      res.status(202).json(result);
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- OTP Challenges ---
  router.get('/otp-challenges', async (_req: Request, res: Response) => {
    try {
      const challenges = await db.all(
        `SELECT o.id, o.application_id, a.name as application_name, o.destination_masked,
                o.purpose, o.status, o.is_test, o.expires_at, o.attempts, o.max_attempts,
                o.consumed_at, o.message_id, o.created_at
         FROM otp_challenges o
         JOIN applications a ON a.id = o.application_id
         ORDER BY o.created_at DESC
         LIMIT 100`
      );
      res.json({ challenges });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  const handleAdminCreateOtp = async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, to, purpose, ttl_seconds, bypass_cooldown } = req.body ?? {};
      if (!application_id || !to) {
        throw new AppError(400, 'BAD_REQUEST', 'application_id and to are required.');
      }
      const result = await createOtpChallenge(db, {
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

  const handleAdminVerifyOtp = async (req: Request, res: Response) => {
    try {
      const { challenge_id, code } = req.body ?? {};
      const result = await verifyOtpChallenge(db, {
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
  router.get('/devices', async (_req: Request, res: Response) => {
    try {
      const devices = await db.all(
        'SELECT id, name, status, app_version, android_version, permission_send_sms, network_type, battery_pct, sim_ready, last_heartbeat_at, enrolled_at, revoked_at FROM gateway_devices ORDER BY enrolled_at DESC'
      );
      const tokens = await db.all(
        'SELECT id, device_name, expires_at, used_at, created_at FROM enrollment_tokens ORDER BY created_at DESC LIMIT 10'
      );
      const sims = await db.all('SELECT * FROM sims');
      const queuedRow = await db.get<{ c: number | string }>("SELECT COUNT(*) as c FROM messages WHERE status = 'queued'");
      const leasedJobs = await db.all(
        `SELECT m.id, m.destination_masked, m.template_id, m.purpose, m.status, m.is_test, m.leased_at, m.ttl_expires_at, l.lease_expires_at, l.attempt_count
         FROM messages m
         LEFT JOIN gateway_job_leases l ON l.message_id = m.id
         WHERE m.status IN ('queued', 'leased', 'accepted_by_device')
         ORDER BY m.created_at ASC
         LIMIT 20`
      );

      res.json({
        devices,
        enrollment_tokens: tokens,
        sims,
        queued_count: Number(queuedRow?.c ?? 0),
        pending_jobs: leasedJobs,
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/devices/enrollment-tokens', async (req: Request, res: Response) => {
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

      await db.run(
        `INSERT INTO enrollment_tokens (id, device_name, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?)`,
        id,
        String(device_name).trim().slice(0, 80),
        tokenHash,
        expiresAt,
        now.toISOString()
      );

      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'gateway.enrollment_token_created',
        targetType: 'enrollment_token',
        targetId: id,
        metadata: { device_name: String(device_name).trim(), expires_at: expiresAt },
        ipAddress: req.ip,
      });

      res.status(201).json({
        id,
        device_name: String(device_name).trim(),
        enrollment_token_once: rawToken,
        expires_at: expiresAt,
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/devices/:id/action', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { action } = req.body ?? {};
      const devId = req.params.id;
      const dev = await db.get<{ id: string; status: string }>('SELECT id, status FROM gateway_devices WHERE id = ?', devId);
      if (!dev) throw new AppError(404, 'NOT_FOUND', 'Device not found.');

      const nowIso = new Date().toISOString();
      if (action === 'pause') {
        await db.run("UPDATE gateway_devices SET status = 'paused' WHERE id = ? AND status != 'revoked'", devId);
      } else if (action === 'resume') {
        await db.run(
          "UPDATE gateway_devices SET status = CASE WHEN last_heartbeat_at IS NOT NULL THEN 'online' ELSE 'offline' END WHERE id = ? AND status != 'revoked'",
          devId
        );
      } else if (action === 'revoke') {
        await db.run("UPDATE gateway_devices SET status = 'revoked', revoked_at = ? WHERE id = ?", nowIso, devId);
      } else {
        throw new AppError(400, 'BAD_REQUEST', 'Unsupported device action. Allowed: pause, resume, revoke.');
      }

      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: `gateway.device_${action}`,
        targetType: 'gateway_device',
        targetId: devId,
        ipAddress: req.ip,
      });

      res.json({ device: await db.get('SELECT * FROM gateway_devices WHERE id = ?', devId) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- SIM & Usage ---
  router.get('/sim-usage', async (_req: Request, res: Response) => {
    try {
      const sims = await db.all(
        `SELECT s.*, d.name as device_name, d.status as device_status
         FROM sims s JOIN gateway_devices d ON d.id = s.device_id`
      );

      const usageByApp = await db.all<{
        application_id: string;
        application_name: string;
        environment: string;
        daily_limit: number | string;
        total_messages: number | string;
        sent_to_network: number | string | null;
        delivered: number | string | null;
        failed: number | string | null;
        delivery_unknown: number | string | null;
      }>(
        `SELECT a.id as application_id, a.name as application_name, a.environment, a.daily_limit,
                COUNT(m.id) as total_messages,
                SUM(CASE WHEN m.status = 'sent_to_network' THEN 1 ELSE 0 END) as sent_to_network,
                SUM(CASE WHEN m.status = 'delivered' THEN 1 ELSE 0 END) as delivered,
                SUM(CASE WHEN m.status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN m.status = 'delivery_unknown' THEN 1 ELSE 0 END) as delivery_unknown
         FROM applications a
         LEFT JOIN messages m ON m.application_id = a.id
         GROUP BY a.id, a.name, a.environment, a.daily_limit`
      );

      res.json({
        sims,
        usage_by_app: usageByApp.map((r) => ({
          ...r,
          daily_limit: Number(r.daily_limit ?? 0),
          total_messages: Number(r.total_messages ?? 0),
          sent_to_network: Number(r.sent_to_network ?? 0),
          delivered: Number(r.delivered ?? 0),
          failed: Number(r.failed ?? 0),
          delivery_unknown: Number(r.delivery_unknown ?? 0),
        })),
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.patch('/sim-usage/:id/reconcile', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { plan_sms_limit, estimated_sms_sent, warning_threshold, carrier_label, period_start, period_end, notes } = req.body ?? {};
      const sim = await db.get<{ id: string; plan_sms_limit: number; estimated_sms_sent: number }>(
        'SELECT * FROM sims WHERE id = ?',
        req.params.id
      );
      if (!sim) throw new AppError(404, 'NOT_FOUND', 'SIM record not found.');

      const nextLimit = typeof plan_sms_limit === 'number' ? Math.max(0, plan_sms_limit) : Number(sim.plan_sms_limit);
      const nextSent = typeof estimated_sms_sent === 'number' ? Math.max(0, estimated_sms_sent) : Number(sim.estimated_sms_sent);
      const { remaining } = calculateSimRemainingEstimate(nextLimit, nextSent);
      const nowIso = new Date().toISOString();

      await db.run(
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
         WHERE id = ?`,
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

      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'sim.manual_reconciliation',
        targetType: 'sim',
        targetId: req.params.id,
        metadata: { plan_sms_limit: nextLimit, estimated_sms_sent: nextSent, estimated_sms_remaining: remaining },
        ipAddress: req.ip,
      });

      res.json({ sim: await db.get('SELECT * FROM sims WHERE id = ?', req.params.id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Templates ---
  router.get('/templates', async (_req: Request, res: Response) => {
    try {
      const templates = await db.all('SELECT * FROM message_templates ORDER BY created_at DESC');
      res.json({ templates, valid_purposes: VALID_MESSAGE_PURPOSES });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/templates', async (req: Request, res: Response) => {
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
      await db.run(
        `INSERT INTO message_templates (id, owner_user_id, code, purpose, body, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        id,
        owner.id,
        cleanCode,
        cleanPurpose,
        String(body).trim(),
        status === 'draft' ? 'draft' : 'approved',
        nowIso,
        nowIso
      );

      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'template.created',
        targetType: 'message_template',
        targetId: id,
        metadata: { code: cleanCode, purpose: cleanPurpose },
        ipAddress: req.ip,
      });
      res.status(201).json({ template: await db.get('SELECT * FROM message_templates WHERE id = ?', id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.patch('/templates/:id', async (req: Request, res: Response) => {
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
      const result = await db.run(
        `UPDATE message_templates
         SET body = COALESCE(?, body),
             status = COALESCE(?, status),
             purpose = COALESCE(?, purpose),
             updated_at = ?
         WHERE id = ?`,
        body ?? null,
        status ?? null,
        purpose ?? null,
        nowIso,
        req.params.id
      );

      if (result.changes === 0) throw new AppError(404, 'NOT_FOUND', 'Template not found.');
      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'template.updated',
        targetType: 'message_template',
        targetId: req.params.id,
        metadata: { status, purpose },
        ipAddress: req.ip,
      });
      res.json({ template: await db.get('SELECT * FROM message_templates WHERE id = ?', req.params.id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Destination Allowlist ---
  router.get('/allowlist', async (_req: Request, res: Response) => {
    try {
      const entries = await db.all(
        `SELECT d.id, d.application_id, a.name as application_name, d.e164_masked, d.label, d.created_at
         FROM destination_allowlist d JOIN applications a ON a.id = d.application_id
         ORDER BY d.created_at DESC`
      );
      res.json({ entries });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/allowlist', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, phone, label } = req.body ?? {};
      const appExists = await db.get('SELECT id FROM applications WHERE id = ?', String(application_id ?? ''));
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
      await db.run(
        `INSERT INTO destination_allowlist (id, application_id, e164_masked, e164_hash, e164_encrypted, label, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        id,
        String(application_id),
        masked,
        hashDestination(normalized),
        encryptField(normalized),
        String(label || 'Approved Destination').slice(0, 80),
        nowIso
      );

      await writeAuditLog(db, {
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

  router.delete('/allowlist/:id', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      await db.run('DELETE FROM destination_allowlist WHERE id = ?', req.params.id);
      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'allowlist.removed',
        targetType: 'destination_allowlist',
        targetId: req.params.id,
        ipAddress: req.ip,
      });
      res.json({ deleted: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Webhooks (SSRF-hardened HTTPS endpoints only) ---
  router.get('/webhooks', async (_req: Request, res: Response) => {
    try {
      const endpoints = await db.all(
        `SELECT w.id, w.application_id, a.name as application_name, w.url, w.enabled, w.event_types_json, w.created_at
         FROM webhook_endpoints w JOIN applications a ON a.id = w.application_id
         ORDER BY w.created_at DESC`
      );
      const deliveries = await db.all(
        `SELECT d.*, e.url
         FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id
         ORDER BY d.created_at DESC LIMIT 40`
      );
      res.json({ endpoints, deliveries });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/webhooks', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      const { application_id, url, event_types } = req.body ?? {};
      const appExists = await db.get('SELECT id FROM applications WHERE id = ?', String(application_id ?? ''));
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

      await db.run(
        `INSERT INTO webhook_endpoints (id, application_id, url, secret_encrypted, enabled, event_types_json, created_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`,
        id,
        String(application_id),
        cleanUrl,
        encryptField(rawSecret),
        JSON.stringify(events),
        nowIso
      );

      await writeAuditLog(db, {
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

  router.post('/webhooks/:id/test', async (req: Request, res: Response) => {
    try {
      const ep = await db.get<{ id: string; application_id: string; url: string; secret_encrypted: string }>(
        'SELECT id, application_id, url, secret_encrypted FROM webhook_endpoints WHERE id = ?',
        req.params.id
      );
      if (!ep) throw new AppError(404, 'NOT_FOUND', 'Webhook endpoint not found.');
      const eventId = `evt_test_${crypto.randomBytes(4).toString('hex')}`;
      const nowIso = new Date().toISOString();
      const payload = JSON.stringify({ event_id: eventId, event_type: 'message.status', test: true, occurred_at: nowIso });
      await db.run(
        `INSERT INTO webhook_deliveries (id, endpoint_id, event_id, event_type, payload_redacted_json, status, attempt_count, next_attempt_at, last_http_status, created_at)
         VALUES (?, ?, ?, 'message.status', ?, 'pending', 0, ?, NULL, ?)`,
        crypto.randomUUID(),
        ep.id,
        eventId,
        payload,
        nowIso,
        nowIso
      );
      const tick = await runSweeperTick(db);
      res.json({ queued: true, event_id: eventId, sweeper: tick });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.patch('/webhooks/:id/toggle', async (req: Request, res: Response) => {
    try {
      const owner = getOwner(req);
      await db.run('UPDATE webhook_endpoints SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?', req.params.id);
      await writeAuditLog(db, {
        actorType: 'owner',
        actorId: owner.id,
        action: 'webhook.toggled',
        targetType: 'webhook_endpoint',
        targetId: req.params.id,
        ipAddress: req.ip,
      });
      res.json({ ok: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Audit Logs ---
  router.get('/audit-logs', async (req: Request, res: Response) => {
    try {
      const q = typeof req.query.q === 'string' ? req.query.q.trim() : '';
      let sql = 'SELECT * FROM audit_logs WHERE 1=1';
      const params: string[] = [];
      if (q) {
        const likeTerm = `%${escapeLikePattern(q)}%`;
        sql += " AND (LOWER(action) LIKE LOWER(?) ESCAPE '!' OR LOWER(target_type) LIKE LOWER(?) ESCAPE '!' OR LOWER(target_id) LIKE LOWER(?) ESCAPE '!' OR LOWER(metadata_redacted_json) LIKE LOWER(?) ESCAPE '!')";
        params.push(likeTerm, likeTerm, likeTerm, likeTerm);
      }
      sql += ' ORDER BY created_at DESC LIMIT 120';
      res.json({ logs: await db.all(sql, ...params) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  // --- Settings & Kill Switch ---
  router.get('/settings', async (_req: Request, res: Response) => {
    try {
      res.json({ settings: await getSettingsMap(db) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.patch('/settings', async (req: Request, res: Response) => {
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
          await updateSetting(db, k, val, owner.id, req.ip);
        } else if (k in numericBounds) {
          const num = Number(v);
          const [min, max] = numericBounds[k];
          if (!Number.isFinite(num) || num < min || num > max) {
            throw new AppError(422, 'INVALID_SETTING', `Setting ${k} must be between ${min} and ${max}.`);
          }
          await updateSetting(db, k, String(Math.trunc(num)), owner.id, req.ip);
        }
      }
      res.json({ settings: await getSettingsMap(db) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });

  router.post('/sweeper/run', async (_req: Request, res: Response) => {
    try {
      res.json(await runSweeperTick(db));
    } catch (err) {
      sendAdminError(res, err);
    }
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
      vercel_supabase_snippet: `# 1. Create Supabase tables (Supabase Dashboard -> SQL Editor):
#    Paste & run infra/supabase_schema.sql

# 2. Configure .env (local) or Vercel -> Project Settings -> Environment Variables:
SUPABASE_DB_URL="postgresql://postgres.<PROJECT_REF>:<PASSWORD>@aws-0-<REGION>.pooler.supabase.com:6543/postgres"
# OR use separate fields instead of SUPABASE_DB_URL:
# SUPABASE_URL="https://<PROJECT_REF>.supabase.co"
# SUPABASE_DB_PASSWORD="your-db-password"
# SUPABASE_DB_REGION="ap-south-1"

API_KEY_PEPPER="<64-hex-secret>"
JWT_PRIVATE_KEY="<64-hex-secret>"
OTP_PEPPER="<64-hex-secret>"
FIELD_ENCRYPTION_KEY="<64-hex-secret>"
SIMVAULT_ADMIN_EMAIL="owner@yourdomain.com"
SIMVAULT_ADMIN_PASSWORD="ChangeThisStrongPassword!"
CRON_SECRET="<48-hex-secret>"

# 3. Build & Deploy to Vercel:
npm run build`,
      ubuntu_setup_snippet: `# Optional Self-Hosted VPS (Node 22 + systemd + Nginx):
sudo bash deploy/ubuntu-setup.sh sms.yourdomain.com owner@yourdomain.com
npm ci && npm run build && NODE_ENV=production npm run start:prod`,
      ubuntu_nginx_snippet: `server {
  listen 80;
  server_name sms.yourdomain.com;
  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}`,
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
      localHeader.writeUInt16LE(20, 4);
      localHeader.writeUInt16LE(0x0800, 6);
      localHeader.writeUInt16LE(0, 8);
      localHeader.writeUInt16LE(0, 10);
      localHeader.writeUInt16LE(0x5421, 12);
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
