import crypto from 'node:crypto';
import { Router, Request, Response, NextFunction } from 'express';
import { generateDeviceToken, hashApiKey, hashToken } from '../crypto';
import { DbClient, writeAuditLog } from '../db';
import {
  AppError,
  authenticateApiKey,
  authenticateGatewayDevice,
  createOtpChallenge,
  createSmsRequest,
  leaseNextGatewayJob,
  markJobAcceptedByDevice,
  reportDeliveryReceipt,
  reportJobResult,
  requireScope,
  verifyOtpChallenge,
} from '../services';

function getBearer(req: Request): string {
  const auth = req.headers.authorization ?? '';
  if (!auth.startsWith('Bearer ')) {
    throw new AppError(401, 'UNAUTHORIZED', 'Missing Authorization: Bearer token.');
  }
  return auth.slice(7).trim();
}

function sendError(res: Response, err: unknown, requestId: string): void {
  if (err instanceof AppError) {
    res.status(err.status).json({
      error: {
        code: err.code,
        message: err.message,
        request_id: requestId,
      },
    });
    return;
  }
  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'An unexpected server error occurred.',
      request_id: requestId,
    },
  });
}

export function createV1Router(db: DbClient): Router {
  const router = Router();

  router.use((req: Request, _res: Response, next: NextFunction) => {
    (req as Request & { requestId?: string }).requestId = `req_${crypto.randomBytes(6).toString('hex')}`;
    next();
  });

  const getReqId = (req: Request) => (req as Request & { requestId?: string }).requestId ?? 'req_unknown';

  // OpenAPI 3.1 Specification
  router.get('/openapi.json', (_req: Request, res: Response) => {
    res.json({
      openapi: '3.1.0',
      info: {
        title: 'SimVault Personal SIM SMS & OTP API',
        version: '1.0.0',
        description:
          'Application-level SMS and OTP orchestration API routing through an owner-operated Android SIM gateway.',
      },
      servers: [{ url: '/v1' }],
      paths: {
        '/sms': {
          post: {
            summary: 'Queue a templated transactional SMS',
            parameters: [{ name: 'Idempotency-Key', in: 'header', schema: { type: 'string' } }],
            responses: { '202': { description: 'Message queued' } },
          },
        },
        '/otp/challenges': {
          post: {
            summary: 'Create a single-use OTP challenge and queue SMS dispatch',
            responses: { '202': { description: 'Challenge created (OTP secret never returned)' } },
          },
        },
        '/otp/verify': {
          post: {
            summary: 'Verify a submitted OTP code in constant time',
            responses: { '200': { description: 'Verified' }, '422': { description: 'Invalid or expired code' } },
          },
        },
        '/messages/{message_id}': {
          get: {
            summary: 'Retrieve message lifecycle status and timestamps',
            responses: { '200': { description: 'Status metadata' } },
          },
        },
        '/usage': {
          get: {
            summary: 'Retrieve aggregated message usage counts',
            responses: { '200': { description: 'Usage summary' } },
          },
        },
      },
    });
  });

  // POST /v1/sms
  router.post('/sms', async (req: Request, res: Response) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      requireScope(ctx, 'sms:send');

      const { to, template_id, variables, purpose, ttl_seconds } = req.body ?? {};
      if (!to || !template_id || !purpose) {
        throw new AppError(400, 'BAD_REQUEST', 'Fields to, template_id, and purpose are required.');
      }
      const idempotencyKey = typeof req.headers['idempotency-key'] === 'string' ? req.headers['idempotency-key'].trim() : undefined;

      const result = await createSmsRequest(db, {
        applicationId: ctx.applicationId,
        to: String(to),
        templateCode: String(template_id),
        variables: variables && typeof variables === 'object' ? variables : {},
        purpose: String(purpose),
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : undefined,
        idempotencyKey,
        actorId: ctx.keyId,
        ipAddress: req.ip,
      });

      res.status(result.deduplicated ? 200 : 202).json({
        message_id: result.message_id,
        status: result.status,
        created_at: result.created_at,
        ...(result.is_test ? { mode: 'test' } : {}),
        ...(result.deduplicated ? { idempotent_replay: true } : {}),
      });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  // POST /v1/otp/challenges
  router.post('/otp/challenges', async (req: Request, res: Response) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      requireScope(ctx, 'otp:create');

      const { to, purpose, ttl_seconds } = req.body ?? {};
      if (!to || !purpose) {
        throw new AppError(400, 'BAD_REQUEST', 'Fields to and purpose are required.');
      }

      const result = await createOtpChallenge(db, {
        applicationId: ctx.applicationId,
        to: String(to),
        purpose: String(purpose),
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : undefined,
        actorId: ctx.keyId,
        ipAddress: req.ip,
      });

      res.status(202).json({
        challenge_id: result.challenge_id,
        message_id: result.message_id,
        status: result.status,
        expires_at: result.expires_at,
      });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  // POST /v1/otp/verify
  router.post('/otp/verify', async (req: Request, res: Response) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      requireScope(ctx, 'otp:verify');

      const { challenge_id, code } = req.body ?? {};
      if (!challenge_id || !code) {
        throw new AppError(400, 'BAD_REQUEST', 'Fields challenge_id and code are required.');
      }

      const verified = await verifyOtpChallenge(db, {
        applicationId: ctx.applicationId,
        challengeId: String(challenge_id),
        code: String(code),
        ipAddress: req.ip,
      });

      res.json(verified);
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  // GET /v1/messages/:id
  router.get('/messages/:id', async (req: Request, res: Response) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      const row = await db.get(
        `SELECT id, application_id, device_id, destination_masked, template_id, purpose, status, is_test,
                created_at, queued_at, leased_at, accepted_at, sent_at, delivered_at, failed_at, error_code
         FROM messages WHERE id = ? AND application_id = ?`,
        req.params.id,
        ctx.applicationId
      );

      if (!row) {
        throw new AppError(404, 'NOT_FOUND', 'Message not found.');
      }
      res.json(row);
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  // GET /v1/usage
  router.get('/usage', async (req: Request, res: Response) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      requireScope(ctx, 'usage:read');

      const from = typeof req.query.from === 'string' ? req.query.from : new Date(Date.now() - 30 * 86400_000).toISOString();
      const to = typeof req.query.to === 'string' ? req.query.to : new Date().toISOString();

      const byStatus = await db.all<{ status: string; count: number | string }>(
        `SELECT status, COUNT(*) as count
         FROM messages
         WHERE application_id = ? AND created_at >= ? AND created_at <= ?
         GROUP BY status`,
        ctx.applicationId,
        from,
        to
      );

      res.json({
        application_id: ctx.applicationId,
        from,
        to,
        counts_by_status: byStatus.map((r) => ({ status: r.status, count: Number(r.count ?? 0) })),
      });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  // --- Gateway Device Endpoints (authenticated with device credential, never app API key) ---

  router.post('/gateway/enroll', async (req: Request, res: Response) => {
    try {
      const { enrollment_token, device_name, app_version, android_version } = req.body ?? {};
      if (!enrollment_token) {
        throw new AppError(400, 'BAD_REQUEST', 'enrollment_token is required.');
      }

      const tokenHash = hashToken(String(enrollment_token));
      const enrollRow = await db.get<{ id: string; device_name: string; expires_at: string; used_at: string | null }>(
        'SELECT id, device_name, expires_at, used_at FROM enrollment_tokens WHERE token_hash = ?',
        tokenHash
      );

      if (!enrollRow || enrollRow.used_at || new Date(enrollRow.expires_at).getTime() <= Date.now()) {
        throw new AppError(401, 'INVALID_ENROLLMENT_TOKEN', 'Enrollment token is invalid, expired, or already used.');
      }

      const now = new Date();
      const nowIso = now.toISOString();
      const cycleStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10);
      const cycleEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().slice(0, 10);
      const deviceId = `dev_${crypto.randomBytes(5).toString('hex')}`;
      const devCred = generateDeviceToken();

      await db.transaction(async (tx) => {
        const claim = await tx.run(
          'UPDATE enrollment_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL',
          nowIso,
          enrollRow.id
        );
        if (claim.changes === 0) {
          throw new AppError(401, 'INVALID_ENROLLMENT_TOKEN', 'Enrollment token is invalid, expired, or already used.');
        }

        await tx.run(
          `INSERT INTO gateway_devices (id, name, device_token_hash, status, app_version, android_version, permission_send_sms, network_type, battery_pct, sim_ready, last_heartbeat_at, enrolled_at)
           VALUES (?, ?, ?, 'online', ?, ?, 1, 'Pending Heartbeat', 100, 0, ?, ?)`,
          deviceId,
          String(device_name || enrollRow.device_name).slice(0, 80),
          devCred.tokenHash,
          String(app_version || '1.0.0').slice(0, 32),
          String(android_version || '14').slice(0, 40),
          nowIso,
          nowIso
        );
        await tx.run(
          `INSERT INTO sims (id, device_id, carrier_label, masked_msisdn, slot_index, plan_sms_limit, period_start, period_end, estimated_sms_sent, estimated_sms_remaining, warning_threshold, notes, updated_at)
           VALUES (?, ?, ?, ?, 0, 3000, ?, ?, 0, 3000, 300, ?, ?)`,
          `sim_${deviceId}_0`,
          deviceId,
          'Active SIM Slot 0',
          'Pending telemetry',
          cycleStart,
          cycleEnd,
          'Live SIM — reconcile monthly against your carrier statement.',
          nowIso
        );
      });

      await writeAuditLog(db, {
        actorType: 'device',
        actorId: deviceId,
        action: 'gateway.device_enrolled',
        targetType: 'gateway_device',
        targetId: deviceId,
        metadata: { device_name: String(device_name || enrollRow.device_name), android_version: String(android_version || '14') },
        ipAddress: req.ip,
      });

      res.status(201).json({
        device_id: deviceId,
        device_token: devCred.rawToken,
        enrolled_at: nowIso,
      });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  router.post('/gateway/heartbeat', async (req: Request, res: Response) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const {
        app_version,
        android_version,
        permission_send_sms,
        network_type,
        battery_pct,
        sim_ready,
        sim_slot,
        carrier_label,
        masked_msisdn,
      } = req.body ?? {};
      const now = new Date();
      const nowIso = now.toISOString();
      const nextStatus = dev.status === 'paused' ? 'paused' : 'online';
      const boundedBattery =
        typeof battery_pct === 'number' && Number.isFinite(battery_pct)
          ? Math.max(0, Math.min(100, Math.round(battery_pct)))
          : null;

      await db.run(
        `UPDATE gateway_devices
         SET status = ?,
             app_version = COALESCE(?, app_version),
             android_version = COALESCE(?, android_version),
             permission_send_sms = COALESCE(?, permission_send_sms),
             network_type = COALESCE(?, network_type),
             battery_pct = COALESCE(?, battery_pct),
             sim_ready = COALESCE(?, sim_ready),
             last_heartbeat_at = ?
         WHERE id = ?`,
        nextStatus,
        app_version ? String(app_version).slice(0, 32) : null,
        android_version ? String(android_version).slice(0, 40) : null,
        typeof permission_send_sms === 'boolean' ? (permission_send_sms ? 1 : 0) : null,
        network_type ? String(network_type).slice(0, 40) : null,
        boundedBattery,
        typeof sim_ready === 'boolean' ? (sim_ready ? 1 : 0) : null,
        nowIso,
        dev.id
      );

      if (carrier_label || masked_msisdn || typeof sim_slot === 'number') {
        const slotIdx = typeof sim_slot === 'number' && Number.isFinite(sim_slot) ? Math.max(0, Math.min(3, Math.trunc(sim_slot))) : 0;
        const simRow = await db.get<{ id: string }>(
          'SELECT id FROM sims WHERE device_id = ? AND slot_index = ?',
          dev.id,
          slotIdx
        );
        if (simRow) {
          await db.run(
            `UPDATE sims
             SET carrier_label = COALESCE(?, carrier_label),
                 masked_msisdn = COALESCE(?, masked_msisdn),
                 updated_at = ?
             WHERE id = ?`,
            carrier_label ? String(carrier_label).slice(0, 64) : null,
            masked_msisdn ? String(masked_msisdn).slice(0, 32) : null,
            nowIso,
            simRow.id
          );
        } else {
          const cycleStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10);
          const cycleEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().slice(0, 10);
          await db.run(
            `INSERT INTO sims (id, device_id, carrier_label, masked_msisdn, slot_index, plan_sms_limit, period_start, period_end, estimated_sms_sent, estimated_sms_remaining, warning_threshold, notes, updated_at)
             VALUES (?, ?, ?, ?, ?, 3000, ?, ?, 0, 3000, 300, ?, ?)`,
            `sim_${dev.id}_${slotIdx}`,
            dev.id,
            carrier_label ? String(carrier_label).slice(0, 64) : `SIM Slot ${slotIdx}`,
            masked_msisdn ? String(masked_msisdn).slice(0, 32) : 'Pending telemetry',
            slotIdx,
            cycleStart,
            cycleEnd,
            'Live SIM — reconcile monthly against your carrier statement.',
            nowIso
          );
        }
      }

      res.json({ device_id: dev.id, status: nextStatus, server_time: nowIso });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  router.get('/gateway/jobs/next', async (req: Request, res: Response) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const job = await leaseNextGatewayJob(db, dev.id);
      if (!job) {
        res.status(204).end();
        return;
      }
      res.json(job);
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  router.post('/gateway/jobs/:id/accepted', async (req: Request, res: Response) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const result = await markJobAcceptedByDevice(db, dev.id, req.params.id);
      res.json({ job_id: req.params.id, ...result });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  router.post('/gateway/jobs/:id/result', async (req: Request, res: Response) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const { status, error_code } = req.body ?? {};
      if (!['sent_to_network', 'failed', 'delivery_unknown'].includes(status)) {
        throw new AppError(400, 'BAD_REQUEST', 'status must be sent_to_network, failed, or delivery_unknown.');
      }
      const result = await reportJobResult(db, dev.id, req.params.id, status, error_code);
      res.json({ job_id: req.params.id, ...result });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  router.post('/gateway/jobs/:id/delivery-report', async (req: Request, res: Response) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const result = await reportDeliveryReceipt(db, dev.id, req.params.id);
      res.json({ job_id: req.params.id, ...result });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });

  return router;
}
