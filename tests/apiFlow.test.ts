import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import { createIsolatedTestDb, resolveDbPath, syncEnvAdminCredentials } from '../server/db';
import { decryptField, generateApiKey, hashApiKey, hashOtpCode, verifyPassword } from '../server/crypto';
import { createAdminRouter } from '../server/routes/admin';
import { createV1Router } from '../server/routes/v1';
import {
  AppError,
  assertPublicWebhookHost,
  authenticateApiKey,
  createOtpChallenge,
  createSmsRequest,
  leaseNextGatewayJob,
  markJobAcceptedByDevice,
  reportJobResult,
  runSweeperTick,
  verifyOtpChallenge,
} from '../server/services';

async function withServer(db: ReturnType<typeof createIsolatedTestDb>, fn: (baseUrl: string) => Promise<void>) {
  const app = express();
  app.use(express.json({ limit: '64kb' }));
  app.use('/v1', createV1Router(db));
  app.use('/api/admin', createAdminRouter(db));
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const addr = server.address() as { port: number };
  try {
    await fn(`http://127.0.0.1:${addr.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('Live mode fresh DB starts clean with zero demo devices, messages, OTPs, or keys', () => {
  const db = createIsolatedTestDb();
  const deviceCount = (db.prepare('SELECT COUNT(*) as c FROM gateway_devices').get() as { c: number }).c;
  const msgCount = (db.prepare('SELECT COUNT(*) as c FROM messages').get() as { c: number }).c;
  const otpCount = (db.prepare('SELECT COUNT(*) as c FROM otp_challenges').get() as { c: number }).c;
  const keyCount = (db.prepare('SELECT COUNT(*) as c FROM api_keys').get() as { c: number }).c;
  const whCount = (db.prepare('SELECT COUNT(*) as c FROM webhook_endpoints').get() as { c: number }).c;

  assert.equal(deviceCount, 0);
  assert.equal(msgCount, 0);
  assert.equal(otpCount, 0);
  assert.equal(keyCount, 0);
  assert.equal(whCount, 0);
});

test('API key creation, authentication, and revocation work on live app', () => {
  const db = createIsolatedTestDb();
  const { rawKey, keyPrefix, secretHash } = generateApiKey('live');

  db.prepare(
    `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
     VALUES (?, 'app_portal_prod', 'Live Key', ?, ?, '["sms:send","otp:create","otp:verify"]', 'active', ?)`
  ).run('key_live_1', keyPrefix, secretHash, new Date().toISOString());

  const ctx = authenticateApiKey(db, rawKey, hashApiKey);
  assert.equal(ctx.applicationId, 'app_portal_prod');
  assert.equal(ctx.environment, 'live');

  db.prepare("UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE id = 'key_live_1'").run(new Date().toISOString());
  assert.throws(
    () => authenticateApiKey(db, rawKey, hashApiKey),
    (err: unknown) => err instanceof AppError && err.code === 'KEY_REVOKED'
  );
});

test('Idempotency-Key deduplicates repeated SMS requests without creating duplicate jobs', () => {
  const db = createIsolatedTestDb();

  const first = createSmsRequest(db, {
    applicationId: 'app_portal_prod',
    to: '+919876543210',
    templateCode: 'login_notice',
    variables: { name: 'User', device_label: 'Web' },
    purpose: 'account_transactional',
    idempotencyKey: 'idem_live_001',
    actorId: 'test',
  });
  const second = createSmsRequest(db, {
    applicationId: 'app_portal_prod',
    to: '+919876543210',
    templateCode: 'login_notice',
    variables: { name: 'User', device_label: 'Web' },
    purpose: 'account_transactional',
    idempotencyKey: 'idem_live_001',
    actorId: 'test',
  });

  assert.equal(first.deduplicated, false);
  assert.equal(second.deduplicated, true);
  assert.equal(first.message_id, second.message_id);
});

test('OTP challenge verifies once from encrypted outbound payload, rejects replay, and locks after 5 bad attempts', () => {
  const db = createIsolatedTestDb();

  const created = createOtpChallenge(db, {
    applicationId: 'app_portal_prod',
    to: '+919876543210',
    purpose: 'login',
    ttlSeconds: 300,
    actorId: 'test',
    bypassCooldown: true,
  });

  // Confirm DB OTP row stores only HMAC hash (not plaintext), while outbound SMS body is encrypted
  const otpRow = db.prepare('SELECT code_hash, message_id FROM otp_challenges WHERE id = ?').get(created.challenge_id) as {
    code_hash: string;
    message_id: string;
  };
  const msgRow = db.prepare('SELECT body_encrypted FROM messages WHERE id = ?').get(otpRow.message_id) as {
    body_encrypted: string;
  };
  const smsBody = decryptField(msgRow.body_encrypted);
  const match = /\b(\d{6})\b/.exec(smsBody);
  assert.ok(match, 'Queued encrypted SMS payload should contain 6-digit OTP');
  const code = match[1];

  assert.notEqual(otpRow.code_hash, code);
  assert.equal(otpRow.code_hash, hashOtpCode(created.challenge_id, code));

  const verified = verifyOtpChallenge(db, {
    applicationId: 'app_portal_prod',
    challengeId: created.challenge_id,
    code,
  });
  assert.equal(verified.verified, true);

  assert.throws(
    () => verifyOtpChallenge(db, { applicationId: 'app_portal_prod', challengeId: created.challenge_id, code }),
    (err: unknown) => err instanceof AppError && err.code === 'OTP_INVALID'
  );

  const created2 = createOtpChallenge(db, {
    applicationId: 'app_portal_prod',
    to: '+919811223344',
    purpose: 'login',
    ttlSeconds: 300,
    actorId: 'test',
    bypassCooldown: true,
  });
  for (let i = 0; i < 5; i++) {
    assert.throws(
      () => verifyOtpChallenge(db, { applicationId: 'app_portal_prod', challengeId: created2.challenge_id, code: '000000' }),
      (err: unknown) => err instanceof AppError && err.code === 'OTP_INVALID'
    );
  }
  const lockedRow = db.prepare('SELECT status, attempts FROM otp_challenges WHERE id = ?').get(created2.challenge_id) as {
    status: string;
    attempts: number;
  };
  assert.equal(lockedRow.status, 'locked');
  assert.equal(lockedRow.attempts, 5);
});

test('Admin endpoints enforce strict 401 auth, CSRF protection, enrollment -> SIM creation -> lease/TTL lifecycle, and SSRF protection', async () => {
  const db = createIsolatedTestDb();

  await assert.rejects(
    () => assertPublicWebhookHost('https://127.0.0.1/hook'),
    (err: unknown) => err instanceof AppError && err.status === 422
  );

  await withServer(db, async (baseUrl) => {
    // 1. Unauthenticated access to admin API must return 401
    const unauthOverview = await fetch(`${baseUrl}/api/admin/overview`);
    assert.equal(unauthOverview.status, 401);

    // 2. Owner login succeeds and issues session cookie + CSRF token
    const loginRes = await fetch(`${baseUrl}/api/admin/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owner@simvault.local', password: 'SimVault!2026' }),
    });
    assert.equal(loginRes.status, 200);
    const cookieHeader = (loginRes.headers.get('set-cookie') ?? '').split(';')[0];
    const loginBody = (await loginRes.json()) as { authenticated: boolean; csrf_token: string };
    assert.equal(loginBody.authenticated, true);
    assert.ok(loginBody.csrf_token);

    // 3. State-changing admin request without X-CSRF-Token must fail 403
    const noCsrfRes = await fetch(`${baseUrl}/api/admin/devices/enrollment-tokens`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookieHeader },
      body: JSON.stringify({ device_name: 'Pixel 8 Live', ttl_minutes: 15 }),
    });
    assert.equal(noCsrfRes.status, 403);

    // 4. Generate one-time enrollment token with CSRF header
    const tokenRes = await fetch(`${baseUrl}/api/admin/devices/enrollment-tokens`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({ device_name: 'Pixel 8 Live', ttl_minutes: 15 }),
    });
    assert.equal(tokenRes.status, 201);
    const { enrollment_token_once } = (await tokenRes.json()) as { enrollment_token_once: string };

    // 5. Enroll physical Android device via /v1/gateway/enroll (creates device + SIM row)
    const enrollRes = await fetch(`${baseUrl}/v1/gateway/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollment_token: enrollment_token_once,
        device_name: 'Pixel 8 Live',
        app_version: '1.0.0',
        android_version: '14 (API 34)',
      }),
    });
    assert.equal(enrollRes.status, 201);
    const enrolled = (await enrollRes.json()) as { device_id: string; device_token: string };

    const simRow = db.prepare('SELECT id FROM sims WHERE device_id = ?').get(enrolled.device_id) as { id: string } | undefined;
    assert.ok(simRow, 'Enrolling a gateway device should initialize its SIM quota record');

    // 6. Heartbeat updates permission/SIM readiness
    const hbRes = await fetch(`${baseUrl}/v1/gateway/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${enrolled.device_token}`,
      },
      body: JSON.stringify({
        app_version: '1.0.0',
        android_version: '14 (API 34)',
        permission_send_sms: true,
        network_type: 'Wi-Fi',
        battery_pct: 88,
        sim_ready: true,
        sim_slot: 0,
        carrier_label: 'Jio 5G',
        masked_msisdn: '+91••••••4321',
      }),
    });
    assert.equal(hbRes.status, 200);

    // 7. Queue live SMS, lease by device, test lease expiry & TTL expiry via sweeper
    const sms = createSmsRequest(db, {
      applicationId: 'app_portal_prod',
      to: '+919876543210',
      templateCode: 'login_notice',
      variables: { name: 'Owner', device_label: 'Pixel 8' },
      purpose: 'account_transactional',
      actorId: 'test',
    });

    const leased = leaseNextGatewayJob(db, enrolled.device_id);
    assert.ok(leased);
    assert.equal(leased.job_id, sms.message_id);

    markJobAcceptedByDevice(db, enrolled.device_id, leased.job_id);
    db.prepare('UPDATE gateway_job_leases SET lease_expires_at = ? WHERE message_id = ?').run(
      new Date(Date.now() - 10_000).toISOString(),
      sms.message_id
    );
    const tick = runSweeperTick(db);
    assert.equal(tick.requeuedLeases, 1);

    const msgAfterRequeue = db.prepare('SELECT status FROM messages WHERE id = ?').get(sms.message_id) as { status: string };
    assert.equal(msgAfterRequeue.status, 'queued');

    db.prepare('UPDATE messages SET ttl_expires_at = ? WHERE id = ?').run(new Date(Date.now() - 5000).toISOString(), sms.message_id);
    const tick2 = runSweeperTick(db);
    assert.equal(tick2.expiredMessages, 1);
    const expiredRow = db.prepare('SELECT status, error_code FROM messages WHERE id = ?').get(sms.message_id) as {
      status: string;
      error_code: string;
    };
    assert.equal(expiredRow.status, 'expired');
    assert.equal(expiredRow.error_code, 'TTL_EXPIRED');

    // 8. Verify MFA endpoint never exposes current_demo_code
    const mfaRes = await fetch(`${baseUrl}/api/admin/security/mfa`, {
      headers: { Cookie: cookieHeader },
    });
    assert.equal(mfaRes.status, 200);
    const mfaJson = (await mfaRes.json()) as Record<string, unknown>;
    assert.equal('current_demo_code' in mfaJson, false);

    // 9. Verify SSRF webhook rejected via admin API
    const badWhRes = await fetch(`${baseUrl}/api/admin/webhooks`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({ application_id: 'app_portal_prod', url: 'https://169.254.169.254/latest/meta-data' }),
    });
    assert.equal(badWhRes.status, 422);
    assert.ok(reportJobResult);
    assert.ok(crypto.randomBytes(1).length === 1);
  });
});

test('resolveDbPath handles empty strings, sqlite:// URIs, and relative paths', () => {
  assert.equal(resolveDbPath(':memory:'), ':memory:');
  assert.equal(resolveDbPath(''), path.resolve(process.cwd(), 'data', 'simvault.db'));
  assert.equal(resolveDbPath('   '), path.resolve(process.cwd(), 'data', 'simvault.db'));
  assert.equal(resolveDbPath('sqlite://./data/custom.db'), path.resolve(process.cwd(), 'data/custom.db'));
});

test('syncEnvAdminCredentials updates existing owner email/password when .env values change without clobbering unchanged restarts', () => {
  const db = createIsolatedTestDb();

  // Updating via .env overrides updates the seeded owner user
  const updated1 = syncEnvAdminCredentials(db, { email: 'admin@example.org', password: 'NewStrongPassword!99' });
  assert.equal(updated1, true);
  const row1 = db.prepare("SELECT email, password_hash FROM users WHERE id = 'usr_owner_primary'").get() as {
    email: string;
    password_hash: string;
  };
  assert.equal(row1.email, 'admin@example.org');
  assert.equal(verifyPassword('NewStrongPassword!99', row1.password_hash), true);

  // Calling again with identical .env values is a no-op so UI password changes are preserved
  const updated2 = syncEnvAdminCredentials(db, { email: 'admin@example.org', password: 'NewStrongPassword!99' });
  assert.equal(updated2, false);

  // Changing password in .env again triggers another sync
  const updated3 = syncEnvAdminCredentials(db, { email: 'admin@example.org', password: 'RotatedEnvPassword!22' });
  assert.equal(updated3, true);
  const row2 = db.prepare("SELECT password_hash FROM users WHERE id = 'usr_owner_primary'").get() as { password_hash: string };
  assert.equal(verifyPassword('RotatedEnvPassword!22', row2.password_hash), true);
});

