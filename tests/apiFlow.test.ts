import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import {
  convertPlaceholdersToPostgres,
  createIsolatedTestDb,
  DbClient,
  resolveDbPath,
  resolvePostgresUrl,
  syncEnvAdminCredentials,
} from '../server/db';
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

async function withServer(db: DbClient, fn: (baseUrl: string) => Promise<void>) {
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

test('Live mode fresh DB starts clean with zero demo devices, messages, OTPs, or keys', async () => {
  const db = await createIsolatedTestDb();
  const deviceCount = Number((await db.get<{ c: number }>('SELECT COUNT(*) as c FROM gateway_devices'))?.c ?? 0);
  const msgCount = Number((await db.get<{ c: number }>('SELECT COUNT(*) as c FROM messages'))?.c ?? 0);
  const otpCount = Number((await db.get<{ c: number }>('SELECT COUNT(*) as c FROM otp_challenges'))?.c ?? 0);
  const keyCount = Number((await db.get<{ c: number }>('SELECT COUNT(*) as c FROM api_keys'))?.c ?? 0);
  const whCount = Number((await db.get<{ c: number }>('SELECT COUNT(*) as c FROM webhook_endpoints'))?.c ?? 0);

  assert.equal(deviceCount, 0);
  assert.equal(msgCount, 0);
  assert.equal(otpCount, 0);
  assert.equal(keyCount, 0);
  assert.equal(whCount, 0);
});

test('API key creation, authentication, and revocation work on live app', async () => {
  const db = await createIsolatedTestDb();
  const { rawKey, keyPrefix, secretHash } = generateApiKey('live');

  await db.run(
    `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
     VALUES (?, 'app_portal_prod', 'Live Key', ?, ?, '["sms:send","otp:create","otp:verify"]', 'active', ?)`,
    'key_live_1',
    keyPrefix,
    secretHash,
    new Date().toISOString()
  );

  const ctx = await authenticateApiKey(db, rawKey, hashApiKey);
  assert.equal(ctx.applicationId, 'app_portal_prod');
  assert.equal(ctx.environment, 'live');

  await db.run("UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE id = 'key_live_1'", new Date().toISOString());
  await assert.rejects(
    () => authenticateApiKey(db, rawKey, hashApiKey),
    (err: unknown) => err instanceof AppError && err.code === 'KEY_REVOKED'
  );
});

test('Idempotency-Key deduplicates repeated SMS requests without creating duplicate jobs', async () => {
  const db = await createIsolatedTestDb();

  const first = await createSmsRequest(db, {
    applicationId: 'app_portal_prod',
    to: '+919876543210',
    templateCode: 'login_notice',
    variables: { name: 'User', device_label: 'Web' },
    purpose: 'account_transactional',
    idempotencyKey: 'idem_live_001',
    actorId: 'test',
  });
  const second = await createSmsRequest(db, {
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

test('OTP challenge verifies once from encrypted outbound payload, rejects replay, and locks after 5 bad attempts', async () => {
  const db = await createIsolatedTestDb();

  const created = await createOtpChallenge(db, {
    applicationId: 'app_portal_prod',
    to: '+919876543210',
    purpose: 'login',
    ttlSeconds: 300,
    actorId: 'test',
    bypassCooldown: true,
  });

  // Confirm DB OTP row stores only HMAC hash (not plaintext), while outbound SMS body is encrypted
  const otpRow = (await db.get<{ code_hash: string; message_id: string }>(
    'SELECT code_hash, message_id FROM otp_challenges WHERE id = ?',
    created.challenge_id
  ))!;
  const msgRow = (await db.get<{ body_encrypted: string }>(
    'SELECT body_encrypted FROM messages WHERE id = ?',
    otpRow.message_id
  ))!;
  const smsBody = decryptField(msgRow.body_encrypted);
  const match = /\b(\d{6})\b/.exec(smsBody);
  assert.ok(match, 'Queued encrypted SMS payload should contain 6-digit OTP');
  const code = match[1];

  assert.notEqual(otpRow.code_hash, code);
  assert.equal(otpRow.code_hash, hashOtpCode(created.challenge_id, code));

  const verified = await verifyOtpChallenge(db, {
    applicationId: 'app_portal_prod',
    challengeId: created.challenge_id,
    code,
  });
  assert.equal(verified.verified, true);

  await assert.rejects(
    () => verifyOtpChallenge(db, { applicationId: 'app_portal_prod', challengeId: created.challenge_id, code }),
    (err: unknown) => err instanceof AppError && err.code === 'OTP_INVALID'
  );

  const created2 = await createOtpChallenge(db, {
    applicationId: 'app_portal_prod',
    to: '+919811223344',
    purpose: 'login',
    ttlSeconds: 300,
    actorId: 'test',
    bypassCooldown: true,
  });
  for (let i = 0; i < 5; i++) {
    await assert.rejects(
      () => verifyOtpChallenge(db, { applicationId: 'app_portal_prod', challengeId: created2.challenge_id, code: '000000' }),
      (err: unknown) => err instanceof AppError && err.code === 'OTP_INVALID'
    );
  }
  const lockedRow = (await db.get<{ status: string; attempts: number }>(
    'SELECT status, attempts FROM otp_challenges WHERE id = ?',
    created2.challenge_id
  ))!;
  assert.equal(lockedRow.status, 'locked');
  assert.equal(lockedRow.attempts, 5);
});

test('Admin endpoints enforce strict 401 auth, CSRF protection, enrollment -> SIM creation -> lease/TTL lifecycle, and SSRF protection', async () => {
  const db = await createIsolatedTestDb();

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

    const simRow = await db.get<{ id: string }>('SELECT id FROM sims WHERE device_id = ?', enrolled.device_id);
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
    const sms = await createSmsRequest(db, {
      applicationId: 'app_portal_prod',
      to: '+919876543210',
      templateCode: 'login_notice',
      variables: { name: 'Owner', device_label: 'Pixel 8' },
      purpose: 'account_transactional',
      actorId: 'test',
    });

    const leased = await leaseNextGatewayJob(db, enrolled.device_id);
    assert.ok(leased);
    assert.equal(leased.job_id, sms.message_id);

    await markJobAcceptedByDevice(db, enrolled.device_id, leased.job_id);
    await db.run(
      'UPDATE gateway_job_leases SET lease_expires_at = ? WHERE message_id = ?',
      new Date(Date.now() - 10_000).toISOString(),
      sms.message_id
    );
    const tick = await runSweeperTick(db);
    assert.equal(tick.requeuedLeases, 1);

    const msgAfterRequeue = (await db.get<{ status: string }>('SELECT status FROM messages WHERE id = ?', sms.message_id))!;
    assert.equal(msgAfterRequeue.status, 'queued');

    await db.run(
      'UPDATE messages SET ttl_expires_at = ? WHERE id = ?',
      new Date(Date.now() - 5000).toISOString(),
      sms.message_id
    );
    const tick2 = await runSweeperTick(db);
    assert.equal(tick2.expiredMessages, 1);
    const expiredRow = (await db.get<{ status: string; error_code: string }>(
      'SELECT status, error_code FROM messages WHERE id = ?',
      sms.message_id
    ))!;
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

test('convertPlaceholdersToPostgres converts SQL bind ? without modifying string literals or comments', () => {
  const input =
    "SELECT * FROM messages WHERE status = '?' AND id = ? /* comment ? */ AND note = 'it''s ?' AND app = ?";
  const output = convertPlaceholdersToPostgres(input);
  assert.equal(
    output,
    "SELECT * FROM messages WHERE status = '?' AND id = $1 /* comment ? */ AND note = 'it''s ?' AND app = $2"
  );
});

test('syncEnvAdminCredentials updates existing owner email/password when .env values change without clobbering unchanged restarts', async () => {
  const db = await createIsolatedTestDb();

  // Updating via .env overrides updates the seeded owner user
  const updated1 = await syncEnvAdminCredentials(db, { email: 'admin@example.org', password: 'NewStrongPassword!99' });
  assert.equal(updated1, true);
  const row1 = (await db.get<{ email: string; password_hash: string }>(
    "SELECT email, password_hash FROM users WHERE id = 'usr_owner_primary'"
  ))!;
  assert.equal(row1.email, 'admin@example.org');
  assert.equal(verifyPassword('NewStrongPassword!99', row1.password_hash), true);

  // Calling again with identical .env values is a no-op so UI password changes are preserved
  const updated2 = await syncEnvAdminCredentials(db, { email: 'admin@example.org', password: 'NewStrongPassword!99' });
  assert.equal(updated2, false);

  // Changing password in .env again triggers another sync
  const updated3 = await syncEnvAdminCredentials(db, { email: 'admin@example.org', password: 'RotatedEnvPassword!22' });
  assert.equal(updated3, true);
  const row2 = (await db.get<{ password_hash: string }>(
    "SELECT password_hash FROM users WHERE id = 'usr_owner_primary'"
  ))!;
  assert.equal(verifyPassword('RotatedEnvPassword!22', row2.password_hash), true);
});

test('resolvePostgresUrl supports SUPABASE_DB_URL, quote stripping, POSTGRES_URL, and SUPABASE_URL + SUPABASE_DB_PASSWORD + SUPABASE_DB_REGION', () => {
  assert.equal(
    resolvePostgresUrl({
      SUPABASE_DB_URL: '"postgresql://postgres.ref:pass@aws-0-ap-south-1.pooler.supabase.com:6543/postgres"',
    }),
    'postgresql://postgres.ref:pass@aws-0-ap-south-1.pooler.supabase.com:6543/postgres'
  );

  assert.equal(
    resolvePostgresUrl({
      POSTGRES_URL: " 'postgresql://user:pass@localhost:5432/simvault' ",
    }),
    'postgresql://user:pass@localhost:5432/simvault'
  );

  assert.equal(
    resolvePostgresUrl({
      SUPABASE_URL: 'https://nysrogpulcrnvgprbczh.supabase.co',
      SUPABASE_DB_PASSWORD: 'p@ss#word!',
      SUPABASE_DB_REGION: 'ap-south-1',
    }),
    'postgresql://postgres.nysrogpulcrnvgprbczh:p%40ss%23word!@aws-0-ap-south-1.pooler.supabase.com:6543/postgres'
  );

  assert.equal(
    resolvePostgresUrl({
      SUPABASE_URL: 'https://nysrogpulcrnvgprbczh.supabase.co',
      SUPABASE_DB_PASSWORD: 'secret',
      SUPABASE_DB_POOLER_HOST: 'aws-1-ap-south-1.pooler.supabase.com',
    }),
    'postgresql://postgres.nysrogpulcrnvgprbczh:secret@aws-1-ap-south-1.pooler.supabase.com:6543/postgres'
  );

  assert.equal(
    resolvePostgresUrl({
      SUPABASE_URL: 'https://nysrogpulcrnvgprbczh.supabase.co',
      SUPABASE_DB_PASSWORD: 'secret',
    }),
    'postgresql://postgres:secret@db.nysrogpulcrnvgprbczh.supabase.co:5432/postgres'
  );

  assert.equal(
    resolvePostgresUrl({
      SUPABASE_DB_URL: 'https://nysrogpulcrnvgprbczh.supabase.co',
      SUPABASE_DB_PASSWORD: 'p@ss#word!',
      SUPABASE_DB_REGION: 'ap-south-1',
    }),
    'postgresql://postgres.nysrogpulcrnvgprbczh:p%40ss%23word!@aws-0-ap-south-1.pooler.supabase.com:6543/postgres'
  );
});

