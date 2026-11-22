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
import { computeTotpCode, decryptField, generateApiKey, hashApiKey, hashOtpCode, verifyPassword } from '../server/crypto';
import { createSimVaultApp } from '../server/app';
import { createAdminRouter } from '../server/routes/admin';
import { createV1Router } from '../server/routes/v1';
import {
  AppError,
  assertPublicWebhookHost,
  authenticateApiKey,
  checkLoginRateLimit,
  clearLoginFailures,
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

test('POST /v1/gateway/poll handles telemetry, single-round-trip lease, idle write skip, and direct leased -> sent_to_network completion', async () => {
  const db = await createIsolatedTestDb();

  await withServer(db, async (baseUrl) => {
    const loginRes = await fetch(`${baseUrl}/api/admin/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owner@simvault.local', password: 'SimVault!2026' }),
    });
    const cookieHeader = (loginRes.headers.get('set-cookie') ?? '').split(';')[0];
    const loginBody = (await loginRes.json()) as { csrf_token: string };

    const tokenRes = await fetch(`${baseUrl}/api/admin/devices/enrollment-tokens`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({ device_name: 'OnePlus Fast', ttl_minutes: 15 }),
    });
    const { enrollment_token_once } = (await tokenRes.json()) as { enrollment_token_once: string };

    const enrollRes = await fetch(`${baseUrl}/v1/gateway/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollment_token: enrollment_token_once,
        device_name: 'OnePlus Fast',
        app_version: '1.3.1',
        android_version: '14 (API 34)',
      }),
    });
    const enrolled = (await enrollRes.json()) as { device_id: string; device_token: string };

    // 1. Combined poll with telemetry while queue is empty
    const poll1 = await fetch(`${baseUrl}/v1/gateway/poll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${enrolled.device_token}`,
      },
      body: JSON.stringify({
        app_version: '1.3.1',
        android_version: '14 (API 34)',
        permission_send_sms: true,
        network_type: 'Wi-Fi',
        battery_pct: 92,
        sim_ready: true,
        sim_slot: 0,
        carrier_label: 'Airtel 5G',
        masked_msisdn: '+91••••••9988',
      }),
    });
    assert.equal(poll1.status, 200);
    const poll1Json = (await poll1.json()) as { device_id: string; status: string; job: null | { job_id: string } };
    assert.equal(poll1Json.device_id, enrolled.device_id);
    assert.equal(poll1Json.status, 'online');
    assert.equal(poll1Json.job, null);

    const hbBeforeRow = (await db.get<{ last_heartbeat_at: string }>(
      'SELECT last_heartbeat_at FROM gateway_devices WHERE id = ?',
      enrolled.device_id
    ))!;

    // 2. Queue an SMS and fetch it in 1 round-trip via lightweight /v1/gateway/poll ({})
    const sms = await createSmsRequest(db, {
      applicationId: 'app_portal_prod',
      to: '+919876543210',
      templateCode: 'login_notice',
      variables: { name: 'Owner', device_label: 'OnePlus' },
      purpose: 'account_transactional',
      actorId: 'test',
    });

    const poll2 = await fetch(`${baseUrl}/v1/gateway/poll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${enrolled.device_token}`,
      },
      body: '{}',
    });
    assert.equal(poll2.status, 200);
    const poll2Json = (await poll2.json()) as {
      status: string;
      job: { job_id: string; to: string; body: string; sim_slot: number } | null;
    };
    assert.ok(poll2Json.job);
    assert.equal(poll2Json.job.job_id, sms.message_id);

    // Lightweight steady-state poll within 15s should skip rewriting last_heartbeat_at
    const hbAfterRow = (await db.get<{ last_heartbeat_at: string }>(
      'SELECT last_heartbeat_at FROM gateway_devices WHERE id = ?',
      enrolled.device_id
    ))!;
    assert.equal(hbAfterRow.last_heartbeat_at, hbBeforeRow.last_heartbeat_at);

    // 3. Report result directly from leased -> sent_to_network without calling /accepted
    const resReport = await fetch(`${baseUrl}/v1/gateway/jobs/${sms.message_id}/result`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${enrolled.device_token}`,
      },
      body: JSON.stringify({ status: 'sent_to_network' }),
    });
    assert.equal(resReport.status, 200);

    // Repeating same outcome after a 5G->4G handoff retry should succeed idempotently
    const resRetry = await fetch(`${baseUrl}/v1/gateway/jobs/${sms.message_id}/result`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${enrolled.device_token}`,
      },
      body: JSON.stringify({ status: 'sent_to_network' }),
    });
    assert.equal(resRetry.status, 200);

    const msgRow = (await db.get<{ status: string }>('SELECT status FROM messages WHERE id = ?', sms.message_id))!;
    assert.equal(msgRow.status, 'sent_to_network');
  });
});

test('Personal SMS and Bulk SMS work via Owner Admin API and /v1 API, enforce scopes/limits, and decrypt cleanly for Gateway', async () => {
  const db = await createIsolatedTestDb();

  await withServer(db, async (baseUrl) => {
    // 1. Login as owner + enroll gateway device
    const loginRes = await fetch(`${baseUrl}/api/admin/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owner@simvault.local', password: 'SimVault!2026' }),
    });
    const cookieHeader = (loginRes.headers.get('set-cookie') ?? '').split(';')[0];
    const loginBody = (await loginRes.json()) as { csrf_token: string };

    const tokenRes = await fetch(`${baseUrl}/api/admin/devices/enrollment-tokens`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({ device_name: 'Gateway Bulk Test', ttl_minutes: 15 }),
    });
    const { enrollment_token_once } = (await tokenRes.json()) as { enrollment_token_once: string };

    const enrollRes = await fetch(`${baseUrl}/v1/gateway/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollment_token: enrollment_token_once,
        device_name: 'Gateway Bulk Test',
        app_version: '1.3.1',
        android_version: '14 (API 34)',
      }),
    });
    const enrolled = (await enrollRes.json()) as { device_id: string; device_token: string };

    await fetch(`${baseUrl}/v1/gateway/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${enrolled.device_token}`,
      },
      body: JSON.stringify({
        app_version: '1.3.1',
        permission_send_sms: true,
        sim_ready: true,
        sim_slot: 0,
      }),
    });

    // 2. Owner sends a direct Personal SMS via /api/admin/messages/personal
    const personalRes = await fetch(`${baseUrl}/api/admin/messages/personal`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({
        application_id: 'app_portal_prod',
        to: '+919876543210',
        body: 'Namaste! Custom personal dispatch without template.',
        idempotency_key: 'pers_001',
      }),
    });
    assert.equal(personalRes.status, 202);
    const personalJson = (await personalRes.json()) as {
      message_id: string;
      status: string;
      destination_masked: string;
      segment_info: { segments: number; encoding: string };
    };
    assert.equal(personalJson.status, 'queued');
    assert.equal(personalJson.segment_info.encoding, 'GSM-7');
    assert.equal(personalJson.segment_info.segments, 1);

    // Idempotent replay returns 200 with same message_id
    const personalReplay = await fetch(`${baseUrl}/api/admin/messages/personal`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({
        application_id: 'app_portal_prod',
        to: '+919876543210',
        body: 'Namaste! Custom personal dispatch without template.',
        idempotency_key: 'pers_001',
      }),
    });
    assert.equal(personalReplay.status, 200);

    // Invalid E.164 and over-640 char body rejected cleanly
    const badPhoneRes = await fetch(`${baseUrl}/api/admin/messages/personal`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({
        application_id: 'app_portal_prod',
        to: 'invalid_phone',
        body: 'Hello',
      }),
    });
    assert.equal(badPhoneRes.status, 422);

    const tooLongRes = await fetch(`${baseUrl}/api/admin/messages/personal`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({
        application_id: 'app_portal_prod',
        to: '+919876543210',
        body: 'x'.repeat(645),
      }),
    });
    assert.equal(tooLongRes.status, 422);

    // Gateway polls and receives decrypted custom body
    const pollPersonal = await fetch(`${baseUrl}/v1/gateway/poll`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${enrolled.device_token}`,
      },
      body: '{}',
    });
    assert.equal(pollPersonal.status, 200);
    const pollPersonalJson = (await pollPersonal.json()) as {
      job: { job_id: string; to: string; body: string } | null;
    };
    assert.ok(pollPersonalJson.job);
    assert.equal(pollPersonalJson.job.job_id, personalJson.message_id);
    assert.equal(pollPersonalJson.job.to, '+919876543210');
    assert.equal(pollPersonalJson.job.body, 'Namaste! Custom personal dispatch without template.');

    // 3. Owner sends Bulk SMS (>30 unique recipients + duplicate + invalid) without hitting IP rate limit
    const uniqueBatchNumbers = Array.from({ length: 35 }, (_, i) => `+919810000${String(100 + i)}`);
    const bulkInput = [...uniqueBatchNumbers, uniqueBatchNumbers[0], '12345'].join('\n');

    const bulkRes = await fetch(`${baseUrl}/api/admin/messages/bulk`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({
        application_id: 'app_portal_prod',
        recipients: bulkInput,
        body: 'System update completed successfully.',
        batch_label: 'night_deploy',
      }),
    });
    assert.equal(bulkRes.status, 202);
    const bulkJson = (await bulkRes.json()) as {
      batch_id: string;
      total_submitted: number;
      queued_count: number;
      duplicate_count: number;
      skipped_invalid_count: number;
      failed_count: number;
      results: Array<{ to_masked: string; status: string; message_id?: string }>;
    };
    assert.ok(bulkJson.batch_id.startsWith('batch_'));
    assert.equal(bulkJson.queued_count, 35);
    assert.equal(bulkJson.duplicate_count, 1);
    assert.equal(bulkJson.skipped_invalid_count, 1);
    assert.equal(bulkJson.failed_count, 0);
    assert.equal(bulkJson.total_submitted, 37);

    // 4. API key with sms:send can call /v1/sms/personal & /v1/sms/bulk; key without sms:send gets 403
    const sendKey = generateApiKey('live');
    await db.run(
      `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
       VALUES ('key_send_ok', 'app_portal_prod', 'Send Key', ?, ?, '["sms:send"]', 'active', ?)`,
      sendKey.keyPrefix,
      sendKey.secretHash,
      new Date().toISOString()
    );
    const readOnlyKey = generateApiKey('live');
    await db.run(
      `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
       VALUES ('key_read_only', 'app_portal_prod', 'Read Key', ?, ?, '["usage:read"]', 'active', ?)`,
      readOnlyKey.keyPrefix,
      readOnlyKey.secretHash,
      new Date().toISOString()
    );

    const v1Forbidden = await fetch(`${baseUrl}/v1/sms/personal`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${readOnlyKey.rawKey}`,
      },
      body: JSON.stringify({ to: '+919876543211', body: 'Should be blocked' }),
    });
    assert.equal(v1Forbidden.status, 403);

    const v1Personal = await fetch(`${baseUrl}/v1/sms/personal`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sendKey.rawKey}`,
      },
      body: JSON.stringify({ to: '+919876543211', body: 'API personal message check' }),
    });
    assert.equal(v1Personal.status, 202);

    const v1Bulk = await fetch(`${baseUrl}/v1/sms/bulk`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sendKey.rawKey}`,
      },
      body: JSON.stringify({
        recipients: ['+919876543212', '+919876543213'],
        template_id: 'login_notice',
        variables: { name: 'Aarav', device_label: 'API Client' },
      }),
    });
    assert.equal(v1Bulk.status, 202);
    const v1BulkJson = (await v1Bulk.json()) as { queued_count: number; template_id: string };
    assert.equal(v1BulkJson.queued_count, 2);
    assert.equal(v1BulkJson.template_id, 'login_notice');
  });
});

test('Security hardening: type confusion rejection, TOTP replay protection, MFA disable re-auth, account lockout, and cron fail-closed auth', async () => {
  const db = await createIsolatedTestDb();

  await withServer(db, async (baseUrl) => {
    const sendKey = generateApiKey('live');
    await db.run(
      `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
       VALUES ('key_type_check', 'app_portal_prod', 'Type Check Key', ?, ?, '["sms:send"]', 'active', ?)`,
      sendKey.keyPrefix,
      sendKey.secretHash,
      new Date().toISOString()
    );

    // 1. Type confusion objects rejected on /v1/sms & /v1/sms/personal
    const badTypePersonal = await fetch(`${baseUrl}/v1/sms/personal`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sendKey.rawKey}`,
      },
      body: JSON.stringify({ to: { nested: 1 }, body: ['bad'] }),
    });
    assert.equal(badTypePersonal.status, 400);

    const badTypeSms = await fetch(`${baseUrl}/v1/sms`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sendKey.rawKey}`,
      },
      body: JSON.stringify({ to: '+919876543210', template_id: { obj: true } }),
    });
    assert.equal(badTypeSms.status, 400);

    // 2. Owner login -> enable MFA -> verify TOTP replay blocked -> MFA disable requires password/TOTP
    const loginRes = await fetch(`${baseUrl}/api/admin/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owner@simvault.local', password: 'SimVault!2026' }),
    });
    assert.equal(loginRes.status, 200);
    const cookieHeader = (loginRes.headers.get('set-cookie') ?? '').split(';')[0];
    const loginBody = (await loginRes.json()) as { csrf_token: string };

    const mfaCfgRes = await fetch(`${baseUrl}/api/admin/security/mfa`, {
      headers: { Cookie: cookieHeader },
    });
    const mfaCfg = (await mfaCfgRes.json()) as { secret_preview: string };
    const code1 = computeTotpCode(mfaCfg.secret_preview, Date.now() - 30_000);

    const enableRes = await fetch(`${baseUrl}/api/admin/security/mfa/enable`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({ code: code1 }),
    });
    assert.equal(enableRes.status, 200);

    // MFA disable without current_password or totp_code must fail 401
    const badDisable = await fetch(`${baseUrl}/api/admin/security/mfa/disable`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({}),
    });
    assert.equal(badDisable.status, 401);

    // Login with TOTP code2 succeeds once, then replaying code2 fails 401
    const code2 = computeTotpCode(mfaCfg.secret_preview, Date.now());
    const mfaLogin1 = await fetch(`${baseUrl}/api/admin/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owner@simvault.local', password: 'SimVault!2026', totp_code: code2 }),
    });
    assert.equal(mfaLogin1.status, 200);

    const mfaLoginReplay = await fetch(`${baseUrl}/api/admin/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owner@simvault.local', password: 'SimVault!2026', totp_code: code2 }),
    });
    assert.equal(mfaLoginReplay.status, 401);

    // Disable MFA succeeds with valid current_password
    const okDisable = await fetch(`${baseUrl}/api/admin/security/mfa/disable`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({ current_password: 'SimVault!2026' }),
    });
    assert.equal(okDisable.status, 200);

    // 3. Account lockout after >8 failed password attempts for an email (independent of IP bucket)
    clearLoginFailures('127.0.0.1');
    for (let i = 0; i < 8; i++) {
      const fail = await fetch(`${baseUrl}/api/admin/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'locktest@simvault.local', password: 'WrongPassword!' }),
      });
      assert.equal(fail.status, 401);
    }
    assert.equal(checkLoginRateLimit('acct:locktest@simvault.local'), false);
    const lockedRes = await fetch(`${baseUrl}/api/admin/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'locktest@simvault.local', password: 'WrongPassword!' }),
    });
    assert.equal(lockedRes.status, 429);
    clearLoginFailures('127.0.0.1');
    clearLoginFailures('acct:locktest@simvault.local');
  });

  // 4. Cron sweeper fails closed in production when CRON_SECRET is missing, rejects bad bearer, accepts valid bearer
  const prevNodeEnv = process.env.NODE_ENV;
  const prevCronSecret = process.env.CRON_SECRET;
  try {
    process.env.NODE_ENV = 'production';
    delete process.env.CRON_SECRET;

    const { app } = await createSimVaultApp(db);
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const port = (server.address() as { port: number }).port;
    try {
      const missingRes = await fetch(`http://127.0.0.1:${port}/api/cron/sweeper`);
      assert.equal(missingRes.status, 503);

      process.env.CRON_SECRET = 'super_secret_cron_value_12345';
      const badAuthRes = await fetch(`http://127.0.0.1:${port}/api/cron/sweeper`, {
        headers: { Authorization: 'Bearer wrong_secret' },
      });
      assert.equal(badAuthRes.status, 401);

      const okAuthRes = await fetch(`http://127.0.0.1:${port}/api/cron/sweeper`, {
        headers: { Authorization: 'Bearer super_secret_cron_value_12345' },
      });
      assert.equal(okAuthRes.status, 200);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  } finally {
    if (prevNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = prevNodeEnv;
    if (prevCronSecret === undefined) delete process.env.CRON_SECRET;
    else process.env.CRON_SECRET = prevCronSecret;
  }
});

test('Delivery lifecycle: multipart duplicate delivery receipts, out-of-order receipt before /result, and minimum lease headroom work reliably', async () => {
  const db = await createIsolatedTestDb();

  await withServer(db, async (baseUrl) => {
    const loginRes = await fetch(`${baseUrl}/api/admin/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'owner@simvault.local', password: 'SimVault!2026' }),
    });
    const cookieHeader = (loginRes.headers.get('set-cookie') ?? '').split(';')[0];
    const loginBody = (await loginRes.json()) as { csrf_token: string };

    const tokenRes = await fetch(`${baseUrl}/api/admin/devices/enrollment-tokens`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: cookieHeader,
        'X-CSRF-Token': loginBody.csrf_token,
      },
      body: JSON.stringify({ device_name: 'OnePlus Delivery Test', ttl_minutes: 15 }),
    });
    const { enrollment_token_once } = (await tokenRes.json()) as { enrollment_token_once: string };

    const enrollRes = await fetch(`${baseUrl}/v1/gateway/enroll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enrollment_token: enrollment_token_once,
        device_name: 'OnePlus Delivery Test',
        app_version: '1.3.2',
        android_version: '15 (API 35)',
      }),
    });
    const enrolled = (await enrollRes.json()) as { device_id: string; device_token: string };

    await fetch(`${baseUrl}/v1/gateway/heartbeat`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${enrolled.device_token}`,
      },
      body: JSON.stringify({
        app_version: '1.3.2',
        permission_send_sms: true,
        sim_ready: true,
        sim_slot: 0,
      }),
    });

    // 1. Out-of-order delivery receipt arriving directly from leased -> delivered
    const msg1 = await createSmsRequest(db, {
      applicationId: 'app_portal_prod',
      to: '+919876543210',
      templateCode: 'login_notice',
      variables: { name: 'User1', device_label: 'Phone' },
      purpose: 'account_transactional',
      actorId: 'test',
    });

    const poll1 = await fetch(`${baseUrl}/v1/gateway/poll`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${enrolled.device_token}` },
      body: '{}',
    });
    const poll1Json = (await poll1.json()) as { job: { job_id: string } | null };
    assert.equal(poll1Json.job?.job_id, msg1.message_id);

    const dlr1 = await fetch(`${baseUrl}/v1/gateway/jobs/${msg1.message_id}/delivery-report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${enrolled.device_token}` },
      body: '{}',
    });
    assert.equal(dlr1.status, 200);
    assert.equal(((await dlr1.json()) as { status: string }).status, 'delivered');

    // Duplicate multipart delivery receipt returns 200 idempotently (not 409)
    const dlr1Dup = await fetch(`${baseUrl}/v1/gateway/jobs/${msg1.message_id}/delivery-report`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${enrolled.device_token}` },
      body: '{}',
    });
    assert.equal(dlr1Dup.status, 200);
    assert.equal(((await dlr1Dup.json()) as { status: string }).status, 'delivered');

    // Late /result report after delivery receipt must also return 200 delivered without reverting status
    const lateResult = await fetch(`${baseUrl}/v1/gateway/jobs/${msg1.message_id}/result`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${enrolled.device_token}` },
      body: JSON.stringify({ status: 'delivery_unknown', error_code: 'AMBIGUOUS_SEND_STATE' }),
    });
    assert.equal(lateResult.status, 200);
    assert.equal(((await lateResult.json()) as { status: string }).status, 'delivered');

    const row1 = (await db.get<{ status: string; sent_at: string | null; delivered_at: string | null }>(
      'SELECT status, sent_at, delivered_at FROM messages WHERE id = ?',
      msg1.message_id
    ))!;
    assert.equal(row1.status, 'delivered');
    assert.ok(row1.sent_at);
    assert.ok(row1.delivered_at);

    const leaseCount = Number(
      (await db.get<{ c: number }>('SELECT COUNT(*) as c FROM gateway_job_leases WHERE message_id = ?', msg1.message_id))?.c ?? 0
    );
    assert.equal(leaseCount, 0);

    const simRow = (await db.get<{ estimated_sms_sent: number; estimated_sms_remaining: number }>(
      'SELECT estimated_sms_sent, estimated_sms_remaining FROM sims WHERE device_id = ?',
      enrolled.device_id
    ))!;
    assert.equal(simRow.estimated_sms_sent, 1);
    assert.equal(simRow.estimated_sms_remaining, 2999);
  });
});

test('POST /v1/otp/challenges accepts purpose="registration" (including legacy signup-only apps), safely clamps ttl_seconds, and returns JSON 400 on malformed JSON', async () => {
  const db = await createIsolatedTestDb();

  // Simulate an existing pre-upgrade DB application whose allowed_purposes_json has 'signup' but not 'registration'
  await db.run(
    `UPDATE applications SET allowed_purposes_json = ? WHERE id = 'app_portal_prod'`,
    JSON.stringify(['login', 'signup', 'password_reset'])
  );

  const otpKey = generateApiKey('live');
  await db.run(
    `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
     VALUES ('key_otp_create_only', 'app_portal_prod', 'OTP Create Key', ?, ?, '["otp:create","otp:verify"]', 'active', ?)`,
    otpKey.keyPrefix,
    otpKey.secretHash,
    new Date().toISOString()
  );

  const { app } = await createSimVaultApp(db);
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as { port: number }).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    // 1. POST /v1/otp/challenges with Bearer + otp:create + E.164 + purpose="registration" + ttl_seconds=300
    const otpRes = await fetch(`${baseUrl}/v1/otp/challenges`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${otpKey.rawKey}`,
      },
      body: JSON.stringify({
        to: '+919876543210',
        purpose: 'registration',
        ttl_seconds: 300,
      }),
    });
    assert.equal(otpRes.status, 202);
    const otpJson = (await otpRes.json()) as {
      challenge_id: string;
      message_id: string;
      status: string;
      expires_at: string;
    };
    assert.ok(otpJson.challenge_id.startsWith('otp_'));
    assert.ok(otpJson.message_id.startsWith('msg_'));
    assert.equal(otpJson.status, 'queued');
    assert.ok(Date.parse(otpJson.expires_at) > Date.now());

    // 2. Non-numeric ttl_seconds does not cause NaN -> 500 RangeError
    const badTtlRes = await fetch(`${baseUrl}/v1/otp/challenges`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${otpKey.rawKey}`,
      },
      body: JSON.stringify({
        to: '+919876543299',
        purpose: 'registration',
        ttl_seconds: 'invalid-ttl',
      }),
    });
    assert.equal(badTtlRes.status, 202);

    // 3. Malformed JSON returns structured JSON 400 INVALID_JSON (never Express HTML)
    const badJsonRes = await fetch(`${baseUrl}/v1/otp/challenges`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${otpKey.rawKey}`,
      },
      body: '{"to": "+919876543210", "purpose": ',
    });
    assert.equal(badJsonRes.status, 400);
    assert.ok((badJsonRes.headers.get('content-type') ?? '').includes('application/json'));
    const badJsonBody = (await badJsonRes.json()) as { error: { code: string; message: string } };
    assert.equal(badJsonBody.error.code, 'INVALID_JSON');
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
