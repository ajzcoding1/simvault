import test from 'node:test';
import assert from 'node:assert/strict';
import {
  calculateSimRemainingEstimate,
  extractTemplateVariables,
  isPrivateOrReservedIp,
  isValidE164,
  isValidMessageTransition,
  isValidWebhookUrl,
  maskE164,
  parseApiKeyPrefix,
  redactSensitiveMetadata,
  renderTemplate,
} from '../src/shared/smsRules';

test('E.164 validation and masking hide inner digits while preserving last 4', () => {
  assert.equal(isValidE164('+919876543210'), true);
  assert.equal(isValidE164('+14155550142'), true);
  assert.equal(isValidE164('9876543210'), false);
  assert.equal(isValidE164('+0123456'), false);

  const masked = maskE164('+919876543210');
  assert.ok(masked.startsWith('+91'));
  assert.ok(masked.endsWith('3210'));
  assert.ok(masked.includes('•'));
  assert.ok(!masked.includes('987654'));
});

test('template rendering substitutes variables and reports missing ones', () => {
  const vars = extractTemplateVariables('Code for {{app_name}}: {{code}}');
  assert.deepEqual(vars, ['app_name', 'code']);

  const ok = renderTemplate('Hello {{name}}, code {{code}}', { name: 'Customer', code: '492011' });
  assert.equal(ok.rendered, 'Hello Customer, code 492011');
  assert.deepEqual(ok.missingVariables, []);

  const missing = renderTemplate('Hello {{name}}, code {{code}}', { name: 'Customer' });
  assert.deepEqual(missing.missingVariables, ['code']);
});

test('message state machine enforces truthful lifecycle transitions', () => {
  assert.equal(isValidMessageTransition('queued', 'leased'), true);
  assert.equal(isValidMessageTransition('leased', 'accepted_by_device'), true);
  assert.equal(isValidMessageTransition('accepted_by_device', 'sent_to_network'), true);
  assert.equal(isValidMessageTransition('sent_to_network', 'delivered'), true);
  assert.equal(isValidMessageTransition('sent_to_network', 'delivery_unknown'), true);
  assert.equal(isValidMessageTransition('queued', 'delivered'), false);
  assert.equal(isValidMessageTransition('delivered', 'failed'), false);
  assert.equal(isValidMessageTransition('expired', 'queued'), false);
});

test('redactSensitiveMetadata scrubs OTPs, secrets, API keys, and phone numbers', () => {
  const cleaned = redactSensitiveMetadata({
    api_key: 'sv_live_1234567890abcdef123456',
    otp_code: '482910',
    phone: '+919876543210',
    application_id: 'app_portal_prod',
    destination_masked: '+91••••••3210',
  }) as Record<string, unknown>;

  assert.equal(cleaned.api_key, '[REDACTED]');
  assert.equal(cleaned.otp_code, '[REDACTED]');
  assert.equal(cleaned.phone, '+91••••••3210');
  assert.equal(cleaned.application_id, 'app_portal_prod');
});

test('API key prefix parser distinguishes test and live formats', () => {
  const live = parseApiKeyPrefix('sv_live_AbCdEfGhIjKlMnOpQrStUvWx');
  assert.equal(live.validFormat, true);
  assert.equal(live.environment, 'live');

  const bad = parseApiKeyPrefix('sk_test_short');
  assert.equal(bad.validFormat, false);
});

test('SIM remaining estimate calculates bounded values', () => {
  assert.deepEqual(calculateSimRemainingEstimate(3000, 142), { remaining: 2858, utilizationPct: 5 });
  assert.deepEqual(calculateSimRemainingEstimate(100, 140), { remaining: 0, utilizationPct: 100 });
});

test('SSRF guards block non-HTTPS, private/loopback IPs, metadata IPs, and .example/.local hosts', () => {
  assert.equal(isPrivateOrReservedIp('127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('10.0.0.5'), true);
  assert.equal(isPrivateOrReservedIp('169.254.169.254'), true);
  assert.equal(isPrivateOrReservedIp('172.16.0.1'), true);
  assert.equal(isPrivateOrReservedIp('192.168.1.10'), true);
  assert.equal(isPrivateOrReservedIp('::1'), true);
  assert.equal(isPrivateOrReservedIp('fc00::1'), true);
  assert.equal(isPrivateOrReservedIp('::ffff:127.0.0.1'), true);
  assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);

  assert.equal(isValidWebhookUrl('http://api.acme.com/hooks'), false);
  assert.equal(isValidWebhookUrl('https://localhost/hooks'), false);
  assert.equal(isValidWebhookUrl('https://127.0.0.1/hooks'), false);
  assert.equal(isValidWebhookUrl('https://169.254.169.254/latest/meta-data'), false);
  assert.equal(isValidWebhookUrl('https://app.internal.example/hooks'), false);
  assert.equal(isValidWebhookUrl('https://user:pass@api.acme.com/hooks'), false);
  assert.equal(isValidWebhookUrl('https://api.acme.com/webhooks/simvault'), true);
});
