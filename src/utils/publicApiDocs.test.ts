import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PUBLIC_ENDPOINTS,
  PUBLIC_PLACEHOLDER_BASE_URL,
  WEBHOOK_VERIFY_SNIPPET,
  buildQuickstartSnippet,
} from './publicApiDocs';

test('PUBLIC_ENDPOINTS documents all 5 core /v1 endpoints with required scopes', () => {
  const paths = PUBLIC_ENDPOINTS.map((ep) => `${ep.method} ${ep.path}`);
  assert.deepEqual(paths, [
    'POST /v1/sms',
    'POST /v1/otp/challenges',
    'POST /v1/otp/verify',
    'GET /v1/messages/:id',
    'GET /v1/usage',
  ]);
  for (const ep of PUBLIC_ENDPOINTS) {
    assert.ok(ep.scope.length > 0);
    assert.ok(ep.responseExample.includes('{'));
  }
});

test('buildQuickstartSnippet uses redacted placeholder by default and strips trailing slashes', () => {
  const defaultNode = buildQuickstartSnippet('node');
  assert.ok(defaultNode.includes(PUBLIC_PLACEHOLDER_BASE_URL));
  assert.ok(!defaultNode.includes('localhost'));

  const curl = buildQuickstartSnippet('curl', 'https://sms.example.com/');
  assert.ok(curl.includes('https://sms.example.com/v1/otp/challenges'));
  assert.ok(!curl.includes('https://sms.example.com//v1'));

  const node = buildQuickstartSnippet('node', 'https://sms.example.com');
  assert.ok(node.includes('Idempotency-Key'));
  assert.ok(node.includes('SIMVAULT_API_KEY'));

  const py = buildQuickstartSnippet('python', 'https://sms.example.com');
  assert.ok(py.includes('requests.post'));

  const php = buildQuickstartSnippet('php', 'https://sms.example.com');
  assert.ok(php.includes('curl_init'));
});

test('WEBHOOK_VERIFY_SNIPPET matches server X-SimVault-Signature format', () => {
  assert.ok(WEBHOOK_VERIFY_SNIPPET.includes('X-SimVault-Signature'));
  assert.ok(WEBHOOK_VERIFY_SNIPPET.includes('timestampHeader'));
  assert.ok(WEBHOOK_VERIFY_SNIPPET.includes('timingSafeEqual'));
});
