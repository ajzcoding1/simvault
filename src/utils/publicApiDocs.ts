export type CodeLanguage = 'curl' | 'node' | 'python' | 'php';

export interface PublicEndpointSpec {
  id: string;
  method: 'GET' | 'POST';
  path: string;
  scope: string;
  title: string;
  summary: string;
  headers: Array<{ name: string; required: boolean; description: string }>;
  requestExample: string | null;
  responseStatus: string;
  responseExample: string;
  notes: string[];
}

export const PUBLIC_ENDPOINTS: PublicEndpointSpec[] = [
  {
    id: 'send-sms',
    method: 'POST',
    path: '/v1/sms',
    scope: 'sms:send',
    title: 'Queue Templated SMS',
    summary:
      'Validates E.164 recipient, approved template variables, and application quota before enqueueing a job for your paired Android SIM gateway.',
    headers: [
      { name: 'Authorization', required: true, description: 'Bearer sv_live_... or sv_test_...' },
      { name: 'Content-Type', required: true, description: 'application/json' },
      { name: 'Idempotency-Key', required: false, description: 'Prevents duplicate SMS sends on network retries' },
    ],
    requestExample: `{
  "to": "+919876543210",
  "template_id": "login_notice",
  "variables": {
    "name": "Aarav",
    "device_label": "Chrome on Linux"
  },
  "purpose": "account_transactional",
  "ttl_seconds": 180
}`,
    responseStatus: '202 Accepted (or 200 OK on idempotent replay)',
    responseExample: `{
  "message_id": "msg_94f1c8a2d01b4e7c",
  "status": "queued",
  "created_at": "2026-11-20T12:15:00.000Z"
}`,
    notes: [
      'Use sv_test_ keys during staging to exercise validation and quotas without using physical SIM balance.',
      'Reusing the same Idempotency-Key returns the original message_id with idempotent_replay: true.',
    ],
  },
  {
    id: 'otp-create',
    method: 'POST',
    path: '/v1/otp/challenges',
    scope: 'otp:create',
    title: 'Create OTP Challenge',
    summary:
      'Generates a cryptographically random 6-digit OTP server-side, stores only its salted HMAC hash, and queues an SMS dispatch.',
    headers: [
      { name: 'Authorization', required: true, description: 'Bearer sv_live_... or sv_test_...' },
      { name: 'Content-Type', required: true, description: 'application/json' },
    ],
    requestExample: `{
  "to": "+919876543210",
  "purpose": "login",
  "ttl_seconds": 300
}`,
    responseStatus: '202 Accepted',
    responseExample: `{
  "challenge_id": "otp_6d2b8e110c4a9f32",
  "message_id": "msg_38a7c10e9b2f4d11",
  "status": "queued",
  "expires_at": "2026-11-20T12:20:00.000Z"
}`,
    notes: [
      'Supported purpose values: "login", "signup", "registration", "password_reset", "mfa" (ttl_seconds: 60–600, default 300).',
      'The plaintext 6-digit OTP is never returned in the API response or stored in logs.',
      'Save challenge_id in your backend session so you can validate the user input via POST /v1/otp/verify.',
      'Set SIMVAULT_BASE_URL to the root host from Owner Console -> API Docs without a trailing /v1 suffix.',
    ],
  },
  {
    id: 'otp-verify',
    method: 'POST',
    path: '/v1/otp/verify',
    scope: 'otp:verify',
    title: 'Verify OTP Code',
    summary:
      'Performs a constant-time hash comparison inside an atomic transaction. Single-use once verified, and automatically locks after 5 wrong attempts.',
    headers: [
      { name: 'Authorization', required: true, description: 'Bearer sv_live_... or sv_test_...' },
      { name: 'Content-Type', required: true, description: 'application/json' },
    ],
    requestExample: `{
  "challenge_id": "otp_6d2b8e110c4a9f32",
  "code": "482910"
}`,
    responseStatus: '200 OK (422 OTP_INVALID on mismatch, expiry, or lock)',
    responseExample: `{
  "verified": true,
  "verified_at": "2026-11-20T12:16:12.408Z",
  "challenge_id": "otp_6d2b8e110c4a9f32"
}`,
    notes: [
      'Atomic SQL status transition guarantees replay protection under concurrent verification requests.',
      'Expired or locked challenges return HTTP 422 with error.code = "OTP_INVALID".',
    ],
  },
  {
    id: 'get-message',
    method: 'GET',
    path: '/v1/messages/:id',
    scope: 'any active key',
    title: 'Inspect Message Status',
    summary:
      'Retrieves the truthful carrier lifecycle state, masked destination, and timestamps for a message belonging to your application.',
    headers: [{ name: 'Authorization', required: true, description: 'Bearer sv_live_... or sv_test_...' }],
    requestExample: null,
    responseStatus: '200 OK',
    responseExample: `{
  "id": "msg_94f1c8a2d01b4e7c",
  "application_id": "app_portal_prod",
  "device_id": "dev_pixel_01",
  "destination_masked": "+91••••••3210",
  "template_id": "login_notice",
  "purpose": "account_transactional",
  "status": "sent_to_network",
  "is_test": false,
  "created_at": "2026-11-20T12:15:00.000Z",
  "queued_at": "2026-11-20T12:15:00.012Z",
  "leased_at": "2026-11-20T12:15:03.400Z",
  "accepted_at": "2026-11-20T12:15:03.510Z",
  "sent_at": "2026-11-20T12:15:04.120Z",
  "delivered_at": null,
  "failed_at": null,
  "error_code": null
}`,
    notes: [
      'sent_to_network confirms Android SmsManager handed the SMS to the cellular radio; delivered is set only on carrier receipt.',
      'Phone numbers are masked in responses; raw numbers stay encrypted at rest with AES-256-GCM.',
    ],
  },
  {
    id: 'get-usage',
    method: 'GET',
    path: '/v1/usage',
    scope: 'usage:read',
    title: 'Read Application Usage',
    summary:
      'Aggregates message counts grouped by lifecycle status for an optional ISO-8601 from/to window (defaults to last 30 days).',
    headers: [{ name: 'Authorization', required: true, description: 'Bearer sv_live_... or sv_test_...' }],
    requestExample: null,
    responseStatus: '200 OK',
    responseExample: `{
  "application_id": "app_portal_prod",
  "from": "2026-10-21T12:15:00.000Z",
  "to": "2026-11-20T12:15:00.000Z",
  "counts_by_status": [
    { "status": "sent_to_network", "count": 142 },
    { "status": "delivered", "count": 98 },
    { "status": "queued", "count": 1 }
  ]
}`,
    notes: ['Pass ?from=...&to=... ISO-8601 query parameters to scope reporting to a billing or audit window.'],
  },
];

export const PUBLIC_PLACEHOLDER_BASE_URL = 'https://<YOUR_SIMVAULT_HOST>';

export function buildQuickstartSnippet(
  language: CodeLanguage,
  baseUrl: string = PUBLIC_PLACEHOLDER_BASE_URL
): string {
  const normalizedBase = baseUrl.replace(/\/+$/, '');
  if (language === 'curl') {
    return `# 1. Create an OTP challenge (server-side only)
curl -X POST "${normalizedBase}/v1/otp/challenges" \\
  -H "Authorization: Bearer $SIMVAULT_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "to": "+919876543210",
    "purpose": "login",
    "ttl_seconds": 300
  }'

# 2. Verify the 6-digit code entered by your user
curl -X POST "${normalizedBase}/v1/otp/verify" \\
  -H "Authorization: Bearer $SIMVAULT_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "challenge_id": "otp_6d2b8e110c4a9f32",
    "code": "482910"
  }'`;
  }

  if (language === 'node') {
    return `// Backend service (Express / Next.js Route Handler / Node 20+)
const baseUrl = "${normalizedBase}";
const apiKey = process.env.SIMVAULT_API_KEY!;

export async function sendLoginNotice(userPhone: string, requestId: string) {
  const res = await fetch(\`\${baseUrl}/v1/sms\`, {
    method: "POST",
    headers: {
      Authorization: \`Bearer \${apiKey}\`,
      "Idempotency-Key": \`login-\${requestId}\`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      to: userPhone,
      template_id: "login_notice",
      variables: { name: "Customer", device_label: "Web Session" },
      purpose: "account_transactional",
      ttl_seconds: 180,
    }),
  });

  if (!res.ok) throw new Error(await res.text());
  return res.json();
}`;
  }

  if (language === 'python') {
    return `# Python backend (FastAPI / Django / Flask)
import os
import requests

BASE_URL = "${normalizedBase}"
API_KEY = os.environ["SIMVAULT_API_KEY"]

def create_otp(phone_e164: str) -> dict:
    resp = requests.post(
        f"{BASE_URL}/v1/otp/challenges",
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": "application/json",
        },
        json={"to": phone_e164, "purpose": "login", "ttl_seconds": 300},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()`;
  }

  return `<?php
// PHP / Laravel backend helper
$baseUrl = "${normalizedBase}";
$apiKey = getenv("SIMVAULT_API_KEY");

$ch = curl_init("$baseUrl/v1/otp/challenges");
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        "Authorization: Bearer $apiKey",
        "Content-Type: application/json",
    ],
    CURLOPT_POSTFIELDS => json_encode([
        "to" => "+919876543210",
        "purpose" => "login",
        "ttl_seconds" => 300,
    ]),
]);
$response = json_decode(curl_exec($ch), true);`;
}

export function buildNextJsSafeOtpSnippet(baseUrl: string = PUBLIC_PLACEHOLDER_BASE_URL): string {
  const normalizedBase = baseUrl.trim().replace(/\/+$/, '').replace(/\/v1$/, '');
  return `// app/api/auth/send-otp/route.ts (Next.js App Router — server-only)
function normalizeBaseUrl(raw: string): string {
  return raw.trim().replace(/\\/+$/, "").replace(/\\/v1$/, "");
}

export async function POST(req: Request) {
  const { phone } = (await req.json()) as { phone?: string };
  const baseUrl = normalizeBaseUrl(process.env.SIMVAULT_BASE_URL || "${normalizedBase}");
  const apiKey = process.env.SIMVAULT_API_KEY;
  if (!apiKey) {
    return Response.json({ error: { code: "CONFIG_MISSING", message: "SIMVAULT_API_KEY is not set." } }, { status: 500 });
  }

  let upstream: Response;
  try {
    upstream = await fetch(\`\${baseUrl}/v1/otp/challenges\`, {
      method: "POST",
      headers: {
        Authorization: \`Bearer \${apiKey}\`, // Never log Authorization or apiKey
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ to: phone, purpose: "registration", ttl_seconds: 300 }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    console.error("[OTP] Network error calling SimVault", {
      host: new URL(baseUrl).host,
      reason: err instanceof Error ? err.message : "fetch_failed",
    });
    return Response.json({ error: { code: "UPSTREAM_UNREACHABLE", message: "Could not reach OTP gateway." } }, { status: 502 });
  }

  const rawText = await upstream.text();
  const isJson = (upstream.headers.get("content-type") || "").includes("application/json");
  let payload: { error?: { code?: string; message?: string; request_id?: string }; [k: string]: unknown } | null = null;
  if (isJson && rawText) {
    try { payload = JSON.parse(rawText); } catch { payload = null; }
  }

  if (!upstream.ok) {
    const safeError = {
      upstream_status: upstream.status,
      code: payload?.error?.code ?? "UPSTREAM_NON_JSON",
      message: payload?.error?.message ?? \`Upstream returned HTTP \${upstream.status}\`,
      request_id: payload?.error?.request_id ?? null,
    };
    console.error("[OTP] SimVault rejected request", safeError);
    return Response.json({ error: safeError }, { status: upstream.status >= 500 ? 502 : upstream.status });
  }

  return Response.json(payload ?? {}, { status: upstream.status });
}`;
}

export const WEBHOOK_VERIFY_SNIPPET = `import crypto from "node:crypto";

export function verifySimVaultWebhook(params: {
  secret: string;
  signatureHeader: string; // X-SimVault-Signature: v1=<hex>
  timestampHeader: string; // X-SimVault-Timestamp (unix seconds)
  eventIdHeader: string;   // X-SimVault-Event-Id
  rawBody: string;         // Unparsed JSON request body
}): boolean {
  const ageSeconds = Math.abs(Math.floor(Date.now() / 1000) - Number(params.timestampHeader));
  if (!Number.isFinite(ageSeconds) || ageSeconds > 300) return false;

  const expectedHex = crypto
    .createHmac("sha256", params.secret)
    .update(\`\${params.timestampHeader}.\${params.eventIdHeader}.\${params.rawBody}\`)
    .digest("hex");

  const receivedHex = params.signatureHeader.replace(/^v1=/, "");
  const a = Buffer.from(expectedHex, "hex");
  const b = Buffer.from(receivedHex, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}`;
