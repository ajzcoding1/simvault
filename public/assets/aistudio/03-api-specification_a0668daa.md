# 03 — API Specification (v1)

Base URL example: `https://verify.example.com`
All endpoints use JSON and HTTPS. API requests from owned applications use `Authorization: Bearer <API_KEY>`. Never put secret keys in browser JavaScript or a public mobile binary; route requests through your trusted application backend.

## 1. API key rules
- Key format: prefix such as `sv_live_` + 32+ random bytes encoded safely.
- Store only a strong hash of the secret; show the raw secret once.
- Associate key with `application_id`, scopes, status, created/last-used/revoked timestamps.
- Support key rotation with a short overlap window.
- Separate test and live keys.
- Suggested scopes: `sms:send`, `otp:create`, `otp:verify`, `usage:read`.

## 2. Endpoints

### Health (public, no secrets)
`GET /health`
Response: `{ "status": "ok", "version": "1.0.0" }`

### Create SMS
`POST /v1/sms`
Headers: `Authorization`, `Idempotency-Key`
```json
{
  "to": "+91XXXXXXXXXX",
  "template_id": "login_notice",
  "variables": { "name": "User" },
  "purpose": "account_transactional",
  "ttl_seconds": 120
}
```
Response `202`:
```json
{
  "message_id": "msg_uuid",
  "status": "queued",
  "created_at": "2026-01-01T10:00:00Z"
}
```
Do not accept arbitrary bulk message bodies by default. Allow only approved templates and permitted use cases.

### Create OTP challenge
`POST /v1/otp/challenges`
```json
{
  "to": "+91XXXXXXXXXX",
  "purpose": "login",
  "channel": "sms",
  "ttl_seconds": 300
}
```
Response:
```json
{
  "challenge_id": "otp_uuid",
  "status": "queued",
  "expires_at": "2026-01-01T10:05:00Z"
}
```
The response must never contain the OTP in live mode.

### Verify OTP
`POST /v1/otp/verify`
```json
{
  "challenge_id": "otp_uuid",
  "code": "123456"
}
```
Response success:
```json
{ "verified": true, "verified_at": "2026-01-01T10:02:00Z" }
```
Failure responses must not reveal whether the phone number or code was correct. Enforce max attempts and lockout.

### Message status
`GET /v1/messages/{message_id}`
Returns status, timestamps, and safe error code. Never return OTP body or API secret.

### Usage
`GET /v1/usage?from=...&to=...`
Requires `usage:read`. Returns counts by state and device, not message contents.

## 3. Gateway device endpoints
These use device credentials, not application API keys.

- `POST /v1/gateway/enroll` — one-time enrollment token exchange.
- `POST /v1/gateway/heartbeat` — device health, app version, permission state, network state.
- `GET /v1/gateway/jobs/next` — lease one eligible job.
- `POST /v1/gateway/jobs/{job_id}/accepted`
- `POST /v1/gateway/jobs/{job_id}/result` — result code and timestamps.
- `POST /v1/gateway/jobs/{job_id}/delivery-report` — optional carrier delivery receipt.

Device endpoints must be scoped to that device ID. A device must never be able to fetch arbitrary messages.

## 4. Webhooks
Optional application callback:
- `message.status`
- `otp.sent`
- `otp.failed`
- `otp.verified`

Sign webhook body with HMAC-SHA256 using a per-application webhook secret. Include timestamp and event ID. Consumers must reject old timestamps and deduplicate event IDs.

## 5. Standard errors
```json
{
  "error": {
    "code": "RATE_LIMITED",
    "message": "Request limit exceeded.",
    "request_id": "req_uuid"
  }
}
```
Use appropriate HTTP status codes: `400`, `401`, `403`, `404`, `409`, `422`, `429`, `500`, `503`.
