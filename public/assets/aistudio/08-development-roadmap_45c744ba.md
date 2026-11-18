# 08 — Development Roadmap

## Phase 0: Feasibility gate
- Confirm carrier plan terms allow the intended automated transactional SMS use.
- Confirm Android version/device and permitted app distribution method.
- Validate one manual SMS from Android test app.
- Validate network and delivery receipt behavior.
- If consumer plan automation is disallowed, stop this route and use an approved alternative. Do not build around carrier restrictions.

## Phase 1: Backend foundation
- Monorepo, TypeScript, linting, tests
- PostgreSQL migrations
- Owner authentication and MFA
- API Gateway, app registry, API key lifecycle
- OpenAPI/Swagger docs
- Audit logs

## Phase 2: Queue and message API
- Redis/BullMQ
- SMS request validation and template engine
- Idempotency
- Queue state machine
- Test mode and simulated gateway

## Phase 3: Android gateway proof of concept
- Pair device
- Heartbeat
- Poll job
- Send one approved test SMS
- Report send result
- Pause/revoke device
- Validate SIM selection and permission handling

## Phase 4: OTP service
- Create challenge
- Send OTP through queue
- Hash and verify OTP
- Expiry, attempt limit, resend cooldown
- Tests for replay, brute force, race conditions

## Phase 5: Web dashboard
- Applications and API keys
- API integration settings
- Device and SIM status
- Messages and OTP history
- Usage reports and alerts

## Phase 6: Hardening and production
- Load and failure tests
- Security review
- Backup/restore
- Monitoring and alerting
- Carrier/legal compliance review
- Controlled rollout

## Acceptance criteria
- API key can be created, shown once, used, rotated, and revoked.
- An owned backend can request a test SMS using API.
- A paired Android device receives only its own leased jobs.
- Duplicate HTTP retries do not create duplicate SMS jobs.
- OTP expires, cannot be reused, and locks after max attempts.
- Device offline state is visible; jobs expire safely.
- Dashboard displays truthful status distinctions.
- Logs never contain OTP plaintext or secrets.
