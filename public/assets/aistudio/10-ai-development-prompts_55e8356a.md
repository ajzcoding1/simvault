# 10 — AI Development Prompts

Use these prompts sequentially with your preferred AI coding agent. Ask it to read all project docs first. Require tests and a short implementation report after each phase.

## Master instruction
You are a senior full-stack engineer. Build the Personal SIM SMS & OTP Platform described in this documentation. Treat these Markdown files as the source of truth. Do not invent features that conflict with them. Do not bypass Android permissions, carrier restrictions, telecom compliance, or platform security. Build a simulated gateway first so backend development does not depend on a physical SIM. Use TypeScript, clear module boundaries, migrations, OpenAPI, automated tests, secure defaults, and Docker Compose. Never put secrets in source control.

## Prompt 1 — Repository and backend
Read `01` through `04`. Create a monorepo with `apps/api`, `apps/worker`, `apps/web`, `packages/shared`, and `infra`. Implement owner authentication, PostgreSQL schema/migrations, application registry, API-key generation/hash/rotation/revocation, scoped API middleware, rate limiting, audit logging, and OpenAPI. Include unit/integration tests. Do not implement real SMS sending yet; use a mock gateway.

## Prompt 2 — Queue and APIs
Implement SMS request, OTP challenge, OTP verify, message status, usage endpoints, idempotency, BullMQ jobs, message state machine, expiry, retries, and dead-letter handling. Ensure OTP plaintext is never persisted or logged. Add tests for duplicate requests, expiry, replay, brute-force attempts, and worker restart.

## Prompt 3 — Android gateway
Read `05`. Create a Kotlin Android app with pairing, secure device credential storage, heartbeat, job polling, job acknowledgement, SIM status, permission status, pause/resume, and native SMS send integration. Use explicit user-granted permissions and explicit SIM selection. Include a fake/mock mode. Do not attempt to bypass Android or carrier restrictions.

## Prompt 4 — Dashboard
Read `06`. Build a responsive Next.js dashboard with overview, applications, API keys, API docs/configuration, messages, OTP history, gateway devices, SIM usage estimates, templates, webhooks, security settings, and audit logs. Reveal API secret only once. Include test mode.

## Prompt 5 — Security and deployment
Read `07` and `09`. Add security headers, strict CORS, CSRF protection for dashboard sessions, secure cookies, MFA, secret redaction, encrypted backups, monitoring, health checks, Docker Compose, Nginx, and deployment instructions. Add a threat model and security test report.

## Prompt 6 — Final verification
Read all docs and inspect the implementation against each acceptance criterion in `08`. Run tests, lint, type checks, migrations, and build. Report missing requirements honestly. Do not claim carrier delivery unless supported by an actual delivery receipt. Produce a setup guide for Windows and Ubuntu.
