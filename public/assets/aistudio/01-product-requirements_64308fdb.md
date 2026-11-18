# 01 — Product Requirements

## 1. Goal
Build a private SMS and OTP platform that allows our own website/application(s) to request SMS or OTP messages through a documented API. The backend queues work and assigns it to an enrolled Android phone containing our SIM. The phone sends the message through the SIM's carrier plan and reports status.

## 2. User roles
- **Owner/Super Admin:** controls all settings, devices, SIMs, API keys, templates, quotas, and audit logs.
- **Application:** a website/mobile app registered in the dashboard and assigned API credentials.
- **Gateway Device:** Android phone enrolled to the platform.
- **Operator (optional later):** can view operational status but cannot reveal secrets or change security settings.

## 3. Core modules
1. Authentication and owner account
2. API Gateway and API-key management
3. Application/project management
4. SMS request service
5. OTP generation and verification service
6. Message queue and scheduler
7. Android device enrollment and command channel
8. SIM/device health and quota tracking
9. Delivery/status tracking
10. Templates and sender configuration
11. Usage, audit logs, alerts, and reports
12. Admin dashboard and application-side API configuration

## 4. Functional requirements
- Create/revoke/rotate API keys. Show secret only once at creation.
- Scope each key to one application and specific permissions.
- Support `POST /v1/sms` for approved transactional SMS.
- Support `POST /v1/otp/challenges`, `POST /v1/otp/verify`.
- Provide idempotency keys to prevent duplicate sends on retries.
- Queue messages if the gateway is temporarily offline.
- Enforce expiry, retry limits, per-number throttles, daily limits, and an owner-defined allowlist.
- Device must authenticate with its own device credential and receive only jobs assigned to it.
- Record each state transition with timestamps.
- Dashboard must show API base URL, app ID, key status, integration examples, device status, and usage.
- The application must never receive the SIM's private data or device credential.
- Provide test mode that simulates requests without sending a real SMS.

## 5. Non-functional requirements
- TLS for all network traffic.
- Encrypt sensitive data at rest where appropriate.
- OTPs must be short-lived, single-use, and stored hashed.
- Queue processing must be resilient to restarts.
- API rate limits and request-size limits.
- Structured logs with secrets and OTP values redacted.
- Backups and restore tests.
- Health endpoint and alerting.

## 6. Explicit exclusions for MVP
- No public customer signup or resale.
- No bulk marketing campaigns.
- No SIM-bank or multi-SIM automation.
- No spoofing sender IDs, bypassing carrier restrictions, or circumventing Android permissions.
- No guarantee that a carrier plan's bundled SMS allowance permits automated application traffic.
