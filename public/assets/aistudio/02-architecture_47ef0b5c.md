# 02 — System Architecture

## 1. High-level flow

```text
Owned Website / Mobile App
          |
          | HTTPS + API Key
          v
       NGINX / TLS
          |
          v
      API Gateway
          |
     Auth + Scope + Rate Limit
          |
   +------+-------------------+
   |                          |
SMS Service               OTP Service
   |                          |
   +-----------+--------------+
               |
         PostgreSQL
               |
         Redis / BullMQ
               |
       Device Dispatcher
               |
      HTTPS Poll / WebSocket
               |
       Android Gateway App
               |
      Android SMS Manager
               |
          Owned SIM
               |
        Carrier Network
               |
         Recipient phone
```

## 2. Services
- **API Gateway:** validates API key, application scope, request schema, rate limits, idempotency.
- **Application Service:** manages website/app registrations, allowed origins (for dashboard only), credentials, and quotas.
- **SMS Service:** validates destination, template, message policy, and creates message job.
- **OTP Service:** generates cryptographically secure OTP, stores hash, expiry and attempt count, verifies submitted code.
- **Queue Service:** durable job queue, retry/backoff, dead-letter queue.
- **Device Registry:** enrollment, heartbeat, capability, SIM slot metadata, online/offline status.
- **Dispatcher:** leases jobs to a suitable enrolled gateway.
- **Gateway Agent:** Android app polls for commands, sends SMS with native APIs, reports state.
- **Usage Service:** tracks requested/sent/failed counts. Do not treat SMS as billable/consumed until the chosen state is reached; define policy explicitly.
- **Audit Service:** append-only security and administrative events.

## 3. Message lifecycle
`created -> queued -> leased -> accepted_by_device -> sent_to_network -> delivered | delivery_unknown | failed | expired`

Definitions:
- `accepted_by_device`: Android app acknowledged the job.
- `sent_to_network`: Android API reported successful handoff; not proof of recipient delivery.
- `delivered`: only when a supported delivery report is received.
- `delivery_unknown`: no trustworthy final receipt.
- `failed`: known send failure.
- `expired`: job was not sent before TTL.

## 4. Device communication
MVP: Android gateway polls `GET /v1/gateway/jobs/next` every 5–15 seconds while connected and reports acknowledgements/results. Use short-lived device access tokens and rotate credentials. Later, use WebSocket/FCM only for wake-up signals; the gateway should still fetch the job securely over HTTPS.

Do not expose the gateway device to the public internet. It initiates outbound TLS connections to the server.

## 5. Deployment topology
- One EC2 instance for MVP, Docker Compose.
- Containers: `api`, `worker`, `web`, `postgres`, `redis`, `nginx`.
- Android gateway is a separate physical device.
- For production growth: managed PostgreSQL, Redis, separate worker instances, object storage for exports/backups.
