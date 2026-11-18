# 09 — Deployment & Operations

## MVP server layout
- AWS EC2 Ubuntu LTS
- Docker + Docker Compose
- Nginx reverse proxy
- TLS certificate
- Containers: `web`, `api`, `worker`, `postgres`, `redis`
- Firewall: expose only 80/443 and restricted SSH; database/Redis private to Docker network.
- Store secrets in environment/secret manager, never in Git.
- Automated encrypted PostgreSQL backups.

## Environments
- `development`: local services and simulated gateway
- `staging`: test API keys, test destinations, no production sends
- `production`: live keys, owner-approved destinations, strict quotas

## Environment variables (names only)
- `DATABASE_URL`
- `REDIS_URL`
- `APP_BASE_URL`
- `API_BASE_URL`
- `JWT_PRIVATE_KEY` or signing key reference
- `API_KEY_PEPPER`
- `OTP_PEPPER`
- `WEBHOOK_ENCRYPTION_KEY`
- `LOG_LEVEL`

Do not commit actual values.

## Monitoring
- API latency and error rate
- Queue depth and oldest job age
- Gateway heartbeat age
- Job send failure rate
- Delivery receipt rate (where supported)
- OTP verification failure rate
- SMS count per SIM/cycle (estimated)
- Disk, memory, CPU, database health

## Operational rules
- Alert if gateway offline for a configured duration.
- Alert before estimated SIM SMS quota is exhausted.
- Never auto-switch to a third-party provider unless the owner explicitly enables it.
- Provide a global kill switch to stop all sends.
- Reconcile SIM usage against carrier account records manually unless official integration exists.
