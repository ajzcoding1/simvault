# Personal SIM SMS & OTP Platform

**Purpose:** A private, self-hosted SMS/OTP system for applications owned by the operator. An AWS-hosted backend exposes authenticated APIs. One or more Android Gateway devices, each containing an authorized SIM, receive jobs over HTTPS and send SMS using Android's native SMS APIs.

> This is not a telecom network, SIM-cloning system, or a public SMS reseller. It is an application-level SMS orchestration platform. Use only SIMs and plans whose terms permit the intended automated messaging. Carrier plan limits, anti-spam rules, Android permissions, Google Play policy, and applicable Indian telecom rules may restrict this design.

## Product boundaries
- First release: one owner account, one web app, one Android gateway device, one SIM.
- Later: multiple owned applications, gateway devices, SIMs, sender profiles, and usage policies.
- The API Gateway is our own backend API layer; it does **not** bypass the carrier or Android.
- Do not promise guaranteed delivery. Track `accepted_by_device`, `sent_to_network`, and delivery receipt separately where available.
- Never use a personal SIM to send unsolicited, bulk, promotional, or third-party traffic. Confirm carrier terms and compliance before production use.

## Documentation
1. `01-product-requirements.md`
2. `02-architecture.md`
3. `03-api-specification.md`
4. `04-database-design.md`
5. `05-android-gateway.md`
6. `06-web-dashboard.md`
7. `07-security-and-abuse-controls.md`
8. `08-development-roadmap.md`
9. `09-deployment-and-operations.md`
10. `10-ai-development-prompts.md`

## Recommended stack
- Backend: Node.js + TypeScript + NestJS (or Fastify)
- Web dashboard: Next.js + TypeScript
- Database: PostgreSQL
- Queue/cache: Redis + BullMQ
- Android gateway: Kotlin + Android native SMS APIs
- Realtime device channel: HTTPS long-polling initially; WebSocket only if operationally justified
- Deployment: Docker Compose on AWS EC2; Nginx reverse proxy; TLS
- Observability: structured logs, health checks, metrics, alerts

## Important Android limitation
Android requires runtime permissions and may restrict background SMS behavior. Google Play heavily restricts SMS permissions for apps distributed through Play. For a private owner-operated gateway, evaluate managed/private distribution and Android Enterprise/device-owner options. Do not silently bypass platform protections. Test on the exact Android version and device model.
