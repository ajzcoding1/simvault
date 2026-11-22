<div align="center">
  <h1>SimVault</h1>
  <p><strong>Self-hosted SMS and OTP delivery through your own Android SIM gateway.</strong></p>
  <p>
    <a href="./LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/License-MIT-blue.svg"></a>
    <img alt="Node.js 22" src="https://img.shields.io/badge/Node.js-22.x-339933?logo=nodedotjs&logoColor=white">
    <img alt="Android 10+" src="https://img.shields.io/badge/Android-10%2B-3DDC84?logo=android&logoColor=white">
  </p>
</div>

SimVault is an owner-operated platform for queuing transactional SMS and one-time passwords (OTPs) from your applications. It pairs a REST API and web console with an Android phone that sends messages through a physical SIM.

SimVault is self-hosted software, not a managed messaging provider. You supply and operate the Android device, SIM, database, and deployment.

## How it works

```mermaid
flowchart LR
    App[Your application] -->|HTTPS REST API| API[SimVault API]
    API --> Queue[(Message queue)]
    Queue -->|Leased jobs| Phone[Paired Android gateway]
    Phone -->|SMS via physical SIM| Carrier[Mobile network]
    Carrier -->|Receipt when available| Phone
    Phone --> API
    Console[Owner console] --> API
```

The API creates queued jobs; the paired gateway polls for work, dispatches SMS using Android's native SMS APIs, and reports status. A carrier handoff is not treated as proof of delivery: SimVault distinguishes `sent_to_network` from `delivered`, which requires a delivery receipt.

## Features

- REST endpoints for templated SMS, personal SMS, bulk requests, OTP challenges, verification, and usage
- Native Android gateway with SIM-slot selection, background polling, and delivery receipt handling
- Test and live application modes, scoped API keys, per-application limits, and optional destination allowlists
- Idempotency support, leased jobs, retries, and message lifecycle tracking
- Owner console for applications, devices, SIM usage estimates, messages, templates, webhooks, and audit events
- Security controls including encrypted sensitive fields, hashed API keys, rate limits, and CSRF-protected dashboard actions
- PostgreSQL through Supabase for hosted deployments; SQLite for local development and tests

## Requirements

- Node.js 22.x and npm
- For the Android gateway: Android Studio, JDK 17, and an Android 10 or later device with an active SIM
- For a Vercel deployment: a Supabase PostgreSQL database and the environment variables described in [`.env.example`](./.env.example)

## Run locally

1. Install dependencies and create your local environment file:

   ```bash
   npm ci
   cp .env.example .env
   ```

2. Set `SIMVAULT_ADMIN_EMAIL` and `SIMVAULT_ADMIN_PASSWORD` in `.env`. Use a password of at least 16 characters. Leave the PostgreSQL settings empty to use local SQLite.
3. Start the development server:

   ```bash
   npm run dev
   ```

   Open [http://localhost:3000](http://localhost:3000). Local cryptographic keys are generated and saved in the local data directory when needed.

Run the checks and production build with:

```bash
npm test
npm run lint
npm run build
```

## Deploy

### Vercel and Supabase

1. Create a Supabase project and apply [`infra/supabase_schema.sql`](./infra/supabase_schema.sql).
2. Configure the database connection, four distinct cryptographic keys, owner credentials, and `CRON_SECRET` in Vercel.
3. Deploy the repository. Vercel uses [`vercel.json`](./vercel.json) and runs `npm run build`.

See the [database and deployment guide](./DATABASE_SETUP.md) for the exact Supabase and Vercel configuration. Keep cryptographic keys stable: changing them can make previously stored encrypted values or credentials unusable.

### Android gateway

Open [`android-gateway/`](./android-gateway/) in Android Studio and follow its [build and pairing instructions](./android-gateway/README.md). Pair the phone using an enrollment token created in the owner console.

The gateway requires sensitive Android permissions, including SMS access. Distribute it only to devices you control and review applicable Android distribution policies before publishing.

## API example

Create a templated SMS request:

```bash
curl -X POST "https://YOUR_SIMVAULT_HOST/v1/sms" \
  -H "Authorization: Bearer sv_live_YOUR_API_KEY" \
  -H "Idempotency-Key: order-1001" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "+12025550143",
    "template_id": "login_notice",
    "variables": { "name": "Example User" },
    "purpose": "account_transactional"
  }'
```

Create an OTP challenge at `POST /v1/otp/challenges`, then submit the user's code to `POST /v1/otp/verify`. Requests require an API key with the appropriate scope and must satisfy the application's configured policies. The OpenAPI document is available at `/v1/openapi.json`.

## Project layout

| Path | Description |
| --- | --- |
| [`src/`](./src/) | React, TypeScript, and Tailwind owner console |
| [`server/`](./server/) | Express API, authentication, business logic, and database layer |
| [`android-gateway/`](./android-gateway/) | Kotlin and Jetpack Compose Android gateway |
| [`infra/supabase_schema.sql`](./infra/supabase_schema.sql) | PostgreSQL schema |
| [`tests/`](./tests/) | Unit and API flow tests |
| [`deploy/`](./deploy/) | Self-hosted deployment assets |
| [`DATABASE_SETUP.md`](./DATABASE_SETUP.md) | Supabase and Vercel setup guide |

## Operational and legal considerations

- Use SMS only for recipients who have given appropriate consent, and follow applicable laws, carrier rules, and SIM-plan limits.
- Sending SMS may incur carrier charges. Delivery and availability depend on the Android device, mobile network, and carrier.
- Protect the owner account, API keys, database credentials, and cryptographic environment variables. Never commit `.env` or production secrets.
- The Android gateway is designed for owner-operated devices; it is not intended for unsolicited messaging or bypassing provider or carrier controls.

## License

SimVault is licensed under the [MIT License](./LICENSE).
