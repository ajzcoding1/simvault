# 06 — Web Dashboard

## 1. Navigation
- Overview
- Applications
- API Keys
- API Documentation
- Messages
- OTP Challenges
- Gateway Devices
- SIM & Usage
- Templates
- Webhooks
- Security & Rate Limits
- Audit Logs
- Settings

## 2. Overview cards
- Gateway online/offline
- SIM detected / no SIM
- SMS requests today
- Sent to network
- Delivered (if receipt available)
- Failed / delivery unknown
- Estimated plan SMS remaining
- Queue depth

## 3. Application configuration
Each owned website/app gets:
- Application name and environment
- Application ID
- API base URL
- API key creation, rotation, revocation
- Scopes and daily limits
- Allowed OTP purposes
- Webhook URL and signing secret
- Copyable server-side integration snippets
- Test/live mode toggle

**Important:** API secret is shown once. Never embed a live secret in frontend/browser code. The website frontend calls its own backend; that backend calls this platform.

## 4. API integration settings page
Display:
- Base URL
- Application ID
- Key prefix (not full key)
- Key status and last-used timestamp
- Enabled scopes
- Rate limit
- Example cURL and Node.js server code
- Webhook signing instructions
- Test request button that does not send real SMS

## 5. SIM usage display
Show:
- Carrier label and masked number
- Device associated
- Plan cycle dates entered by owner
- Estimated SMS sent this cycle
- Estimated remaining bundle
- Warning threshold
- Manual reconciliation field

Do not claim to read the carrier's exact bundled SMS balance unless an official carrier interface provides it.
