# 07 — Security & Abuse Controls

## Mandatory controls
- HTTPS/TLS everywhere.
- API keys are high entropy, scoped, hashed at rest, revocable, and shown only once.
- Separate device credentials from application API keys.
- Owner dashboard requires strong password and MFA.
- OTP: cryptographically secure random generation, short expiry (e.g. 3–5 minutes), one-time use, maximum attempts (e.g. 5), resend cooldown, per-number and per-IP throttles.
- Hash OTP with a server-side pepper/key; compare in constant time.
- Do not log OTP values, full phone numbers, API keys, or message bodies.
- Encrypt phone numbers and message content at rest; restrict decryption to worker service.
- Idempotency key prevents duplicate sends.
- Per-application daily cap and global SIM cap.
- Destination allowlist during development; owner-approved destinations in production.
- Pause switch if unusual volume or repeated failures occur.
- Device enrollment uses one-time expiring tokens.
- Device can be revoked immediately.
- Audit all key creation, rotation, revocation, template changes, device enrollment, and policy changes.
- Webhooks signed with HMAC and timestamp; retry with backoff and deduplicate.
- Backups encrypted; test restore.

## Abuse prevention
- Only send messages for legitimate, user-initiated account/security events.
- No unsolicited marketing or purchased phone lists.
- No sender-ID spoofing or attempts to bypass telecom filtering.
- Apply applicable Indian telecom, privacy, and messaging rules. Obtain legal/compliance review before production.
- Carrier terms may prohibit automated use of consumer plan SMS bundles. Confirm written permission or use an approved service if required.

## Incident response
1. Pause gateway and disable affected API key.
2. Preserve audit logs.
3. Rotate credentials.
4. Review destinations, request origin, and message volume.
5. Resume only after cause is understood.
