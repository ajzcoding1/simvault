# 05 — Android Gateway App

## 1. Purpose
A privately managed Android application on a dedicated phone with the owner-authorized SIM. It receives queued send jobs from our server and submits SMS through Android's native SMS framework.

## 2. Main screens
- Pair Device (scan one-time enrollment QR / enter code)
- Gateway Status (connected, server, last heartbeat)
- SIM Status (slot, carrier label, network availability; mask phone number)
- Permissions Status
- Pending / Recent Jobs
- Pause / Resume Gateway
- Diagnostics and app version

## 3. Android components
- Kotlin
- `SmsManager` / appropriate subscription-specific API
- WorkManager for reliable scheduled work where allowed
- Foreground service only when justified and compliant with current Android rules
- EncryptedSharedPreferences or Android Keystore-backed storage for device credential
- HTTPS client with certificate validation
- Local job journal to prevent duplicate sends after app/process restart

## 4. Job handling
1. Poll server over HTTPS.
2. Validate job signature/lease and expiry.
3. Persist job ID locally as `received`.
4. Check permission, SIM, subscription, network, destination, and policy.
5. Submit SMS using the selected SIM subscription.
6. Report `sent_to_network` or a safe failure code.
7. If app restarts, reconcile local job state before retrying.
8. Never resend automatically when send outcome is ambiguous; mark `delivery_unknown` and require controlled reconciliation.

## 5. Permissions and platform constraints
- Request `SEND_SMS` only where allowed by Android distribution and policy.
- Runtime permission must be granted by the device owner.
- Multi-SIM selection must be explicit; do not silently choose a SIM.
- Android version, OEM battery management, default-SMS role, and distribution channel can affect behavior.
- Google Play has strict restrictions on SMS permissions. A private/internal distribution route may be required, but must still respect Android security controls.
- Do not attempt to bypass permissions, carrier limits, spam controls, or device safeguards.

## 6. Device security
- One-time enrollment token expires quickly and can be used once.
- Device token is unique, revocable, and stored in Android Keystore-backed storage.
- TLS only; no plaintext credentials in logs.
- Remote pause/revoke.
- Device sends heartbeat and app version.
- No remote arbitrary shell commands; server may issue only a narrow `send_sms` job schema.
