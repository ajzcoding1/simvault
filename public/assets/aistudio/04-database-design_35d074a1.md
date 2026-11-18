# 04 — Database Design

Use PostgreSQL, UUID primary keys, UTC timestamps, migrations, and foreign keys.

## Tables

### users
`id, email, password_hash, role, mfa_enabled, created_at, updated_at`

### applications
`id, owner_user_id, name, environment(test/live), status, allowed_purposes_json, daily_limit, created_at`

### api_keys
`id, application_id, key_prefix, secret_hash, scopes_json, status, last_used_at, expires_at, revoked_at, created_at`
Never store raw API keys.

### gateway_devices
`id, name, device_token_hash, status(online/offline/paused), app_version, android_version, last_heartbeat_at, enrolled_at, revoked_at`

### sims
`id, device_id, carrier_label, masked_msisdn, slot_index, plan_sms_limit, period_start, period_end, estimated_sms_remaining, notes, updated_at`
The remaining count is an estimate unless the carrier provides authoritative usage data. Do not claim it is exact based only on app sends.

### message_templates
`id, owner_user_id, code, purpose, body, status, created_at, updated_at`
Templates should be reviewed for applicable carrier/regulatory requirements before live use.

### messages
`id, application_id, device_id, destination_e164_encrypted, template_id, body_encrypted, purpose, status, idempotency_key, ttl_expires_at, created_at, queued_at, leased_at, sent_at, delivered_at, failed_at, error_code`
Restrict access to encrypted message content. Redact from logs.

### otp_challenges
`id, application_id, destination_hash, destination_encrypted, code_hash, purpose, status, expires_at, attempts, max_attempts, consumed_at, message_id, created_at`
Store only a keyed hash of OTP; never store plaintext OTP after creation.

### gateway_job_leases
`id, message_id, device_id, lease_token_hash, leased_at, lease_expires_at, attempt_count`

### usage_events
`id, application_id, device_id, message_id, event_type, units, occurred_at`
Use immutable events to calculate usage.

### webhook_endpoints
`id, application_id, url, secret_encrypted, enabled, event_types_json, created_at`

### webhook_deliveries
`id, endpoint_id, event_id, status, attempt_count, next_attempt_at, last_http_status, created_at`

### audit_logs
`id, actor_type, actor_id, action, target_type, target_id, metadata_redacted_json, ip_address, created_at`

## Indexes
- `messages(status, created_at)`
- `messages(application_id, created_at)`
- `otp_challenges(application_id, expires_at, status)`
- `gateway_job_leases(device_id, lease_expires_at)`
- Unique `(application_id, idempotency_key)` where key is not null
- `api_keys(key_prefix, status)`
- `usage_events(application_id, occurred_at)`

## Retention
Define and document retention for message metadata, phone numbers, OTP challenge metadata, audit logs, and delivery receipts. Delete or anonymize data when no longer needed, subject to legal obligations.
