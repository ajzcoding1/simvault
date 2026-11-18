import type { ApiKeyScope, MessageStatus } from './shared/smsRules';

export interface OverviewResponse {
  global_paused: boolean;
  settings: Record<string, string>;
  kpis: {
    requests_today: number;
    sent_to_network_today: number;
    queue_depth: number;
    active_otps: number;
    status_breakdown: Array<{ status: MessageStatus; count: number }>;
  };
  devices: GatewayDevice[];
  sims: SimRecord[];
  recent_messages: MessageRecord[];
  recent_audit: AuditLogRecord[];
}

export interface ApplicationRecord {
  id: string;
  owner_user_id: string;
  name: string;
  environment: 'test' | 'live';
  status: 'active' | 'paused' | 'disabled';
  allowed_purposes_json: string;
  daily_limit: number;
  allowlist_only: number;
  created_at: string;
  active_keys_count?: number;
  total_messages_count?: number;
}

export interface ApiKeyRecord {
  id: string;
  application_id: string;
  application_name: string;
  environment: 'test' | 'live';
  name: string;
  key_prefix: string;
  scopes_json: string;
  status: 'active' | 'rotating' | 'revoked';
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
  available_scopes?: ApiKeyScope[];
}

export interface GatewayDevice {
  id: string;
  name: string;
  status: 'online' | 'offline' | 'paused' | 'revoked';
  app_version: string;
  android_version: string;
  permission_send_sms: number;
  network_type: string;
  battery_pct: number;
  sim_ready: number;
  last_heartbeat_at: string | null;
  enrolled_at: string;
  revoked_at: string | null;
}

export interface SimRecord {
  id: string;
  device_id: string;
  device_name?: string;
  device_status?: string;
  carrier_label: string;
  masked_msisdn: string;
  slot_index: number;
  plan_sms_limit: number;
  period_start: string;
  period_end: string;
  estimated_sms_sent: number;
  estimated_sms_remaining: number;
  warning_threshold: number;
  notes: string;
  updated_at: string;
}

export interface MessageRecord {
  id: string;
  application_id: string;
  application_name?: string;
  environment?: 'test' | 'live';
  device_id: string | null;
  destination_masked: string;
  template_id: string;
  purpose: string;
  status: MessageStatus;
  is_test: number;
  idempotency_key: string | null;
  ttl_expires_at: string;
  created_at: string;
  queued_at: string | null;
  leased_at: string | null;
  accepted_at: string | null;
  sent_at: string | null;
  delivered_at: string | null;
  failed_at: string | null;
  error_code: string | null;
}

export interface OtpChallengeRecord {
  id: string;
  application_id: string;
  application_name: string;
  destination_masked: string;
  purpose: string;
  status: 'queued' | 'sent' | 'verified' | 'expired' | 'locked' | 'failed';
  is_test: number;
  expires_at: string;
  attempts: number;
  max_attempts: number;
  consumed_at: string | null;
  message_id: string | null;
  created_at: string;
}

export interface TemplateRecord {
  id: string;
  code: string;
  purpose: string;
  body: string;
  status: 'approved' | 'draft' | 'archived';
  created_at: string;
  updated_at: string;
}

export interface AllowlistEntry {
  id: string;
  application_id: string;
  application_name: string;
  e164_masked: string;
  label: string;
  created_at: string;
}

export interface WebhookEndpointRecord {
  id: string;
  application_id: string;
  application_name: string;
  url: string;
  enabled: number;
  event_types_json: string;
  created_at: string;
}

export interface WebhookDeliveryRecord {
  id: string;
  endpoint_id: string;
  event_id: string;
  event_type: string;
  payload_redacted_json: string;
  status: 'pending' | 'delivered' | 'failed';
  attempt_count: number;
  next_attempt_at: string;
  last_http_status: number | null;
  created_at: string;
  url: string;
}

export interface AuditLogRecord {
  id: string;
  actor_type: string;
  actor_id: string;
  action: string;
  target_type: string;
  target_id: string;
  metadata_redacted_json: string;
  ip_address: string;
  created_at: string;
}

export type NavSection =
  | 'overview'
  | 'applications'
  | 'api-keys'
  | 'api-docs'
  | 'messages'
  | 'otp-challenges'
  | 'gateway-devices'
  | 'sim-usage'
  | 'templates'
  | 'webhooks'
  | 'security'
  | 'audit-logs'
  | 'settings';
