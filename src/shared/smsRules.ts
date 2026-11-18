export type MessageStatus =
  | 'created'
  | 'queued'
  | 'leased'
  | 'accepted_by_device'
  | 'sent_to_network'
  | 'delivered'
  | 'delivery_unknown'
  | 'failed'
  | 'expired';

export type OtpChallengeStatus = 'queued' | 'sent' | 'verified' | 'expired' | 'locked' | 'failed';

export type ApiKeyScope = 'sms:send' | 'otp:create' | 'otp:verify' | 'usage:read';

export const ALL_API_SCOPES: ApiKeyScope[] = [
  'sms:send',
  'otp:create',
  'otp:verify',
  'usage:read',
];

export const VALID_MESSAGE_PURPOSES = [
  'login',
  'signup',
  'password_reset',
  'mfa',
  'account_transactional',
  'security_alert',
  'order_alert',
] as const;

export type MessagePurpose = (typeof VALID_MESSAGE_PURPOSES)[number];

const E164_REGEX = /^\+[1-9]\d{6,14}$/;

export function normalizeE164(raw: string): string {
  return raw.trim().replace(/[\s()-]/g, '');
}

export function isValidE164(phone: string): boolean {
  const normalized = normalizeE164(phone);
  return E164_REGEX.test(normalized);
}

export function maskE164(phone: string): string {
  const normalized = normalizeE164(phone);
  if (!normalized.startsWith('+') || normalized.length < 7) {
    return '+••••••';
  }
  const prefixLen = normalized.startsWith('+1') || normalized.startsWith('+7') ? 2 : 3;
  const prefix = normalized.slice(0, prefixLen);
  const suffix = normalized.slice(-4);
  const maskLen = Math.max(4, normalized.length - prefix.length - suffix.length);
  return `${prefix}${'•'.repeat(maskLen)}${suffix}`;
}

const ALLOWED_TRANSITIONS: Record<MessageStatus, MessageStatus[]> = {
  created: ['queued', 'failed', 'expired'],
  queued: ['leased', 'expired', 'failed'],
  leased: ['accepted_by_device', 'queued', 'sent_to_network', 'delivery_unknown', 'failed', 'expired'],
  accepted_by_device: ['sent_to_network', 'delivery_unknown', 'failed', 'expired'],
  sent_to_network: ['delivered', 'delivery_unknown', 'failed'],
  delivered: [],
  delivery_unknown: ['delivered', 'failed'],
  failed: [],
  expired: [],
};

export function isValidMessageTransition(from: MessageStatus, to: MessageStatus): boolean {
  return ALLOWED_TRANSITIONS[from]?.includes(to) ?? false;
}

export function isTerminalMessageStatus(status: MessageStatus): boolean {
  return status === 'delivered' || status === 'failed' || status === 'expired';
}

export function renderTemplate(
  templateBody: string,
  variables: Record<string, string | number | boolean>
): { rendered: string; missingVariables: string[] } {
  const missing = new Set<string>();
  const rendered = templateBody.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_match, key: string) => {
    if (Object.prototype.hasOwnProperty.call(variables, key) && variables[key] !== undefined && variables[key] !== null) {
      const clean = String(variables[key]).replace(/[\r\n\t]+/g, ' ').trim();
      return clean.slice(0, 64);
    }
    missing.add(key);
    return `{{${key}}}`;
  });
  return {
    rendered,
    missingVariables: Array.from(missing),
  };
}

export function extractTemplateVariables(templateBody: string): string[] {
  const vars = new Set<string>();
  const regex = /\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(templateBody)) !== null) {
    vars.add(match[1]);
  }
  return Array.from(vars);
}

const SENSITIVE_KEY_PATTERN = /(secret|token|password|otp|code|authorization|api_key|apikey|body|phone|msisdn|destination|to)/i;

export function redactSensitiveMetadata(input: unknown): unknown {
  if (input === null || input === undefined) return input;
  if (typeof input === 'string') {
    if (E164_REGEX.test(input.trim())) {
      return maskE164(input);
    }
    if (/^sv_(live|test)_[a-zA-Z0-9_-]{8,}$/.test(input.trim())) {
      return `${input.trim().slice(0, 12)}••••[REDACTED]`;
    }
    return input;
  }
  if (Array.isArray(input)) {
    return input.map((item) => redactSensitiveMetadata(item));
  }
  if (typeof input === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
      if (SENSITIVE_KEY_PATTERN.test(k) && !k.endsWith('_masked') && !k.endsWith('_prefix') && !k.endsWith('_id')) {
        if (typeof v === 'string' && E164_REGEX.test(v.trim())) {
          out[k] = maskE164(v);
        } else {
          out[k] = '[REDACTED]';
        }
      } else {
        out[k] = redactSensitiveMetadata(v);
      }
    }
    return out;
  }
  return input;
}

export function parseApiKeyPrefix(rawKey: string): { validFormat: boolean; environment: 'live' | 'test' | null; prefix: string } {
  const trimmed = rawKey.trim();
  const match = /^sv_(live|test)_([a-zA-Z0-9_-]{16,})$/.exec(trimmed);
  if (!match) {
    return { validFormat: false, environment: null, prefix: '' };
  }
  const env = match[1] as 'live' | 'test';
  const prefix = trimmed.slice(0, env === 'live' ? 16 : 16);
  return { validFormat: true, environment: env, prefix };
}

export function calculateSimRemainingEstimate(planLimit: number, sentCount: number): {
  remaining: number;
  utilizationPct: number;
} {
  const safeLimit = Math.max(0, planLimit);
  const safeSent = Math.max(0, sentCount);
  const remaining = Math.max(0, safeLimit - safeSent);
  const utilizationPct = safeLimit > 0 ? Math.min(100, Math.round((safeSent / safeLimit) * 100)) : 0;
  return { remaining, utilizationPct };
}

export function isValidHttpUrl(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:';
  } catch {
    return false;
  }
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const clean = ip.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!clean) return true;

  // IPv4-mapped IPv6 e.g. ::ffff:127.0.0.1
  if (clean.startsWith('::ffff:')) {
    return isPrivateOrReservedIp(clean.slice(7));
  }

  // IPv6 loopback, unspecified, ULA (fc00::/7), link-local (fe80::/10)
  if (
    clean === '::1' ||
    clean === '::' ||
    clean.startsWith('fc') ||
    clean.startsWith('fd') ||
    clean.startsWith('fe8') ||
    clean.startsWith('fe9') ||
    clean.startsWith('fea') ||
    clean.startsWith('feb')
  ) {
    return true;
  }

  const ipv4Parts = clean.split('.');
  if (ipv4Parts.length === 4 && ipv4Parts.every((p) => /^\d+$/.test(p))) {
    const [a, b] = ipv4Parts.map((n) => Number(n));
    if (a === 0 || a === 10 || a === 127) return true; // 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
    if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
    if (a === 192 && b === 168) return true; // 192.168.0.0/16
    if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a >= 224) return true; // multicast / reserved
  }

  return false;
}

export function isValidWebhookUrl(value: string): boolean {
  try {
    const parsed = new URL(value.trim());
    if (parsed.protocol !== 'https:') return false;
    if (parsed.username || parsed.password) return false;
    const host = parsed.hostname.toLowerCase();
    if (!host) return false;
    if (
      host === 'localhost' ||
      host.endsWith('.localhost') ||
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      host.endsWith('.example') ||
      host === 'example.com'
    ) {
      return false;
    }
    if (isPrivateOrReservedIp(host)) return false;
    return true;
  } catch {
    return false;
  }
}
