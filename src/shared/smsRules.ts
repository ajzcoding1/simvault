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
  'personal_message',
  'bulk_broadcast',
] as const;

export type MessagePurpose = (typeof VALID_MESSAGE_PURPOSES)[number];

export const MAX_PERSONAL_SMS_LENGTH = 640;
export const MAX_BULK_RECIPIENTS = 100;

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
  leased: ['accepted_by_device', 'queued', 'sent_to_network', 'delivered', 'delivery_unknown', 'failed', 'expired'],
  accepted_by_device: ['sent_to_network', 'delivered', 'delivery_unknown', 'failed', 'expired'],
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

function isPrivateIpv4Octets(a: number, b: number, c: number): boolean {
  if (a === 0 || a === 10 || a === 127) return true; // 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local / cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // 192.0.0.0/24, 192.0.2.0/24 TEST-NET-1
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 TEST-NET-3
  if (a >= 224) return true; // multicast / reserved
  return false;
}

function isPrivateIpv4Words(hi: number, lo: number): boolean {
  return isPrivateIpv4Octets((hi >> 8) & 0xff, hi & 0xff, (lo >> 8) & 0xff);
}

function parseIpv6Words(raw: string): number[] | null {
  if (!raw.includes(':')) return null;
  let working = raw;
  // Convert trailing dotted-IPv4 segment (e.g. ::ffff:127.0.0.1 or ::127.0.0.1) to 2 hex words
  const lastColon = working.lastIndexOf(':');
  const tail = working.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = tail.split('.');
    if (v4.length !== 4 || !v4.every((p) => /^\d+$/.test(p))) return null;
    const oct = v4.map(Number);
    if (oct.some((n) => n < 0 || n > 255)) return null;
    const wHi = ((oct[0] << 8) | oct[1]).toString(16);
    const wLo = ((oct[2] << 8) | oct[3]).toString(16);
    working = `${working.slice(0, lastColon + 1)}${wHi}:${wLo}`;
  }

  const dblIdx = working.indexOf('::');
  if (dblIdx !== -1 && working.indexOf('::', dblIdx + 2) !== -1) return null;

  let groups: string[];
  if (dblIdx !== -1) {
    const left = working.slice(0, dblIdx).split(':').filter(Boolean);
    const right = working.slice(dblIdx + 2).split(':').filter(Boolean);
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...Array<string>(missing).fill('0'), ...right];
  } else {
    groups = working.split(':');
  }

  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const clean = ip.trim().toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  if (!clean) return true;

  if (clean.includes(':')) {
    const w = parseIpv6Words(clean);
    if (!w) return true;
    const isAllZeroPrefix = (count: number) => {
      for (let i = 0; i < count; i++) if (w[i] !== 0) return false;
      return true;
    };
    // Unspecified (::) and Loopback (::1)
    if (isAllZeroPrefix(7) && (w[7] === 0 || w[7] === 1)) return true;
    // IPv4-compatible IPv6 (::/96)
    if (isAllZeroPrefix(6)) return isPrivateIpv4Words(w[6], w[7]);
    // IPv4-mapped IPv6 (::ffff:0:0/96)
    if (isAllZeroPrefix(5) && w[5] === 0xffff) return isPrivateIpv4Words(w[6], w[7]);
    // IPv4-translated IPv6 (::ffff:0:0:0/96)
    if (isAllZeroPrefix(4) && w[4] === 0xffff && w[5] === 0) return isPrivateIpv4Words(w[6], w[7]);
    // Discard-only (100::/64)
    if (w[0] === 0x0100 && w[1] === 0 && w[2] === 0 && w[3] === 0) return true;
    // NAT64 (64:ff9b::/96 and 64:ff9b:1::/48)
    if (w[0] === 0x0064 && w[1] === 0xff9b) return true;
    // Teredo (2001::/32) & Documentation (2001:db8::/32)
    if (w[0] === 0x2001 && (w[1] === 0 || w[1] === 0x0db8)) return true;
    // 6to4 embedded IPv4 (2002::/16)
    if (w[0] === 0x2002) return isPrivateIpv4Words(w[1], w[2]);
    // ULA (fc00::/7), Link-local (fe80::/10), Multicast (ff00::/8)
    if ((w[0] & 0xfe00) === 0xfc00) return true;
    if ((w[0] & 0xffc0) === 0xfe80) return true;
    if ((w[0] & 0xff00) === 0xff00) return true;
    return false;
  }

  const ipv4Parts = clean.split('.');
  if (ipv4Parts.length === 4 && ipv4Parts.every((p) => /^\d+$/.test(p))) {
    const octets = ipv4Parts.map((n) => Number(n));
    if (octets.some((n) => n < 0 || n > 255)) return true;
    return isPrivateIpv4Octets(octets[0], octets[1], octets[2]);
  }

  return false;
}

export function sanitizeSmsText(raw: string): string {
  // Strip NUL and dangerous ASCII C0/DEL control bytes while keeping normal newlines/tabs
  return String(raw ?? '').replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim();
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

export interface SmsSegmentInfo {
  encoding: 'GSM-7' | 'UCS-2';
  length: number;
  segments: number;
  perSegmentLimit: number;
}

// Standard ASCII + common GSM-7 characters (non-GSM triggers UCS-2 70-char segments)
const GSM7_SAFE_REGEX = /^[\x20-\x7E\r\n£¥èéùìòÇØøÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ€^{}\\[~\]|]*$/;

export function calculateSmsSegmentInfo(text: string): SmsSegmentInfo {
  const value = text ?? '';
  const length = value.length;
  const isGsm7 = GSM7_SAFE_REGEX.test(value);
  const encoding: 'GSM-7' | 'UCS-2' = isGsm7 ? 'GSM-7' : 'UCS-2';
  if (length === 0) {
    return { encoding, length: 0, segments: 0, perSegmentLimit: isGsm7 ? 160 : 70 };
  }
  const singleLimit = isGsm7 ? 160 : 70;
  const multiLimit = isGsm7 ? 153 : 67;
  const segments = length <= singleLimit ? 1 : Math.ceil(length / multiLimit);
  return {
    encoding,
    length,
    segments,
    perSegmentLimit: length <= singleLimit ? singleLimit : multiLimit,
  };
}

export interface ParsedBulkRecipients {
  validNumbers: string[];
  invalidInputs: string[];
  duplicateCount: number;
}

export function parseBulkPhoneList(input: string | string[]): ParsedBulkRecipients {
  const rawTokens: string[] = [];
  if (Array.isArray(input)) {
    for (const item of input) {
      if (typeof item === 'string' && item.trim()) rawTokens.push(item.trim());
    }
  } else {
    const chunks = String(input ?? '').split(/[\r\n,;]+/);
    for (const chunk of chunks) {
      const trimmed = chunk.trim();
      if (!trimmed) continue;
      const plusCount = (trimmed.match(/\+/g) ?? []).length;
      if (plusCount >= 2) {
        for (const sub of trimmed.split(/(?=\+)/)) {
          if (sub.trim()) rawTokens.push(sub.trim());
        }
      } else {
        rawTokens.push(trimmed);
      }
    }
  }

  const seen = new Set<string>();
  const validNumbers: string[] = [];
  const invalidInputs: string[] = [];
  let duplicateCount = 0;

  for (const token of rawTokens) {
    const normalized = normalizeE164(token);
    if (!isValidE164(normalized)) {
      invalidInputs.push(token);
      continue;
    }
    if (seen.has(normalized)) {
      duplicateCount++;
      continue;
    }
    seen.add(normalized);
    validNumbers.push(normalized);
  }

  return { validNumbers, invalidInputs, duplicateCount };
}
