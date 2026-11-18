import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

type KeyName = 'API_KEY_PEPPER' | 'JWT_PRIVATE_KEY' | 'OTP_PEPPER' | 'FIELD_ENCRYPTION_KEY';

let runtimeKeysCache: Record<KeyName, string> | null = null;

function loadOrCreateRuntimeKeys(): Record<KeyName, string> {
  if (runtimeKeysCache) return runtimeKeysCache;

  const isInMemory = process.env.NODE_ENV === 'test' || process.env.SIMVAULT_DB_PATH === ':memory:';
  const keysPath = path.resolve(process.cwd(), 'data', '.simvault.keys');

  if (!isInMemory && fs.existsSync(keysPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(keysPath, 'utf8')) as Partial<Record<KeyName, string>>;
      if (
        parsed.API_KEY_PEPPER &&
        parsed.JWT_PRIVATE_KEY &&
        parsed.OTP_PEPPER &&
        parsed.FIELD_ENCRYPTION_KEY
      ) {
        runtimeKeysCache = parsed as Record<KeyName, string>;
        return runtimeKeysCache;
      }
    } catch {
      // Regenerate below if corrupted
    }
  }

  const generated: Record<KeyName, string> = {
    API_KEY_PEPPER: crypto.randomBytes(32).toString('hex'),
    JWT_PRIVATE_KEY: crypto.randomBytes(32).toString('hex'),
    OTP_PEPPER: crypto.randomBytes(32).toString('hex'),
    FIELD_ENCRYPTION_KEY: crypto.randomBytes(32).toString('hex'),
  };

  if (!isInMemory) {
    fs.mkdirSync(path.dirname(keysPath), { recursive: true });
    fs.writeFileSync(keysPath, JSON.stringify(generated, null, 2), { mode: 0o600 });
  }

  runtimeKeysCache = generated;
  return runtimeKeysCache;
}

function getEnvKey(name: KeyName, _fallbackSeed: string): Buffer {
  const raw = process.env[name];
  if (raw && raw.length >= 16) {
    return crypto.createHash('sha256').update(raw).digest();
  }
  const keys = loadOrCreateRuntimeKeys();
  return crypto.createHash('sha256').update(keys[name]).digest();
}

export function hashApiKey(rawKey: string): string {
  const pepper = getEnvKey('API_KEY_PEPPER', 'api-key');
  return crypto.createHmac('sha256', pepper).update(rawKey.trim()).digest('hex');
}

export function generateApiKey(environment: 'test' | 'live'): { rawKey: string; keyPrefix: string; secretHash: string } {
  const token = crypto.randomBytes(24).toString('base64url');
  const rawKey = `sv_${environment}_${token}`;
  const keyPrefix = rawKey.slice(0, 16);
  const secretHash = hashApiKey(rawKey);
  return { rawKey, keyPrefix, secretHash };
}

export function generateDeviceToken(): { rawToken: string; tokenHash: string } {
  const rawToken = `sv_dev_${crypto.randomBytes(24).toString('base64url')}`;
  const tokenHash = hashToken(rawToken);
  return { rawToken, tokenHash };
}

export function generateEnrollmentToken(): { rawToken: string; tokenHash: string } {
  const code = crypto.randomBytes(6).toString('hex').toUpperCase();
  const rawToken = `ENROLL-${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}`;
  const tokenHash = hashToken(rawToken);
  return { rawToken, tokenHash };
}

export function hashToken(rawToken: string): string {
  const pepper = getEnvKey('JWT_PRIVATE_KEY', 'token');
  return crypto.createHmac('sha256', pepper).update(rawToken.trim()).digest('hex');
}

export function hashDestination(e164: string): string {
  const pepper = getEnvKey('OTP_PEPPER', 'destination');
  return crypto.createHmac('sha256', pepper).update(e164.trim()).digest('hex');
}

export function generateOtpCode(digits = 6): string {
  const min = Math.pow(10, digits - 1);
  const max = Math.pow(10, digits);
  return String(crypto.randomInt(min, max));
}

export function hashOtpCode(challengeId: string, code: string): string {
  const pepper = getEnvKey('OTP_PEPPER', 'otp');
  return crypto.createHmac('sha256', pepper).update(`${challengeId}:${code.trim()}`).digest('hex');
}

export function verifyOtpHashConstantTime(challengeId: string, submittedCode: string, expectedHashHex: string): boolean {
  const actualHex = hashOtpCode(challengeId, submittedCode);
  const a = Buffer.from(actualHex, 'hex');
  const b = Buffer.from(expectedHashHex, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function encryptField(plaintext: string): string {
  const key = getEnvKey('FIELD_ENCRYPTION_KEY', 'field-aes');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString('base64')}.${tag.toString('base64')}.${encrypted.toString('base64')}`;
}

export function decryptField(ciphertext: string): string {
  const parts = ciphertext.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted field payload');
  }
  const [ivB64, tagB64, dataB64] = parts;
  const key = getEnvKey('FIELD_ENCRYPTION_KEY', 'field-aes');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]);
  return decrypted.toString('utf8');
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, storedHash: string): boolean {
  const [salt, keyHex] = storedHash.split(':');
  if (!salt || !keyHex) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(keyHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

export function signWebhookPayload(secret: string, timestamp: string, eventId: string, bodyJson: string): string {
  const signedContent = `${timestamp}.${eventId}.${bodyJson}`;
  return crypto.createHmac('sha256', secret).update(signedContent).digest('hex');
}

// RFC 6238 TOTP (Base32 secret, 30s step, 6 digits)
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTotpSecret(): string {
  const bytes = crypto.randomBytes(20);
  let out = '';
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

function decodeBase32(secret: string): Buffer {
  const cleaned = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

export function computeTotpCode(secret: string, timeMs = Date.now()): string {
  const key = decodeBase32(secret);
  const counter = Math.floor(timeMs / 1000 / 30);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const codeInt =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(codeInt % 1000000).padStart(6, '0');
}

export function verifyTotpCode(secret: string, submittedCode: string, timeMs = Date.now()): boolean {
  const clean = submittedCode.trim();
  if (!/^\d{6}$/.test(clean)) return false;
  for (const delta of [-30000, 0, 30000]) {
    const expected = computeTotpCode(secret, timeMs + delta);
    if (crypto.timingSafeEqual(Buffer.from(clean), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}
