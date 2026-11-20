var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res, err) => function __init() {
  if (err) throw err[0];
  try {
    return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
  } catch (e) {
    throw err = [e], e;
  }
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/crypto.ts
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
function resolveKeysPath() {
  const raw = process.env.SIMVAULT_KEYS_PATH?.trim();
  if (!raw) return path.resolve(process.cwd(), "data", ".simvault.keys");
  const expanded = raw.startsWith("~/") ? path.join(os.homedir(), raw.slice(2)) : raw;
  return path.resolve(process.cwd(), expanded);
}
function loadOrCreateRuntimeKeys() {
  if (runtimeKeysCache) return runtimeKeysCache;
  const isInMemory = process.env.NODE_ENV === "test" || process.env.SIMVAULT_DB_PATH === ":memory:";
  const isServerless = Boolean(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME);
  const keysPath = resolveKeysPath();
  if (!isInMemory && fs.existsSync(keysPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(keysPath, "utf8"));
      if (parsed.API_KEY_PEPPER && parsed.JWT_PRIVATE_KEY && parsed.OTP_PEPPER && parsed.FIELD_ENCRYPTION_KEY) {
        runtimeKeysCache = parsed;
        return runtimeKeysCache;
      }
    } catch {
    }
  }
  const generated = {
    API_KEY_PEPPER: crypto.randomBytes(32).toString("hex"),
    JWT_PRIVATE_KEY: crypto.randomBytes(32).toString("hex"),
    OTP_PEPPER: crypto.randomBytes(32).toString("hex"),
    FIELD_ENCRYPTION_KEY: crypto.randomBytes(32).toString("hex")
  };
  if (!isInMemory && !isServerless) {
    try {
      fs.mkdirSync(path.dirname(keysPath), { recursive: true });
      fs.writeFileSync(keysPath, JSON.stringify(generated, null, 2), { mode: 384 });
    } catch {
    }
  } else if (isServerless && !warnedMissingEnvKeys) {
    warnedMissingEnvKeys = true;
    console.warn(
      "[SimVault] Missing API_KEY_PEPPER/JWT_PRIVATE_KEY/OTP_PEPPER/FIELD_ENCRYPTION_KEY env vars in serverless environment; using ephemeral runtime keys."
    );
  }
  runtimeKeysCache = generated;
  return runtimeKeysCache;
}
function getEnvKey(name, _fallbackSeed) {
  const raw = process.env[name];
  if (raw && raw.length >= 16) {
    return crypto.createHash("sha256").update(raw).digest();
  }
  const keys = loadOrCreateRuntimeKeys();
  return crypto.createHash("sha256").update(keys[name]).digest();
}
function hashApiKey(rawKey) {
  const pepper = getEnvKey("API_KEY_PEPPER", "api-key");
  return crypto.createHmac("sha256", pepper).update(rawKey.trim()).digest("hex");
}
function generateApiKey(environment) {
  const token = crypto.randomBytes(24).toString("base64url");
  const rawKey = `sv_${environment}_${token}`;
  const keyPrefix = rawKey.slice(0, 16);
  const secretHash = hashApiKey(rawKey);
  return { rawKey, keyPrefix, secretHash };
}
function generateDeviceToken() {
  const rawToken = `sv_dev_${crypto.randomBytes(24).toString("base64url")}`;
  const tokenHash = hashToken(rawToken);
  return { rawToken, tokenHash };
}
function generateEnrollmentToken() {
  const code = crypto.randomBytes(6).toString("hex").toUpperCase();
  const rawToken = `ENROLL-${code.slice(0, 4)}-${code.slice(4, 8)}-${code.slice(8, 12)}`;
  const tokenHash = hashToken(rawToken);
  return { rawToken, tokenHash };
}
function hashToken(rawToken) {
  const pepper = getEnvKey("JWT_PRIVATE_KEY", "token");
  return crypto.createHmac("sha256", pepper).update(rawToken.trim()).digest("hex");
}
function hashDestination(e164) {
  const pepper = getEnvKey("OTP_PEPPER", "destination");
  return crypto.createHmac("sha256", pepper).update(e164.trim()).digest("hex");
}
function generateOtpCode(digits = 6) {
  const min = Math.pow(10, digits - 1);
  const max = Math.pow(10, digits);
  return String(crypto.randomInt(min, max));
}
function hashOtpCode(challengeId, code) {
  const pepper = getEnvKey("OTP_PEPPER", "otp");
  return crypto.createHmac("sha256", pepper).update(`${challengeId}:${code.trim()}`).digest("hex");
}
function verifyOtpHashConstantTime(challengeId, submittedCode, expectedHashHex) {
  const actualHex = hashOtpCode(challengeId, submittedCode);
  const a = Buffer.from(actualHex, "hex");
  const b = Buffer.from(expectedHashHex, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
function encryptField(plaintext) {
  const key = getEnvKey("FIELD_ENCRYPTION_KEY", "field-aes");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}.${tag.toString("base64")}.${encrypted.toString("base64")}`;
}
function decryptField(ciphertext) {
  const parts = ciphertext.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid encrypted field payload");
  }
  const [ivB64, tagB64, dataB64] = parts;
  const key = getEnvKey("FIELD_ENCRYPTION_KEY", "field-aes");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivB64, "base64"));
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(dataB64, "base64")), decipher.final()]);
  return decrypted.toString("utf8");
}
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}
function verifyPassword(password, storedHash) {
  const [salt, keyHex] = storedHash.split(":");
  if (!salt || !keyHex) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(keyHex, "hex");
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}
function signWebhookPayload(secret, timestamp, eventId, bodyJson) {
  const signedContent = `${timestamp}.${eventId}.${bodyJson}`;
  return crypto.createHmac("sha256", secret).update(signedContent).digest("hex");
}
function generateTotpSecret() {
  const bytes = crypto.randomBytes(20);
  let out = "";
  let bits = 0;
  let value = 0;
  for (const byte of bytes) {
    value = value << 8 | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[value >>> bits - 5 & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[value << 5 - bits & 31];
  }
  return out;
}
function decodeBase32(secret) {
  const cleaned = secret.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = value << 5 | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push(value >>> bits - 8 & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}
function computeTotpCode(secret, timeMs = Date.now()) {
  const key = decodeBase32(secret);
  const counter = Math.floor(timeMs / 1e3 / 30);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeUInt32BE(Math.floor(counter / 4294967296), 0);
  counterBuf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac("sha1", key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 15;
  const codeInt = (hmac[offset] & 127) << 24 | (hmac[offset + 1] & 255) << 16 | (hmac[offset + 2] & 255) << 8 | hmac[offset + 3] & 255;
  return String(codeInt % 1e6).padStart(6, "0");
}
function verifyTotpCode(secret, submittedCode, timeMs = Date.now()) {
  const clean = submittedCode.trim();
  if (!/^\d{6}$/.test(clean)) return false;
  for (const delta of [-3e4, 0, 3e4]) {
    const expected = computeTotpCode(secret, timeMs + delta);
    if (crypto.timingSafeEqual(Buffer.from(clean), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}
var runtimeKeysCache, warnedMissingEnvKeys, BASE32_ALPHABET;
var init_crypto = __esm({
  "server/crypto.ts"() {
    runtimeKeysCache = null;
    warnedMissingEnvKeys = false;
    BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  }
});

// src/shared/smsRules.ts
function normalizeE164(raw) {
  return raw.trim().replace(/[\s()-]/g, "");
}
function isValidE164(phone) {
  const normalized = normalizeE164(phone);
  return E164_REGEX.test(normalized);
}
function maskE164(phone) {
  const normalized = normalizeE164(phone);
  if (!normalized.startsWith("+") || normalized.length < 7) {
    return "+\u2022\u2022\u2022\u2022\u2022\u2022";
  }
  const prefixLen = normalized.startsWith("+1") || normalized.startsWith("+7") ? 2 : 3;
  const prefix = normalized.slice(0, prefixLen);
  const suffix = normalized.slice(-4);
  const maskLen = Math.max(4, normalized.length - prefix.length - suffix.length);
  return `${prefix}${"\u2022".repeat(maskLen)}${suffix}`;
}
function isValidMessageTransition(from, to) {
  return ALLOWED_TRANSITIONS[from]?.includes(to) ?? false;
}
function renderTemplate(templateBody, variables) {
  const missing = /* @__PURE__ */ new Set();
  const rendered = templateBody.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_match, key) => {
    if (Object.prototype.hasOwnProperty.call(variables, key) && variables[key] !== void 0 && variables[key] !== null) {
      const clean = String(variables[key]).replace(/[\r\n\t]+/g, " ").trim();
      return clean.slice(0, 64);
    }
    missing.add(key);
    return `{{${key}}}`;
  });
  return {
    rendered,
    missingVariables: Array.from(missing)
  };
}
function redactSensitiveMetadata(input) {
  if (input === null || input === void 0) return input;
  if (typeof input === "string") {
    if (E164_REGEX.test(input.trim())) {
      return maskE164(input);
    }
    if (/^sv_(live|test)_[a-zA-Z0-9_-]{8,}$/.test(input.trim())) {
      return `${input.trim().slice(0, 12)}\u2022\u2022\u2022\u2022[REDACTED]`;
    }
    return input;
  }
  if (Array.isArray(input)) {
    return input.map((item) => redactSensitiveMetadata(item));
  }
  if (typeof input === "object") {
    const out = {};
    for (const [k, v] of Object.entries(input)) {
      if (SENSITIVE_KEY_PATTERN.test(k) && !k.endsWith("_masked") && !k.endsWith("_prefix") && !k.endsWith("_id")) {
        if (typeof v === "string" && E164_REGEX.test(v.trim())) {
          out[k] = maskE164(v);
        } else {
          out[k] = "[REDACTED]";
        }
      } else {
        out[k] = redactSensitiveMetadata(v);
      }
    }
    return out;
  }
  return input;
}
function calculateSimRemainingEstimate(planLimit, sentCount) {
  const safeLimit = Math.max(0, planLimit);
  const safeSent = Math.max(0, sentCount);
  const remaining = Math.max(0, safeLimit - safeSent);
  const utilizationPct = safeLimit > 0 ? Math.min(100, Math.round(safeSent / safeLimit * 100)) : 0;
  return { remaining, utilizationPct };
}
function isPrivateOrReservedIp(ip) {
  const clean = ip.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (!clean) return true;
  if (clean.startsWith("::ffff:")) {
    return isPrivateOrReservedIp(clean.slice(7));
  }
  if (clean === "::1" || clean === "::" || clean.startsWith("fc") || clean.startsWith("fd") || clean.startsWith("fe8") || clean.startsWith("fe9") || clean.startsWith("fea") || clean.startsWith("feb")) {
    return true;
  }
  const ipv4Parts = clean.split(".");
  if (ipv4Parts.length === 4 && ipv4Parts.every((p) => /^\d+$/.test(p))) {
    const [a, b] = ipv4Parts.map((n) => Number(n));
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a >= 224) return true;
  }
  return false;
}
function isValidWebhookUrl(value) {
  try {
    const parsed = new URL(value.trim());
    if (parsed.protocol !== "https:") return false;
    if (parsed.username || parsed.password) return false;
    const host = parsed.hostname.toLowerCase();
    if (!host) return false;
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".example") || host === "example.com") {
      return false;
    }
    if (isPrivateOrReservedIp(host)) return false;
    return true;
  } catch {
    return false;
  }
}
var ALL_API_SCOPES, VALID_MESSAGE_PURPOSES, E164_REGEX, ALLOWED_TRANSITIONS, SENSITIVE_KEY_PATTERN;
var init_smsRules = __esm({
  "src/shared/smsRules.ts"() {
    ALL_API_SCOPES = [
      "sms:send",
      "otp:create",
      "otp:verify",
      "usage:read"
    ];
    VALID_MESSAGE_PURPOSES = [
      "login",
      "signup",
      "password_reset",
      "mfa",
      "account_transactional",
      "security_alert",
      "order_alert"
    ];
    E164_REGEX = /^\+[1-9]\d{6,14}$/;
    ALLOWED_TRANSITIONS = {
      created: ["queued", "failed", "expired"],
      queued: ["leased", "expired", "failed"],
      leased: ["accepted_by_device", "queued", "sent_to_network", "delivery_unknown", "failed", "expired"],
      accepted_by_device: ["sent_to_network", "delivery_unknown", "failed", "expired"],
      sent_to_network: ["delivered", "delivery_unknown", "failed"],
      delivered: [],
      delivery_unknown: ["delivered", "failed"],
      failed: [],
      expired: []
    };
    SENSITIVE_KEY_PATTERN = /(secret|token|password|otp|code|authorization|api_key|apikey|body|phone|msisdn|destination|to)/i;
  }
});

// server/db.ts
import fs2 from "node:fs";
import os2 from "node:os";
import path2 from "node:path";
import crypto2 from "node:crypto";
import pg from "pg";
function convertPlaceholdersToPostgres(sql) {
  let out = "";
  let idx = 1;
  let inSingle = false;
  let inDouble = false;
  let inLineComment = false;
  let inBlockComment = false;
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    const next = sql[i + 1];
    if (inLineComment) {
      out += ch;
      if (ch === "\n") inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      out += ch;
      if (ch === "*" && next === "/") {
        out += "/";
        i++;
        inBlockComment = false;
      }
      continue;
    }
    if (inSingle) {
      out += ch;
      if (ch === "'" && next === "'") {
        out += "'";
        i++;
      } else if (ch === "'") {
        inSingle = false;
      }
      continue;
    }
    if (inDouble) {
      out += ch;
      if (ch === '"' && next === '"') {
        out += '"';
        i++;
      } else if (ch === '"') {
        inDouble = false;
      }
      continue;
    }
    if (ch === "-" && next === "-") {
      out += "--";
      i++;
      inLineComment = true;
      continue;
    }
    if (ch === "/" && next === "*") {
      out += "/*";
      i++;
      inBlockComment = true;
      continue;
    }
    if (ch === "'") {
      out += ch;
      inSingle = true;
      continue;
    }
    if (ch === '"') {
      out += ch;
      inDouble = true;
      continue;
    }
    if (ch === "?") {
      out += `$${idx++}`;
      continue;
    }
    out += ch;
  }
  return out;
}
function normalizeSqliteParams(params) {
  return params.map((p) => {
    if (p === void 0 || p === null) return null;
    if (typeof p === "boolean") return p ? 1 : 0;
    return p;
  });
}
function normalizePgParams(params) {
  return params.map((p) => {
    if (p === void 0 || p === null) return null;
    if (typeof p === "boolean") return p ? 1 : 0;
    return p;
  });
}
function stripOuterQuotes(value) {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2 || trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2) {
    return trimmed.slice(1, -1).trim();
  }
  return trimmed;
}
function resolvePostgresUrl(env = process.env) {
  const raw = env.SUPABASE_DB_URL || env.DATABASE_URL || env.POSTGRES_URL || env.POSTGRES_PRISMA_URL || env.POSTGRES_URL_NON_POOLING || "";
  const candidate = stripOuterQuotes(raw);
  if (candidate && /^postgres(ql)?:\/\//i.test(candidate)) {
    return candidate;
  }
  const supabaseUrl = stripOuterQuotes(env.SUPABASE_URL || "");
  const supabaseDbPassword = stripOuterQuotes(env.SUPABASE_DB_PASSWORD || "");
  if (supabaseUrl && supabaseDbPassword) {
    try {
      const parsed = new URL(supabaseUrl);
      const match = /^([a-z0-9-]+)\.supabase\.co$/i.exec(parsed.hostname);
      if (match) {
        const ref = match[1];
        const encodedPass = encodeURIComponent(supabaseDbPassword);
        const poolerHost = stripOuterQuotes(env.SUPABASE_DB_POOLER_HOST || "");
        const region = stripOuterQuotes(env.SUPABASE_DB_REGION || "");
        if (poolerHost) {
          return `postgresql://postgres.${ref}:${encodedPass}@${poolerHost}:6543/postgres`;
        }
        if (region) {
          return `postgresql://postgres.${ref}:${encodedPass}@aws-0-${region}.pooler.supabase.com:6543/postgres`;
        }
        return `postgresql://postgres:${encodedPass}@db.${ref}.supabase.co:5432/postgres`;
      }
    } catch {
    }
  }
  return null;
}
function resolveDbPath(dbPath) {
  const raw = (dbPath !== void 0 ? dbPath : process.env.SIMVAULT_DB_PATH)?.trim() ?? "";
  if (raw === ":memory:") return ":memory:";
  if (!raw) return path2.resolve(process.cwd(), "data", "simvault.db");
  let cleaned = raw;
  if (cleaned.startsWith("sqlite://")) cleaned = cleaned.slice("sqlite://".length);
  else if (cleaned.startsWith("file://")) cleaned = cleaned.slice("file://".length);
  if (cleaned === "~/") cleaned = os2.homedir();
  else if (cleaned.startsWith("~/")) cleaned = path2.join(os2.homedir(), cleaned.slice(2));
  return path2.resolve(process.cwd(), cleaned);
}
async function getDb(dbPath) {
  if (dbCache.client) return dbCache.client;
  if (dbCache.initPromise) return dbCache.initPromise;
  dbCache.initPromise = (async () => {
    const rawPgCandidate = stripOuterQuotes(
      process.env.SUPABASE_DB_URL || process.env.DATABASE_URL || process.env.POSTGRES_URL || process.env.POSTGRES_PRISMA_URL || process.env.POSTGRES_URL_NON_POOLING || ""
    );
    if (dbPath === void 0 && rawPgCandidate && /^https?:\/\//i.test(rawPgCandidate)) {
      throw new Error(
        "SUPABASE_DB_URL/DATABASE_URL appears to be an https:// API URL. Either paste the postgresql:// Transaction Pooler URI from Supabase -> Connect, or use SUPABASE_URL + SUPABASE_DB_PASSWORD + SUPABASE_DB_REGION."
      );
    }
    const pgUrl = dbPath === void 0 ? resolvePostgresUrl() : null;
    let client;
    if (pgUrl) {
      let connectionString = pgUrl;
      let useSsl = { rejectUnauthorized: false };
      try {
        const parsed = new URL(pgUrl);
        if (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1") {
          useSsl = false;
        } else {
          const sslMode = parsed.searchParams.get("sslmode");
          if (sslMode === "verify-full") {
            useSsl = { rejectUnauthorized: true };
          } else if (sslMode) {
            parsed.searchParams.delete("sslmode");
            connectionString = parsed.toString();
          }
        }
      } catch {
      }
      const pool = new PgPool({
        connectionString,
        ssl: useSsl,
        max: process.env.VERCEL ? 5 : 10,
        idleTimeoutMillis: 2e4,
        connectionTimeoutMillis: 1e4
      });
      pool.on("error", (err) => {
        console.error("[SimVault pg pool]", err.message);
      });
      const pgClient = new PostgresDbClient(pool);
      try {
        await pgClient.transaction(async (tx) => {
          await tx.exec("SELECT pg_advisory_xact_lock(84729103);");
          await migrateSchema(tx);
          await seedInitialData(tx);
          await syncEnvAdminCredentials(tx);
        });
      } catch (err) {
        await pool.end().catch(() => void 0);
        const msg = err instanceof Error ? err.message : String(err);
        if (/ENETUNREACH|EAI_AGAIN|ECONNREFUSED/i.test(msg) && pgUrl.includes(":5432")) {
          throw new Error(
            `Cannot reach Supabase direct port 5432 from this IPv4 serverless environment (${msg}). Set SUPABASE_DB_REGION (e.g. ap-south-1) or paste the port 6543 Transaction Pooler URI into SUPABASE_DB_URL.`
          );
        }
        throw err;
      }
      client = pgClient;
    } else {
      const explicitDbPath = (dbPath !== void 0 ? dbPath : process.env.SIMVAULT_DB_PATH)?.trim() ?? "";
      const allowEphemeralSqliteOnVercel = explicitDbPath === ":memory:" || explicitDbPath.startsWith("/tmp/");
      if (process.env.VERCEL && !allowEphemeralSqliteOnVercel) {
        throw new Error(
          "Missing Supabase PostgreSQL connection string for Vercel. Add SUPABASE_DB_URL, DATABASE_URL, or POSTGRES_URL (postgresql://...) in Vercel Project Settings -> Environment Variables, and remove SIMVAULT_DB_PATH."
        );
      }
      const targetPath = resolveDbPath(dbPath);
      if (targetPath !== ":memory:") {
        const dir = path2.dirname(targetPath);
        try {
          fs2.mkdirSync(dir, { recursive: true });
          fs2.accessSync(dir, fs2.constants.W_OK);
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          throw new Error(
            `Cannot write to SimVault database directory "${dir}" (resolved from SIMVAULT_DB_PATH="${process.env.SIMVAULT_DB_PATH ?? ""}", cwd="${process.cwd()}"). Fix folder permissions or set SIMVAULT_DB_PATH="./data/simvault.db" in .env. Details: ${reason}`
          );
        }
      }
      let rawDb;
      try {
        const { DatabaseSync: SqliteDatabaseSync } = await import("node:sqlite");
        rawDb = new SqliteDatabaseSync(targetPath);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        throw new Error(
          `Unable to open SQLite database at "${targetPath}". Check file/folder permissions (if created with sudo, run "sudo chown -R $USER:$USER ${path2.dirname(targetPath)}") or check SIMVAULT_DB_PATH in .env. Details: ${reason}`
        );
      }
      rawDb.exec("PRAGMA journal_mode = WAL;");
      rawDb.exec("PRAGMA foreign_keys = ON;");
      const sqliteClient = new SqliteDbClient(rawDb);
      await migrateSchema(sqliteClient);
      await seedInitialData(sqliteClient);
      await syncEnvAdminCredentials(sqliteClient);
      client = sqliteClient;
    }
    dbCache.client = client;
    return client;
  })();
  try {
    return await dbCache.initPromise;
  } catch (err) {
    dbCache.initPromise = void 0;
    throw err;
  }
}
async function migrateSchema(db) {
  await db.exec(SCHEMA_SQL);
  await runLiveModeMigration(db);
}
async function runLiveModeMigration(db) {
  const alreadyMigrated = await db.get(
    "SELECT value FROM platform_settings WHERE key = 'migration_live_mode_v2'"
  );
  if (alreadyMigrated?.value === "done") return;
  const hasUsers = await db.get("SELECT COUNT(*) as cnt FROM users");
  const userCount = Number(hasUsers?.cnt ?? 0);
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  if (userCount > 0) {
    await db.run("DELETE FROM webhook_deliveries WHERE endpoint_id = 'wh_portal_events'");
    await db.run("DELETE FROM webhook_endpoints WHERE id = 'wh_portal_events' OR url LIKE '%.example%'");
    await db.run("DELETE FROM otp_challenges WHERE id IN ('otp_c84a12', 'otp_c84a13')");
    await db.run(
      "DELETE FROM usage_events WHERE message_id IN ('msg_91f0a1', 'msg_91f0a2', 'msg_91f0a3', 'msg_91f0a4', 'msg_91f0a5', 'msg_91f0a6')"
    );
    await db.run(
      "DELETE FROM messages WHERE id IN ('msg_91f0a1', 'msg_91f0a2', 'msg_91f0a3', 'msg_91f0a4', 'msg_91f0a5', 'msg_91f0a6')"
    );
    await db.run("DELETE FROM sims WHERE id = 'sim_primary_slot0' OR device_id = 'dev_pixel7_gateway'");
    await db.run("DELETE FROM gateway_devices WHERE id = 'dev_pixel7_gateway'");
    await db.run(
      "DELETE FROM destination_allowlist WHERE label IN ('Owner Primary Handset', 'QA Verification Phone', 'US Staging Test Number')"
    );
    await db.run("DELETE FROM api_keys WHERE id IN ('key_portal_primary', 'key_sandbox_ci')");
    await db.run("DELETE FROM applications WHERE id = 'app_sandbox_test'");
    await db.run("DELETE FROM audit_logs WHERE target_id IN ('dev_pixel7_gateway', 'sim_primary_slot0', 'key_portal_primary')");
    await db.run("DELETE FROM platform_settings WHERE key = 'simulator_auto_process'");
    await db.run("UPDATE applications SET environment = 'live', status = 'active', allowlist_only = 0 WHERE id = 'app_portal_prod'");
    await db.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES ('live_mode', 'true', ?)
       ON CONFLICT(key) DO UPDATE SET value = 'true', updated_at = excluded.updated_at`,
      nowIso
    );
    await db.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES ('migration_live_mode_v2', 'done', ?)
       ON CONFLICT(key) DO UPDATE SET value = 'done', updated_at = excluded.updated_at`,
      nowIso
    );
  }
}
async function writeAuditLog(db, entry) {
  const redacted = redactSensitiveMetadata(entry.metadata ?? {});
  await db.run(
    `INSERT INTO audit_logs (id, actor_type, actor_id, action, target_type, target_id, metadata_redacted_json, ip_address, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    crypto2.randomUUID(),
    entry.actorType,
    entry.actorId,
    entry.action,
    entry.targetType,
    entry.targetId,
    JSON.stringify(redacted),
    entry.ipAddress ?? "127.0.0.1",
    (/* @__PURE__ */ new Date()).toISOString()
  );
}
async function seedInitialData(db) {
  const existingUsers = await db.get("SELECT COUNT(*) as cnt FROM users");
  if (Number(existingUsers?.cnt ?? 0) > 0) return;
  const now = /* @__PURE__ */ new Date();
  const isoNow = now.toISOString();
  const ownerId = "usr_owner_primary";
  const initialEmail = (process.env.SIMVAULT_ADMIN_EMAIL || "owner@simvault.local").trim().toLowerCase();
  const initialPassword = process.env.SIMVAULT_ADMIN_PASSWORD || "SimVault!2026";
  await db.run(
    `INSERT INTO users (id, email, password_hash, role, mfa_enabled, mfa_secret, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ownerId,
    initialEmail,
    hashPassword(initialPassword),
    "owner",
    0,
    generateTotpSecret(),
    isoNow,
    isoNow
  );
  const settings = [
    ["global_paused", "false"],
    ["live_mode", "true"],
    ["migration_live_mode_v2", "done"],
    ["otp_ttl_seconds", "300"],
    ["otp_max_attempts", "5"],
    ["otp_resend_cooldown_seconds", "45"],
    ["rate_limit_per_number_hourly", "6"],
    ["rate_limit_per_ip_minute", "30"],
    ["lease_timeout_seconds", "30"],
    ["max_send_retries", "3"],
    ["retention_days", "30"],
    ["global_daily_sim_cap", "300"]
  ];
  for (const [k, v] of settings) {
    await db.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO NOTHING`,
      k,
      v,
      isoNow
    );
  }
  const appProdId = "app_portal_prod";
  await db.run(
    `INSERT INTO applications (id, owner_user_id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO NOTHING`,
    appProdId,
    ownerId,
    "Customer Account Portal",
    "live",
    "active",
    JSON.stringify(["login", "signup", "mfa", "password_reset", "security_alert", "account_transactional"]),
    250,
    0,
    isoNow
  );
  const templates = [
    {
      id: "tpl_otp_login",
      code: "otp_login",
      purpose: "login",
      body: "Your verification code for {{app_name}} is {{code}}. Valid for {{ttl_minutes}} minutes. Do not share this code.",
      status: "approved"
    },
    {
      id: "tpl_login_notice",
      code: "login_notice",
      purpose: "account_transactional",
      body: "New sign-in detected for {{name}} on {{device_label}}. If this was not you, reset your credentials immediately.",
      status: "approved"
    },
    {
      id: "tpl_security_alert",
      code: "security_alert",
      purpose: "security_alert",
      body: "Security notice: {{event_summary}} on your account. Review recent activity in your security settings.",
      status: "approved"
    },
    {
      id: "tpl_password_reset",
      code: "otp_password_reset",
      purpose: "password_reset",
      body: "Password reset code for {{app_name}}: {{code}}. Expires in {{ttl_minutes}} minutes.",
      status: "approved"
    }
  ];
  for (const t of templates) {
    await db.run(
      `INSERT INTO message_templates (id, owner_user_id, code, purpose, body, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(id) DO NOTHING`,
      t.id,
      ownerId,
      t.code,
      t.purpose,
      t.body,
      t.status,
      isoNow,
      isoNow
    );
  }
  if (process.env.SIMVAULT_ADMIN_EMAIL?.trim() || process.env.SIMVAULT_ADMIN_PASSWORD?.trim()) {
    const initialSig = crypto2.createHash("sha256").update(`${process.env.SIMVAULT_ADMIN_EMAIL?.trim().toLowerCase() ?? ""}:${process.env.SIMVAULT_ADMIN_PASSWORD?.trim() ?? ""}`).digest("hex");
    await db.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      "env_admin_sync_sig",
      initialSig,
      isoNow
    );
  }
  await writeAuditLog(db, {
    actorType: "system",
    actorId: "bootstrap",
    action: "platform.live_mode_initialized",
    targetType: "platform_settings",
    targetId: "live_mode",
    metadata: { live_mode: true },
    ipAddress: "127.0.0.1"
  });
}
async function syncEnvAdminCredentials(db, overrides) {
  const rawEmail = (overrides?.email !== void 0 ? overrides.email : process.env.SIMVAULT_ADMIN_EMAIL)?.trim().toLowerCase() ?? "";
  const rawPassword = (overrides?.password !== void 0 ? overrides.password : process.env.SIMVAULT_ADMIN_PASSWORD)?.trim() ?? "";
  if (!rawEmail && !rawPassword) return false;
  const sig = crypto2.createHash("sha256").update(`${rawEmail}:${rawPassword}`).digest("hex");
  const existingSig = await db.get(
    "SELECT value FROM platform_settings WHERE key = 'env_admin_sync_sig'"
  );
  if (existingSig?.value === sig) return false;
  const owner = await db.get(
    "SELECT id, email FROM users WHERE role = 'owner' ORDER BY created_at ASC LIMIT 1"
  );
  if (!owner) return false;
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  const nextEmail = rawEmail || owner.email;
  const applySync = async (tx) => {
    if (rawPassword) {
      await tx.run(
        "UPDATE users SET email = ?, password_hash = ?, updated_at = ? WHERE id = ?",
        nextEmail,
        hashPassword(rawPassword),
        nowIso,
        owner.id
      );
      await tx.run("DELETE FROM sessions WHERE user_id = ?", owner.id);
    } else {
      await tx.run("UPDATE users SET email = ?, updated_at = ? WHERE id = ?", nextEmail, nowIso, owner.id);
    }
    await tx.run(
      `INSERT INTO platform_settings (key, value, updated_at) VALUES ('env_admin_sync_sig', ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
      sig,
      nowIso
    );
  };
  if ("transaction" in db && typeof db.transaction === "function") {
    await db.transaction(applySync);
  } else {
    await applySync(db);
  }
  await writeAuditLog(db, {
    actorType: "system",
    actorId: "env_sync",
    action: "owner.env_credentials_synced",
    targetType: "user",
    targetId: owner.id,
    metadata: { email: nextEmail, password_updated: Boolean(rawPassword) },
    ipAddress: "127.0.0.1"
  });
  return true;
}
var PgPool, SqliteDbClient, PgExecutor, PostgresDbClient, SCHEMA_SQL, globalForDb, dbCache;
var init_db = __esm({
  "server/db.ts"() {
    init_crypto();
    init_smsRules();
    ({ Pool: PgPool } = pg);
    SqliteDbClient = class {
      constructor(raw) {
        this.dialect = "sqlite";
        this.txTail = Promise.resolve();
        this.raw = raw;
      }
      async get(sql, ...params) {
        return this.raw.prepare(sql).get(...normalizeSqliteParams(params));
      }
      async all(sql, ...params) {
        return this.raw.prepare(sql).all(...normalizeSqliteParams(params));
      }
      async run(sql, ...params) {
        const res = this.raw.prepare(sql).run(...normalizeSqliteParams(params));
        return { changes: Number(res.changes ?? 0) };
      }
      async exec(sql) {
        this.raw.exec(sql);
      }
      async transaction(fn) {
        let release;
        const prev = this.txTail;
        this.txTail = new Promise((resolve) => {
          release = resolve;
        });
        await prev;
        this.raw.exec("BEGIN IMMEDIATE;");
        try {
          const result = await fn(this);
          this.raw.exec("COMMIT;");
          return result;
        } catch (err) {
          try {
            this.raw.exec("ROLLBACK;");
          } catch {
          }
          throw err;
        } finally {
          release();
        }
      }
      async close() {
        try {
          this.raw.exec("PRAGMA wal_checkpoint(TRUNCATE);");
        } catch {
        }
        try {
          this.raw.close();
        } catch {
        }
      }
    };
    PgExecutor = class {
      constructor(queryable) {
        this.dialect = "postgres";
        this.queryable = queryable;
      }
      async get(sql, ...params) {
        const pgSql = convertPlaceholdersToPostgres(sql);
        const res = await this.queryable.query(pgSql, normalizePgParams(params));
        return res.rows[0];
      }
      async all(sql, ...params) {
        const pgSql = convertPlaceholdersToPostgres(sql);
        const res = await this.queryable.query(pgSql, normalizePgParams(params));
        return res.rows;
      }
      async run(sql, ...params) {
        const pgSql = convertPlaceholdersToPostgres(sql);
        const res = await this.queryable.query(pgSql, normalizePgParams(params));
        return { changes: Number(res.rowCount ?? 0) };
      }
      async exec(sql) {
        await this.queryable.query(sql);
      }
    };
    PostgresDbClient = class extends PgExecutor {
      constructor(pool) {
        super(pool);
        this.pool = pool;
      }
      async transaction(fn) {
        const client = await this.pool.connect();
        const txExec = new PgExecutor(client);
        try {
          await client.query("BEGIN");
          const result = await fn(txExec);
          await client.query("COMMIT");
          return result;
        } catch (err) {
          try {
            await client.query("ROLLBACK");
          } catch {
          }
          throw err;
        } finally {
          client.release();
        }
      }
      async close() {
        await this.pool.end();
      }
    };
    SCHEMA_SQL = `
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'owner',
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_secret TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    mfa_verified INTEGER NOT NULL DEFAULT 1,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS applications (
    id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('test', 'live')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'paused', 'disabled')),
    allowed_purposes_json TEXT NOT NULL,
    daily_limit INTEGER NOT NULL DEFAULT 200,
    allowlist_only INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    secret_hash TEXT NOT NULL UNIQUE,
    scopes_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'rotating', 'revoked')),
    last_used_at TEXT,
    expires_at TEXT,
    revoked_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS gateway_devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    device_token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'offline' CHECK(status IN ('online', 'offline', 'paused', 'revoked')),
    app_version TEXT NOT NULL DEFAULT '1.0.0',
    android_version TEXT NOT NULL DEFAULT '14',
    permission_send_sms INTEGER NOT NULL DEFAULT 1,
    network_type TEXT NOT NULL DEFAULT '4G LTE',
    battery_pct INTEGER NOT NULL DEFAULT 92,
    sim_ready INTEGER NOT NULL DEFAULT 1,
    last_heartbeat_at TEXT,
    enrolled_at TEXT NOT NULL,
    revoked_at TEXT
  );

  CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id TEXT PRIMARY KEY,
    device_name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sims (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES gateway_devices(id) ON DELETE CASCADE,
    carrier_label TEXT NOT NULL,
    masked_msisdn TEXT NOT NULL,
    slot_index INTEGER NOT NULL DEFAULT 0,
    plan_sms_limit INTEGER NOT NULL DEFAULT 3000,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    estimated_sms_sent INTEGER NOT NULL DEFAULT 0,
    estimated_sms_remaining INTEGER NOT NULL DEFAULT 3000,
    warning_threshold INTEGER NOT NULL DEFAULT 300,
    notes TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS message_templates (
    id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'approved' CHECK(status IN ('approved', 'draft', 'archived')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS destination_allowlist (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    e164_masked TEXT NOT NULL,
    e164_hash TEXT NOT NULL,
    e164_encrypted TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(application_id, e164_hash)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    device_id TEXT REFERENCES gateway_devices(id) ON DELETE SET NULL,
    destination_masked TEXT NOT NULL,
    destination_hash TEXT NOT NULL,
    destination_encrypted TEXT NOT NULL,
    template_id TEXT NOT NULL,
    body_encrypted TEXT NOT NULL,
    purpose TEXT NOT NULL,
    status TEXT NOT NULL,
    is_test INTEGER NOT NULL DEFAULT 0,
    idempotency_key TEXT,
    ttl_expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    queued_at TEXT,
    leased_at TEXT,
    accepted_at TEXT,
    sent_at TEXT,
    delivered_at TEXT,
    failed_at TEXT,
    error_code TEXT
  );

  CREATE TABLE IF NOT EXISTS otp_challenges (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    destination_masked TEXT NOT NULL,
    destination_hash TEXT NOT NULL,
    destination_encrypted TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    purpose TEXT NOT NULL,
    status TEXT NOT NULL,
    is_test INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    consumed_at TEXT,
    message_id TEXT REFERENCES messages(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS gateway_job_leases (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES gateway_devices(id) ON DELETE CASCADE,
    lease_token_hash TEXT NOT NULL,
    leased_at TEXT NOT NULL,
    lease_expires_at TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS usage_events (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    device_id TEXT,
    message_id TEXT,
    event_type TEXT NOT NULL,
    units INTEGER NOT NULL DEFAULT 1,
    occurred_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id TEXT PRIMARY KEY,
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    secret_encrypted TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    event_types_json TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY,
    endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_redacted_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'delivered', 'failed')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    last_http_status INTEGER,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    metadata_redacted_json TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS platform_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_messages_status_created ON messages(status, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_messages_app_created ON messages(application_id, created_at DESC);
  CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_app_idempotency ON messages(application_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
  CREATE INDEX IF NOT EXISTS idx_otp_app_exp_status ON otp_challenges(application_id, expires_at, status);
  CREATE INDEX IF NOT EXISTS idx_leases_device_exp ON gateway_job_leases(device_id, lease_expires_at);
  CREATE INDEX IF NOT EXISTS idx_apikeys_prefix_status ON api_keys(key_prefix, status);
  CREATE INDEX IF NOT EXISTS idx_usage_app_occurred ON usage_events(application_id, occurred_at);
`;
    globalForDb = globalThis;
    if (!globalForDb.__simvaultDbCache) {
      globalForDb.__simvaultDbCache = {};
    }
    dbCache = globalForDb.__simvaultDbCache;
  }
});

// server/services.ts
import crypto3 from "node:crypto";
import dns from "node:dns";
async function getSettingsMap(db) {
  const rows = await db.all("SELECT key, value FROM platform_settings");
  const map = {};
  for (const r of rows) map[r.key] = r.value;
  return map;
}
async function updateSetting(db, key, value, actorId, ipAddress = "127.0.0.1") {
  const now = (/* @__PURE__ */ new Date()).toISOString();
  await db.run(
    `INSERT INTO platform_settings (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
    key,
    value,
    now
  );
  await writeAuditLog(db, {
    actorType: "owner",
    actorId,
    action: "settings.updated",
    targetType: "platform_settings",
    targetId: key,
    metadata: { key, value },
    ipAddress
  });
}
function checkIpRateLimit(ip, limitPerMinute) {
  const now = Date.now();
  const windowStart = now - 6e4;
  const timestamps = (ipWindow.get(ip) ?? []).filter((t) => t > windowStart);
  if (timestamps.length >= limitPerMinute) {
    ipWindow.set(ip, timestamps);
    return false;
  }
  timestamps.push(now);
  ipWindow.set(ip, timestamps);
  return true;
}
function checkLoginRateLimit(ip, maxFailures = 8, windowMs = 5 * 6e4) {
  const now = Date.now();
  const cutoff = now - windowMs;
  const recent = (loginFailureWindow.get(ip) ?? []).filter((t) => t > cutoff);
  loginFailureWindow.set(ip, recent);
  return recent.length < maxFailures;
}
function recordLoginFailure(ip) {
  const now = Date.now();
  const cutoff = now - 5 * 6e4;
  const recent = (loginFailureWindow.get(ip) ?? []).filter((t) => t > cutoff);
  recent.push(now);
  loginFailureWindow.set(ip, recent);
}
function clearLoginFailures(ip) {
  loginFailureWindow.delete(ip);
}
async function assertPublicWebhookHost(rawUrl) {
  if (!isValidWebhookUrl(rawUrl)) {
    throw new AppError(
      422,
      "INVALID_WEBHOOK_URL",
      "Webhook URL must be a public HTTPS URL (localhost, private/reserved IPs, and .example/.local domains are blocked)."
    );
  }
  const parsed = new URL(rawUrl.trim());
  const hostname = parsed.hostname.replace(/^\[|\]$/g, "");
  if (isPrivateOrReservedIp(hostname)) {
    throw new AppError(422, "SSRF_BLOCKED", "Webhook host resolves to a private or reserved IP address.");
  }
  try {
    const records = await dns.promises.lookup(hostname, { all: true });
    if (!records || records.length === 0) {
      throw new AppError(422, "DNS_LOOKUP_FAILED", "Webhook hostname could not be resolved.");
    }
    for (const rec of records) {
      if (isPrivateOrReservedIp(rec.address)) {
        throw new AppError(422, "SSRF_BLOCKED", "Webhook host resolves to a private or reserved IP address.");
      }
    }
  } catch (err) {
    if (err instanceof AppError) throw err;
    throw new AppError(422, "DNS_LOOKUP_FAILED", "Webhook hostname could not be resolved via DNS.");
  }
  return parsed;
}
async function authenticateApiKey(db, rawBearerToken, hashFn) {
  const secretHash = hashFn(rawBearerToken);
  const row = await db.get(
    `SELECT k.id as key_id, k.key_prefix, k.scopes_json, k.status as key_status, k.expires_at,
            a.id as app_id, a.name as app_name, a.environment, a.status as app_status,
            a.allowed_purposes_json, a.daily_limit, a.allowlist_only
     FROM api_keys k
     JOIN applications a ON a.id = k.application_id
     WHERE k.secret_hash = ?`,
    secretHash
  );
  if (!row) {
    throw new AppError(401, "UNAUTHORIZED", "Invalid API key.");
  }
  if (row.key_status === "revoked") {
    throw new AppError(401, "KEY_REVOKED", "API key has been revoked.");
  }
  if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
    throw new AppError(401, "KEY_EXPIRED", "API key overlap window has expired.");
  }
  if (row.app_status !== "active") {
    throw new AppError(403, "APPLICATION_INACTIVE", "Application is currently paused or disabled.");
  }
  await db.run("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (/* @__PURE__ */ new Date()).toISOString(), row.key_id);
  return {
    applicationId: row.app_id,
    applicationName: row.app_name,
    environment: row.environment,
    status: row.app_status,
    allowedPurposes: JSON.parse(row.allowed_purposes_json),
    dailyLimit: Number(row.daily_limit),
    allowlistOnly: Boolean(row.allowlist_only),
    keyId: row.key_id,
    keyPrefix: row.key_prefix,
    scopes: JSON.parse(row.scopes_json)
  };
}
function requireScope(ctx, scope) {
  if (!ctx.scopes.includes(scope)) {
    throw new AppError(403, "INSUFFICIENT_SCOPE", `API key lacks required scope: ${scope}`);
  }
}
async function checkQuotasAndDestination(db, app, toE164, purpose, ipAddress) {
  const settings = await getSettingsMap(db);
  if (settings.global_paused === "true") {
    throw new AppError(503, "GATEWAY_PAUSED", "Global SMS kill switch is active. All outbound requests are paused.");
  }
  const ipLimit = Number(settings.rate_limit_per_ip_minute ?? 30);
  if (!checkIpRateLimit(ipAddress, ipLimit)) {
    throw new AppError(429, "RATE_LIMITED", "IP request limit exceeded.");
  }
  if (!app.allowedPurposes.includes(purpose)) {
    throw new AppError(403, "PURPOSE_NOT_ALLOWED", `Purpose '${purpose}' is not enabled for this application.`);
  }
  const destHash = hashDestination(toE164);
  if (app.allowlistOnly && app.environment === "live") {
    const allowed = await db.get(
      "SELECT id FROM destination_allowlist WHERE application_id = ? AND e164_hash = ?",
      app.id,
      destHash
    );
    if (!allowed) {
      throw new AppError(
        403,
        "DESTINATION_NOT_ALLOWLISTED",
        "Destination number is not in the approved allowlist for this live application."
      );
    }
  }
  const dayStart = /* @__PURE__ */ new Date();
  dayStart.setUTCHours(0, 0, 0, 0);
  const dayStartIso = dayStart.toISOString();
  const appToday = await db.get(
    "SELECT COUNT(*) as cnt FROM messages WHERE application_id = ? AND created_at >= ? AND is_test = 0",
    app.id,
    dayStartIso
  );
  if (app.environment === "live" && Number(appToday?.cnt ?? 0) >= app.dailyLimit) {
    throw new AppError(429, "APP_DAILY_CAP_REACHED", "Application daily message cap reached.");
  }
  const globalCap = Number(settings.global_daily_sim_cap ?? 300);
  const globalToday = await db.get(
    "SELECT COUNT(*) as cnt FROM messages WHERE created_at >= ? AND is_test = 0",
    dayStartIso
  );
  if (app.environment === "live" && Number(globalToday?.cnt ?? 0) >= globalCap) {
    throw new AppError(429, "GLOBAL_SIM_CAP_REACHED", "Global daily SIM safety cap reached.");
  }
  const hourAgo = new Date(Date.now() - 36e5).toISOString();
  const perNumberHourlyLimit = Number(settings.rate_limit_per_number_hourly ?? 6);
  const numberHourCount = await db.get(
    "SELECT COUNT(*) as cnt FROM messages WHERE destination_hash = ? AND created_at >= ?",
    destHash,
    hourAgo
  );
  if (Number(numberHourCount?.cnt ?? 0) >= perNumberHourlyLimit) {
    throw new AppError(429, "DESTINATION_THROTTLED", "Hourly per-number message limit exceeded.");
  }
}
async function enqueueWebhookEvent(db, applicationId, eventType, payload) {
  const endpoints = await db.all(
    "SELECT id, event_types_json FROM webhook_endpoints WHERE application_id = ? AND enabled = 1",
    applicationId
  );
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const eventId = `evt_${crypto3.randomBytes(8).toString("hex")}`;
  const redactedPayload = {
    event_id: eventId,
    event_type: eventType,
    occurred_at: now,
    data: payload
  };
  for (const ep of endpoints) {
    const subscribed = JSON.parse(ep.event_types_json);
    if (subscribed.includes(eventType)) {
      await db.run(
        `INSERT INTO webhook_deliveries (id, endpoint_id, event_id, event_type, payload_redacted_json, status, attempt_count, next_attempt_at, last_http_status, created_at)
         VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, NULL, ?)`,
        crypto3.randomUUID(),
        ep.id,
        eventId,
        eventType,
        JSON.stringify(redactedPayload),
        now,
        now
      );
    }
  }
}
async function createSmsRequest(db, input) {
  const normalizedTo = normalizeE164(input.to);
  if (!isValidE164(normalizedTo)) {
    throw new AppError(422, "INVALID_PHONE", "Destination phone must be valid E.164 format (e.g. +919876543210).");
  }
  const appRow = await db.get(
    "SELECT id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only FROM applications WHERE id = ?",
    input.applicationId
  );
  if (!appRow) {
    throw new AppError(404, "APPLICATION_NOT_FOUND", "Application not found.");
  }
  if (appRow.status !== "active") {
    throw new AppError(403, "APPLICATION_INACTIVE", "Application is paused or disabled.");
  }
  if (input.idempotencyKey) {
    const existing = await db.get(
      "SELECT id, status, created_at, is_test FROM messages WHERE application_id = ? AND idempotency_key = ?",
      appRow.id,
      input.idempotencyKey
    );
    if (existing) {
      return {
        message_id: existing.id,
        status: existing.status,
        created_at: existing.created_at,
        is_test: Boolean(existing.is_test),
        deduplicated: true
      };
    }
  }
  await checkQuotasAndDestination(
    db,
    {
      id: appRow.id,
      dailyLimit: Number(appRow.daily_limit),
      allowlistOnly: Boolean(appRow.allowlist_only),
      environment: appRow.environment,
      allowedPurposes: JSON.parse(appRow.allowed_purposes_json)
    },
    normalizedTo,
    input.purpose,
    input.ipAddress ?? "127.0.0.1"
  );
  const template = await db.get(
    "SELECT id, code, purpose, body, status FROM message_templates WHERE code = ? AND status = 'approved'",
    input.templateCode
  );
  if (!template) {
    throw new AppError(422, "TEMPLATE_NOT_APPROVED", `Approved template '${input.templateCode}' not found.`);
  }
  const { rendered, missingVariables } = renderTemplate(template.body, input.variables ?? {});
  if (missingVariables.length > 0) {
    throw new AppError(422, "MISSING_TEMPLATE_VARIABLES", `Missing template variables: ${missingVariables.join(", ")}`);
  }
  const now = /* @__PURE__ */ new Date();
  const ttl = Math.min(Math.max(Number(input.ttlSeconds ?? 180), 30), 3600);
  const ttlExpiresAt = new Date(now.getTime() + ttl * 1e3).toISOString();
  const createdAt = now.toISOString();
  const messageId = `msg_${crypto3.randomBytes(6).toString("hex")}`;
  const isTest = appRow.environment === "test" ? 1 : 0;
  await db.run(
    `INSERT INTO messages (id, application_id, device_id, destination_masked, destination_hash, destination_encrypted, template_id, body_encrypted, purpose, status, is_test, idempotency_key, ttl_expires_at, created_at, queued_at)
     VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?)`,
    messageId,
    appRow.id,
    maskE164(normalizedTo),
    hashDestination(normalizedTo),
    encryptField(normalizedTo),
    template.code,
    encryptField(rendered),
    input.purpose,
    isTest,
    input.idempotencyKey ?? null,
    ttlExpiresAt,
    createdAt,
    createdAt
  );
  await db.run(
    `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
     VALUES (?, ?, NULL, ?, 'message.requested', 1, ?)`,
    crypto3.randomUUID(),
    appRow.id,
    messageId,
    createdAt
  );
  await writeAuditLog(db, {
    actorType: "application",
    actorId: input.actorId,
    action: "sms.queued",
    targetType: "message",
    targetId: messageId,
    metadata: {
      application_id: appRow.id,
      template_id: template.code,
      purpose: input.purpose,
      destination_masked: maskE164(normalizedTo),
      is_test: Boolean(isTest)
    },
    ipAddress: input.ipAddress
  });
  await enqueueWebhookEvent(db, appRow.id, "message.status", {
    message_id: messageId,
    status: "queued",
    destination_masked: maskE164(normalizedTo),
    is_test: Boolean(isTest)
  });
  return {
    message_id: messageId,
    status: "queued",
    created_at: createdAt,
    is_test: Boolean(isTest),
    deduplicated: false
  };
}
async function createOtpChallenge(db, input) {
  const normalizedTo = normalizeE164(input.to);
  if (!isValidE164(normalizedTo)) {
    throw new AppError(422, "INVALID_PHONE", "Destination phone must be valid E.164 format.");
  }
  const settings = await getSettingsMap(db);
  const appRow = await db.get(
    "SELECT id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only FROM applications WHERE id = ?",
    input.applicationId
  );
  if (!appRow) throw new AppError(404, "APPLICATION_NOT_FOUND", "Application not found.");
  if (appRow.status !== "active") throw new AppError(403, "APPLICATION_INACTIVE", "Application is paused or disabled.");
  const destHash = hashDestination(normalizedTo);
  const cooldownSeconds = Number(settings.otp_resend_cooldown_seconds ?? 45);
  if (!input.bypassCooldown && cooldownSeconds > 0) {
    const cooldownCutoff = new Date(Date.now() - cooldownSeconds * 1e3).toISOString();
    const recent = await db.get(
      `SELECT id FROM otp_challenges
       WHERE application_id = ? AND destination_hash = ? AND created_at > ? AND status IN ('queued', 'sent')`,
      appRow.id,
      destHash,
      cooldownCutoff
    );
    if (recent) {
      throw new AppError(
        429,
        "RESEND_COOLDOWN",
        `Please wait ${cooldownSeconds} seconds before requesting another verification code.`
      );
    }
  }
  await checkQuotasAndDestination(
    db,
    {
      id: appRow.id,
      dailyLimit: Number(appRow.daily_limit),
      allowlistOnly: Boolean(appRow.allowlist_only),
      environment: appRow.environment,
      allowedPurposes: JSON.parse(appRow.allowed_purposes_json)
    },
    normalizedTo,
    input.purpose,
    input.ipAddress ?? "127.0.0.1"
  );
  const defaultTtl = Number(settings.otp_ttl_seconds ?? 300);
  const ttlSeconds = Math.min(Math.max(Number(input.ttlSeconds ?? defaultTtl), 60), 600);
  const maxAttempts = Number(settings.otp_max_attempts ?? 5);
  const challengeId = `otp_${crypto3.randomBytes(6).toString("hex")}`;
  const otpCode = generateOtpCode(6);
  const codeHash = hashOtpCode(challengeId, otpCode);
  const templateCode = input.purpose === "password_reset" ? "otp_password_reset" : "otp_login";
  const template = await db.get(
    "SELECT code, body FROM message_templates WHERE code = ? AND status = 'approved'",
    templateCode
  );
  const fallbackTemplate = "Your verification code for {{app_name}} is {{code}}. Valid for {{ttl_minutes}} minutes.";
  const { rendered } = renderTemplate(template?.body ?? fallbackTemplate, {
    app_name: appRow.name,
    code: otpCode,
    ttl_minutes: Math.max(1, Math.round(ttlSeconds / 60))
  });
  const now = /* @__PURE__ */ new Date();
  const createdAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + ttlSeconds * 1e3).toISOString();
  const messageId = `msg_${crypto3.randomBytes(6).toString("hex")}`;
  const isTest = appRow.environment === "test" ? 1 : 0;
  await db.transaction(async (tx) => {
    await tx.run(
      `INSERT INTO messages (id, application_id, device_id, destination_masked, destination_hash, destination_encrypted, template_id, body_encrypted, purpose, status, is_test, idempotency_key, ttl_expires_at, created_at, queued_at)
       VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, 'queued', ?, NULL, ?, ?, ?)`,
      messageId,
      appRow.id,
      maskE164(normalizedTo),
      destHash,
      encryptField(normalizedTo),
      template?.code ?? "otp_login",
      encryptField(rendered),
      input.purpose,
      isTest,
      expiresAt,
      createdAt,
      createdAt
    );
    await tx.run(
      `INSERT INTO otp_challenges (id, application_id, destination_masked, destination_hash, destination_encrypted, code_hash, purpose, status, is_test, expires_at, attempts, max_attempts, consumed_at, message_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?, 0, ?, NULL, ?, ?)`,
      challengeId,
      appRow.id,
      maskE164(normalizedTo),
      destHash,
      encryptField(normalizedTo),
      codeHash,
      input.purpose,
      isTest,
      expiresAt,
      maxAttempts,
      messageId,
      createdAt
    );
    await tx.run(
      `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
       VALUES (?, ?, NULL, ?, 'otp.requested', 1, ?)`,
      crypto3.randomUUID(),
      appRow.id,
      messageId,
      createdAt
    );
  });
  await writeAuditLog(db, {
    actorType: "application",
    actorId: input.actorId,
    action: "otp.challenge_created",
    targetType: "otp_challenge",
    targetId: challengeId,
    metadata: {
      application_id: appRow.id,
      purpose: input.purpose,
      destination_masked: maskE164(normalizedTo),
      expires_at: expiresAt,
      is_test: Boolean(isTest)
    },
    ipAddress: input.ipAddress
  });
  return {
    challenge_id: challengeId,
    message_id: messageId,
    status: "queued",
    expires_at: expiresAt,
    is_test: Boolean(isTest)
  };
}
async function verifyOtpChallenge(db, input) {
  const cleanCode = input.code.trim();
  if (!/^\d{4,10}$/.test(cleanCode)) {
    throw new AppError(422, "OTP_INVALID", "Invalid or expired verification code.");
  }
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  const txOutcome = await db.transaction(async (tx) => {
    const selectSql = tx.dialect === "postgres" ? `SELECT id, application_id, code_hash, status, expires_at, attempts, max_attempts
           FROM otp_challenges WHERE id = ? FOR UPDATE` : `SELECT id, application_id, code_hash, status, expires_at, attempts, max_attempts
           FROM otp_challenges WHERE id = ?`;
    const row = await tx.get(selectSql, input.challengeId);
    let nextAttempts = 0;
    let locked = false;
    let invalidReason = null;
    if (!row || input.applicationId && row.application_id !== input.applicationId) {
      invalidReason = "missing";
    } else if (new Date(row.expires_at).getTime() <= Date.now()) {
      if (row.status === "queued" || row.status === "sent") {
        await tx.run("UPDATE otp_challenges SET status = 'expired' WHERE id = ? AND status IN ('queued', 'sent')", row.id);
      }
      invalidReason = "expired";
    } else if (row.status !== "queued" && row.status !== "sent") {
      invalidReason = "terminal";
    } else {
      nextAttempts = Number(row.attempts) + 1;
      const isMatch = verifyOtpHashConstantTime(row.id, cleanCode, row.code_hash);
      if (!isMatch) {
        locked = nextAttempts >= Number(row.max_attempts);
        await tx.run(
          "UPDATE otp_challenges SET attempts = ?, status = ? WHERE id = ? AND status IN ('queued', 'sent')",
          nextAttempts,
          locked ? "locked" : row.status,
          row.id
        );
        invalidReason = "mismatch";
      } else {
        const updateRes = await tx.run(
          "UPDATE otp_challenges SET status = 'verified', attempts = ?, consumed_at = ? WHERE id = ? AND status IN ('queued', 'sent')",
          nextAttempts,
          nowIso,
          row.id
        );
        if (updateRes.changes === 0) {
          invalidReason = "terminal";
        }
      }
    }
    return { row, nextAttempts, locked, invalidReason };
  });
  if (txOutcome.invalidReason === "missing" || txOutcome.invalidReason === "expired" || txOutcome.invalidReason === "terminal") {
    throw new AppError(422, "OTP_INVALID", "Invalid or expired verification code.");
  }
  if (txOutcome.invalidReason === "mismatch" && txOutcome.row) {
    await writeAuditLog(db, {
      actorType: "application",
      actorId: txOutcome.row.application_id,
      action: txOutcome.locked ? "otp.locked_max_attempts" : "otp.verify_failed",
      targetType: "otp_challenge",
      targetId: txOutcome.row.id,
      metadata: { attempts: txOutcome.nextAttempts, max_attempts: Number(txOutcome.row.max_attempts) },
      ipAddress: input.ipAddress
    });
    if (txOutcome.locked) {
      await enqueueWebhookEvent(db, txOutcome.row.application_id, "otp.failed", {
        challenge_id: txOutcome.row.id,
        reason: "MAX_ATTEMPTS_EXCEEDED"
      });
    }
    throw new AppError(422, "OTP_INVALID", "Invalid or expired verification code.");
  }
  const verifiedRow = txOutcome.row;
  await writeAuditLog(db, {
    actorType: "application",
    actorId: verifiedRow.application_id,
    action: "otp.verified",
    targetType: "otp_challenge",
    targetId: verifiedRow.id,
    metadata: { attempts: txOutcome.nextAttempts },
    ipAddress: input.ipAddress
  });
  await enqueueWebhookEvent(db, verifiedRow.application_id, "otp.verified", {
    challenge_id: verifiedRow.id,
    verified_at: nowIso
  });
  return { verified: true, verified_at: nowIso, challenge_id: verifiedRow.id };
}
async function authenticateGatewayDevice(db, rawToken) {
  const tokenHash = hashToken(rawToken);
  const dev = await db.get(
    `SELECT id, name, status, permission_send_sms, sim_ready, revoked_at
     FROM gateway_devices WHERE device_token_hash = ?`,
    tokenHash
  );
  if (!dev || dev.status === "revoked" || dev.revoked_at) {
    throw new AppError(401, "DEVICE_UNAUTHORIZED", "Invalid or revoked device credential.");
  }
  return {
    id: dev.id,
    name: dev.name,
    status: dev.status,
    permissionSendSms: Boolean(dev.permission_send_sms),
    simReady: Boolean(dev.sim_ready)
  };
}
async function leaseNextGatewayJob(db, deviceId) {
  await maybeRunOpportunisticSweep(db);
  const settings = await getSettingsMap(db);
  if (settings.global_paused === "true") {
    return null;
  }
  const dev = await db.get(
    "SELECT id, status, permission_send_sms, sim_ready FROM gateway_devices WHERE id = ?",
    deviceId
  );
  if (!dev || dev.status !== "online" || !dev.permission_send_sms || !dev.sim_ready) {
    return null;
  }
  const now = /* @__PURE__ */ new Date();
  const nowIso = now.toISOString();
  const leaseTimeoutSec = Number(settings.lease_timeout_seconds ?? 30);
  const leaseExpiresAt = new Date(now.getTime() + leaseTimeoutSec * 1e3).toISOString();
  return db.transaction(async (tx) => {
    const candidateSql = tx.dialect === "postgres" ? `SELECT id, destination_encrypted, body_encrypted, is_test, ttl_expires_at
           FROM messages
           WHERE status = 'queued' AND ttl_expires_at > ?
           ORDER BY created_at ASC
           FOR UPDATE SKIP LOCKED
           LIMIT 1` : `SELECT id, destination_encrypted, body_encrypted, is_test, ttl_expires_at
           FROM messages
           WHERE status = 'queued' AND ttl_expires_at > ?
           ORDER BY created_at ASC
           LIMIT 1`;
    const candidate = await tx.get(candidateSql, nowIso);
    if (!candidate) {
      return null;
    }
    const existingAttempts = await tx.get(
      "SELECT COUNT(*) as cnt FROM gateway_job_leases WHERE message_id = ?",
      candidate.id
    );
    const leaseToken = `lease_${crypto3.randomBytes(16).toString("hex")}`;
    await tx.run(
      `INSERT INTO gateway_job_leases (id, message_id, device_id, lease_token_hash, leased_at, lease_expires_at, attempt_count)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      crypto3.randomUUID(),
      candidate.id,
      deviceId,
      hashToken(leaseToken),
      nowIso,
      leaseExpiresAt,
      Number(existingAttempts?.cnt ?? 0) + 1
    );
    await tx.run("UPDATE messages SET status = 'leased', device_id = ?, leased_at = ? WHERE id = ?", deviceId, nowIso, candidate.id);
    const sim = await tx.get(
      "SELECT slot_index FROM sims WHERE device_id = ? ORDER BY slot_index ASC LIMIT 1",
      deviceId
    );
    return {
      job_id: candidate.id,
      lease_token: leaseToken,
      to: decryptField(candidate.destination_encrypted),
      body: decryptField(candidate.body_encrypted),
      sim_slot: sim?.slot_index ?? 0,
      is_test: Boolean(candidate.is_test),
      expires_at: candidate.ttl_expires_at
    };
  });
}
async function markJobAcceptedByDevice(db, deviceId, jobId) {
  const msg = await db.get("SELECT id, application_id, device_id, status, destination_masked FROM messages WHERE id = ?", jobId);
  if (!msg || msg.device_id !== deviceId) {
    throw new AppError(404, "JOB_NOT_FOUND", "Leased job not found for this device.");
  }
  if (!isValidMessageTransition(msg.status, "accepted_by_device")) {
    throw new AppError(409, "INVALID_TRANSITION", `Cannot transition from ${msg.status} to accepted_by_device.`);
  }
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  await db.run("UPDATE messages SET status = 'accepted_by_device', accepted_at = ? WHERE id = ?", nowIso, jobId);
  await enqueueWebhookEvent(db, msg.application_id, "message.status", {
    message_id: msg.id,
    status: "accepted_by_device",
    destination_masked: msg.destination_masked
  });
  return { status: "accepted_by_device" };
}
async function reportJobResult(db, deviceId, jobId, outcome, errorCode) {
  const msg = await db.get("SELECT id, application_id, device_id, status, is_test, destination_masked FROM messages WHERE id = ?", jobId);
  if (!msg || msg.device_id !== deviceId) {
    throw new AppError(404, "JOB_NOT_FOUND", "Job not found for this device.");
  }
  if (!isValidMessageTransition(msg.status, outcome)) {
    throw new AppError(409, "INVALID_TRANSITION", `Cannot transition from ${msg.status} to ${outcome}.`);
  }
  const cleanErrorCode = errorCode ? String(errorCode).replace(/[^A-Z0-9_:-]/gi, "").slice(0, 48) : void 0;
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  await db.transaction(async (tx) => {
    if (outcome === "sent_to_network") {
      await tx.run("UPDATE messages SET status = 'sent_to_network', sent_at = ?, error_code = NULL WHERE id = ?", nowIso, jobId);
      await tx.run("UPDATE otp_challenges SET status = 'sent' WHERE message_id = ? AND status = 'queued'", jobId);
      await tx.run(
        `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
         VALUES (?, ?, ?, ?, 'message.sent_to_network', 1, ?)`,
        crypto3.randomUUID(),
        msg.application_id,
        deviceId,
        jobId,
        nowIso
      );
      if (!msg.is_test) {
        await tx.run(
          `UPDATE sims
           SET estimated_sms_sent = estimated_sms_sent + 1,
               estimated_sms_remaining = CASE WHEN estimated_sms_remaining > 0 THEN estimated_sms_remaining - 1 ELSE 0 END,
               updated_at = ?
           WHERE device_id = ?`,
          nowIso,
          deviceId
        );
      }
    } else if (outcome === "delivery_unknown") {
      await tx.run(
        "UPDATE messages SET status = 'delivery_unknown', sent_at = COALESCE(sent_at, ?), error_code = ? WHERE id = ?",
        nowIso,
        cleanErrorCode || "NO_CARRIER_RECEIPT",
        jobId
      );
    } else {
      await tx.run(
        "UPDATE messages SET status = 'failed', failed_at = ?, error_code = ? WHERE id = ?",
        nowIso,
        cleanErrorCode || "SEND_FAILED",
        jobId
      );
      await tx.run(
        "UPDATE otp_challenges SET status = 'failed' WHERE message_id = ? AND status IN ('queued', 'sent')",
        jobId
      );
      await tx.run(
        `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
         VALUES (?, ?, ?, ?, 'message.failed', 1, ?)`,
        crypto3.randomUUID(),
        msg.application_id,
        deviceId,
        jobId,
        nowIso
      );
    }
    await tx.run("DELETE FROM gateway_job_leases WHERE message_id = ?", jobId);
  });
  await enqueueWebhookEvent(db, msg.application_id, "message.status", {
    message_id: msg.id,
    status: outcome,
    error_code: errorCode ?? null,
    destination_masked: msg.destination_masked
  });
  if (outcome === "sent_to_network") {
    const otp = await db.get("SELECT id FROM otp_challenges WHERE message_id = ?", jobId);
    if (otp) {
      await enqueueWebhookEvent(db, msg.application_id, "otp.sent", { challenge_id: otp.id, message_id: jobId });
    }
  } else if (outcome === "failed") {
    const otp = await db.get("SELECT id FROM otp_challenges WHERE message_id = ?", jobId);
    if (otp) {
      await enqueueWebhookEvent(db, msg.application_id, "otp.failed", {
        challenge_id: otp.id,
        message_id: jobId,
        error_code: errorCode ?? "SEND_FAILED"
      });
    }
  }
  return { status: outcome };
}
async function reportDeliveryReceipt(db, deviceId, jobId) {
  const msg = await db.get("SELECT id, application_id, device_id, status, destination_masked FROM messages WHERE id = ?", jobId);
  if (!msg || msg.device_id !== deviceId) {
    throw new AppError(404, "JOB_NOT_FOUND", "Job not found for this device.");
  }
  if (!isValidMessageTransition(msg.status, "delivered")) {
    throw new AppError(409, "INVALID_TRANSITION", `Cannot transition from ${msg.status} to delivered.`);
  }
  const nowIso = (/* @__PURE__ */ new Date()).toISOString();
  await db.run("UPDATE messages SET status = 'delivered', delivered_at = ?, error_code = NULL WHERE id = ?", nowIso, jobId);
  await db.run(
    `INSERT INTO usage_events (id, application_id, device_id, message_id, event_type, units, occurred_at)
     VALUES (?, ?, ?, ?, 'message.delivered', 1, ?)`,
    crypto3.randomUUID(),
    msg.application_id,
    deviceId,
    jobId,
    nowIso
  );
  await enqueueWebhookEvent(db, msg.application_id, "message.status", {
    message_id: msg.id,
    status: "delivered",
    delivered_at: nowIso,
    destination_masked: msg.destination_masked
  });
  return { status: "delivered" };
}
async function runSweeperTick(db) {
  const now = /* @__PURE__ */ new Date();
  const nowIso = now.toISOString();
  const settings = await getSettingsMap(db);
  const maxRetries = Number(settings.max_send_retries ?? 3);
  const expiredRows = await db.all(
    `SELECT id, application_id, destination_masked FROM messages
     WHERE status IN ('created', 'queued', 'leased', 'accepted_by_device') AND ttl_expires_at <= ?`,
    nowIso
  );
  for (const row of expiredRows) {
    await db.run("UPDATE messages SET status = 'expired', failed_at = ?, error_code = 'TTL_EXPIRED' WHERE id = ?", nowIso, row.id);
    await db.run("DELETE FROM gateway_job_leases WHERE message_id = ?", row.id);
    await enqueueWebhookEvent(db, row.application_id, "message.status", {
      message_id: row.id,
      status: "expired",
      error_code: "TTL_EXPIRED",
      destination_masked: row.destination_masked
    });
  }
  const expOtps = await db.run(
    "UPDATE otp_challenges SET status = 'expired' WHERE status IN ('queued', 'sent') AND expires_at <= ?",
    nowIso
  );
  const staleLeases = await db.all(
    `SELECT l.id as lease_id, l.message_id, l.attempt_count, m.application_id, m.destination_masked
     FROM gateway_job_leases l
     JOIN messages m ON m.id = l.message_id
     WHERE l.lease_expires_at <= ? AND m.status IN ('leased', 'accepted_by_device')`,
    nowIso
  );
  let requeuedLeases = 0;
  let failedMaxRetries = 0;
  for (const lease of staleLeases) {
    await db.run("DELETE FROM gateway_job_leases WHERE id = ?", lease.lease_id);
    if (Number(lease.attempt_count) >= maxRetries) {
      await db.run(
        "UPDATE messages SET status = 'failed', failed_at = ?, error_code = 'LEASE_EXPIRED_MAX_RETRIES' WHERE id = ?",
        nowIso,
        lease.message_id
      );
      failedMaxRetries++;
      await enqueueWebhookEvent(db, lease.application_id, "message.status", {
        message_id: lease.message_id,
        status: "failed",
        error_code: "LEASE_EXPIRED_MAX_RETRIES",
        destination_masked: lease.destination_masked
      });
    } else {
      await db.run("UPDATE messages SET status = 'queued', device_id = NULL WHERE id = ?", lease.message_id);
      requeuedLeases++;
    }
  }
  const staleHeartbeatCutoff = new Date(now.getTime() - 45e3).toISOString();
  await db.run(
    `UPDATE gateway_devices
     SET status = 'offline'
     WHERE status = 'online' AND last_heartbeat_at IS NOT NULL AND last_heartbeat_at < ?`,
    staleHeartbeatCutoff
  );
  const pendingHooks = await db.all(
    `SELECT d.id, d.event_id, d.payload_redacted_json, d.attempt_count, e.url, e.secret_encrypted
     FROM webhook_deliveries d
     JOIN webhook_endpoints e ON e.id = d.endpoint_id
     WHERE d.status = 'pending' AND d.next_attempt_at <= ?
     LIMIT 10`,
    nowIso
  );
  let processedWebhooks = 0;
  const webhookPromises = [];
  for (const hook of pendingHooks) {
    processedWebhooks++;
    const ts = String(Math.floor(Date.now() / 1e3));
    const secret = decryptField(hook.secret_encrypted);
    const sig = signWebhookPayload(secret, ts, hook.event_id, hook.payload_redacted_json);
    const nextAttempt = Number(hook.attempt_count) + 1;
    await db.run(
      "UPDATE webhook_deliveries SET next_attempt_at = ? WHERE id = ?",
      new Date(Date.now() + 1e4).toISOString(),
      hook.id
    );
    const deliveryTask = assertPublicWebhookHost(hook.url).then(
      () => fetch(hook.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-SimVault-Event-Id": hook.event_id,
          "X-SimVault-Timestamp": ts,
          "X-SimVault-Signature": `v1=${sig}`
        },
        body: hook.payload_redacted_json,
        redirect: "error",
        signal: AbortSignal.timeout(4e3)
      })
    ).then(async (res) => {
      if (res.ok) {
        await db.run(
          "UPDATE webhook_deliveries SET status = 'delivered', attempt_count = ?, last_http_status = ? WHERE id = ?",
          nextAttempt,
          res.status,
          hook.id
        );
      } else {
        const backoffMs = Math.min(6e4, Math.pow(2, nextAttempt) * 1e3);
        await db.run(
          "UPDATE webhook_deliveries SET status = ?, attempt_count = ?, next_attempt_at = ?, last_http_status = ? WHERE id = ?",
          nextAttempt >= 4 ? "failed" : "pending",
          nextAttempt,
          new Date(Date.now() + backoffMs).toISOString(),
          res.status,
          hook.id
        );
      }
    }).catch(async () => {
      const backoffMs = Math.min(6e4, Math.pow(2, nextAttempt) * 1e3);
      await db.run(
        "UPDATE webhook_deliveries SET status = ?, attempt_count = ?, next_attempt_at = ?, last_http_status = 0 WHERE id = ?",
        nextAttempt >= 4 ? "failed" : "pending",
        nextAttempt,
        new Date(Date.now() + backoffMs).toISOString(),
        hook.id
      );
    });
    webhookPromises.push(deliveryTask);
  }
  if (webhookPromises.length > 0) {
    await Promise.allSettled(webhookPromises);
  }
  return {
    expiredMessages: expiredRows.length,
    requeuedLeases,
    failedMaxRetries,
    expiredOtps: Number(expOtps.changes ?? 0),
    processedWebhooks
  };
}
async function maybeRunOpportunisticSweep(db, minIntervalMs = 5e3) {
  const now = Date.now();
  const lastAt = lastSweepAtByDb.get(db) ?? 0;
  if (now - lastAt < minIntervalMs) return;
  const active = inFlightSweepByDb.get(db);
  if (active) {
    await active;
    return;
  }
  lastSweepAtByDb.set(db, now);
  const promise = runSweeperTick(db).then(() => void 0).catch(() => void 0).finally(() => {
    inFlightSweepByDb.delete(db);
  });
  inFlightSweepByDb.set(db, promise);
  await promise;
}
var AppError, ipWindow, loginFailureWindow, lastSweepAtByDb, inFlightSweepByDb;
var init_services = __esm({
  "server/services.ts"() {
    init_crypto();
    init_db();
    init_smsRules();
    AppError = class extends Error {
      constructor(status, code, message) {
        super(message);
        this.status = status;
        this.code = code;
      }
    };
    ipWindow = /* @__PURE__ */ new Map();
    loginFailureWindow = /* @__PURE__ */ new Map();
    lastSweepAtByDb = /* @__PURE__ */ new WeakMap();
    inFlightSweepByDb = /* @__PURE__ */ new WeakMap();
  }
});

// server/routes/v1.ts
import crypto4 from "node:crypto";
import { Router } from "express";
function getBearer(req) {
  const auth = req.headers.authorization ?? "";
  if (!auth.startsWith("Bearer ")) {
    throw new AppError(401, "UNAUTHORIZED", "Missing Authorization: Bearer token.");
  }
  return auth.slice(7).trim();
}
function sendError(res, err, requestId) {
  if (err instanceof AppError) {
    res.status(err.status).json({
      error: {
        code: err.code,
        message: err.message,
        request_id: requestId
      }
    });
    return;
  }
  res.status(500).json({
    error: {
      code: "INTERNAL_ERROR",
      message: "An unexpected server error occurred.",
      request_id: requestId
    }
  });
}
function createV1Router(db) {
  const router = Router();
  router.use((req, _res, next) => {
    req.requestId = `req_${crypto4.randomBytes(6).toString("hex")}`;
    next();
  });
  const getReqId = (req) => req.requestId ?? "req_unknown";
  router.get("/openapi.json", (_req, res) => {
    res.json({
      openapi: "3.1.0",
      info: {
        title: "SimVault Personal SIM SMS & OTP API",
        version: "1.0.0",
        description: "Application-level SMS and OTP orchestration API routing through an owner-operated Android SIM gateway."
      },
      servers: [{ url: "/v1" }],
      paths: {
        "/sms": {
          post: {
            summary: "Queue a templated transactional SMS",
            parameters: [{ name: "Idempotency-Key", in: "header", schema: { type: "string" } }],
            responses: { "202": { description: "Message queued" } }
          }
        },
        "/otp/challenges": {
          post: {
            summary: "Create a single-use OTP challenge and queue SMS dispatch",
            responses: { "202": { description: "Challenge created (OTP secret never returned)" } }
          }
        },
        "/otp/verify": {
          post: {
            summary: "Verify a submitted OTP code in constant time",
            responses: { "200": { description: "Verified" }, "422": { description: "Invalid or expired code" } }
          }
        },
        "/messages/{message_id}": {
          get: {
            summary: "Retrieve message lifecycle status and timestamps",
            responses: { "200": { description: "Status metadata" } }
          }
        },
        "/usage": {
          get: {
            summary: "Retrieve aggregated message usage counts",
            responses: { "200": { description: "Usage summary" } }
          }
        }
      }
    });
  });
  router.post("/sms", async (req, res) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      requireScope(ctx, "sms:send");
      const { to, template_id, variables, purpose, ttl_seconds } = req.body ?? {};
      if (!to || !template_id || !purpose) {
        throw new AppError(400, "BAD_REQUEST", "Fields to, template_id, and purpose are required.");
      }
      const idempotencyKey = typeof req.headers["idempotency-key"] === "string" ? req.headers["idempotency-key"].trim() : void 0;
      const result = await createSmsRequest(db, {
        applicationId: ctx.applicationId,
        to: String(to),
        templateCode: String(template_id),
        variables: variables && typeof variables === "object" ? variables : {},
        purpose: String(purpose),
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : void 0,
        idempotencyKey,
        actorId: ctx.keyId,
        ipAddress: req.ip
      });
      res.status(result.deduplicated ? 200 : 202).json({
        message_id: result.message_id,
        status: result.status,
        created_at: result.created_at,
        ...result.is_test ? { mode: "test" } : {},
        ...result.deduplicated ? { idempotent_replay: true } : {}
      });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.post("/otp/challenges", async (req, res) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      requireScope(ctx, "otp:create");
      const { to, purpose, ttl_seconds } = req.body ?? {};
      if (!to || !purpose) {
        throw new AppError(400, "BAD_REQUEST", "Fields to and purpose are required.");
      }
      const result = await createOtpChallenge(db, {
        applicationId: ctx.applicationId,
        to: String(to),
        purpose: String(purpose),
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : void 0,
        actorId: ctx.keyId,
        ipAddress: req.ip
      });
      res.status(202).json({
        challenge_id: result.challenge_id,
        message_id: result.message_id,
        status: result.status,
        expires_at: result.expires_at
      });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.post("/otp/verify", async (req, res) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      requireScope(ctx, "otp:verify");
      const { challenge_id, code } = req.body ?? {};
      if (!challenge_id || !code) {
        throw new AppError(400, "BAD_REQUEST", "Fields challenge_id and code are required.");
      }
      const verified = await verifyOtpChallenge(db, {
        applicationId: ctx.applicationId,
        challengeId: String(challenge_id),
        code: String(code),
        ipAddress: req.ip
      });
      res.json(verified);
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.get("/messages/:id", async (req, res) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      const row = await db.get(
        `SELECT id, application_id, device_id, destination_masked, template_id, purpose, status, is_test,
                created_at, queued_at, leased_at, accepted_at, sent_at, delivered_at, failed_at, error_code
         FROM messages WHERE id = ? AND application_id = ?`,
        req.params.id,
        ctx.applicationId
      );
      if (!row) {
        throw new AppError(404, "NOT_FOUND", "Message not found.");
      }
      res.json(row);
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.get("/usage", async (req, res) => {
    try {
      const ctx = await authenticateApiKey(db, getBearer(req), hashApiKey);
      requireScope(ctx, "usage:read");
      const from = typeof req.query.from === "string" ? req.query.from : new Date(Date.now() - 30 * 864e5).toISOString();
      const to = typeof req.query.to === "string" ? req.query.to : (/* @__PURE__ */ new Date()).toISOString();
      const byStatus = await db.all(
        `SELECT status, COUNT(*) as count
         FROM messages
         WHERE application_id = ? AND created_at >= ? AND created_at <= ?
         GROUP BY status`,
        ctx.applicationId,
        from,
        to
      );
      res.json({
        application_id: ctx.applicationId,
        from,
        to,
        counts_by_status: byStatus.map((r) => ({ status: r.status, count: Number(r.count ?? 0) }))
      });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.post("/gateway/enroll", async (req, res) => {
    try {
      const { enrollment_token, device_name, app_version, android_version } = req.body ?? {};
      if (!enrollment_token) {
        throw new AppError(400, "BAD_REQUEST", "enrollment_token is required.");
      }
      const tokenHash = hashToken(String(enrollment_token));
      const enrollRow = await db.get(
        "SELECT id, device_name, expires_at, used_at FROM enrollment_tokens WHERE token_hash = ?",
        tokenHash
      );
      if (!enrollRow || enrollRow.used_at || new Date(enrollRow.expires_at).getTime() <= Date.now()) {
        throw new AppError(401, "INVALID_ENROLLMENT_TOKEN", "Enrollment token is invalid, expired, or already used.");
      }
      const now = /* @__PURE__ */ new Date();
      const nowIso = now.toISOString();
      const cycleStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10);
      const cycleEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().slice(0, 10);
      const deviceId = `dev_${crypto4.randomBytes(5).toString("hex")}`;
      const devCred = generateDeviceToken();
      await db.transaction(async (tx) => {
        const claim = await tx.run(
          "UPDATE enrollment_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL",
          nowIso,
          enrollRow.id
        );
        if (claim.changes === 0) {
          throw new AppError(401, "INVALID_ENROLLMENT_TOKEN", "Enrollment token is invalid, expired, or already used.");
        }
        await tx.run(
          `INSERT INTO gateway_devices (id, name, device_token_hash, status, app_version, android_version, permission_send_sms, network_type, battery_pct, sim_ready, last_heartbeat_at, enrolled_at)
           VALUES (?, ?, ?, 'online', ?, ?, 1, 'Pending Heartbeat', 100, 0, ?, ?)`,
          deviceId,
          String(device_name || enrollRow.device_name).slice(0, 80),
          devCred.tokenHash,
          String(app_version || "1.0.0").slice(0, 32),
          String(android_version || "14").slice(0, 40),
          nowIso,
          nowIso
        );
        await tx.run(
          `INSERT INTO sims (id, device_id, carrier_label, masked_msisdn, slot_index, plan_sms_limit, period_start, period_end, estimated_sms_sent, estimated_sms_remaining, warning_threshold, notes, updated_at)
           VALUES (?, ?, ?, ?, 0, 3000, ?, ?, 0, 3000, 300, ?, ?)`,
          `sim_${deviceId}_0`,
          deviceId,
          "Active SIM Slot 0",
          "Pending telemetry",
          cycleStart,
          cycleEnd,
          "Live SIM \u2014 reconcile monthly against your carrier statement.",
          nowIso
        );
      });
      await writeAuditLog(db, {
        actorType: "device",
        actorId: deviceId,
        action: "gateway.device_enrolled",
        targetType: "gateway_device",
        targetId: deviceId,
        metadata: { device_name: String(device_name || enrollRow.device_name), android_version: String(android_version || "14") },
        ipAddress: req.ip
      });
      res.status(201).json({
        device_id: deviceId,
        device_token: devCred.rawToken,
        enrolled_at: nowIso
      });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.post("/gateway/heartbeat", async (req, res) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const {
        app_version,
        android_version,
        permission_send_sms,
        network_type,
        battery_pct,
        sim_ready,
        sim_slot,
        carrier_label,
        masked_msisdn
      } = req.body ?? {};
      const now = /* @__PURE__ */ new Date();
      const nowIso = now.toISOString();
      const nextStatus = dev.status === "paused" ? "paused" : "online";
      const boundedBattery = typeof battery_pct === "number" && Number.isFinite(battery_pct) ? Math.max(0, Math.min(100, Math.round(battery_pct))) : null;
      await db.run(
        `UPDATE gateway_devices
         SET status = ?,
             app_version = COALESCE(?, app_version),
             android_version = COALESCE(?, android_version),
             permission_send_sms = COALESCE(?, permission_send_sms),
             network_type = COALESCE(?, network_type),
             battery_pct = COALESCE(?, battery_pct),
             sim_ready = COALESCE(?, sim_ready),
             last_heartbeat_at = ?
         WHERE id = ?`,
        nextStatus,
        app_version ? String(app_version).slice(0, 32) : null,
        android_version ? String(android_version).slice(0, 40) : null,
        typeof permission_send_sms === "boolean" ? permission_send_sms ? 1 : 0 : null,
        network_type ? String(network_type).slice(0, 40) : null,
        boundedBattery,
        typeof sim_ready === "boolean" ? sim_ready ? 1 : 0 : null,
        nowIso,
        dev.id
      );
      if (carrier_label || masked_msisdn || typeof sim_slot === "number") {
        const slotIdx = typeof sim_slot === "number" && Number.isFinite(sim_slot) ? Math.max(0, Math.min(3, Math.trunc(sim_slot))) : 0;
        const simRow = await db.get(
          "SELECT id FROM sims WHERE device_id = ? AND slot_index = ?",
          dev.id,
          slotIdx
        );
        if (simRow) {
          await db.run(
            `UPDATE sims
             SET carrier_label = COALESCE(?, carrier_label),
                 masked_msisdn = COALESCE(?, masked_msisdn),
                 updated_at = ?
             WHERE id = ?`,
            carrier_label ? String(carrier_label).slice(0, 64) : null,
            masked_msisdn ? String(masked_msisdn).slice(0, 32) : null,
            nowIso,
            simRow.id
          );
        } else {
          const cycleStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString().slice(0, 10);
          const cycleEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0).toISOString().slice(0, 10);
          await db.run(
            `INSERT INTO sims (id, device_id, carrier_label, masked_msisdn, slot_index, plan_sms_limit, period_start, period_end, estimated_sms_sent, estimated_sms_remaining, warning_threshold, notes, updated_at)
             VALUES (?, ?, ?, ?, ?, 3000, ?, ?, 0, 3000, 300, ?, ?)`,
            `sim_${dev.id}_${slotIdx}`,
            dev.id,
            carrier_label ? String(carrier_label).slice(0, 64) : `SIM Slot ${slotIdx}`,
            masked_msisdn ? String(masked_msisdn).slice(0, 32) : "Pending telemetry",
            slotIdx,
            cycleStart,
            cycleEnd,
            "Live SIM \u2014 reconcile monthly against your carrier statement.",
            nowIso
          );
        }
      }
      res.json({ device_id: dev.id, status: nextStatus, server_time: nowIso });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.get("/gateway/jobs/next", async (req, res) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const job = await leaseNextGatewayJob(db, dev.id);
      if (!job) {
        res.status(204).end();
        return;
      }
      res.json(job);
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.post("/gateway/jobs/:id/accepted", async (req, res) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const result = await markJobAcceptedByDevice(db, dev.id, req.params.id);
      res.json({ job_id: req.params.id, ...result });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.post("/gateway/jobs/:id/result", async (req, res) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const { status, error_code } = req.body ?? {};
      if (!["sent_to_network", "failed", "delivery_unknown"].includes(status)) {
        throw new AppError(400, "BAD_REQUEST", "status must be sent_to_network, failed, or delivery_unknown.");
      }
      const result = await reportJobResult(db, dev.id, req.params.id, status, error_code);
      res.json({ job_id: req.params.id, ...result });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  router.post("/gateway/jobs/:id/delivery-report", async (req, res) => {
    try {
      const dev = await authenticateGatewayDevice(db, getBearer(req));
      const result = await reportDeliveryReceipt(db, dev.id, req.params.id);
      res.json({ job_id: req.params.id, ...result });
    } catch (err) {
      sendError(res, err, getReqId(req));
    }
  });
  return router;
}
var init_v1 = __esm({
  "server/routes/v1.ts"() {
    init_crypto();
    init_db();
    init_services();
  }
});

// server/routes/admin.ts
import crypto5 from "node:crypto";
import fs3 from "node:fs";
import path3 from "node:path";
import { Router as Router2 } from "express";
function sendAdminError(res, err) {
  if (err instanceof AppError) {
    res.status(err.status).json({ error: { code: err.code, message: err.message } });
    return;
  }
  const message = err instanceof Error ? err.message : "Unexpected server error";
  res.status(500).json({ error: { code: "INTERNAL_ERROR", message } });
}
function isHttpsRequest(req) {
  const xfProto = req.headers["x-forwarded-proto"];
  return req.secure || typeof xfProto === "string" && xfProto.split(",")[0].trim() === "https";
}
function createAdminRouter(db) {
  const router = Router2();
  router.use(async (req, res, next) => {
    try {
      const cookieHeader = req.headers.cookie ?? "";
      const match = /simvault_session=([^;]+)/.exec(cookieHeader);
      let user;
      let sessionCsrf = null;
      let currentTokenHash = null;
      if (match) {
        const tokHash = hashToken(decodeURIComponent(match[1]));
        const sess = await db.get(
          `SELECT s.csrf_token, s.expires_at, s.mfa_verified, u.id, u.email, u.role, u.mfa_enabled
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ?`,
          tokHash
        );
        if (sess && new Date(sess.expires_at).getTime() > Date.now() && sess.mfa_verified) {
          user = { id: sess.id, email: sess.email, role: sess.role, mfa_enabled: sess.mfa_enabled };
          sessionCsrf = sess.csrf_token;
          currentTokenHash = tokHash;
        }
      }
      req.ownerUser = user;
      req.csrfToken = sessionCsrf;
      req.currentTokenHash = currentTokenHash;
      const isAuthRoute = req.path.startsWith("/auth/");
      if (!user && !isAuthRoute) {
        res.status(401).json({ error: { code: "AUTH_REQUIRED", message: "Owner authentication required." } });
        return;
      }
      if (!isAuthRoute && ["POST", "PATCH", "PUT", "DELETE"].includes(req.method)) {
        const providedCsrf = req.headers["x-csrf-token"];
        if (!sessionCsrf || typeof providedCsrf !== "string" || providedCsrf !== sessionCsrf) {
          res.status(403).json({ error: { code: "CSRF_INVALID", message: "Invalid or missing CSRF token." } });
          return;
        }
      }
      next();
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  const getOwner = (req) => req.ownerUser;
  router.get("/auth/session", (req, res) => {
    const owner = req.ownerUser;
    const csrf = req.csrfToken;
    if (!owner) {
      res.json({ authenticated: false, mfa_required: false });
      return;
    }
    res.json({
      authenticated: true,
      user: {
        id: owner.id,
        email: owner.email,
        role: owner.role,
        mfa_enabled: Boolean(owner.mfa_enabled)
      },
      csrf_token: csrf ?? null
    });
  });
  router.post("/auth/login", async (req, res) => {
    try {
      const clientIp = req.ip || "127.0.0.1";
      if (!checkLoginRateLimit(clientIp)) {
        throw new AppError(429, "LOGIN_RATE_LIMITED", "Too many failed sign-in attempts. Please wait 5 minutes before trying again.");
      }
      const { email, password, totp_code } = req.body ?? {};
      const cleanEmail = String(email ?? "").trim().toLowerCase();
      const user = await db.get("SELECT id, email, password_hash, role, mfa_enabled, mfa_secret FROM users WHERE email = ?", cleanEmail);
      if (!user || !verifyPassword(String(password ?? ""), user.password_hash)) {
        recordLoginFailure(clientIp);
        await writeAuditLog(db, {
          actorType: "system",
          actorId: "auth_guard",
          action: "owner.login_failed",
          targetType: "user",
          targetId: cleanEmail || "unknown",
          metadata: { reason: "invalid_credentials" },
          ipAddress: clientIp
        });
        throw new AppError(401, "INVALID_CREDENTIALS", "Invalid email or password.");
      }
      if (user.mfa_enabled && user.mfa_secret) {
        if (!totp_code) {
          res.status(200).json({ authenticated: false, mfa_required: true });
          return;
        }
        if (!verifyTotpCode(user.mfa_secret, String(totp_code))) {
          recordLoginFailure(clientIp);
          await writeAuditLog(db, {
            actorType: "owner",
            actorId: user.id,
            action: "owner.login_failed",
            targetType: "user",
            targetId: user.id,
            metadata: { reason: "invalid_totp" },
            ipAddress: clientIp
          });
          throw new AppError(401, "INVALID_MFA", "Invalid authenticator code.");
        }
      }
      clearLoginFailures(clientIp);
      const rawToken = crypto5.randomBytes(32).toString("base64url");
      const csrfToken = crypto5.randomBytes(24).toString("base64url");
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      const expiresAt = new Date(Date.now() + 24 * 36e5).toISOString();
      await db.run(
        `INSERT INTO sessions (id, user_id, token_hash, csrf_token, mfa_verified, expires_at, created_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`,
        crypto5.randomUUID(),
        user.id,
        hashToken(rawToken),
        csrfToken,
        expiresAt,
        nowIso
      );
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: user.id,
        action: "owner.login",
        targetType: "session",
        targetId: user.id,
        metadata: { mfa_used: Boolean(user.mfa_enabled) },
        ipAddress: clientIp
      });
      const isHttps = isHttpsRequest(req);
      const cookiePolicy = isHttps ? "SameSite=None; Secure; Partitioned" : "SameSite=Lax";
      res.setHeader("Set-Cookie", [
        `simvault_session=${encodeURIComponent(rawToken)}; Path=/; HttpOnly; ${cookiePolicy}`,
        `simvault_locked=; Path=/; Max-Age=0; ${cookiePolicy}`
      ]);
      res.json({
        authenticated: true,
        user: { id: user.id, email: user.email, role: user.role, mfa_enabled: Boolean(user.mfa_enabled) },
        csrf_token: csrfToken
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/auth/logout", async (req, res) => {
    try {
      const cookieHeader = req.headers.cookie ?? "";
      const match = /simvault_session=([^;]+)/.exec(cookieHeader);
      if (match) {
        await db.run("DELETE FROM sessions WHERE token_hash = ?", hashToken(decodeURIComponent(match[1])));
      }
      const isHttps = isHttpsRequest(req);
      const cookiePolicy = isHttps ? "SameSite=None; Secure; Partitioned" : "SameSite=Lax";
      res.setHeader("Set-Cookie", [
        `simvault_session=; Path=/; Max-Age=0; HttpOnly; ${cookiePolicy}`,
        `simvault_locked=; Path=/; Max-Age=0; HttpOnly; ${cookiePolicy}`
      ]);
      res.json({ ok: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/security/password", async (req, res) => {
    try {
      const owner = getOwner(req);
      const currentTokenHash = req.currentTokenHash;
      const { current_password, new_password } = req.body ?? {};
      const nextPass = String(new_password ?? "");
      if (nextPass.length < 10) {
        throw new AppError(422, "WEAK_PASSWORD", "New password must be at least 10 characters long.");
      }
      const userRow = await db.get(
        "SELECT id, password_hash FROM users WHERE id = ?",
        owner.id
      );
      if (!userRow || !verifyPassword(String(current_password ?? ""), userRow.password_hash)) {
        throw new AppError(401, "INVALID_CURRENT_PASSWORD", "Current password is incorrect.");
      }
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      await db.run("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?", hashPassword(nextPass), nowIso, owner.id);
      if (currentTokenHash) {
        await db.run("DELETE FROM sessions WHERE user_id = ? AND token_hash != ?", owner.id, currentTokenHash);
      }
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "owner.password_changed",
        targetType: "user",
        targetId: owner.id,
        ipAddress: req.ip
      });
      res.json({ updated: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/security/mfa", async (req, res) => {
    try {
      const owner = getOwner(req);
      const user = await db.get(
        "SELECT email, mfa_enabled, mfa_secret FROM users WHERE id = ?",
        owner.id
      );
      if (!user) throw new AppError(404, "NOT_FOUND", "Owner account not found.");
      const secret = user.mfa_secret || generateTotpSecret();
      if (!user.mfa_secret) {
        await db.run("UPDATE users SET mfa_secret = ? WHERE id = ?", secret, owner.id);
      }
      const otpauthUri = `otpauth://totp/SimVault:${encodeURIComponent(user.email)}?secret=${secret}&issuer=SimVault`;
      res.json({
        mfa_enabled: Boolean(user.mfa_enabled),
        secret_preview: user.mfa_enabled ? "Configured" : secret,
        otpauth_uri: user.mfa_enabled ? null : otpauthUri
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/security/mfa/enable", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { code } = req.body ?? {};
      const user = await db.get("SELECT mfa_secret FROM users WHERE id = ?", owner.id);
      if (!user?.mfa_secret || !verifyTotpCode(user.mfa_secret, String(code ?? ""))) {
        throw new AppError(422, "INVALID_TOTP", "Verification code did not match.");
      }
      await db.run("UPDATE users SET mfa_enabled = 1, updated_at = ? WHERE id = ?", (/* @__PURE__ */ new Date()).toISOString(), owner.id);
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "owner.mfa_enabled",
        targetType: "user",
        targetId: owner.id,
        ipAddress: req.ip
      });
      res.json({ mfa_enabled: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/security/mfa/disable", async (req, res) => {
    try {
      const owner = getOwner(req);
      await db.run("UPDATE users SET mfa_enabled = 0, updated_at = ? WHERE id = ?", (/* @__PURE__ */ new Date()).toISOString(), owner.id);
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "owner.mfa_disabled",
        targetType: "user",
        targetId: owner.id,
        ipAddress: req.ip
      });
      res.json({ mfa_enabled: false });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/overview", async (_req, res) => {
    try {
      await maybeRunOpportunisticSweep(db);
      const settings = await getSettingsMap(db);
      const dayStart = /* @__PURE__ */ new Date();
      dayStart.setUTCHours(0, 0, 0, 0);
      const dayIso = dayStart.toISOString();
      const statusCounts = await db.all(
        "SELECT status, COUNT(*) as count FROM messages GROUP BY status"
      );
      const todayRequests = await db.get(
        "SELECT COUNT(*) as count FROM messages WHERE created_at >= ?",
        dayIso
      );
      const todaySent = await db.get(
        "SELECT COUNT(*) as count FROM messages WHERE sent_at >= ? AND status IN ('sent_to_network', 'delivered', 'delivery_unknown')",
        dayIso
      );
      const queueDepth = await db.get(
        "SELECT COUNT(*) as count FROM messages WHERE status IN ('created', 'queued', 'leased', 'accepted_by_device')"
      );
      const devices = await db.all(
        `SELECT id, name, status, app_version, android_version, permission_send_sms, network_type, battery_pct, sim_ready, last_heartbeat_at
         FROM gateway_devices WHERE status != 'revoked' ORDER BY enrolled_at ASC`
      );
      const sims = await db.all("SELECT * FROM sims ORDER BY updated_at DESC");
      const recentMessages = await db.all(
        `SELECT m.id, m.application_id, a.name as application_name, m.device_id, m.destination_masked, m.template_id,
                m.purpose, m.status, m.is_test, m.created_at, m.sent_at, m.delivered_at, m.failed_at, m.error_code
         FROM messages m
         JOIN applications a ON a.id = m.application_id
         ORDER BY m.created_at DESC
         LIMIT 12`
      );
      const recentAudit = await db.all(
        "SELECT id, actor_type, actor_id, action, target_type, target_id, metadata_redacted_json, ip_address, created_at FROM audit_logs ORDER BY created_at DESC LIMIT 8"
      );
      const activeOtpCount = await db.get(
        "SELECT COUNT(*) as count FROM otp_challenges WHERE status IN ('queued', 'sent')"
      );
      res.json({
        global_paused: settings.global_paused === "true",
        settings,
        kpis: {
          requests_today: Number(todayRequests?.count ?? 0),
          sent_to_network_today: Number(todaySent?.count ?? 0),
          queue_depth: Number(queueDepth?.count ?? 0),
          active_otps: Number(activeOtpCount?.count ?? 0),
          status_breakdown: statusCounts.map((r) => ({ status: r.status, count: Number(r.count ?? 0) }))
        },
        devices,
        sims,
        recent_messages: recentMessages,
        recent_audit: recentAudit
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/applications", async (_req, res) => {
    try {
      const apps = await db.all(
        `SELECT a.*,
                (SELECT COUNT(*) FROM api_keys k WHERE k.application_id = a.id AND k.status != 'revoked') as active_keys_count,
                (SELECT COUNT(*) FROM messages m WHERE m.application_id = a.id) as total_messages_count
         FROM applications a ORDER BY a.created_at DESC`
      );
      res.json({
        applications: apps.map((a) => ({
          ...a,
          daily_limit: Number(a.daily_limit ?? 0),
          allowlist_only: Number(a.allowlist_only ?? 0),
          active_keys_count: Number(a.active_keys_count ?? 0),
          total_messages_count: Number(a.total_messages_count ?? 0)
        })),
        valid_purposes: VALID_MESSAGE_PURPOSES
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/applications", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { name, environment, daily_limit, allowlist_only, allowed_purposes } = req.body ?? {};
      if (!name || String(name).trim().length < 2) {
        throw new AppError(400, "BAD_REQUEST", "Application name is required (min 2 chars).");
      }
      const env = environment === "test" ? "test" : "live";
      const parsedLimit = Number(daily_limit ?? 200);
      if (!Number.isFinite(parsedLimit) || parsedLimit < 1 || parsedLimit > 1e5) {
        throw new AppError(422, "INVALID_LIMIT", "Daily limit must be between 1 and 100000.");
      }
      const id = `app_${crypto5.randomBytes(5).toString("hex")}`;
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      const rawPurposes = Array.isArray(allowed_purposes) ? allowed_purposes.filter((p) => typeof p === "string" && VALID_MESSAGE_PURPOSES.includes(p)) : [];
      const purposes = rawPurposes.length > 0 ? rawPurposes : ["login", "mfa", "account_transactional"];
      await db.run(
        `INSERT INTO applications (id, owner_user_id, name, environment, status, allowed_purposes_json, daily_limit, allowlist_only, created_at)
         VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)`,
        id,
        owner.id,
        String(name).trim().slice(0, 80),
        env,
        JSON.stringify(purposes),
        Math.trunc(parsedLimit),
        allowlist_only === true ? 1 : 0,
        nowIso
      );
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "application.created",
        targetType: "application",
        targetId: id,
        metadata: { name: String(name).trim(), environment: env },
        ipAddress: req.ip
      });
      const created = await db.get("SELECT * FROM applications WHERE id = ?", id);
      res.status(201).json({ application: created });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.patch("/applications/:id", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { status, daily_limit, allowlist_only, allowed_purposes } = req.body ?? {};
      const existing = await db.get("SELECT id FROM applications WHERE id = ?", req.params.id);
      if (!existing) throw new AppError(404, "NOT_FOUND", "Application not found.");
      if (status !== void 0 && !["active", "paused", "disabled"].includes(String(status))) {
        throw new AppError(422, "INVALID_STATUS", "Status must be active, paused, or disabled.");
      }
      if (daily_limit !== void 0 && (!Number.isFinite(Number(daily_limit)) || Number(daily_limit) < 1 || Number(daily_limit) > 1e5)) {
        throw new AppError(422, "INVALID_LIMIT", "Daily limit must be between 1 and 100000.");
      }
      const nextPurposes = Array.isArray(allowed_purposes) ? allowed_purposes.filter((p) => typeof p === "string" && VALID_MESSAGE_PURPOSES.includes(p)) : null;
      await db.run(
        `UPDATE applications
         SET status = COALESCE(?, status),
             daily_limit = COALESCE(?, daily_limit),
             allowlist_only = COALESCE(?, allowlist_only),
             allowed_purposes_json = COALESCE(?, allowed_purposes_json)
         WHERE id = ?`,
        status !== void 0 ? String(status) : null,
        daily_limit !== void 0 ? Math.trunc(Number(daily_limit)) : null,
        typeof allowlist_only === "boolean" ? allowlist_only ? 1 : 0 : null,
        nextPurposes && nextPurposes.length > 0 ? JSON.stringify(nextPurposes) : null,
        req.params.id
      );
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "application.updated",
        targetType: "application",
        targetId: req.params.id,
        metadata: { status, daily_limit, allowlist_only },
        ipAddress: req.ip
      });
      res.json({ application: await db.get("SELECT * FROM applications WHERE id = ?", req.params.id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/api-keys", async (_req, res) => {
    try {
      const keys = await db.all(
        `SELECT k.id, k.application_id, a.name as application_name, a.environment,
                k.name, k.key_prefix, k.scopes_json, k.status, k.last_used_at, k.expires_at, k.revoked_at, k.created_at
         FROM api_keys k
         JOIN applications a ON a.id = k.application_id
         ORDER BY k.created_at DESC`
      );
      res.json({ api_keys: keys, available_scopes: ALL_API_SCOPES });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/api-keys", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { application_id, name, scopes } = req.body ?? {};
      const app = await db.get(
        "SELECT id, environment FROM applications WHERE id = ?",
        application_id
      );
      if (!app) throw new AppError(404, "NOT_FOUND", "Application not found.");
      if (!name || String(name).trim().length < 2) throw new AppError(400, "BAD_REQUEST", "Key label is required.");
      const validScopes = Array.isArray(scopes) && scopes.length > 0 ? scopes.filter((s) => ALL_API_SCOPES.includes(s)) : ["sms:send", "otp:create", "otp:verify", "usage:read"];
      const { rawKey, keyPrefix, secretHash } = generateApiKey(app.environment);
      const id = `key_${crypto5.randomBytes(5).toString("hex")}`;
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      await db.run(
        `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
        id,
        app.id,
        String(name).trim(),
        keyPrefix,
        secretHash,
        JSON.stringify(validScopes),
        nowIso
      );
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "api_key.created",
        targetType: "api_key",
        targetId: id,
        metadata: { application_id: app.id, key_prefix: keyPrefix, scopes: validScopes },
        ipAddress: req.ip
      });
      const created = await db.get(
        `SELECT k.id, k.application_id, a.name as application_name, a.environment,
                k.name, k.key_prefix, k.scopes_json, k.status, k.last_used_at, k.expires_at, k.revoked_at, k.created_at
         FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.id = ?`,
        id
      );
      res.status(201).json({ api_key: created, secret_once: rawKey });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/api-keys/:id/rotate", async (req, res) => {
    try {
      const owner = getOwner(req);
      const existing = await db.get(
        `SELECT k.id, k.application_id, k.name, k.scopes_json, k.status, a.environment
         FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.id = ?`,
        req.params.id
      );
      if (!existing || existing.status === "revoked") {
        throw new AppError(404, "NOT_FOUND", "Active API key not found.");
      }
      const now = /* @__PURE__ */ new Date();
      const nowIso = now.toISOString();
      const overlapExpires = new Date(now.getTime() + 15 * 6e4).toISOString();
      const { rawKey, keyPrefix, secretHash } = generateApiKey(existing.environment);
      const newId = `key_${crypto5.randomBytes(5).toString("hex")}`;
      await db.transaction(async (tx) => {
        await tx.run("UPDATE api_keys SET status = 'rotating', expires_at = ? WHERE id = ?", overlapExpires, existing.id);
        await tx.run(
          `INSERT INTO api_keys (id, application_id, name, key_prefix, secret_hash, scopes_json, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, 'active', ?)`,
          newId,
          existing.application_id,
          `${existing.name} (Rotated)`,
          keyPrefix,
          secretHash,
          existing.scopes_json,
          nowIso
        );
      });
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "api_key.rotated",
        targetType: "api_key",
        targetId: newId,
        metadata: { previous_key_id: existing.id, key_prefix: keyPrefix, overlap_expires_at: overlapExpires },
        ipAddress: req.ip
      });
      const created = await db.get(
        `SELECT k.id, k.application_id, a.name as application_name, a.environment,
                k.name, k.key_prefix, k.scopes_json, k.status, k.last_used_at, k.expires_at, k.revoked_at, k.created_at
         FROM api_keys k JOIN applications a ON a.id = k.application_id WHERE k.id = ?`,
        newId
      );
      res.status(201).json({ api_key: created, secret_once: rawKey, overlap_expires_at: overlapExpires });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/api-keys/:id/revoke", async (req, res) => {
    try {
      const owner = getOwner(req);
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      const result = await db.run(
        "UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE id = ? AND status != 'revoked'",
        nowIso,
        req.params.id
      );
      if (result.changes === 0) throw new AppError(404, "NOT_FOUND", "API key not found or already revoked.");
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "api_key.revoked",
        targetType: "api_key",
        targetId: req.params.id,
        ipAddress: req.ip
      });
      res.json({ revoked: true, revoked_at: nowIso });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/messages", async (req, res) => {
    try {
      const status = typeof req.query.status === "string" && req.query.status !== "all" ? req.query.status : null;
      const appId = typeof req.query.application_id === "string" && req.query.application_id !== "all" ? req.query.application_id : null;
      const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
      let sql = `
        SELECT m.id, m.application_id, a.name as application_name, a.environment, m.device_id,
               m.destination_masked, m.template_id, m.purpose, m.status, m.is_test, m.idempotency_key,
               m.ttl_expires_at, m.created_at, m.queued_at, m.leased_at, m.accepted_at,
               m.sent_at, m.delivered_at, m.failed_at, m.error_code
        FROM messages m
        JOIN applications a ON a.id = m.application_id
        WHERE 1=1
      `;
      const params = [];
      if (status) {
        sql += " AND m.status = ?";
        params.push(status);
      }
      if (appId) {
        sql += " AND m.application_id = ?";
        params.push(appId);
      }
      if (q) {
        sql += " AND (LOWER(m.id) LIKE LOWER(?) OR LOWER(m.destination_masked) LIKE LOWER(?) OR LOWER(m.template_id) LIKE LOWER(?))";
        params.push(`%${q}%`, `%${q}%`, `%${q}%`);
      }
      sql += " ORDER BY m.created_at DESC LIMIT 100";
      const rows = await db.all(sql, ...params);
      res.json({ messages: rows });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  const handleAdminSendSms = async (req, res) => {
    try {
      const owner = getOwner(req);
      const { application_id, to, template_id, variables, purpose, ttl_seconds, idempotency_key } = req.body ?? {};
      if (!application_id || !to || !template_id) {
        throw new AppError(400, "BAD_REQUEST", "application_id, to, and template_id are required.");
      }
      const result = await createSmsRequest(db, {
        applicationId: String(application_id),
        to: String(to),
        templateCode: String(template_id),
        variables: variables && typeof variables === "object" ? variables : {},
        purpose: String(purpose || "account_transactional"),
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : 180,
        idempotencyKey: idempotency_key ? String(idempotency_key).trim() : void 0,
        actorId: owner.id,
        ipAddress: req.ip
      });
      res.status(result.deduplicated ? 200 : 202).json(result);
    } catch (err) {
      sendAdminError(res, err);
    }
  };
  router.post("/messages/send", handleAdminSendSms);
  router.post("/messages/test-send", handleAdminSendSms);
  router.get("/otp-challenges", async (_req, res) => {
    try {
      const challenges = await db.all(
        `SELECT o.id, o.application_id, a.name as application_name, o.destination_masked,
                o.purpose, o.status, o.is_test, o.expires_at, o.attempts, o.max_attempts,
                o.consumed_at, o.message_id, o.created_at
         FROM otp_challenges o
         JOIN applications a ON a.id = o.application_id
         ORDER BY o.created_at DESC
         LIMIT 100`
      );
      res.json({ challenges });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  const handleAdminCreateOtp = async (req, res) => {
    try {
      const owner = getOwner(req);
      const { application_id, to, purpose, ttl_seconds, bypass_cooldown } = req.body ?? {};
      if (!application_id || !to) {
        throw new AppError(400, "BAD_REQUEST", "application_id and to are required.");
      }
      const result = await createOtpChallenge(db, {
        applicationId: String(application_id),
        to: String(to),
        purpose: String(purpose || "login"),
        ttlSeconds: ttl_seconds ? Number(ttl_seconds) : void 0,
        actorId: owner.id,
        ipAddress: req.ip,
        bypassCooldown: Boolean(bypass_cooldown)
      });
      res.status(202).json(result);
    } catch (err) {
      sendAdminError(res, err);
    }
  };
  router.post("/otp-challenges/create", handleAdminCreateOtp);
  router.post("/otp-challenges/test-create", handleAdminCreateOtp);
  const handleAdminVerifyOtp = async (req, res) => {
    try {
      const { challenge_id, code } = req.body ?? {};
      const result = await verifyOtpChallenge(db, {
        challengeId: String(challenge_id ?? ""),
        code: String(code ?? ""),
        ipAddress: req.ip
      });
      res.json(result);
    } catch (err) {
      sendAdminError(res, err);
    }
  };
  router.post("/otp-challenges/verify", handleAdminVerifyOtp);
  router.post("/otp-challenges/test-verify", handleAdminVerifyOtp);
  router.get("/devices", async (_req, res) => {
    try {
      const devices = await db.all(
        "SELECT id, name, status, app_version, android_version, permission_send_sms, network_type, battery_pct, sim_ready, last_heartbeat_at, enrolled_at, revoked_at FROM gateway_devices ORDER BY enrolled_at DESC"
      );
      const tokens = await db.all(
        "SELECT id, device_name, expires_at, used_at, created_at FROM enrollment_tokens ORDER BY created_at DESC LIMIT 10"
      );
      const sims = await db.all("SELECT * FROM sims");
      const queuedRow = await db.get("SELECT COUNT(*) as c FROM messages WHERE status = 'queued'");
      const leasedJobs = await db.all(
        `SELECT m.id, m.destination_masked, m.template_id, m.purpose, m.status, m.is_test, m.leased_at, m.ttl_expires_at, l.lease_expires_at, l.attempt_count
         FROM messages m
         LEFT JOIN gateway_job_leases l ON l.message_id = m.id
         WHERE m.status IN ('queued', 'leased', 'accepted_by_device')
         ORDER BY m.created_at ASC
         LIMIT 20`
      );
      res.json({
        devices,
        enrollment_tokens: tokens,
        sims,
        queued_count: Number(queuedRow?.c ?? 0),
        pending_jobs: leasedJobs
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/devices/enrollment-tokens", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { device_name, ttl_minutes } = req.body ?? {};
      if (!device_name || String(device_name).trim().length < 2) {
        throw new AppError(400, "BAD_REQUEST", "Device name is required.");
      }
      const { rawToken, tokenHash } = generateEnrollmentToken();
      const now = /* @__PURE__ */ new Date();
      const ttlMins = Number(ttl_minutes ?? 15);
      const boundedTtl = Number.isFinite(ttlMins) ? Math.min(Math.max(ttlMins, 2), 60) : 15;
      const expiresAt = new Date(now.getTime() + boundedTtl * 6e4).toISOString();
      const id = `enr_${crypto5.randomBytes(4).toString("hex")}`;
      await db.run(
        `INSERT INTO enrollment_tokens (id, device_name, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?)`,
        id,
        String(device_name).trim().slice(0, 80),
        tokenHash,
        expiresAt,
        now.toISOString()
      );
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "gateway.enrollment_token_created",
        targetType: "enrollment_token",
        targetId: id,
        metadata: { device_name: String(device_name).trim(), expires_at: expiresAt },
        ipAddress: req.ip
      });
      res.status(201).json({
        id,
        device_name: String(device_name).trim(),
        enrollment_token_once: rawToken,
        expires_at: expiresAt
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/devices/:id/action", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { action } = req.body ?? {};
      const devId = req.params.id;
      const dev = await db.get("SELECT id, status FROM gateway_devices WHERE id = ?", devId);
      if (!dev) throw new AppError(404, "NOT_FOUND", "Device not found.");
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      if (action === "pause") {
        await db.run("UPDATE gateway_devices SET status = 'paused' WHERE id = ? AND status != 'revoked'", devId);
      } else if (action === "resume") {
        await db.run(
          "UPDATE gateway_devices SET status = CASE WHEN last_heartbeat_at IS NOT NULL THEN 'online' ELSE 'offline' END WHERE id = ? AND status != 'revoked'",
          devId
        );
      } else if (action === "revoke") {
        await db.run("UPDATE gateway_devices SET status = 'revoked', revoked_at = ? WHERE id = ?", nowIso, devId);
      } else {
        throw new AppError(400, "BAD_REQUEST", "Unsupported device action. Allowed: pause, resume, revoke.");
      }
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: `gateway.device_${action}`,
        targetType: "gateway_device",
        targetId: devId,
        ipAddress: req.ip
      });
      res.json({ device: await db.get("SELECT * FROM gateway_devices WHERE id = ?", devId) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/sim-usage", async (_req, res) => {
    try {
      const sims = await db.all(
        `SELECT s.*, d.name as device_name, d.status as device_status
         FROM sims s JOIN gateway_devices d ON d.id = s.device_id`
      );
      const usageByApp = await db.all(
        `SELECT a.id as application_id, a.name as application_name, a.environment, a.daily_limit,
                COUNT(m.id) as total_messages,
                SUM(CASE WHEN m.status = 'sent_to_network' THEN 1 ELSE 0 END) as sent_to_network,
                SUM(CASE WHEN m.status = 'delivered' THEN 1 ELSE 0 END) as delivered,
                SUM(CASE WHEN m.status = 'failed' THEN 1 ELSE 0 END) as failed,
                SUM(CASE WHEN m.status = 'delivery_unknown' THEN 1 ELSE 0 END) as delivery_unknown
         FROM applications a
         LEFT JOIN messages m ON m.application_id = a.id
         GROUP BY a.id, a.name, a.environment, a.daily_limit`
      );
      res.json({
        sims,
        usage_by_app: usageByApp.map((r) => ({
          ...r,
          daily_limit: Number(r.daily_limit ?? 0),
          total_messages: Number(r.total_messages ?? 0),
          sent_to_network: Number(r.sent_to_network ?? 0),
          delivered: Number(r.delivered ?? 0),
          failed: Number(r.failed ?? 0),
          delivery_unknown: Number(r.delivery_unknown ?? 0)
        }))
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.patch("/sim-usage/:id/reconcile", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { plan_sms_limit, estimated_sms_sent, warning_threshold, carrier_label, period_start, period_end, notes } = req.body ?? {};
      const sim = await db.get(
        "SELECT * FROM sims WHERE id = ?",
        req.params.id
      );
      if (!sim) throw new AppError(404, "NOT_FOUND", "SIM record not found.");
      const nextLimit = typeof plan_sms_limit === "number" ? Math.max(0, plan_sms_limit) : Number(sim.plan_sms_limit);
      const nextSent = typeof estimated_sms_sent === "number" ? Math.max(0, estimated_sms_sent) : Number(sim.estimated_sms_sent);
      const { remaining } = calculateSimRemainingEstimate(nextLimit, nextSent);
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      await db.run(
        `UPDATE sims
         SET plan_sms_limit = ?,
             estimated_sms_sent = ?,
             estimated_sms_remaining = ?,
             warning_threshold = COALESCE(?, warning_threshold),
             carrier_label = COALESCE(?, carrier_label),
             period_start = COALESCE(?, period_start),
             period_end = COALESCE(?, period_end),
             notes = COALESCE(?, notes),
             updated_at = ?
         WHERE id = ?`,
        nextLimit,
        nextSent,
        remaining,
        typeof warning_threshold === "number" ? warning_threshold : null,
        carrier_label ?? null,
        period_start ?? null,
        period_end ?? null,
        notes ?? null,
        nowIso,
        req.params.id
      );
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "sim.manual_reconciliation",
        targetType: "sim",
        targetId: req.params.id,
        metadata: { plan_sms_limit: nextLimit, estimated_sms_sent: nextSent, estimated_sms_remaining: remaining },
        ipAddress: req.ip
      });
      res.json({ sim: await db.get("SELECT * FROM sims WHERE id = ?", req.params.id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/templates", async (_req, res) => {
    try {
      const templates = await db.all("SELECT * FROM message_templates ORDER BY created_at DESC");
      res.json({ templates, valid_purposes: VALID_MESSAGE_PURPOSES });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/templates", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { code, purpose, body, status } = req.body ?? {};
      const cleanCode = String(code ?? "").trim().toLowerCase().replace(/[^a-z0-9_]/g, "_");
      if (!cleanCode || cleanCode.length < 2 || !body || String(body).trim().length < 8) {
        throw new AppError(400, "BAD_REQUEST", "Template code and body (min 8 chars) are required.");
      }
      const cleanPurpose = String(purpose || "account_transactional");
      if (!VALID_MESSAGE_PURPOSES.includes(cleanPurpose)) {
        throw new AppError(422, "INVALID_PURPOSE", "Invalid message purpose.");
      }
      const id = `tpl_${crypto5.randomBytes(5).toString("hex")}`;
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      await db.run(
        `INSERT INTO message_templates (id, owner_user_id, code, purpose, body, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        id,
        owner.id,
        cleanCode,
        cleanPurpose,
        String(body).trim(),
        status === "draft" ? "draft" : "approved",
        nowIso,
        nowIso
      );
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "template.created",
        targetType: "message_template",
        targetId: id,
        metadata: { code: cleanCode, purpose: cleanPurpose },
        ipAddress: req.ip
      });
      res.status(201).json({ template: await db.get("SELECT * FROM message_templates WHERE id = ?", id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.patch("/templates/:id", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { body, status, purpose } = req.body ?? {};
      if (status !== void 0 && !["approved", "draft", "archived"].includes(String(status))) {
        throw new AppError(422, "INVALID_STATUS", "Status must be approved, draft, or archived.");
      }
      if (purpose !== void 0 && !VALID_MESSAGE_PURPOSES.includes(String(purpose))) {
        throw new AppError(422, "INVALID_PURPOSE", "Invalid message purpose.");
      }
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      const result = await db.run(
        `UPDATE message_templates
         SET body = COALESCE(?, body),
             status = COALESCE(?, status),
             purpose = COALESCE(?, purpose),
             updated_at = ?
         WHERE id = ?`,
        body ?? null,
        status ?? null,
        purpose ?? null,
        nowIso,
        req.params.id
      );
      if (result.changes === 0) throw new AppError(404, "NOT_FOUND", "Template not found.");
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "template.updated",
        targetType: "message_template",
        targetId: req.params.id,
        metadata: { status, purpose },
        ipAddress: req.ip
      });
      res.json({ template: await db.get("SELECT * FROM message_templates WHERE id = ?", req.params.id) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/allowlist", async (_req, res) => {
    try {
      const entries = await db.all(
        `SELECT d.id, d.application_id, a.name as application_name, d.e164_masked, d.label, d.created_at
         FROM destination_allowlist d JOIN applications a ON a.id = d.application_id
         ORDER BY d.created_at DESC`
      );
      res.json({ entries });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/allowlist", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { application_id, phone, label } = req.body ?? {};
      const appExists = await db.get("SELECT id FROM applications WHERE id = ?", String(application_id ?? ""));
      if (!appExists) {
        throw new AppError(404, "APPLICATION_NOT_FOUND", "Application not found.");
      }
      const normalized = normalizeE164(String(phone ?? ""));
      if (!isValidE164(normalized)) {
        throw new AppError(422, "INVALID_PHONE", "Phone number must be valid E.164 format (e.g. +919876543210).");
      }
      const id = crypto5.randomUUID();
      const masked = maskE164(normalized);
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      await db.run(
        `INSERT INTO destination_allowlist (id, application_id, e164_masked, e164_hash, e164_encrypted, label, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        id,
        String(application_id),
        masked,
        hashDestination(normalized),
        encryptField(normalized),
        String(label || "Approved Destination").slice(0, 80),
        nowIso
      );
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "allowlist.added",
        targetType: "destination_allowlist",
        targetId: id,
        metadata: { application_id, e164_masked: masked, label },
        ipAddress: req.ip
      });
      res.status(201).json({ entry: { id, application_id, e164_masked: masked, label, created_at: nowIso } });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.delete("/allowlist/:id", async (req, res) => {
    try {
      const owner = getOwner(req);
      await db.run("DELETE FROM destination_allowlist WHERE id = ?", req.params.id);
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "allowlist.removed",
        targetType: "destination_allowlist",
        targetId: req.params.id,
        ipAddress: req.ip
      });
      res.json({ deleted: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/webhooks", async (_req, res) => {
    try {
      const endpoints = await db.all(
        `SELECT w.id, w.application_id, a.name as application_name, w.url, w.enabled, w.event_types_json, w.created_at
         FROM webhook_endpoints w JOIN applications a ON a.id = w.application_id
         ORDER BY w.created_at DESC`
      );
      const deliveries = await db.all(
        `SELECT d.*, e.url
         FROM webhook_deliveries d JOIN webhook_endpoints e ON e.id = d.endpoint_id
         ORDER BY d.created_at DESC LIMIT 40`
      );
      res.json({ endpoints, deliveries });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/webhooks", async (req, res) => {
    try {
      const owner = getOwner(req);
      const { application_id, url, event_types } = req.body ?? {};
      const appExists = await db.get("SELECT id FROM applications WHERE id = ?", String(application_id ?? ""));
      if (!appExists) {
        throw new AppError(404, "APPLICATION_NOT_FOUND", "Application not found.");
      }
      const validatedUrl = await assertPublicWebhookHost(String(url ?? ""));
      const cleanUrl = validatedUrl.toString();
      const id = `wh_${crypto5.randomBytes(5).toString("hex")}`;
      const rawSecret = `whsec_${crypto5.randomBytes(20).toString("hex")}`;
      const allowedEvents = /* @__PURE__ */ new Set(["message.status", "otp.sent", "otp.verified", "otp.failed"]);
      const events = Array.isArray(event_types) && event_types.length > 0 ? event_types.filter((e) => typeof e === "string" && allowedEvents.has(e)) : ["message.status", "otp.sent", "otp.verified", "otp.failed"];
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      await db.run(
        `INSERT INTO webhook_endpoints (id, application_id, url, secret_encrypted, enabled, event_types_json, created_at)
         VALUES (?, ?, ?, ?, 1, ?, ?)`,
        id,
        String(application_id),
        cleanUrl,
        encryptField(rawSecret),
        JSON.stringify(events),
        nowIso
      );
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "webhook.created",
        targetType: "webhook_endpoint",
        targetId: id,
        metadata: { application_id, url: cleanUrl, events },
        ipAddress: req.ip
      });
      res.status(201).json({
        endpoint: { id, application_id, url: cleanUrl, enabled: 1, event_types_json: JSON.stringify(events), created_at: nowIso },
        signing_secret_once: rawSecret
      });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/webhooks/:id/test", async (req, res) => {
    try {
      const ep = await db.get(
        "SELECT id, application_id, url, secret_encrypted FROM webhook_endpoints WHERE id = ?",
        req.params.id
      );
      if (!ep) throw new AppError(404, "NOT_FOUND", "Webhook endpoint not found.");
      const eventId = `evt_test_${crypto5.randomBytes(4).toString("hex")}`;
      const nowIso = (/* @__PURE__ */ new Date()).toISOString();
      const payload = JSON.stringify({ event_id: eventId, event_type: "message.status", test: true, occurred_at: nowIso });
      await db.run(
        `INSERT INTO webhook_deliveries (id, endpoint_id, event_id, event_type, payload_redacted_json, status, attempt_count, next_attempt_at, last_http_status, created_at)
         VALUES (?, ?, ?, 'message.status', ?, 'pending', 0, ?, NULL, ?)`,
        crypto5.randomUUID(),
        ep.id,
        eventId,
        payload,
        nowIso,
        nowIso
      );
      const tick = await runSweeperTick(db);
      res.json({ queued: true, event_id: eventId, sweeper: tick });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.patch("/webhooks/:id/toggle", async (req, res) => {
    try {
      const owner = getOwner(req);
      await db.run("UPDATE webhook_endpoints SET enabled = CASE WHEN enabled = 1 THEN 0 ELSE 1 END WHERE id = ?", req.params.id);
      await writeAuditLog(db, {
        actorType: "owner",
        actorId: owner.id,
        action: "webhook.toggled",
        targetType: "webhook_endpoint",
        targetId: req.params.id,
        ipAddress: req.ip
      });
      res.json({ ok: true });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/audit-logs", async (req, res) => {
    try {
      const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
      let sql = "SELECT * FROM audit_logs WHERE 1=1";
      const params = [];
      if (q) {
        sql += " AND (LOWER(action) LIKE LOWER(?) OR LOWER(target_type) LIKE LOWER(?) OR LOWER(target_id) LIKE LOWER(?) OR LOWER(metadata_redacted_json) LIKE LOWER(?))";
        params.push(`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`);
      }
      sql += " ORDER BY created_at DESC LIMIT 120";
      res.json({ logs: await db.all(sql, ...params) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/settings", async (_req, res) => {
    try {
      res.json({ settings: await getSettingsMap(db) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.patch("/settings", async (req, res) => {
    try {
      const owner = getOwner(req);
      const updates = req.body ?? {};
      const numericBounds = {
        otp_ttl_seconds: [60, 600],
        otp_max_attempts: [1, 10],
        otp_resend_cooldown_seconds: [0, 300],
        rate_limit_per_number_hourly: [1, 50],
        rate_limit_per_ip_minute: [5, 500],
        lease_timeout_seconds: [10, 300],
        max_send_retries: [1, 10],
        retention_days: [1, 365],
        global_daily_sim_cap: [1, 5e4]
      };
      for (const [k, v] of Object.entries(updates)) {
        if (k === "global_paused") {
          const val = String(v) === "true" ? "true" : "false";
          await updateSetting(db, k, val, owner.id, req.ip);
        } else if (k in numericBounds) {
          const num = Number(v);
          const [min, max] = numericBounds[k];
          if (!Number.isFinite(num) || num < min || num > max) {
            throw new AppError(422, "INVALID_SETTING", `Setting ${k} must be between ${min} and ${max}.`);
          }
          await updateSetting(db, k, String(Math.trunc(num)), owner.id, req.ip);
        }
      }
      res.json({ settings: await getSettingsMap(db) });
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.post("/sweeper/run", async (_req, res) => {
    try {
      res.json(await runSweeperTick(db));
    } catch (err) {
      sendAdminError(res, err);
    }
  });
  router.get("/blueprints", (_req, res) => {
    res.json({
      kotlin_gateway_snippet: `// SimVault Android Gateway Worker (Kotlin / SmsManager)
class SmsDispatchWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
  override suspend fun doWork(): Result {
    if (ContextCompat.checkSelfPermission(applicationContext, Manifest.permission.SEND_SMS) != PackageManager.PERMISSION_GRANTED) {
      return Result.failure() // Never bypass Android runtime permissions
    }
    val job = gatewayApi.pollNextJob() ?: return Result.success()
    if (localJournal.hasProcessed(job.jobId)) return Result.success()
    localJournal.markReceived(job.jobId)
    gatewayApi.ackAccepted(job.jobId)

    val subManager = applicationContext.getSystemService(SubscriptionManager::class.java)
    val subInfo = subManager.activeSubscriptionInfoList?.firstOrNull { it.simSlotIndex == job.simSlot }
      ?: return reportFailure(job.jobId, "SIM_SLOT_UNAVAILABLE")

    val smsManager = applicationContext.getSystemService(SmsManager::class.java)
      .createForSubscriptionId(subInfo.subscriptionId)

    smsManager.sendTextMessage(job.to, null, job.body, sentPendingIntent, deliveryPendingIntent)
    return Result.success()
  }
}`,
      vercel_supabase_snippet: `# 1. Create Supabase tables (Supabase Dashboard -> SQL Editor):
#    Paste & run infra/supabase_schema.sql

# 2. Configure .env (local) or Vercel -> Project Settings -> Environment Variables:
SUPABASE_DB_URL="postgresql://postgres.<PROJECT_REF>:<PASSWORD>@aws-0-<REGION>.pooler.supabase.com:6543/postgres"
# OR use separate fields instead of SUPABASE_DB_URL:
# SUPABASE_URL="https://<PROJECT_REF>.supabase.co"
# SUPABASE_DB_PASSWORD="your-db-password"
# SUPABASE_DB_REGION="ap-south-1"

API_KEY_PEPPER="<64-hex-secret>"
JWT_PRIVATE_KEY="<64-hex-secret>"
OTP_PEPPER="<64-hex-secret>"
FIELD_ENCRYPTION_KEY="<64-hex-secret>"
SIMVAULT_ADMIN_EMAIL="owner@yourdomain.com"
SIMVAULT_ADMIN_PASSWORD="ChangeThisStrongPassword!"
CRON_SECRET="<48-hex-secret>"

# 3. Build & Deploy to Vercel:
npm run build`,
      ubuntu_setup_snippet: `# Optional Self-Hosted VPS (Node 22 + systemd + Nginx):
sudo bash deploy/ubuntu-setup.sh sms.yourdomain.com owner@yourdomain.com
npm ci && npm run build && NODE_ENV=production npm run start:prod`,
      ubuntu_nginx_snippet: `server {
  listen 80;
  server_name sms.yourdomain.com;
  location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}`
    });
  });
  function collectAndroidProjectFiles() {
    const rootDir = path3.resolve(process.cwd(), "android-gateway");
    const files = [];
    function walk(dir) {
      if (!fs3.existsSync(dir)) return;
      for (const entry of fs3.readdirSync(dir, { withFileTypes: true })) {
        const full = path3.join(dir, entry.name);
        if (entry.isDirectory()) {
          walk(full);
        } else {
          files.push({
            path: path3.relative(rootDir, full).replace(/\\/g, "/"),
            data: fs3.readFileSync(full)
          });
        }
      }
    }
    walk(rootDir);
    files.sort((a, b) => a.path.localeCompare(b.path));
    return files;
  }
  function crc32(buf) {
    let crc = 4294967295;
    for (let i = 0; i < buf.length; i++) {
      crc ^= buf[i];
      for (let j = 0; j < 8; j++) {
        crc = crc >>> 1 ^ (crc & 1 ? 3988292384 : 0);
      }
    }
    return (crc ^ 4294967295) >>> 0;
  }
  function buildZipStoreArchive(entries) {
    const localChunks = [];
    const centralChunks = [];
    let offset = 0;
    for (const entry of entries) {
      const nameBuf = Buffer.from(`android-gateway/${entry.path}`, "utf8");
      const crc = crc32(entry.data);
      const size = entry.data.length;
      const localHeader = Buffer.alloc(30);
      localHeader.writeUInt32LE(67324752, 0);
      localHeader.writeUInt16LE(20, 4);
      localHeader.writeUInt16LE(2048, 6);
      localHeader.writeUInt16LE(0, 8);
      localHeader.writeUInt16LE(0, 10);
      localHeader.writeUInt16LE(21537, 12);
      localHeader.writeUInt32LE(crc, 14);
      localHeader.writeUInt32LE(size, 18);
      localHeader.writeUInt32LE(size, 22);
      localHeader.writeUInt16LE(nameBuf.length, 26);
      localHeader.writeUInt16LE(0, 28);
      localChunks.push(localHeader, nameBuf, entry.data);
      const centralHeader = Buffer.alloc(46);
      centralHeader.writeUInt32LE(33639248, 0);
      centralHeader.writeUInt16LE(20, 4);
      centralHeader.writeUInt16LE(20, 6);
      centralHeader.writeUInt16LE(2048, 8);
      centralHeader.writeUInt16LE(0, 10);
      centralHeader.writeUInt16LE(0, 12);
      centralHeader.writeUInt16LE(21537, 14);
      centralHeader.writeUInt32LE(crc, 16);
      centralHeader.writeUInt32LE(size, 20);
      centralHeader.writeUInt32LE(size, 24);
      centralHeader.writeUInt16LE(nameBuf.length, 28);
      centralHeader.writeUInt16LE(0, 30);
      centralHeader.writeUInt16LE(0, 32);
      centralHeader.writeUInt16LE(0, 34);
      centralHeader.writeUInt16LE(0, 36);
      centralHeader.writeUInt32LE(0, 38);
      centralHeader.writeUInt32LE(offset, 42);
      centralChunks.push(centralHeader, nameBuf);
      offset += localHeader.length + nameBuf.length + entry.data.length;
    }
    const centralDir = Buffer.concat(centralChunks);
    const eocd = Buffer.alloc(22);
    eocd.writeUInt32LE(101010256, 0);
    eocd.writeUInt16LE(0, 4);
    eocd.writeUInt16LE(0, 6);
    eocd.writeUInt16LE(entries.length, 8);
    eocd.writeUInt16LE(entries.length, 10);
    eocd.writeUInt32LE(centralDir.length, 12);
    eocd.writeUInt32LE(offset, 16);
    eocd.writeUInt16LE(0, 20);
    return Buffer.concat([...localChunks, centralDir, eocd]);
  }
  router.get("/android-project", (_req, res) => {
    const files = collectAndroidProjectFiles().map((f) => ({
      path: f.path,
      content: f.data.toString("utf8")
    }));
    res.json({ root: "android-gateway", files });
  });
  router.get("/android-project.zip", (_req, res) => {
    const archive = buildZipStoreArchive(collectAndroidProjectFiles());
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", 'attachment; filename="simvault-android-gateway.zip"');
    res.send(archive);
  });
  return router;
}
var init_admin = __esm({
  "server/routes/admin.ts"() {
    init_crypto();
    init_db();
    init_services();
    init_smsRules();
  }
});

// server/app.ts
var app_exports = {};
__export(app_exports, {
  createSimVaultApp: () => createSimVaultApp,
  getSharedSimVaultApp: () => getSharedSimVaultApp
});
import express from "express";
async function createSimVaultApp(existingDb) {
  const db = existingDb ?? await getDb();
  const app = express();
  const isProd = process.env.NODE_ENV === "production";
  app.set("trust proxy", 1);
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    if (req.path.startsWith("/api") || req.path.startsWith("/v1")) {
      res.setHeader("Cache-Control", "no-store");
    }
    next();
  });
  app.use(express.json({ limit: "64kb" }));
  app.get("/health", async (_req, res) => {
    try {
      const queueRow = await db.get(
        "SELECT COUNT(*) as count FROM messages WHERE status IN ('created', 'queued', 'leased', 'accepted_by_device')"
      );
      const onlineDevices = await db.get(
        "SELECT COUNT(*) as count FROM gateway_devices WHERE status = 'online'"
      );
      res.json({
        status: "ok",
        version: "1.0.0",
        mode: isProd ? "production" : "development",
        database: db.dialect,
        uptime_seconds: Math.floor(process.uptime()),
        timestamp: (/* @__PURE__ */ new Date()).toISOString(),
        queue_depth: Number(queueRow?.count ?? 0),
        gateway_devices_online: Number(onlineDevices?.count ?? 0)
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Database health check failed";
      res.status(503).json({
        status: "error",
        error: { code: "DB_UNAVAILABLE", message }
      });
    }
  });
  app.get("/api/cron/sweeper", async (req, res) => {
    const cronSecret = process.env.CRON_SECRET?.trim();
    if (cronSecret) {
      const auth = req.headers.authorization ?? "";
      if (auth !== `Bearer ${cronSecret}`) {
        res.status(401).json({ error: { code: "UNAUTHORIZED", message: "Invalid cron authorization." } });
        return;
      }
    }
    try {
      const result = await runSweeperTick(db);
      res.json({ ok: true, ...result });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Sweeper tick failed";
      res.status(500).json({ error: { code: "SWEEPER_ERROR", message } });
    }
  });
  app.use("/v1", createV1Router(db));
  app.use("/api/admin", createAdminRouter(db));
  app.use("/v1", (_req, res) => {
    res.status(404).json({ error: { code: "NOT_FOUND", message: "API endpoint not found." } });
  });
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: { code: "NOT_FOUND", message: "Admin API endpoint not found." } });
  });
  return { app, db };
}
async function getSharedSimVaultApp() {
  if (!globalForApp.__simvaultAppPromise) {
    globalForApp.__simvaultAppPromise = createSimVaultApp().catch((err) => {
      globalForApp.__simvaultAppPromise = void 0;
      throw err;
    });
  }
  return globalForApp.__simvaultAppPromise;
}
var globalForApp;
var init_app = __esm({
  "server/app.ts"() {
    init_db();
    init_v1();
    init_admin();
    init_services();
    globalForApp = globalThis;
  }
});

// server/vercel/index.ts
async function handler(req, res) {
  try {
    const { getSharedSimVaultApp: getSharedSimVaultApp2 } = await Promise.resolve().then(() => (init_app(), app_exports));
    const { app } = await getSharedSimVaultApp2();
    const maybeParsedReq = req;
    if (maybeParsedReq.readableEnded && maybeParsedReq.body !== void 0 && maybeParsedReq._body === void 0) {
      maybeParsedReq._body = true;
    }
    await new Promise((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        res.off("finish", done);
        res.off("close", done);
        resolve();
      };
      res.once("finish", done);
      res.once("close", done);
      app(req, res);
    });
  } catch (err) {
    console.error("[SimVault api/index]", err);
    const message = err instanceof Error ? err.message : "Server initialization failed";
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
    }
    if (!res.writableEnded) {
      res.end(
        JSON.stringify({
          error: {
            code: "SERVER_INIT_ERROR",
            message
          }
        })
      );
    }
  }
}
export {
  handler as default
};
