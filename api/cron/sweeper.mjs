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
var E164_REGEX, ALLOWED_TRANSITIONS, SENSITIVE_KEY_PATTERN;
var init_smsRules = __esm({
  "src/shared/smsRules.ts"() {
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
var db_exports = {};
__export(db_exports, {
  closeDb: () => closeDb,
  convertPlaceholdersToPostgres: () => convertPlaceholdersToPostgres,
  createIsolatedTestDb: () => createIsolatedTestDb,
  getDb: () => getDb,
  resolveDbPath: () => resolveDbPath,
  resolvePostgresUrl: () => resolvePostgresUrl,
  syncEnvAdminCredentials: () => syncEnvAdminCredentials,
  writeAuditLog: () => writeAuditLog
});
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
  const supabaseUrl = stripOuterQuotes(env.SUPABASE_URL || "") || (/^https?:\/\//i.test(candidate) ? candidate : "");
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
    const pgUrl = dbPath === void 0 ? resolvePostgresUrl() : null;
    if (!pgUrl && dbPath === void 0 && rawPgCandidate && /^https?:\/\//i.test(rawPgCandidate)) {
      throw new Error(
        "SUPABASE_DB_URL/DATABASE_URL appears to be an https:// API URL. Either paste the postgresql:// Transaction Pooler URI from Supabase -> Connect, or add SUPABASE_DB_PASSWORD + SUPABASE_DB_REGION (or use SUPABASE_URL)."
      );
    }
    let client;
    if (pgUrl) {
      const connectPostgresClient = async (targetUrl) => {
        let connectionString = targetUrl;
        let useSsl = { rejectUnauthorized: false };
        try {
          const parsed = new URL(targetUrl);
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
          return pgClient;
        } catch (err) {
          await pool.end().catch(() => void 0);
          throw err;
        }
      };
      try {
        client = await connectPostgresClient(pgUrl);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const isTenantNotFound = /tenant.*not found/i.test(msg);
        const hasAws0Pooler = /@aws-0-([a-z0-9-]+)\.pooler\.supabase\.com/i.test(pgUrl);
        if (isTenantNotFound && hasAws0Pooler && !process.env.SUPABASE_DB_POOLER_HOST?.trim()) {
          const aws1Url = pgUrl.replace(/@aws-0-([a-z0-9-]+)\.pooler\.supabase\.com/i, "@aws-1-$1.pooler.supabase.com");
          try {
            client = await connectPostgresClient(aws1Url);
          } catch (retryErr) {
            const retryMsg = retryErr instanceof Error ? retryErr.message : String(retryErr);
            if (/tenant.*not found/i.test(retryMsg)) {
              throw new Error(
                `Supabase pooler returned "${retryMsg}". Either your SUPABASE_DB_REGION does not match the project's actual region, the project is paused, or you should paste the exact Transaction Pooler URI from Supabase Dashboard -> Connect into SUPABASE_DB_URL.`
              );
            }
            throw retryErr;
          }
        } else if (isTenantNotFound) {
          throw new Error(
            `Supabase pooler returned "${msg}". Check Supabase Dashboard -> Connect -> Transaction Pooler for the exact pooler host (aws-0 vs aws-1 & region) and project ref, and paste that URI into SUPABASE_DB_URL.`
          );
        } else if (/ENETUNREACH|EAI_AGAIN|ECONNREFUSED/i.test(msg) && pgUrl.includes(":5432")) {
          throw new Error(
            `Cannot reach Supabase direct port 5432 from this IPv4 serverless environment (${msg}). Set SUPABASE_DB_REGION (e.g. ap-south-1) or paste the port 6543 Transaction Pooler URI into SUPABASE_DB_URL.`
          );
        } else {
          throw err;
        }
      }
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
async function closeDb() {
  const client = dbCache.client;
  dbCache.client = void 0;
  dbCache.initPromise = void 0;
  if (!client) return;
  await client.close();
}
async function createIsolatedTestDb() {
  const { DatabaseSync: SqliteDatabaseSync } = await import("node:sqlite");
  const rawDb = new SqliteDatabaseSync(":memory:");
  rawDb.exec("PRAGMA foreign_keys = ON;");
  const client = new SqliteDbClient(rawDb);
  await migrateSchema(client);
  await seedInitialData(client);
  return client;
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
var services_exports = {};
__export(services_exports, {
  AppError: () => AppError,
  assertPublicWebhookHost: () => assertPublicWebhookHost,
  authenticateApiKey: () => authenticateApiKey,
  authenticateGatewayDevice: () => authenticateGatewayDevice,
  checkIpRateLimit: () => checkIpRateLimit,
  checkLoginRateLimit: () => checkLoginRateLimit,
  clearLoginFailures: () => clearLoginFailures,
  createOtpChallenge: () => createOtpChallenge,
  createSmsRequest: () => createSmsRequest,
  enqueueWebhookEvent: () => enqueueWebhookEvent,
  getSettingsMap: () => getSettingsMap,
  leaseNextGatewayJob: () => leaseNextGatewayJob,
  markJobAcceptedByDevice: () => markJobAcceptedByDevice,
  maybeRunOpportunisticSweep: () => maybeRunOpportunisticSweep,
  recordLoginFailure: () => recordLoginFailure,
  reportDeliveryReceipt: () => reportDeliveryReceipt,
  reportJobResult: () => reportJobResult,
  requireScope: () => requireScope,
  runSweeperTick: () => runSweeperTick,
  updateSetting: () => updateSetting,
  verifyOtpChallenge: () => verifyOtpChallenge
});
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

// server/vercel/sweeper.ts
async function handler(req, res) {
  const cronSecret = process.env.CRON_SECRET?.trim();
  if (cronSecret) {
    const auth = req.headers.authorization ?? "";
    if (auth !== `Bearer ${cronSecret}`) {
      res.statusCode = 401;
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ error: { code: "UNAUTHORIZED", message: "Invalid cron authorization." } }));
      return;
    }
  }
  try {
    const [{ getDb: getDb2 }, { runSweeperTick: runSweeperTick2 }] = await Promise.all([
      Promise.resolve().then(() => (init_db(), db_exports)),
      Promise.resolve().then(() => (init_services(), services_exports))
    ]);
    const db = await getDb2();
    const result = await runSweeperTick2(db);
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ ok: true, ...result }));
  } catch (err) {
    console.error("[SimVault api/cron/sweeper]", err);
    const message = err instanceof Error ? err.message : "Sweeper execution failed";
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.end(JSON.stringify({ error: { code: "SWEEPER_ERROR", message } }));
  }
}
export {
  handler as default
};
