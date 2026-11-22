import express, { Request, Response, NextFunction } from 'express';
import { constantTimeEquals } from './crypto';
import { DbClient, getDb } from './db';
import { createV1Router } from './routes/v1';
import { createAdminRouter } from './routes/admin';
import { runSweeperTick } from './services';

export interface SimVaultAppContext {
  app: express.Express;
  db: DbClient;
}

export async function createSimVaultApp(existingDb?: DbClient): Promise<SimVaultAppContext> {
  const db = existingDb ?? (await getDb());
  const app = express();
  const isProd = process.env.NODE_ENV === 'production';

  app.set('trust proxy', 1);
  app.disable('x-powered-by');

<<<<<<< HEAD
  // Security headers and Content-Security-Policy
=======
  // Security headers (Doc 07 + CSP compatible with AI Studio iframe preview)
>>>>>>> 359d427a6db7954a6e13a960bc672ab4f7639089
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-DNS-Prefetch-Control', 'off');
    res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (isProd) {
      res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'"
      );
    }
    const xfProto = req.headers['x-forwarded-proto'];
    if (req.secure || (typeof xfProto === 'string' && xfProto.split(',')[0].trim() === 'https')) {
      res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    if (req.path.startsWith('/api') || req.path.startsWith('/v1')) {
      res.setHeader('Cache-Control', 'no-store');
    }
    next();
  });

  app.use(express.json({ limit: '64kb' }));
  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (err && typeof err === 'object' && 'type' in err && (err as { type?: string }).type === 'entity.parse.failed') {
      if (req.path.startsWith('/v1') || req.path.startsWith('/api')) {
        res.status(400).json({
          error: {
            code: 'INVALID_JSON',
            message: 'Request body must be valid JSON with Content-Type: application/json.',
          },
        });
        return;
      }
    }
    next(err);
  });

  // Public health endpoint (no secrets or raw DB error details)
  app.get('/health', async (_req: Request, res: Response) => {
    try {
      const queueRow = await db.get<{ count: number | string }>(
        "SELECT COUNT(*) as count FROM messages WHERE status IN ('created', 'queued', 'leased', 'accepted_by_device')"
      );
      const onlineDevices = await db.get<{ count: number | string }>(
        "SELECT COUNT(*) as count FROM gateway_devices WHERE status = 'online'"
      );
      res.json({
        status: 'ok',
        version: '1.0.0',
        mode: isProd ? 'production' : 'development',
        database: db.dialect,
        uptime_seconds: Math.floor(process.uptime()),
        timestamp: new Date().toISOString(),
        queue_depth: Number(queueRow?.count ?? 0),
        gateway_devices_online: Number(onlineDevices?.count ?? 0),
      });
    } catch (err) {
      console.error('[SimVault /health]', err);
      res.status(503).json({
        status: 'error',
        error: { code: 'DB_UNAVAILABLE', message: 'Database health check failed.' },
      });
    }
  });

  // Vercel Cron / external scheduled sweeper endpoint (fail-closed in production when CRON_SECRET missing)
  app.get('/api/cron/sweeper', async (req: Request, res: Response) => {
    const cronSecret = process.env.CRON_SECRET?.trim();
    if (!cronSecret && (isProd || Boolean(process.env.VERCEL))) {
      res.status(503).json({ error: { code: 'CRON_SECRET_MISSING', message: 'Cron endpoint requires CRON_SECRET in production.' } });
      return;
    }
    if (cronSecret) {
      const auth = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
      if (!constantTimeEquals(auth, `Bearer ${cronSecret}`)) {
        res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid cron authorization.' } });
        return;
      }
    }
    try {
      const result = await runSweeperTick(db);
      res.json({ ok: true, ...result });
    } catch (err) {
      console.error('[SimVault /api/cron/sweeper]', err);
      res.status(500).json({ error: { code: 'SWEEPER_ERROR', message: 'Sweeper tick failed.' } });
    }
  });

  // Public v1 Application & Gateway Device APIs
  app.use('/v1', createV1Router(db));

  // Owner Dashboard APIs
  app.use('/api/admin', createAdminRouter(db));

  // Return structured JSON 404 for unknown API/gateway routes instead of HTML fallback
  app.use('/v1', (_req: Request, res: Response) => {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'API endpoint not found.' } });
  });
  app.use('/api', (_req: Request, res: Response) => {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Admin API endpoint not found.' } });
  });

  app.use((err: unknown, req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/v1') || req.path.startsWith('/api')) {
      console.error('[SimVault API error]', err);
      res.status(500).json({
        error: {
          code: 'INTERNAL_ERROR',
          message: 'An unexpected server error occurred.',
        },
      });
      return;
    }
    next(err);
  });

  return { app, db };
}

const globalForApp = globalThis as typeof globalThis & { __simvaultAppPromise?: Promise<SimVaultAppContext> };

export async function getSharedSimVaultApp(): Promise<SimVaultAppContext> {
  if (!globalForApp.__simvaultAppPromise) {
    globalForApp.__simvaultAppPromise = createSimVaultApp().catch((err) => {
      globalForApp.__simvaultAppPromise = undefined;
      throw err;
    });
  }
  return globalForApp.__simvaultAppPromise;
}
