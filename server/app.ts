import express, { Request, Response, NextFunction } from 'express';
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

  // Security headers (Doc 07)
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (req.path.startsWith('/api') || req.path.startsWith('/v1')) {
      res.setHeader('Cache-Control', 'no-store');
    }
    next();
  });

  app.use(express.json({ limit: '64kb' }));

  // Public health endpoint (no secrets)
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
      const message = err instanceof Error ? err.message : 'Database health check failed';
      res.status(503).json({
        status: 'error',
        error: { code: 'DB_UNAVAILABLE', message },
      });
    }
  });

  // Vercel Cron / external scheduled sweeper endpoint
  app.get('/api/cron/sweeper', async (req: Request, res: Response) => {
    const cronSecret = process.env.CRON_SECRET?.trim();
    if (cronSecret) {
      const auth = req.headers.authorization ?? '';
      if (auth !== `Bearer ${cronSecret}`) {
        res.status(401).json({ error: { code: 'UNAUTHORIZED', message: 'Invalid cron authorization.' } });
        return;
      }
    }
    try {
      const result = await runSweeperTick(db);
      res.json({ ok: true, ...result });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Sweeper tick failed';
      res.status(500).json({ error: { code: 'SWEEPER_ERROR', message } });
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
