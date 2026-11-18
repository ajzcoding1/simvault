import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { closeDb, getDb } from './server/db';
import { createV1Router } from './server/routes/v1';
import { createAdminRouter } from './server/routes/admin';
import { runSweeperTick } from './server/services';

async function startServer() {
  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  const host = process.env.HOST ?? '0.0.0.0';
  const port = Number(process.env.PORT ?? 3000);
  const isProd = process.env.NODE_ENV === 'production';
  const db = getDb();

  // Security headers (Doc 07)
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (req.path.startsWith('/api') || req.path.startsWith('/v1')) {
      res.setHeader('Cache-Control', 'no-store');
    }
    next();
  });

  app.use(express.json({ limit: '64kb' }));

  // Public health endpoint (no secrets)
  app.get('/health', (_req: Request, res: Response) => {
    const queueRow = db
      .prepare("SELECT COUNT(*) as count FROM messages WHERE status IN ('created', 'queued', 'leased', 'accepted_by_device')")
      .get() as { count: number };
    const onlineDevices = db
      .prepare("SELECT COUNT(*) as count FROM gateway_devices WHERE status = 'online'")
      .get() as { count: number };
    res.json({
      status: 'ok',
      version: '1.0.0',
      mode: isProd ? 'production' : 'development',
      uptime_seconds: Math.floor(process.uptime()),
      timestamp: new Date().toISOString(),
      queue_depth: queueRow.count,
      gateway_devices_online: onlineDevices.count,
    });
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

  // Background queue sweeper (stale leases, device offline detection, OTP expiry, webhook retries)
  const sweeperTimer = setInterval(() => {
    try {
      runSweeperTick(db);
    } catch {
      // Keep background worker resilient
    }
  }, 2500);
  sweeperTimer.unref();

  const httpServer = http.createServer(app);

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        ws: { server: httpServer },
        hmr: process.env.DISABLE_HMR === 'true' ? false : { server: httpServer },
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(process.cwd(), 'dist');
    if (!fs.existsSync(path.join(distPath, 'index.html'))) {
      console.error('Production build missing in ./dist. Run "npm run build" before starting in production mode.');
      process.exit(1);
    }

    app.use(
      express.static(distPath, {
        index: false,
        setHeaders: (res, filePath) => {
          if (filePath.includes(`${path.sep}assets${path.sep}`)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
          } else {
            res.setHeader('Cache-Control', 'no-cache');
          }
        },
      })
    );

    app.get('*', (_req: Request, res: Response) => {
      res.setHeader('Cache-Control', 'no-cache');
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  let shuttingDown = false;
  const shutdown = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`Received ${signal}, shutting down SimVault gracefully...`);
    clearInterval(sweeperTimer);
    httpServer.close(() => {
      closeDb();
      process.exit(0);
    });
    setTimeout(() => {
      closeDb();
      process.exit(1);
    }, 8000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  httpServer.listen(port, host, () => {
    console.log(`SimVault server (${isProd ? 'production' : 'development'}) listening on http://${host}:${port}`);
  });
}

startServer();
