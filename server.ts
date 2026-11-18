import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { getDb } from './server/db';
import { createV1Router } from './server/routes/v1';
import { createAdminRouter } from './server/routes/admin';
import { runSweeperTick } from './server/services';

async function startServer() {
  const app = express();
  app.set('trust proxy', 1);
  const port = Number(process.env.PORT ?? 3000);
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
      timestamp: new Date().toISOString(),
      queue_depth: queueRow.count,
      gateway_devices_online: onlineDevices.count,
    });
  });

  // Public v1 Application & Gateway Device APIs
  app.use('/v1', createV1Router(db));

  // Owner Dashboard APIs
  app.use('/api/admin', createAdminRouter(db));

  // Background queue sweeper (stale leases, device offline detection, OTP expiry, webhook retries)
  setInterval(() => {
    try {
      runSweeperTick(db);
    } catch {
      // Keep background worker resilient
    }
  }, 2500);

  const httpServer = http.createServer(app);

  if (process.env.NODE_ENV !== 'production') {
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
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req: Request, res: Response) => {
        res.sendFile(path.join(distPath, 'index.html'));
      });
    }
  }

  httpServer.listen(port, '0.0.0.0', () => {
    console.log(`SimVault server listening on http://0.0.0.0:${port}`);
  });
}

startServer();
