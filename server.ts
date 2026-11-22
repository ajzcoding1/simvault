import 'dotenv/config';
import express, { Request, Response } from 'express';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { closeDb } from './server/db';
import { createSimVaultApp } from './server/app';
import { runSweeperTick } from './server/services';

async function startServer() {
  const host = process.env.HOST ?? '0.0.0.0';
  const port = Number(process.env.PORT ?? 3000);
  const isProd = process.env.NODE_ENV === 'production';

  const { app, db } = await createSimVaultApp();

  // Background queue sweeper (stale leases, device offline detection, OTP expiry, webhook retries)
  const sweeperTimer = setInterval(() => {
    void runSweeperTick(db).catch(() => {
      // Keep background worker resilient
    });
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
      void closeDb().finally(() => process.exit(0));
    });
    setTimeout(() => {
      void closeDb().finally(() => process.exit(1));
    }, 8000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  httpServer.listen(port, host, () => {
    console.log(`SimVault server (${isProd ? 'production' : 'development'}, db=${db.dialect}) listening on http://${host}:${port}`);
  });
}

startServer();
