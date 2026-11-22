import type { IncomingMessage, ServerResponse } from 'node:http';
import { constantTimeEquals } from '../crypto';

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const cronSecret = process.env.CRON_SECRET?.trim();
  const isProd = process.env.NODE_ENV === 'production' || Boolean(process.env.VERCEL);

  if (!cronSecret && isProd) {
    res.statusCode = 503;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: { code: 'CRON_SECRET_MISSING', message: 'Cron endpoint requires CRON_SECRET in production.' } }));
    return;
  }

  if (cronSecret) {
    const auth = typeof req.headers.authorization === 'string' ? req.headers.authorization : '';
    if (!constantTimeEquals(auth, `Bearer ${cronSecret}`)) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: { code: 'UNAUTHORIZED', message: 'Invalid cron authorization.' } }));
      return;
    }
  }

  try {
    const [{ getDb }, { runSweeperTick }] = await Promise.all([
      import('../db'),
      import('../services'),
    ]);
    const db = await getDb();
    const result = await runSweeperTick(db);
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ ok: true, ...result }));
  } catch (err) {
    console.error('[SimVault api/cron/sweeper]', err);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: { code: 'SWEEPER_ERROR', message: 'Sweeper execution failed.' } }));
  }
}
