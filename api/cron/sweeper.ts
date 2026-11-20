import type { IncomingMessage, ServerResponse } from 'node:http';
import { getDb } from '../../server/db';
import { runSweeperTick } from '../../server/services';

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const cronSecret = process.env.CRON_SECRET?.trim();
  if (cronSecret) {
    const auth = req.headers.authorization ?? '';
    if (auth !== `Bearer ${cronSecret}`) {
      res.statusCode = 401;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: { code: 'UNAUTHORIZED', message: 'Invalid cron authorization.' } }));
      return;
    }
  }

  try {
    const db = await getDb();
    const result = await runSweeperTick(db);
    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ ok: true, ...result }));
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Sweeper execution failed';
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: { code: 'SWEEPER_ERROR', message } }));
  }
}
