import type { IncomingMessage, ServerResponse } from 'node:http';
import { getSharedSimVaultApp } from '../server/app';

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const { app } = await getSharedSimVaultApp();
    app(req, res);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Server initialization failed';
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(
      JSON.stringify({
        error: {
          code: 'SERVER_INIT_ERROR',
          message,
        },
      })
    );
  }
}
