import type { IncomingMessage, ServerResponse } from 'node:http';

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const { getSharedSimVaultApp } = await import('../server/app');
    const { app } = await getSharedSimVaultApp();

    // If the serverless runtime already parsed req.body and ended the stream, tell body-parser not to hang
    const maybeParsedReq = req as IncomingMessage & { body?: unknown; _body?: boolean; readableEnded?: boolean };
    if (maybeParsedReq.readableEnded && maybeParsedReq.body !== undefined && maybeParsedReq._body === undefined) {
      maybeParsedReq._body = true;
    }

    await new Promise<void>((resolve) => {
      let settled = false;
      const done = () => {
        if (settled) return;
        settled = true;
        res.off('finish', done);
        res.off('close', done);
        resolve();
      };
      res.once('finish', done);
      res.once('close', done);
      app(req, res);
    });
  } catch (err) {
    console.error('[SimVault api/index]', err);
    const message = err instanceof Error ? err.message : 'Server initialization failed';
    if (!res.headersSent) {
      res.statusCode = 500;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
    }
    if (!res.writableEnded) {
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
}
