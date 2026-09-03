import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';
import { checkDatabase, createPool } from './db.mjs';
import { loggerOptions } from './logger.mjs';

export function buildApp(config, { pool = createPool(config) } = {}) {
  const app = Fastify({ logger: loggerOptions(config.logLevel), genReqId: (req) => req.headers[config.requestIdHeader] || randomUUID() });
  app.decorate('db', pool);
  app.get('/health/live', async () => ({ status: 'ok' }));
  app.get('/health/ready', async (_req, reply) => {
    const ready = await checkDatabase(pool);
    if (!ready) return reply.code(503).send({ status: 'not_ready' });
    return { status: 'ok' };
  });
  app.addHook('onClose', async () => { if (pool) await pool.end(); });
  return app;
}
