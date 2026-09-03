import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';
import { checkDatabase, createPool } from './db.mjs';
import { loggerOptions } from './logger.mjs';
import { createAuthContext } from './auth/init.mjs';
import { registerAuthRoutes } from './auth/routes.mjs';
import { registerDeviceRoutes } from './devices/routes.mjs';

export function buildApp(config, { pool = createPool(config), authContext = createAuthContext(config, { logger: console }) } = {}) {
  const app = Fastify({ logger: loggerOptions(config.logLevel), genReqId: (req) => req.headers[config.requestIdHeader] || randomUUID() });
  app.decorate('db', pool);
  app.get('/health/live', async () => ({ status: 'ok' }));
  app.get('/health/ready', async (_req, reply) => {
    const ready = await checkDatabase(pool);
    if (!ready) return reply.code(503).send({ status: 'not_ready' });
    return { status: 'ok' };
  });
  registerAuthRoutes(app, { pool, ready: authContext.ready, loginStateStore: authContext.loginStateStore, config });
  registerDeviceRoutes(app, { pool });
  app.addHook('onClose', async () => { if (pool) await pool.end(); });
  return app;
}
