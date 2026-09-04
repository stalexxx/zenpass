import Fastify from 'fastify';
import { randomUUID } from 'node:crypto';
import { checkDatabase, createPool } from './db.mjs';
import { loggerOptions } from './logger.mjs';
import { createAuthContext } from './auth/init.mjs';
import { registerAuthRoutes } from './auth/routes.mjs';
import { registerDeviceRoutes } from './devices/routes.mjs';
import { registerSyncRoutes } from './sync/routes.mjs';

export function buildApp(config, { pool = createPool(config), authContext = createAuthContext(config, { logger: console }) } = {}) {
  const app = Fastify({ logger: loggerOptions(config.logLevel), genReqId: (req) => req.headers[config.requestIdHeader] || randomUUID() });
  const isAllowedWebOrigin = (origin) => typeof origin === 'string' && Boolean(config.webOrigin) && origin === config.webOrigin;
  app.addHook('onRequest', async (request, reply) => {
    const origin = request.headers.origin;
    if (!isAllowedWebOrigin(origin)) return;
    reply.header('Vary', 'Origin');
    reply.header('Access-Control-Allow-Origin', origin);
    reply.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
    reply.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    reply.header('Access-Control-Max-Age', '600');
  });
  app.options('/*', async (request, reply) => {
    if (!isAllowedWebOrigin(request.headers.origin)) return reply.code(404).send();
    return reply.code(204).send();
  });
  app.decorate('db', pool);
  app.get('/health/live', async () => ({ status: 'ok' }));
  app.get('/health/ready', async (_req, reply) => {
    const ready = await checkDatabase(pool);
    if (!ready) return reply.code(503).send({ status: 'not_ready' });
    return { status: 'ok' };
  });
  registerAuthRoutes(app, { pool, ready: authContext.ready, loginStateStore: authContext.loginStateStore, config });
  registerDeviceRoutes(app, { pool });
  registerSyncRoutes(app, { pool });
  app.addHook('onClose', async () => { if (pool) await pool.end(); });
  return app;
}
