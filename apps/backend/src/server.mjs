import { buildApp } from './app.mjs';
import { loadConfig } from './config.mjs';

const config = loadConfig();
const app = buildApp(config);
try {
  await app.listen({ host: config.host, port: config.port });
} catch (error) {
  app.log.error({ err: error }, 'server startup failed');
  process.exitCode = 1;
}
