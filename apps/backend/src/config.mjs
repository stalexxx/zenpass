const levels = new Set(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']);

function required(name, env) {
  const value = env[name];
  if (!value || !value.trim()) throw new Error(`${name} is required`);
  return value.trim();
}

export function loadConfig(env = process.env) {
  const nodeEnv = env.NODE_ENV || 'development';
  if (!['development', 'test', 'production'].includes(nodeEnv)) {
    throw new Error('NODE_ENV must be development, test, or production');
  }
  const port = Number(env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be 1..65535');
  const logLevel = env.LOG_LEVEL || 'info';
  if (!levels.has(logLevel)) throw new Error(`LOG_LEVEL must be one of ${[...levels].join(', ')}`);
  return Object.freeze({
    nodeEnv,
    host: env.HOST || '127.0.0.1',
    port,
    logLevel,
    databaseUrl: env.DATABASE_URL || (nodeEnv === 'development' ? 'postgres://pass:pass@127.0.0.1:5434/pass' : null),
    databaseSsl: env.DATABASE_SSL === 'true',
    requestIdHeader: 'x-request-id'
  });
}
