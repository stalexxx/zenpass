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
    // Development-only, exact-origin CORS allowlist for the separately
    // served local web bundle. Production must opt in explicitly; never use
    // a wildcard origin for a bearer-token API.
    webOrigin: env.WEB_ORIGIN || (nodeEnv === 'development' ? 'http://127.0.0.1:4173' : null),
    requestIdHeader: 'x-request-id',
    // ADR-0006 §3: process-wide OPAQUE server setup, base64. Required in
    // production; auto-generated ephemerally otherwise.
    opaqueServerSetup: env.OPAQUE_SERVER_SETUP || null,
    // ADR-0006 §7 / ADR-0005 §1: short-lived session lifetime.
    sessionTtlSeconds: Number(env.SESSION_TTL_SECONDS || 900),
    // ADR-0005 §3: durable fixed-window login-throttling parameters.
    authRateLimitMax: Number(env.AUTH_RATE_LIMIT_MAX || 10),
    authRateLimitWindowSeconds: Number(env.AUTH_RATE_LIMIT_WINDOW_SECONDS || 300)
  });
}
