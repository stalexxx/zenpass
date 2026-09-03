// OPAQUE server setup (private key + OPRF seed) is process-wide singleton
// secret material, not per-account (ADR-0006 §3).
export function loadOrGenerateServerSetup(config, opaque, { logger } = console) {
  if (config.opaqueServerSetup) {
    return Buffer.from(config.opaqueServerSetup, 'base64');
  }
  if (config.nodeEnv === 'production') {
    throw new Error('OPAQUE_SERVER_SETUP is required in production');
  }
  logger?.warn?.(
    'Generating an ephemeral OPAQUE server setup because OPAQUE_SERVER_SETUP is unset; ' +
      'this is only safe outside production and will not survive a restart.'
  );
  return Buffer.from(opaque.generateServerSetup());
}
