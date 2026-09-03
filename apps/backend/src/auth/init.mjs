import { loadOpaqueBinding } from './opaque-binding.mjs';
import { loadOrGenerateServerSetup } from './server-setup.mjs';
import { createLoginStateStore } from './login-state.mjs';

/**
 * Builds the auth module's runtime context. WASM init and server-setup
 * loading are deferred behind `ready` so `buildApp` itself can stay
 * synchronous (route registration is sync; only the first request per
 * process actually awaits `ready`).
 */
export function createAuthContext(config, { logger, opaque: injectedOpaque } = {}) {
  const ready = (injectedOpaque ? Promise.resolve(injectedOpaque) : loadOpaqueBinding()).then((opaque) => ({
    opaque,
    serverSetup: loadOrGenerateServerSetup(config, opaque, { logger })
  }));
  return { ready, loginStateStore: createLoginStateStore() };
}
