// Thin seam between the SDK's HTTP register/login choreography (ADR-0007
// §3: "the SDK owns the actual register/login HTTP choreography [...];
// packages/crypto-wasm only ever returns/consumes protocol message bytes
// and opaque state bytes, never makes an HTTP call itself") and the
// concrete WASM binding. Defined as an interface, not a direct
// `packages/crypto-wasm` import inside AuthClient, so tests can supply a
// lightweight fake and only the one integration test needs a real WASM
// build.

export interface OpaqueStartResult {
  message: Uint8Array;
  state: Uint8Array;
}

export interface OpaqueFinishResult {
  message: Uint8Array;
}

export interface OpaqueClient {
  clientRegistrationStart(password: Uint8Array): OpaqueStartResult;
  clientRegistrationFinish(
    state: Uint8Array,
    password: Uint8Array,
    response: Uint8Array,
  ): OpaqueFinishResult;
  clientLoginStart(password: Uint8Array): OpaqueStartResult;
  clientLoginFinish(
    state: Uint8Array,
    password: Uint8Array,
    response: Uint8Array,
    context: Uint8Array,
  ): OpaqueFinishResult;
}

/** The fixed OPAQUE application-context bytes the real backend uses
 * (`OPAQUE_CONTEXT` in `apps/backend/src/auth/routes.mjs`). Login fails
 * generically against the real server if any other bytes are used. */
export const OPAQUE_CONTEXT = new TextEncoder().encode("zkpm-opaque-v1");

/** Loads the production OpaqueClient backed by `packages/crypto-wasm`'s
 * generated browser WASM module (ADR-0007). Callers must `await` this
 * before use; it calls the module's `init()` internally. Not used by unit
 * tests that supply a fake OpaqueClient — only by the real end-to-end
 * integration test and by real client applications (e.g. C01). */
export async function createWasmOpaqueClient(): Promise<OpaqueClient> {
  const mod = await import("crypto-wasm");
  await mod.default();
  return {
    clientRegistrationStart: (password) => mod.client_registration_start(password) as OpaqueStartResult,
    clientRegistrationFinish: (state, password, response) =>
      mod.client_registration_finish(state, password, response) as OpaqueFinishResult,
    clientLoginStart: (password) => mod.client_login_start(password) as OpaqueStartResult,
    clientLoginFinish: (state, password, response, context) =>
      mod.client_login_finish(state, password, response, context) as OpaqueFinishResult,
  };
}
