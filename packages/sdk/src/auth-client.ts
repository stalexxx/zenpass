import type { ApiClient } from "./http-client.ts";
import { OPAQUE_CONTEXT, type OpaqueClient } from "./opaque-client.ts";
import type { Session } from "./types.ts";

/** Drives the two-leg OPAQUE register/login HTTP choreography (ADR-0006
 * §4, ADR-0007 §3) against an ApiClient, using an injected OpaqueClient
 * for the actual protocol math. On a successful login, the returned
 * session's access token is also set on the ApiClient so subsequent
 * authenticated calls (device registration, mutate, changes) work
 * immediately. */
export class AuthClient {
  constructor(
    private readonly api: ApiClient,
    private readonly opaque: OpaqueClient,
  ) {}

  /** Registers a new account's OPAQUE credential. `password` should be
   * zeroized by the caller after this resolves; the WASM binding zeroizes
   * its own copy on the Rust side but cannot reach across the JS/WASM
   * boundary to wipe the caller's buffer. */
  async register(accountId: string, password: Uint8Array): Promise<void> {
    const start = this.opaque.clientRegistrationStart(password);
    const response = await this.api.opaqueRegisterStep(accountId, start.message);
    const finish = this.opaque.clientRegistrationFinish(start.state, password, response);
    // Second leg's response body is a fixed, non-secret acknowledgement
    // (docs/contracts/api-v1.md / apps/backend REGISTRATION_ACK) — nothing
    // further to do with it.
    await this.api.opaqueRegisterStep(accountId, finish.message);
  }

  /** Logs in against an existing OPAQUE credential and sets the resulting
   * session's access token on the underlying ApiClient. */
  async login(accountId: string, password: Uint8Array): Promise<Session> {
    const start = this.opaque.clientLoginStart(password);
    const leg1 = await this.api.opaqueLoginStep(accountId, start.message);
    if (leg1.kind !== "message") {
      throw new Error("unexpected session response on OPAQUE login leg 1");
    }
    const finish = this.opaque.clientLoginFinish(start.state, password, leg1.message, OPAQUE_CONTEXT);
    const leg2 = await this.api.opaqueLoginStep(accountId, finish.message);
    if (leg2.kind !== "session") {
      throw new Error("unexpected message response on OPAQUE login leg 2");
    }
    this.api.setAccessToken(leg2.session.accessToken);
    return leg2.session;
  }
}
