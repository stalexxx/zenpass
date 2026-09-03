import { decodeB64, encodeB64 } from "./b64.ts";
import type { ChangePage, Conflict, Device, Id, ItemRecord, Mutation, Session } from "./types.ts";

/** Thrown for any non-2xx HTTP response that isn't handled as a typed
 * result by a specific method (e.g. a 409 Conflict from mutateItem, which
 * is returned as a value, not thrown — see sync-state-machine.ts). */
export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly body: unknown,
  ) {
    super(`HTTP ${status}`);
    this.name = "HttpError";
  }
}

/** Thrown when `fetch` itself fails (offline, DNS, TLS, aborted, etc.) —
 * distinct from HttpError so callers (the sync state machine) can tell a
 * network failure (retryable) apart from a definite server response
 * (not retryable the same way). */
export class NetworkError extends Error {
  constructor(cause: unknown) {
    super("network request failed");
    this.name = "NetworkError";
    this.cause = cause;
  }
}

export interface ApiClientOptions {
  baseUrl: string;
  fetchImpl?: typeof fetch;
}

export interface MutateOutcome {
  status: 201;
  item: ItemRecord;
}
export interface MutateConflictOutcome {
  status: 409;
  conflict: Conflict;
}

/** Typed fetch-based HTTP client over the sync/v1 and auth/v1 API
 * surfaces (`@pass/contracts` request/response shapes). No code
 * generation tool, no HTTP library dependency — platform `fetch` only,
 * per C02's brief. */
export class ApiClient {
  private accessToken: string | null = null;
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: ApiClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  setAccessToken(token: string | null): void {
    this.accessToken = token;
  }

  getAccessToken(): string | null {
    return this.accessToken;
  }

  private async request(
    method: string,
    path: string,
    options: { body?: unknown; auth?: boolean; query?: Record<string, string | undefined> } = {},
  ): Promise<{ status: number; body: unknown }> {
    const auth = options.auth ?? true;
    let url = this.baseUrl + path;
    if (options.query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(options.query)) if (v !== undefined) params.set(k, v);
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }
    const headers: Record<string, string> = {};
    if (options.body !== undefined) headers["content-type"] = "application/json";
    if (auth) {
      if (!this.accessToken) throw new Error("ApiClient: no access token set for an authenticated request");
      headers.authorization = `Bearer ${this.accessToken}`;
    }
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        method,
        headers,
        body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      });
    } catch (e) {
      throw new NetworkError(e);
    }
    if (response.status === 204) return { status: 204, body: undefined };
    const text = await response.text();
    const body = text.length > 0 ? JSON.parse(text) : undefined;
    return { status: response.status, body };
  }

  private async expectOk(
    method: string,
    path: string,
    options?: { body?: unknown; auth?: boolean; query?: Record<string, string | undefined> },
  ): Promise<unknown> {
    const { status, body } = await this.request(method, path, options);
    if (status < 200 || status >= 300) throw new HttpError(status, body);
    return body;
  }

  // --- Auth (OPAQUE two-leg register/login, per docs/contracts/api-v1.md) ---

  async opaqueRegisterStep(accountId: string, clientMessage: Uint8Array): Promise<Uint8Array> {
    const body = (await this.expectOk("POST", "/auth/opaque/register", {
      auth: false,
      body: { accountId, clientMessage: encodeB64(clientMessage) },
    })) as { message: string };
    return decodeB64(body.message);
  }

  /** Login leg 1 and leg 2 return different bodies (OpaqueMessage vs.
   * Session), so this returns a discriminated result rather than always
   * decoding a `message` field. */
  async opaqueLoginStep(
    accountId: string,
    clientMessage: Uint8Array,
  ): Promise<{ kind: "message"; message: Uint8Array } | { kind: "session"; session: Session }> {
    const { status, body } = await this.request("POST", "/auth/opaque/login", {
      auth: false,
      body: { accountId, clientMessage: encodeB64(clientMessage) },
    });
    if (status < 200 || status >= 300) throw new HttpError(status, body);
    const b = body as { message?: string; accessToken?: string; expiresAt?: string };
    if (typeof b.accessToken === "string") {
      return { kind: "session", session: { accessToken: b.accessToken, expiresAt: b.expiresAt! } };
    }
    return { kind: "message", message: decodeB64(b.message!) };
  }

  async refresh(): Promise<Session> {
    return (await this.expectOk("POST", "/auth/refresh")) as Session;
  }

  async logout(): Promise<void> {
    await this.expectOk("POST", "/auth/logout");
    this.accessToken = null;
  }

  // --- Devices ---

  async listDevices(): Promise<Device[]> {
    const body = (await this.expectOk("GET", "/devices")) as { devices: Device[] };
    return body.devices;
  }

  async registerDevice(name: string, publicKey: Uint8Array): Promise<Device> {
    return (await this.expectOk("POST", "/devices", {
      body: { name, publicKey: encodeB64(publicKey) },
    })) as Device;
  }

  async revokeDevice(deviceId: Id): Promise<void> {
    await this.expectOk("POST", `/devices/${encodeURIComponent(deviceId)}/revoke`);
  }

  // --- Sync ---

  /** POSTs one mutation. Returns the created/updated ItemRecord on 201, or
   * the server's Conflict object on 409 — never throws for a 409, since a
   * conflict is an expected, handleable outcome (sync-state-machine.ts
   * relies on this to transition to CONFLICT rather than treating it as a
   * transport failure). Any other non-2xx status still throws HttpError. */
  async mutateItem(vaultId: Id, mutation: Mutation): Promise<MutateOutcome | MutateConflictOutcome> {
    const { status, body } = await this.request("POST", `/vaults/${encodeURIComponent(vaultId)}/items`, {
      body: mutation,
    });
    if (status === 201) return { status: 201, item: body as ItemRecord };
    if (status === 409) return { status: 409, conflict: body as Conflict };
    throw new HttpError(status, body);
  }

  async listChanges(vaultId: Id, cursor?: string, limit?: number): Promise<ChangePage> {
    return (await this.expectOk("GET", `/vaults/${encodeURIComponent(vaultId)}/changes`, {
      query: { cursor, limit: limit !== undefined ? String(limit) : undefined },
    })) as ChangePage;
  }
}
