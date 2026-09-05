// Shared test doubles for UI-level tests: a fake OPAQUE client (protocol
// math is already covered by packages/crypto-wasm's and packages/sdk's
// own test suites — these tests are about apps/web's wiring, not OPAQUE
// correctness) and a fake fetch implementing just enough of the
// auth/sync HTTP surface for AuthClient/ApiClient/SyncEngine to complete
// their choreography against, without a live backend.
import type { OpaqueClient } from "@zkpm/sdk";
import { encodeB64 } from "@zkpm/sdk";
import { CryptoWorkerHost, type CryptoBackend } from "../../../../packages/crypto-worker/src/index.ts";
import { createWasmBackend } from "../../../../packages/crypto-worker/src/wasm-adapter.ts";

export const fakeOpaqueClient: OpaqueClient = {
  clientRegistrationStart: () => ({ message: new Uint8Array([1]), state: new Uint8Array([2]) }),
  clientRegistrationFinish: () => ({ message: new Uint8Array([3]) }),
  clientLoginStart: () => ({ message: new Uint8Array([4]), state: new Uint8Array([5]) }),
  clientLoginFinish: () => ({ message: new Uint8Array([6]) }),
};

export interface FakeServerOptions {
  /** When true, all sync (mutate/changes) calls fail as a network error —
   * simulates being offline. */
  offline?: boolean;
  /** Pre-seeds /account/key-bundle as if another device had already
   * published this exact revision, so a test can exercise the 409
   * KeyBundleConflict path (ADR-0011 G1) without a second real client. */
  seedKeyBundle?: { bundle: string; version: number };
  /** Forces publication to return the approved CAS conflict response. */
  forceKeyBundleConflict?: boolean;
}

/** A minimal in-memory fake of the auth+sync HTTP surface. Good enough for
 * AuthClient's two-leg choreography and SyncEngine's push/pull to
 * complete against, without validating real OPAQUE math or persisting
 * anything beyond this test run. */
export function createFakeFetch(options: FakeServerOptions = {}): typeof fetch {
  const items = new Map<string, { itemId: string; vaultId: string; ciphertext: string; envelopeVersion: string; revision: number; deleted: boolean; createdAt: string; updatedAt: string }>();
  let nextRevision = 1;
  const devices = [{ deviceId: "dev1", name: "Test browser", createdAt: new Date().toISOString(), lastSeenAt: new Date().toISOString(), revokedAt: null as string | null }];
  let keyBundle: { bundle: string; version: number } | null = options.seedKeyBundle ?? null;

  return (async (url: string | URL, init?: RequestInit) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;

    if (u.pathname === "/auth/opaque/register" && method === "POST") {
      return json({ message: encodeB64(new Uint8Array([9])) });
    }
    if (u.pathname === "/auth/opaque/login" && method === "POST") {
      // First call carries the fake client's start message; respond with a
      // "message" leg. Second call carries the finish message; respond
      // with a session. We distinguish by the fake client's fixed bytes.
      const clientMessage = body?.clientMessage as string;
      if (clientMessage === encodeB64(new Uint8Array([4]))) {
        return json({ message: encodeB64(new Uint8Array([7])) });
      }
      return json({ accessToken: "fake-access-token", expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
    }
    if (u.pathname === "/devices" && method === "GET") {
      return json({ devices });
    }
    if (/^\/devices\/[^/]+\/revoke$/.test(u.pathname) && method === "POST") {
      const id = u.pathname.split("/")[2];
      const device = devices.find((d) => d.deviceId === id);
      if (device) device.revokedAt = new Date().toISOString();
      return json({});
    }
    if (u.pathname === "/account/key-bundle" && method === "GET") {
      if (!keyBundle) return json({ error: "not_found", message: "no bundle", requestId: "test" }, 404);
      return json(keyBundle);
    }
    if (u.pathname === "/account/key-bundle" && method === "PUT") {
      // Mirrors apps/backend/src/account/store.mjs's CAS rules closely
      // enough for a UI-level test (this is a fake, not a contract-
      // conformance harness — that's apps/backend/test/account's job).
      const attempted = body as { bundle: string; version: number };
      if (options.forceKeyBundleConflict && keyBundle) {
        return json({ error: "key_bundle_conflict", currentVersion: keyBundle.version, attemptedVersion: attempted.version }, 409);
      }
      if (!keyBundle) {
        if (attempted.version !== 1) {
          return json({ error: "key_bundle_conflict", currentVersion: null, attemptedVersion: attempted.version }, 409);
        }
        keyBundle = { bundle: attempted.bundle, version: 1 };
        return new Response(null, { status: 204 });
      }
      if (attempted.version === keyBundle.version) {
        if (attempted.bundle === keyBundle.bundle) return new Response(null, { status: 204 });
        return json(
          { error: "key_bundle_conflict", currentVersion: keyBundle.version, attemptedVersion: attempted.version },
          409,
        );
      }
      if (attempted.version !== keyBundle.version + 1) {
        return json(
          { error: "key_bundle_conflict", currentVersion: keyBundle.version, attemptedVersion: attempted.version },
          409,
        );
      }
      keyBundle = { bundle: attempted.bundle, version: attempted.version };
      return new Response(null, { status: 204 });
    }
    if (/^\/vaults\/[^/]+\/items$/.test(u.pathname) && method === "POST") {
      if (options.offline) return networkFailure();
      const vaultId = decodeURIComponent(u.pathname.split("/")[2]);
      const mutation = body as { mutationId: string; itemId: string; baseRevision: number; ciphertext: string; envelopeVersion: string; deleted: boolean };
      const key = `${vaultId}\0${mutation.itemId}`;
      const existing = items.get(key);
      if (existing && existing.revision !== mutation.baseRevision) {
        return json({ error: "conflict", mutationId: mutation.mutationId, current: existing, attempted: { ...mutation, vaultId } }, 409);
      }
      const now = new Date().toISOString();
      const record = {
        itemId: mutation.itemId, vaultId, ciphertext: mutation.ciphertext, envelopeVersion: mutation.envelopeVersion,
        revision: nextRevision++, deleted: mutation.deleted, createdAt: existing?.createdAt ?? now, updatedAt: now,
      };
      items.set(key, record);
      return json(record, 201);
    }
    if (/^\/vaults\/[^/]+\/changes$/.test(u.pathname) && method === "GET") {
      if (options.offline) return networkFailure();
      const vaultId = decodeURIComponent(u.pathname.split("/")[2]);
      const changes = [...items.values()].filter((i) => i.vaultId === vaultId);
      return json({ changes, nextCursor: null });
    }
    return json({ error: "not_found", message: "no fake route", requestId: "test" }, 404);
  }) as unknown as typeof fetch;

  function json(body: unknown, status = 200): Response {
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }
  function networkFailure(): never {
    throw new TypeError("fetch failed (simulated offline)");
  }
}

class FakeWorker {
  private host: CryptoWorkerHost;
  private listeners = new Map<string, ((event: unknown) => void)[]>();
  constructor(backend: CryptoBackend) { this.host = new CryptoWorkerHost(backend); }
  addEventListener(type: string, listener: (event: unknown) => void): void {
    const list = this.listeners.get(type) ?? []; list.push(listener); this.listeners.set(type, list);
  }
  postMessage(message: unknown): void {
    const cloned = structuredClone(message);
    queueMicrotask(() => {
      const response = this.host.handle(cloned);
      for (const listener of this.listeners.get("message") ?? []) listener({ data: response });
    });
  }
  terminate(): void {}
}

export async function createFakeCryptoWorker(): Promise<Worker> {
  return new FakeWorker(await createWasmBackend()) as unknown as Worker;
}
