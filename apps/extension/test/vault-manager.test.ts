import { describe, expect, test } from "bun:test";
import { ApiClient, buildAccountBundle, encodeB64, type ApiClientOptions } from "../../../packages/sdk/src/index.ts";
import type { CryptoBackend } from "../../../packages/crypto-worker/src/index.ts";
import type { OpaqueClient } from "../../../packages/sdk/src/opaque-client.ts";
import { ExtensionVaultManager, type VaultManagerDeps } from "../src/vault-manager.ts";

const ACCOUNT_ID = "acct_1";
const VAULT_ID = "vault_1";
const WRAP_ITEM_ID = "item_wrap";
const ORIGIN = "https://api.example.test";

function jsonResponse(status: number, body?: unknown): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), { status });
}

const fakeOpaque: OpaqueClient = {
  clientRegistrationStart: () => ({ message: new Uint8Array([1]), state: new Uint8Array([2]) }),
  clientRegistrationFinish: () => ({ message: new Uint8Array([3]) }),
  clientLoginStart: () => ({ message: new Uint8Array([4]), state: new Uint8Array([5]) }),
  clientLoginFinish: () => ({ message: new Uint8Array([6]) }),
};

/** Fake CryptoBackend: `seal`/`open` are identity functions (no real
 * encryption) — business-logic tests below only need round-tripping, not
 * cryptographic correctness (that's covered by crypto-wasm's own tests and
 * the real-browser E2E). `unlockItemSession` always succeeds; nothing here
 * validates wrapped-key bytes. */
function fakeCryptoBackend(): CryptoBackend {
  let nextSession = 1;
  return {
    unlockItemSession: () => nextSession++,
    createAccountSetup: () => { throw new Error("unused"); },
    unlockItemSessionWithRecovery: () => { throw new Error("unused"); },
    sealItemPayload: (_s, _a, _v, _i, _k, plaintext) => plaintext,
    openItemPayload: (_s, _a, _v, _i, _k, envelope) => envelope,
    inspectEnvelope: () => { throw new Error("unused"); },
    closeSession: () => {},
  };
}

function goodBundle(): string {
  return buildAccountBundle({
    accountId: ACCOUNT_ID,
    vaultId: VAULT_ID,
    itemId: WRAP_ITEM_ID,
    kdfParametersCbor: new Uint8Array([9, 9]),
    wrappedAccountKey: new Uint8Array([1]),
    wrappedVaultKey: new Uint8Array([2]),
    wrappedItemKey: new Uint8Array([3]),
    wrappedRecoveryKey: new Uint8Array([4]),
  });
}

interface FakeServerOptions {
  bundle?: string | null;
  changes?: { itemId: string; ciphertext: string; revision: number; deleted?: boolean }[];
  loginSucceeds?: boolean;
  deviceEnrollFails?: boolean;
  mutateResponder?: () => Response;
  listDevicesResponder?: () => Response;
  refreshResponder?: () => Response;
  logoutResponder?: () => Response;
}

function fakeServer(options: FakeServerOptions = {}) {
  const calls: string[] = [];
  let loginCallCount = 0;
  const changes = options.changes ?? [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
    const path = url.pathname;
    const method = (init?.method ?? "GET").toUpperCase();
    calls.push(`${method} ${path}`);
    if (path === "/auth/opaque/login") {
      // A login is always exactly two consecutive POSTs: leg 1 (expects a
      // `message` response), then leg 2. Parity survives across separate
      // unlock() calls sharing this same fake server.
      loginCallCount += 1;
      if (loginCallCount % 2 === 1) return jsonResponse(200, { message: encodeB64(new Uint8Array([7])) });
      if (options.loginSucceeds === false) return jsonResponse(200, { message: encodeB64(new Uint8Array([8])) }); // no accessToken: AuthClient.login throws
      return jsonResponse(200, { accessToken: "token-1", expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
    }
    if (path === "/devices" && method === "GET") {
      return options.listDevicesResponder ? options.listDevicesResponder() : jsonResponse(200, { devices: [] });
    }
    if (path === "/devices" && method === "POST") {
      if (options.deviceEnrollFails) return jsonResponse(400, { error: "bad_request", message: "x", requestId: "r" });
      return jsonResponse(201, { deviceId: "dev_1", name: "test", createdAt: new Date().toISOString(), lastSeenAt: null, revokedAt: null });
    }
    if (path === "/account/key-bundle") {
      if (options.bundle === null) return jsonResponse(404);
      return jsonResponse(200, { bundle: options.bundle ?? goodBundle(), version: 1 });
    }
    if (path.endsWith("/changes")) {
      return jsonResponse(200, { changes, nextCursor: null });
    }
    if (path.endsWith("/items")) {
      return options.mutateResponder ? options.mutateResponder() : jsonResponse(201, {
        itemId: "item-created", vaultId: VAULT_ID, ciphertext: "b64:AA==", envelopeVersion: "crypto-envelope/v1",
        revision: 1, deleted: false, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
      });
    }
    if (path === "/auth/refresh") {
      return options.refreshResponder ? options.refreshResponder() : jsonResponse(200, { accessToken: "token-2", expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
    }
    if (path === "/auth/logout") {
      return options.logoutResponder ? options.logoutResponder() : jsonResponse(204);
    }
    return jsonResponse(404, { error: "not_found", message: "x", requestId: "r" });
  };
  return { fetchImpl, calls };
}

function deps(overrides: Partial<VaultManagerDeps> & { server?: ReturnType<typeof fakeServer> } = {}): VaultManagerDeps {
  const server = overrides.server ?? fakeServer();
  return {
    deviceName: "test device",
    now: overrides.now,
    createApiClient: overrides.createApiClient ?? ((options: ApiClientOptions) => new ApiClient({ baseUrl: options.baseUrl, fetchImpl: server.fetchImpl })),
    createOpaqueClient: overrides.createOpaqueClient ?? (async () => fakeOpaque),
    createCryptoBackend: overrides.createCryptoBackend ?? (async () => fakeCryptoBackend()),
    onAuthFailure: overrides.onAuthFailure,
  };
}

function pw(): Uint8Array {
  return new TextEncoder().encode("hunter2");
}

describe("ExtensionVaultManager.unlock", () => {
  test("succeeds against a valid bundle and loads items into memory", async () => {
    const ciphertext = encodeB64(new TextEncoder().encode(JSON.stringify({ type: "login", title: "Example", username: "alice", password: "s3cr3t", url: "https://example.test" })));
    const server = fakeServer({ changes: [{ itemId: "item-1", ciphertext, revision: 1 }] });
    const manager = new ExtensionVaultManager(deps({ server }));
    const result = await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    expect(result).toEqual({ ok: true });
    expect(manager.isUnlocked()).toBe(true);
    expect(manager.listItems()).toEqual([{ itemId: "item-1", title: "Example", type: "login", username: "alice", url: "https://example.test" }]);
    expect(manager.candidatesFor("https://example.test")).toEqual([{ id: "item-1", title: "Example", origin: "https://example.test" }]);
    expect(manager.candidatesFor("https://other.test")).toEqual([]);
    const fields = await manager.fieldsFor("item-1", "https://example.test");
    expect(fields).toEqual({ username: "alice", password: "s3cr3t" });
  });

  test("zeroes the caller's password buffer", async () => {
    const manager = new ExtensionVaultManager(deps());
    const password = pw();
    await manager.unlock(ACCOUNT_ID, ORIGIN, password);
    expect([...password].every((b) => b === 0)).toBe(true);
  });

  test("a failed OPAQUE login fails generically and leaves no partial state", async () => {
    const server = fakeServer({ loginSucceeds: false });
    const manager = new ExtensionVaultManager(deps({ server }));
    const result = await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    expect(result).toEqual({ ok: false, reason: "unlock-failed" });
    expect(manager.isUnlocked()).toBe(false);
    expect(manager.listItems()).toEqual([]);
  });

  test("a missing key bundle (404) fails the unlock", async () => {
    const server = fakeServer({ bundle: null });
    const manager = new ExtensionVaultManager(deps({ server }));
    expect(await manager.unlock(ACCOUNT_ID, ORIGIN, pw())).toEqual({ ok: false, reason: "unlock-failed" });
  });

  test("a device-enrollment failure fails the whole unlock (fail-closed, not best-effort)", async () => {
    const server = fakeServer({ deviceEnrollFails: true });
    const manager = new ExtensionVaultManager(deps({ server }));
    expect(await manager.unlock(ACCOUNT_ID, ORIGIN, pw())).toEqual({ ok: false, reason: "unlock-failed" });
    expect(manager.isUnlocked()).toBe(false);
  });

  test("a bundle whose accountId does not match the login account fails closed", async () => {
    const mismatched = buildAccountBundle({
      accountId: "other_account", vaultId: VAULT_ID, itemId: WRAP_ITEM_ID,
      kdfParametersCbor: new Uint8Array([1]), wrappedAccountKey: new Uint8Array([1]),
      wrappedVaultKey: new Uint8Array([1]), wrappedItemKey: new Uint8Array([1]), wrappedRecoveryKey: new Uint8Array([1]),
    });
    const server = fakeServer({ bundle: mismatched });
    const manager = new ExtensionVaultManager(deps({ server }));
    expect(await manager.unlock(ACCOUNT_ID, ORIGIN, pw())).toEqual({ ok: false, reason: "unlock-failed" });
  });

  test("an unconfirmable API origin fails before any network call", async () => {
    const server = fakeServer();
    const manager = new ExtensionVaultManager(deps({ server }));
    const result = await manager.unlock(ACCOUNT_ID, "http://api.example.test", pw());
    expect(result).toEqual({ ok: false, reason: "unlock-failed" });
    expect(server.calls).toHaveLength(0);
  });

  test("a failed re-unlock does not resurrect the previous account's state", async () => {
    const goodServer = fakeServer();
    const manager = new ExtensionVaultManager(deps({
      server: goodServer,
      createApiClient: undefined,
      createOpaqueClient: async () => fakeOpaque,
      createCryptoBackend: async () => fakeCryptoBackend(),
    }));
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    expect(manager.isUnlocked()).toBe(true);

    let useFailingOpaque = false;
    const failingOpaque: OpaqueClient = {
      ...fakeOpaque,
      clientLoginFinish: () => { throw new Error("simulated bad password"); },
    };
    const managerWithSwappableOpaque = new ExtensionVaultManager({
      deviceName: "test device",
      createApiClient: (options) => new ApiClient({ baseUrl: options.baseUrl, fetchImpl: goodServer.fetchImpl }),
      createOpaqueClient: async () => (useFailingOpaque ? failingOpaque : fakeOpaque),
      createCryptoBackend: async () => fakeCryptoBackend(),
    });
    expect(await managerWithSwappableOpaque.unlock(ACCOUNT_ID, ORIGIN, pw())).toEqual({ ok: true });
    useFailingOpaque = true;
    expect(await managerWithSwappableOpaque.unlock(ACCOUNT_ID, ORIGIN, pw())).toEqual({ ok: false, reason: "unlock-failed" });
    expect(managerWithSwappableOpaque.isUnlocked()).toBe(false);
    expect(managerWithSwappableOpaque.listItems()).toEqual([]);
  });
});

describe("ExtensionVaultManager empty vault (T07/T09)", () => {
  test("a brand-new vault with no items yet (GET /changes 404) unlocks correctly, not as a failure", async () => {
    const server = fakeServer({ changes: [] });
    // Override the /changes route to actually return 404, matching the
    // real backend's behavior for a vault that has never had an item
    // created (it only auto-creates the vault row on first mutation).
    const originalFetch = server.fetchImpl;
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      if (url.pathname.endsWith("/changes")) return jsonResponse(404, { error: "not_found", message: "x", requestId: "r" });
      return originalFetch(input, init);
    };
    const manager = new ExtensionVaultManager(deps({
      createApiClient: (options) => new ApiClient({ baseUrl: options.baseUrl, fetchImpl }),
    }));
    const result = await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    expect(result).toEqual({ ok: true });
    expect(manager.isUnlocked()).toBe(true);
    expect(manager.listItems()).toEqual([]);
  });
});

describe("ExtensionVaultManager pagination termination (regression)", () => {
  test("a page with no new changes terminates the load, even though the real backend echoes back a non-null nextCursor on an empty page", async () => {
    // apps/backend/src/sync/routes.mjs's GET /vaults/:id/changes returns
    // `cursor ?? encodeCursor(0)` (i.e. the *same* cursor it was given,
    // never null) when a page has no new rows — only a vault that has
    // *never* had any change returns 404. A loop that treats "nextCursor is
    // truthy" as "keep paging" therefore never terminates once any item
    // has ever existed; this fixture reproduces exactly that shape and
    // bounds the call count to fail fast instead of hanging if it regresses.
    let calls = 0;
    const fetchImpl: typeof fetch = async (input, init) => {
      const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.pathname === "/auth/opaque/login") {
        calls += 1;
        if (calls % 2 === 1) return jsonResponse(200, { message: encodeB64(new Uint8Array([7])) });
        return jsonResponse(200, { accessToken: "t", expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
      }
      if (url.pathname === "/devices" && method === "POST") {
        return jsonResponse(201, { deviceId: "d", name: "n", createdAt: new Date().toISOString(), lastSeenAt: null, revokedAt: null });
      }
      if (url.pathname === "/account/key-bundle") return jsonResponse(200, { bundle: goodBundle(), version: 1 });
      if (url.pathname.endsWith("/changes")) {
        calls += 1;
        if (calls > 6) throw new Error("pagination did not terminate (regression: infinite loop)");
        const cursor = url.searchParams.get("cursor");
        if (cursor === null) {
          const ciphertext = encodeB64(new TextEncoder().encode(JSON.stringify({ type: "note", title: "Only item" })));
          return jsonResponse(200, { changes: [{ itemId: "item-1", vaultId: VAULT_ID, ciphertext, envelopeVersion: "crypto-envelope/v1", revision: 1, deleted: false, createdAt: "x", updatedAt: "x" }], nextCursor: "c1" });
        }
        // Real backend behavior: an empty page still echoes the same,
        // non-null cursor back.
        return jsonResponse(200, { changes: [], nextCursor: cursor });
      }
      return jsonResponse(404, { error: "not_found", message: "x", requestId: "r" });
    };
    const manager = new ExtensionVaultManager({
      deviceName: "test",
      createApiClient: (options) => new ApiClient({ baseUrl: options.baseUrl, fetchImpl }),
      createOpaqueClient: async () => fakeOpaque,
      createCryptoBackend: async () => fakeCryptoBackend(),
    });
    const result = await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    expect(result).toEqual({ ok: true });
    expect(manager.listItems()).toEqual([{ itemId: "item-1", title: "Only item", type: "note", username: undefined, url: undefined }]);
  });
});

describe("ExtensionVaultManager.saveItem", () => {
  test("creates a new item and reflects it in listItems/candidatesFor", async () => {
    const manager = new ExtensionVaultManager(deps());
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    const result = await manager.saveItem({ title: "New", itemType: "login", username: "bob", password: "p", url: "https://new.test" });
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(manager.listItems().some((i) => i.itemId === result.itemId && i.title === "New")).toBe(true);
  });

  test("rejects invalid item data locally, before any network call", async () => {
    const server = fakeServer();
    const manager = new ExtensionVaultManager(deps({ server }));
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    const before = server.calls.length;
    const result = await manager.saveItem({ title: "", itemType: "note" });
    expect(result).toEqual({ ok: false, reason: "validation", problems: ["Title is required."] });
    expect(server.calls.length).toBe(before);
  });

  test("surfaces a server conflict distinctly from success", async () => {
    const server = fakeServer({
      mutateResponder: () => new Response(JSON.stringify({ error: "conflict", mutationId: "m1", current: {}, attempted: {} }), { status: 409 }),
    });
    const manager = new ExtensionVaultManager(deps({ server }));
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    const result = await manager.saveItem({ title: "X", itemType: "note" });
    expect(result).toEqual({ ok: false, reason: "conflict" });
  });

  test("refuses to save while locked", async () => {
    const manager = new ExtensionVaultManager(deps());
    const result = await manager.saveItem({ title: "X", itemType: "note" });
    expect(result).toEqual({ ok: false, reason: "locked" });
  });
});

describe("ExtensionVaultManager TOTP", () => {
  test("getTotp returns a code and countdown for a totp-login item", async () => {
    const ciphertext = encodeB64(new TextEncoder().encode(JSON.stringify({ type: "totp-login", title: "GH", username: "a", password: "p", totpSecret: "JBSWY3DPEHPK3PXP" })));
    const server = fakeServer({ changes: [{ itemId: "item-totp", ciphertext, revision: 1 }] });
    const manager = new ExtensionVaultManager(deps({ server, now: () => 59_000 }));
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    const totp = await manager.getTotp("item-totp");
    expect(totp).not.toBeNull();
    expect(totp!.code).toMatch(/^\d{6}$/);
    expect(totp!.secondsRemaining).toBeGreaterThan(0);
  });

  test("getTotp returns null for a non-TOTP item or while locked", async () => {
    const ciphertext = encodeB64(new TextEncoder().encode(JSON.stringify({ type: "login", title: "L", username: "a", password: "p" })));
    const server = fakeServer({ changes: [{ itemId: "item-login", ciphertext, revision: 1 }] });
    const manager = new ExtensionVaultManager(deps({ server }));
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    expect(await manager.getTotp("item-login")).toBeNull();
    await manager.logout();
    expect(await manager.getTotp("item-login")).toBeNull();
  });
});

describe("ExtensionVaultManager freshness and auth-failure lifecycle", () => {
  test("checkFresh reuses a recent check within the 30s window", async () => {
    let time = 0;
    let listDevicesCalls = 0;
    const server = fakeServer({ listDevicesResponder: () => { listDevicesCalls += 1; return jsonResponse(200, { devices: [] }); } });
    const manager = new ExtensionVaultManager(deps({ server, now: () => time }));
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    // Unlock itself just performed a fresh authenticated round trip (login
    // + device enrollment + bundle fetch), so an immediate checkFresh call
    // reuses that within the 30s window rather than calling GET /devices.
    expect(listDevicesCalls).toBe(0);
    expect(await manager.checkFresh()).toBe(true);
    expect(listDevicesCalls).toBe(0);
    time += 31_000;
    expect(await manager.checkFresh()).toBe(true);
    expect(listDevicesCalls).toBe(1);
    time += 5_000;
    expect(await manager.checkFresh()).toBe(true);
    expect(listDevicesCalls).toBe(1); // reused, no new call
    time += 31_000;
    expect(await manager.checkFresh()).toBe(true);
    expect(listDevicesCalls).toBe(2);
  });

  test("a 401 on the freshness check locks the manager and fires onAuthFailure exactly once", async () => {
    let time = 0;
    let authFailures = 0;
    const server = fakeServer({ listDevicesResponder: () => jsonResponse(401, { error: "unauthorized", message: "x", requestId: "r" }) });
    const manager = new ExtensionVaultManager(deps({ server, now: () => time, onAuthFailure: () => { authFailures += 1; } }));
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    time += 31_000; // force a fresh check past the reuse window
    expect(await manager.checkFresh()).toBe(false);
    expect(manager.isUnlocked()).toBe(false);
    expect(authFailures).toBe(1);
    // A second call while already locked does not fire the callback again.
    expect(await manager.checkFresh()).toBe(false);
    expect(authFailures).toBe(1);
  });

  test("logout attempts server revocation but always clears local state", async () => {
    const server = fakeServer({ logoutResponder: () => jsonResponse(500, { error: "internal", message: "x", requestId: "r" }) });
    const manager = new ExtensionVaultManager(deps({ server }));
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    await manager.logout();
    expect(manager.isUnlocked()).toBe(false);
    expect(manager.listItems()).toEqual([]);
  });

  test("candidatesFor/fieldsFor/listItems/getTotp are all empty/null once locked", async () => {
    const manager = new ExtensionVaultManager(deps());
    await manager.unlock(ACCOUNT_ID, ORIGIN, pw());
    await manager.logout();
    expect(manager.candidatesFor("https://example.test")).toEqual([]);
    expect(await manager.fieldsFor("item-1", "https://example.test")).toBeNull();
    expect(manager.listItems()).toEqual([]);
    expect(await manager.getTotp("item-1")).toBeNull();
  });
});
