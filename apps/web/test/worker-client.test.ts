import { describe, expect, test } from "bun:test";
import { CryptoWorkerClient, CryptoError } from "../src/crypto/worker-client.ts";
import { CryptoWorkerHost, type CryptoBackend } from "../../../packages/crypto-worker/src/index.ts";

// A fake `Worker` that runs a real CryptoWorkerHost synchronously (via
// queueMicrotask, to mimic postMessage's async delivery) instead of an
// actual Worker thread — bun test's environment does not spin up real
// Worker threads for module-URL workers the way a browser does, so this
// exercises CryptoWorkerClient's request/response-by-id plumbing against
// the real host logic without needing a live thread boundary.
class FakeWorker {
  private host: CryptoWorkerHost;
  private listeners = new Map<string, ((event: unknown) => void)[]>();
  constructor(backend: CryptoBackend) {
    this.host = new CryptoWorkerHost(backend);
  }
  addEventListener(type: string, listener: (event: unknown) => void): void {
    const list = this.listeners.get(type) ?? [];
    list.push(listener);
    this.listeners.set(type, list);
  }
  postMessage(message: unknown): void {
    // Mimic real postMessage's structured clone so the Worker never sees
    // (and cannot zero) the caller's own buffer.
    const cloned = structuredClone(message);
    queueMicrotask(() => {
      const response = this.host.handle(cloned);
      for (const listener of this.listeners.get("message") ?? []) listener({ data: response });
    });
  }
  terminate(): void {}
}

function backend(): CryptoBackend {
  let next = 1;
  const sessions = new Set<number>();
  return {
    unlockItemSession: () => { const s = next++; sessions.add(s); return s; },
    createAccountSetup: (r) => {
      const s = next++;
      sessions.add(s);
      return {
        accountId: r.accountId, vaultId: r.vaultId, itemId: r.itemId, session: s,
        kdfParametersCbor: new Uint8Array([1]), wrappedAccountKey: new Uint8Array([2]),
        wrappedVaultKey: new Uint8Array([3]), wrappedItemKey: new Uint8Array([4]),
        wrappedRecoveryKey: new Uint8Array([5]), recoveryKey: new Uint8Array(32).fill(9),
      };
    },
    unlockItemSessionWithRecovery: () => { const s = next++; sessions.add(s); return s; },
    sealItemPayload: () => new Uint8Array([1, 2, 3]),
    openItemPayload: () => new Uint8Array([9, 9]),
    inspectEnvelope: () => ({ accountId: "a", vaultId: null, itemId: null, recordKind: "account-wrap", keyVersion: 1n }),
    closeSession: (s) => { sessions.delete(s); },
  };
}

describe("CryptoWorkerClient", () => {
  test("createAccountSetup round-trips through postMessage-shaped request/response", async () => {
    const client = new CryptoWorkerClient(new FakeWorker(backend()) as unknown as Worker);
    const result = await client.createAccountSetup({
      password: new Uint8Array([1, 2, 3]),
      reportedPhysicalMemoryKiB: 262144n,
      accountId: "acct_1", vaultId: "vault_1", itemId: "vault-key",
    });
    expect(result.accountId).toBe("acct_1");
    expect(result.recoveryKey.length).toBe(32);
  });

  test("unlockItemSession, sealItemPayload, openItemPayload, and lock all resolve", async () => {
    const client = new CryptoWorkerClient(new FakeWorker(backend()) as unknown as Worker);
    const session = await client.unlockItemSession({
      password: new Uint8Array([1]), kdfParametersCbor: new Uint8Array(), reportedPhysicalMemoryKiB: 1n,
      accountId: "a", vaultId: "v", itemId: "i", accountKeyVersion: 1n, vaultKeyVersion: 1n, itemKeyVersion: 1n,
      wrappedAccountKey: new Uint8Array(), wrappedVaultKey: new Uint8Array(), wrappedItemKey: new Uint8Array(),
    });
    expect(typeof session).toBe("number");
    const sealed = await client.sealItemPayload(session, "a", "v", "i", 1n, new Uint8Array([1]));
    expect(sealed).toEqual(new Uint8Array([1, 2, 3]));
    const opened = await client.openItemPayload(session, "a", "v", "i", 1n, sealed);
    expect(opened).toEqual(new Uint8Array([9, 9]));
    await client.lock();
  });

  test("a Worker error response rejects with CryptoError carrying the protocol error code", async () => {
    const failingBackend: CryptoBackend = {
      ...backend(),
      unlockItemSession: () => { throw "AuthenticationFailed"; },
    };
    const client = new CryptoWorkerClient(new FakeWorker(failingBackend) as unknown as Worker);
    await expect(
      client.unlockItemSession({
        password: new Uint8Array([1]), kdfParametersCbor: new Uint8Array(), reportedPhysicalMemoryKiB: 1n,
        accountId: "a", vaultId: "v", itemId: "i", accountKeyVersion: 1n, vaultKeyVersion: 1n, itemKeyVersion: 1n,
        wrappedAccountKey: new Uint8Array(), wrappedVaultKey: new Uint8Array(), wrappedItemKey: new Uint8Array(),
      }),
    ).rejects.toBeInstanceOf(CryptoError);
  });
});
