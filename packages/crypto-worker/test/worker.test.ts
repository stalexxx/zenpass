import { expect, test } from "bun:test";
import { CryptoWorkerHost, type CryptoBackend } from "../src/index.ts";
import { installCryptoWorker, type WorkerScope } from "../src/entrypoint.ts";

function makeHost() {
  const closed: number[] = [];
  const wasm: CryptoBackend = {
    unlockItemSession: () => 11,
    sealItemPayload: () => new Uint8Array([9]), openItemPayload: () => new Uint8Array([8]),
    inspectEnvelope: () => ({ accountId: "a", vaultId: null, itemId: null, recordKind: "account-wrap", keyVersion: 1n }),
    closeSession: (session) => { closed.push(session); },
  };
  return { host: new CryptoWorkerHost(wasm), closed };
}

test("malformed messages are rejected without dispatch", () => {
  const { host } = makeHost();
  expect(host.handle({ id: "x", type: "lock", unexpected: true })).toEqual({ id: "", ok: false, error: "InvalidEncoding" });
  expect(host.handle({ id: "x", type: "seal-item-payload", key: new Uint8Array(32) })).toEqual({ id: "", ok: false, error: "InvalidEncoding" });
});

test("lock closes all opaque sessions and makes prior capabilities unusable", () => {
  const { host, closed } = makeHost();
  expect(host.handle(unlock("1"))).toEqual({ id: "1", ok: true, type: "session", session: 11 });
  expect(host.handle({ id: "2", type: "lock" })).toEqual({ id: "2", ok: true, type: "locked" });
  expect(closed).toEqual([11]);
  expect(host.handle({ id: "3", type: "open-item-payload", session: 11, accountId: "a", vaultId: "v", itemId: "i", keyVersion: 1n, envelope: new Uint8Array() })).toEqual({ id: "3", ok: false, error: "Locked" });
});

test("a close failure does not prevent closing other sessions or clearing the registry", () => {
  const closes: number[] = [];
  let next = 0;
  const wasm: CryptoBackend = {
    unlockItemSession: () => ++next,
    sealItemPayload: () => new Uint8Array(), openItemPayload: () => new Uint8Array(),
    inspectEnvelope: () => ({ accountId: "a", vaultId: null, itemId: null, recordKind: "account-wrap", keyVersion: 1n }),
    closeSession: (session) => { closes.push(session); if (session === 1) throw new Error("close failed"); },
  };
  const host = new CryptoWorkerHost(wasm);
  host.handle(unlock("1")); host.handle(unlock("2"));
  expect(host.handle({ id: "3", type: "lock" })).toEqual({ id: "3", ok: false, error: "Internal" });
  expect(closes).toEqual([1, 2]);
  expect(host.handle({ id: "4", type: "open-item-payload", session: 2, accountId: "a", vaultId: "v", itemId: "i", keyVersion: 1n, envelope: new Uint8Array() })).toEqual({ id: "4", ok: false, error: "Locked" });
});

test("entrypoint copies responses and disposes sessions on worker close", () => {
  const { host, closed } = makeHost();
  const listeners = new Map<string, (event: { data: unknown }) => void>();
  const posted: unknown[] = [];
  const scope: WorkerScope = { addEventListener: (type, listener) => listeners.set(type, listener), postMessage: (message) => posted.push(message) };
  installCryptoWorker(scope, host);
  listeners.get("message")!({ data: unlock("1") });
  listeners.get("close")!({ data: undefined });
  expect(posted).toEqual([{ id: "1", ok: true, type: "session", session: 11 }]);
  expect(closed).toEqual([11]);
});

function unlock(id: string) {
  return { id, type: "unlock-item-session" as const, password: new Uint8Array([1]), kdfParametersCbor: new Uint8Array(), reportedPhysicalMemoryKiB: 1n, accountId: "a", vaultId: "v", itemId: "i", accountKeyVersion: 1n, vaultKeyVersion: 1n, itemKeyVersion: 1n, wrappedAccountKey: new Uint8Array(), wrappedVaultKey: new Uint8Array(), wrappedItemKey: new Uint8Array() };
}

test("non-finite sessions and over-limit buffers are malformed", () => {
  const { host } = makeHost();
  expect(host.handle({ id: "x", type: "open-item-payload", session: Infinity, accountId: "a", vaultId: "v", itemId: "i", keyVersion: 1n, envelope: new Uint8Array() })).toEqual({ id: "", ok: false, error: "InvalidEncoding" });
  expect(host.handle({ id: "x", type: "inspect-envelope", envelope: new Uint8Array(1024 * 1024 + 1041) })).toEqual({ id: "", ok: false, error: "InvalidEncoding" });
});

test("generated WASM string error codes map to the protocol error", () => {
  const wasm: CryptoBackend = {
    unlockItemSession: () => { throw "AuthenticationFailed"; }, sealItemPayload: () => new Uint8Array(), openItemPayload: () => new Uint8Array(),
    inspectEnvelope: () => ({ accountId: "a", vaultId: null, itemId: null, recordKind: "account-wrap", keyVersion: 1n }), closeSession: () => {},
  };
  expect(new CryptoWorkerHost(wasm).handle(unlock("x"))).toEqual({ id: "x", ok: false, error: "AuthenticationFailed" });
});

test("worker zeroes its unlock password buffer even when backend fails", () => {
  const password = new Uint8Array([9, 8]);
  const wasm: CryptoBackend = { unlockItemSession: () => { throw "AuthenticationFailed"; }, sealItemPayload: () => new Uint8Array(), openItemPayload: () => new Uint8Array(), inspectEnvelope: () => ({ accountId: "a", vaultId: null, itemId: null, recordKind: "account-wrap", keyVersion: 1n }), closeSession: () => {} };
  const request = unlock("x"); request.password = password;
  new CryptoWorkerHost(wasm).handle(request);
  expect(password).toEqual(new Uint8Array([0, 0]));
});
