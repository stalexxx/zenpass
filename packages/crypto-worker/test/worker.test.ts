import { expect, test } from "bun:test";
import { CryptoWasm, type CryptoWasmExports } from "../../crypto-wasm/src/index.ts";
import { CryptoWorkerHost } from "../src/index.ts";

function makeHost() {
  const closed: number[] = [];
  const wasm: CryptoWasmExports = {
    protocolStatus: () => "crypto-envelope/v1", createItemSession: () => 11,
    sealItemPayload: () => new Uint8Array([9]), openItemPayload: () => new Uint8Array([8]),
    inspectEnvelope: () => ({ accountId: "a", vaultId: null, itemId: null, recordKind: "account-wrap", keyVersion: 1n }),
    closeSession: (session) => { closed.push(session); },
  };
  return { host: new CryptoWorkerHost(new CryptoWasm(wasm)), closed };
}

test("malformed messages are rejected without dispatch", () => {
  const { host } = makeHost();
  expect(host.handle({ id: "x", type: "lock", unexpected: true })).toEqual({ id: "", ok: false, error: "InvalidEncoding" });
  expect(host.handle({ id: "x", type: "seal-item-payload", key: new Uint8Array(32) })).toEqual({ id: "", ok: false, error: "InvalidEncoding" });
});

test("lock closes all opaque sessions and makes prior capabilities unusable", () => {
  const { host, closed } = makeHost();
  expect(host.handle({ id: "1", type: "create-item-session" })).toEqual({ id: "1", ok: true, type: "session", session: 11 });
  expect(host.handle({ id: "2", type: "lock" })).toEqual({ id: "2", ok: true, type: "locked" });
  expect(closed).toEqual([11]);
  expect(host.handle({ id: "3", type: "open-item-payload", session: 11, accountId: "a", vaultId: "v", itemId: "i", keyVersion: 1n, envelope: new Uint8Array() })).toEqual({ id: "3", ok: false, error: "Locked" });
});
