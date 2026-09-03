import { expect, test } from "bun:test";
import { CryptoWasm, type CryptoWasmExports } from "../src/index.ts";

test("safe facade copies caller buffers and exposes no raw-key operation", () => {
  let received: Uint8Array | undefined;
  const fake: CryptoWasmExports = {
    protocolStatus: () => "crypto-envelope/v1", createItemSession: () => 7,
    sealItemPayload: (_s, _a, _v, _i, _n, bytes) => { received = bytes; return bytes; },
    openItemPayload: () => new Uint8Array(), inspectEnvelope: () => ({ accountId: "a", vaultId: null, itemId: null, recordKind: "account-wrap", keyVersion: 1n }), closeSession: () => {},
  };
  const wasm = new CryptoWasm(fake);
  const input = new Uint8Array([1, 2]);
  wasm.sealItemPayload(wasm.createItemSession(), "a", "v", "i", 1n, input);
  input[0] = 9;
  expect(received).toEqual(new Uint8Array([1, 2]));
  expect(wasm.protocolStatus()).toBe("crypto-envelope/v1");
});
