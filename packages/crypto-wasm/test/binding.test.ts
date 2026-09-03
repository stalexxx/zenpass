import { expect, test } from "bun:test";
import init, { encode_item_payload_aad, protocol_status } from "../pkg/crypto_wasm.js";

test("generated browser WASM module matches the native AAD golden vector", async () => {
  await init();
  expect(protocol_status()).toBe("crypto-envelope/v1");
  expect(encode_item_payload_aad("account_01", "vault_01", "item_01", 1n)).toEqual(
    new Uint8Array(Buffer.from("a6017263727970746f2d656e76656c6f70652f7631026a6163636f756e745f303103687661756c745f303104676974656d5f3031056c6974656d2d7061796c6f61640601", "hex")),
  );
});
