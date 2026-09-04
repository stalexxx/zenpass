import { expect, test } from "bun:test";
import init, { encode_item_payload_aad, protocol_status, WasmCrypto } from "../pkg/crypto_wasm.js";

test("generated browser WASM module matches the native AAD golden vector", async () => {
  await init();
  expect(protocol_status()).toBe("crypto-envelope/v1");
  expect(encode_item_payload_aad("account_01", "vault_01", "item_01", 1n)).toEqual(
    new Uint8Array(Buffer.from("a6017263727970746f2d656e76656c6f70652f7631026a6163636f756e745f303103687661756c745f303104676974656d5f3031056c6974656d2d7061796c6f61640601", "hex")),
  );
});

test("generated WASM dynamically creates, unlocks, locks, and uses an opaque hierarchy session", async () => {
  await init();
  const setupPassword = new Uint8Array([1, 2, 3]);
  const unlockPassword = new Uint8Array([1, 2, 3]);
  const crypto = new WasmCrypto();
  let setupSession: number | undefined;
  let session: number | undefined;
  let closedSession: number | undefined;
  try {
    const setup = crypto.create_item_session_for_setup(setupPassword, 262144n) as Record<string, unknown>;
    setupSession = setup.session as number;
    session = crypto.unlock_item_session(unlockPassword, setup.kdfParametersCbor as Uint8Array, 262144n, setup.accountId as string, setup.vaultId as string, setup.itemId as string, 1n, 1n, 1n, setup.wrappedAccountKey as Uint8Array, setup.wrappedVaultKey as Uint8Array, setup.wrappedItemKey as Uint8Array);
    const envelope = crypto.seal_item_payload(session, setup.accountId as string, setup.vaultId as string, setup.itemId as string, 1n, new Uint8Array([4]));
    expect(crypto.open_item_payload(session, setup.accountId as string, setup.vaultId as string, setup.itemId as string, 1n, envelope)).toEqual(new Uint8Array([4]));
    closedSession = session; crypto.close_session(session); session = undefined;
    expect(() => crypto.open_item_payload(closedSession!, setup.accountId as string, setup.vaultId as string, setup.itemId as string, 1n, envelope)).toThrow();
  } finally {
    setupPassword.fill(0); unlockPassword.fill(0);
    if (session !== undefined) crypto.close_session(session);
    if (setupSession !== undefined) crypto.close_session(setupSession);
    crypto.free();
  }
});

test("ADR-0008: create_account_setup wraps under password and recovery, and both open the same session material", async () => {
  await init();
  const password = new Uint8Array([9, 9, 9]);
  const crypto = new WasmCrypto();
  let setupSession: number | undefined;
  let recoverySession: number | undefined;
  try {
    const setup = crypto.create_account_setup(password, 262144n, "acct_1", "vault_1", "vault-key") as Record<string, unknown>;
    setupSession = setup.session as number;
    expect(setup.recoveryKey).toBeInstanceOf(Uint8Array);
    expect((setup.recoveryKey as Uint8Array).length).toBe(32);

    // Password path still opens via the unmodified unlock_item_session.
    const viaPassword = crypto.unlock_item_session(
      new Uint8Array([9, 9, 9]),
      setup.kdfParametersCbor as Uint8Array,
      262144n,
      setup.accountId as string, setup.vaultId as string, setup.itemId as string,
      1n, 1n, 1n,
      setup.wrappedAccountKey as Uint8Array, setup.wrappedVaultKey as Uint8Array, setup.wrappedItemKey as Uint8Array,
    );
    const sealed = crypto.seal_item_payload(viaPassword, setup.accountId as string, setup.vaultId as string, "item_a", 1n, new Uint8Array([7]));
    crypto.close_session(viaPassword);

    // Recovery path opens the same underlying item key material.
    recoverySession = crypto.unlock_item_session_with_recovery(
      setup.recoveryKey as Uint8Array,
      setup.accountId as string, setup.vaultId as string, setup.itemId as string,
      1n, 1n, 1n,
      setup.wrappedRecoveryKey as Uint8Array, setup.wrappedVaultKey as Uint8Array, setup.wrappedItemKey as Uint8Array,
    );
    expect(crypto.open_item_payload(recoverySession, setup.accountId as string, setup.vaultId as string, "item_a", 1n, sealed)).toEqual(new Uint8Array([7]));
  } finally {
    password.fill(0);
    if (setupSession !== undefined) crypto.close_session(setupSession);
    if (recoverySession !== undefined) crypto.close_session(recoverySession);
    crypto.free();
  }
});

test("ADR-0008: unlock_item_session_with_recovery rejects a wrong recovery key with InvalidRecoveryKit", async () => {
  await init();
  const password = new Uint8Array([1, 1, 1]);
  const crypto = new WasmCrypto();
  let setupSession: number | undefined;
  try {
    const setup = crypto.create_account_setup(password, 262144n, "acct_2", "vault_2", "vault-key") as Record<string, unknown>;
    setupSession = setup.session as number;
    const wrong = new Uint8Array(32).fill(0x42);
    expect(() =>
      crypto.unlock_item_session_with_recovery(
        wrong,
        setup.accountId as string, setup.vaultId as string, setup.itemId as string,
        1n, 1n, 1n,
        setup.wrappedRecoveryKey as Uint8Array, setup.wrappedVaultKey as Uint8Array, setup.wrappedItemKey as Uint8Array,
      ),
    ).toThrow();
  } finally {
    password.fill(0);
    if (setupSession !== undefined) crypto.close_session(setupSession);
    crypto.free();
  }
});
