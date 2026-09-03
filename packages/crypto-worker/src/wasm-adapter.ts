import init, { WasmCrypto } from "../../crypto-wasm/pkg/crypto_wasm.js";
import type { CryptoBackend } from "./index.ts";
import type { CryptoRequest } from "./protocol.ts";

/** Creates the only production Worker backend: generated browser WASM. */
export async function createWasmBackend(): Promise<CryptoBackend> {
  await init();
  const wasm = new WasmCrypto();
  return {
    unlockItemSession: (r: Extract<CryptoRequest, { type: "unlock-item-session" }>) => wasm.unlock_item_session(r.password, r.kdfParametersCbor, r.reportedPhysicalMemoryKiB, r.accountId, r.vaultId, r.itemId, r.accountKeyVersion, r.vaultKeyVersion, r.itemKeyVersion, r.wrappedAccountKey, r.wrappedVaultKey, r.wrappedItemKey),
    sealItemPayload: (s, a, v, i, k, p) => wasm.seal_item_payload(s, a, v, i, k, p),
    openItemPayload: (s, a, v, i, k, e) => wasm.open_item_payload(s, a, v, i, k, e),
    inspectEnvelope: (e) => wasm.inspect_envelope(e) as never,
    closeSession: (s) => wasm.close_session(s),
  };
}
