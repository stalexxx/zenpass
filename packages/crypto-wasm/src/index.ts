import type { CryptoWasmExports, EnvelopeMetadata } from "./generated.d.ts";

export type { CryptoErrorCode, CryptoWasmExports, EnvelopeMetadata } from "./generated.d.ts";

/** Safe facade over generated WASM: only opaque session ids cross this line. */
export class CryptoWasm {
  constructor(private readonly exports: CryptoWasmExports) {}
  protocolStatus(): string { return this.exports.protocolStatus(); }
  createItemSession(): number { return this.exports.createItemSession(); }
  sealItemPayload(session: number, accountId: string, vaultId: string, itemId: string, keyVersion: bigint, plaintext: Uint8Array): Uint8Array {
    return this.exports.sealItemPayload(session, accountId, vaultId, itemId, keyVersion, plaintext.slice());
  }
  openItemPayload(session: number, accountId: string, vaultId: string, itemId: string, keyVersion: bigint, envelope: Uint8Array): Uint8Array {
    return this.exports.openItemPayload(session, accountId, vaultId, itemId, keyVersion, envelope.slice());
  }
  inspectEnvelope(envelope: Uint8Array): EnvelopeMetadata { return this.exports.inspectEnvelope(envelope.slice()); }
  closeSession(session: number): void { this.exports.closeSession(session); }
}
