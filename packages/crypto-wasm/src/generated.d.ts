/** GENERATED FROM THE SAFE WASM EXPORT SURFACE. Do not hand-edit. */
export type CryptoErrorCode =
  | "InvalidEncoding" | "UnsupportedVersion" | "NonCanonicalCbor" | "UnknownField"
  | "InvalidContext" | "InvalidNonce" | "AuthenticationFailed" | "InvalidKdfParameters"
  | "KdfResourceLimit" | "InvalidKeyLength" | "InvalidRecoveryKit" | "Locked" | "Internal";

export interface EnvelopeMetadata {
  accountId: string;
  vaultId: string | null;
  itemId: string | null;
  recordKind: string;
  keyVersion: bigint;
}

/** Session ids are opaque capabilities, never encoded key material. */
export interface CryptoWasmExports {
  protocolStatus(): string;
  createItemSession(): number;
  sealItemPayload(session: number, accountId: string, vaultId: string, itemId: string, keyVersion: bigint, plaintext: Uint8Array): Uint8Array;
  openItemPayload(session: number, accountId: string, vaultId: string, itemId: string, keyVersion: bigint, envelope: Uint8Array): Uint8Array;
  inspectEnvelope(envelope: Uint8Array): EnvelopeMetadata;
  closeSession(session: number): void;
}
