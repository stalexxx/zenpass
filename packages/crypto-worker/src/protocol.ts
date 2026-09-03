import type { CryptoErrorCode } from "../../crypto-wasm/src/index.ts";

export interface EnvelopeMetadata { accountId: string; vaultId: string | null; itemId: string | null; recordKind: string; keyVersion: bigint; }

export type CryptoRequest =
  | { id: string; type: "unlock-item-session"; password: Uint8Array; kdfParametersCbor: Uint8Array; reportedPhysicalMemoryKiB: bigint; accountId: string; vaultId: string; itemId: string; accountKeyVersion: bigint; vaultKeyVersion: bigint; itemKeyVersion: bigint; wrappedAccountKey: Uint8Array; wrappedVaultKey: Uint8Array; wrappedItemKey: Uint8Array }
  | { id: string; type: "seal-item-payload"; session: number; accountId: string; vaultId: string; itemId: string; keyVersion: bigint; plaintext: Uint8Array }
  | { id: string; type: "open-item-payload"; session: number; accountId: string; vaultId: string; itemId: string; keyVersion: bigint; envelope: Uint8Array }
  | { id: string; type: "inspect-envelope"; envelope: Uint8Array }
  | { id: string; type: "lock" };

export type CryptoResponse =
  | { id: string; ok: true; type: "session"; session: number }
  | { id: string; ok: true; type: "bytes"; bytes: Uint8Array }
  | { id: string; ok: true; type: "metadata"; metadata: EnvelopeMetadata }
  | { id: string; ok: true; type: "locked" }
  | { id: string; ok: false; error: CryptoErrorCode };
