import type { CryptoErrorCode, EnvelopeMetadata } from "../../crypto-wasm/src/index.ts";

export type CryptoRequest =
  | { id: string; type: "create-item-session" }
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
