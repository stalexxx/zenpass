import type { CryptoErrorCode } from "../../crypto-wasm/src/index.ts";

export interface EnvelopeMetadata { accountId: string; vaultId: string | null; itemId: string | null; recordKind: string; keyVersion: bigint; }

// ADR-0008 (C01) addition: account-setup result shape. `recoveryKey` is
// returned exactly once, on this one response, for the caller to display
// during onboarding's reveal/confirm step; nothing else in this protocol
// ever carries a raw key.
export interface AccountSetupResult {
  accountId: string;
  vaultId: string;
  itemId: string;
  session: number;
  kdfParametersCbor: Uint8Array;
  wrappedAccountKey: Uint8Array;
  wrappedVaultKey: Uint8Array;
  wrappedItemKey: Uint8Array;
  wrappedRecoveryKey: Uint8Array;
  recoveryKey: Uint8Array;
}

export type CryptoRequest =
  | { id: string; type: "unlock-item-session"; password: Uint8Array; kdfParametersCbor: Uint8Array; reportedPhysicalMemoryKiB: bigint; accountId: string; vaultId: string; itemId: string; accountKeyVersion: bigint; vaultKeyVersion: bigint; itemKeyVersion: bigint; wrappedAccountKey: Uint8Array; wrappedVaultKey: Uint8Array; wrappedItemKey: Uint8Array }
  // ADR-0008 (C01) addition: registration. `password` is zeroized on the
  // Worker side after use, matching `unlock-item-session`.
  | { id: string; type: "create-account-setup"; password: Uint8Array; reportedPhysicalMemoryKiB: bigint; accountId: string; vaultId: string; itemId: string }
  // ADR-0008 (C01) addition: open a session with the recovery key instead
  // of the password (registration confirm step; future recovery unlock).
  | { id: string; type: "unlock-item-session-with-recovery"; recoveryKey: Uint8Array; accountId: string; vaultId: string; itemId: string; accountKeyVersion: bigint; vaultKeyVersion: bigint; itemKeyVersion: bigint; wrappedAccountKey: Uint8Array; wrappedVaultKey: Uint8Array; wrappedItemKey: Uint8Array }
  | { id: string; type: "seal-item-payload"; session: number; accountId: string; vaultId: string; itemId: string; keyVersion: bigint; plaintext: Uint8Array }
  | { id: string; type: "open-item-payload"; session: number; accountId: string; vaultId: string; itemId: string; keyVersion: bigint; envelope: Uint8Array }
  | { id: string; type: "inspect-envelope"; envelope: Uint8Array }
  | { id: string; type: "lock" };

export type CryptoResponse =
  | { id: string; ok: true; type: "session"; session: number }
  | { id: string; ok: true; type: "bytes"; bytes: Uint8Array }
  | { id: string; ok: true; type: "metadata"; metadata: EnvelopeMetadata }
  | { id: string; ok: true; type: "locked" }
  | { id: string; ok: true; type: "account-setup"; result: AccountSetupResult }
  | { id: string; ok: false; error: CryptoErrorCode };
