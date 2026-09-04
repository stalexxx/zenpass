// Persists the wrapped key bundle (never raw keys) so offline unlock can
// work from "only the local encrypted snapshot and wrapped key bundle"
// (docs/ux/flows.md). Every byte field here is an AEAD-wrapped envelope —
// ciphertext, not key material — so storing it in localStorage does not
// violate "no keys/vault plaintext in localStorage" (the acceptance
// criterion is about plaintext and raw keys, not encrypted wrappers; the
// wrapped bundle is exactly what a password/recovery key is needed to
// open). The KDF parameters are also non-secret (they're public
// algorithm/cost parameters, not key material).
import { decodeB64, encodeB64 } from "@zkpm/sdk";

export interface AccountBundle {
  accountId: string;
  vaultId: string;
  /** Synthetic id the single vault-wide ItemKey was wrapped under (see
   * packages/crypto-wasm's ADR-0008 `create_account_setup` doc comment for
   * why one ItemKey currently covers a whole vault). */
  itemId: string;
  kdfParametersCbor: Uint8Array;
  wrappedAccountKey: Uint8Array;
  wrappedVaultKey: Uint8Array;
  wrappedItemKey: Uint8Array;
  wrappedRecoveryKey: Uint8Array;
}

interface StoredAccountBundle {
  accountId: string;
  vaultId: string;
  itemId: string;
  kdfParametersCbor: string;
  wrappedAccountKey: string;
  wrappedVaultKey: string;
  wrappedItemKey: string;
  wrappedRecoveryKey: string;
}

function key(accountId: string): string {
  return `zkpm.bundle.${accountId}`;
}

export function saveAccountBundle(bundle: AccountBundle, storage: Storage = localStorage): void {
  const stored: StoredAccountBundle = {
    accountId: bundle.accountId,
    vaultId: bundle.vaultId,
    itemId: bundle.itemId,
    kdfParametersCbor: encodeB64(bundle.kdfParametersCbor),
    wrappedAccountKey: encodeB64(bundle.wrappedAccountKey),
    wrappedVaultKey: encodeB64(bundle.wrappedVaultKey),
    wrappedItemKey: encodeB64(bundle.wrappedItemKey),
    wrappedRecoveryKey: encodeB64(bundle.wrappedRecoveryKey),
  };
  storage.setItem(key(bundle.accountId), JSON.stringify(stored));
}

export function loadAccountBundle(accountId: string, storage: Storage = localStorage): AccountBundle | null {
  const raw = storage.getItem(key(accountId));
  if (!raw) return null;
  const stored = JSON.parse(raw) as StoredAccountBundle;
  return {
    accountId: stored.accountId,
    vaultId: stored.vaultId,
    itemId: stored.itemId,
    kdfParametersCbor: decodeB64(stored.kdfParametersCbor),
    wrappedAccountKey: decodeB64(stored.wrappedAccountKey),
    wrappedVaultKey: decodeB64(stored.wrappedVaultKey),
    wrappedItemKey: decodeB64(stored.wrappedItemKey),
    wrappedRecoveryKey: decodeB64(stored.wrappedRecoveryKey),
  };
}

export function hasAccountBundle(accountId: string, storage: Storage = localStorage): boolean {
  return storage.getItem(key(accountId)) !== null;
}
