import type { AppContext } from "../../src/lib/context.ts";
import type { AccountBundle } from "../../src/vault/account-bundle.ts";

/** Creates a fresh account + vault via the real crypto path and leaves
 * `ctx.vault` unlocked, without going through the onboarding UI — for
 * tests whose subject is something *downstream* of registration (import,
 * export, CRUD, sync). Returns the bundle and the password used, in case
 * a test wants to lock/re-unlock. */
export async function generateTestBundle(ctx: AppContext, accountId = `acct-${crypto.randomUUID()}`): Promise<{ bundle: AccountBundle; password: Uint8Array }> {
  const password = new TextEncoder().encode("correct horse battery staple");
  const setup = await ctx.crypto.createAccountSetup({
    password: password.slice(),
    reportedPhysicalMemoryKiB: 262_144n,
    accountId,
    vaultId: crypto.randomUUID(),
    itemId: "vault-key",
  });
  await ctx.crypto.lock();
  const bundle: AccountBundle = {
    accountId: setup.accountId, vaultId: setup.vaultId, itemId: setup.itemId,
    kdfParametersCbor: setup.kdfParametersCbor, wrappedAccountKey: setup.wrappedAccountKey,
    wrappedVaultKey: setup.wrappedVaultKey, wrappedItemKey: setup.wrappedItemKey,
    wrappedRecoveryKey: setup.wrappedRecoveryKey,
  };
  await ctx.vault.unlockWithPassword(bundle, password.slice());
  return { bundle, password };
}
