import { describe, expect, test } from "bun:test";
import { BackgroundPolicy } from "../src/background.ts";
import { createInMemoryAssociationStorage } from "../src/storage.ts";
import type { ItemSummary, LoginCandidate, SaveItemInput, SaveItemResult, TotpDisplay, UnlockResult, VaultManager } from "../../../../packages/extension-adapters/src/index.ts";

/**
 * Integration tests for BackgroundPolicy's C04-EXT2 popup message handling
 * (unlock, save/update, TOTP, lock/logout lifecycle), driven through a
 * full fake `VaultManager` rather than the real WASM/network-backed
 * `ExtensionVaultManager` (covered separately by vault-manager.test.ts).
 * This isolates "does BackgroundPolicy wire the new popup actions and
 * lifecycle correctly" from "does ExtensionVaultManager talk to the real
 * SDK/crypto-worker correctly".
 */
const ownId = "ext-id";
const popupUrl = `chrome-extension://${ownId}/popup.html`;
const popupSender = { id: ownId, url: popupUrl };

function fakeFullVault(overrides: Partial<VaultManager> = {}): VaultManager & { unlockCalls: number; freshChecks: number; lockCalls: number; logoutCalls: number } {
  let unlocked = false;
  const items = new Map<string, ItemSummary>();
  // `result` is mutated in place (not spread from a separate closure) so
  // the counters the test reads back are the very same object the methods
  // below increment — a spread-copy would freeze their values at creation.
  const result = {
    unlockCalls: 0,
    freshChecks: 0,
    lockCalls: 0,
    logoutCalls: 0,
    candidatesFor: (): readonly LoginCandidate[] => [],
    fieldsFor: async () => null,
    isUnlocked: () => unlocked,
    async unlock(accountId: string, apiOrigin: string, password: Uint8Array): Promise<UnlockResult> {
      result.unlockCalls += 1;
      password.fill(0);
      if (overrides.unlock) return overrides.unlock(accountId, apiOrigin, password);
      unlocked = true;
      return { ok: true };
    },
    lock(): void {
      result.lockCalls += 1;
      unlocked = false;
      items.clear();
    },
    async logout(): Promise<void> {
      result.logoutCalls += 1;
      unlocked = false;
      items.clear();
    },
    listItems: (): readonly ItemSummary[] => [...items.values()],
    async saveItem(input: SaveItemInput): Promise<SaveItemResult> {
      if (overrides.saveItem) return overrides.saveItem(input);
      if (!unlocked) return { ok: false, reason: "locked" };
      const itemId = input.itemId ?? `generated-${items.size + 1}`;
      items.set(itemId, { itemId, title: input.title, type: input.type, username: input.username, url: input.url });
      return { ok: true, itemId };
    },
    async getTotp(itemId: string): Promise<TotpDisplay | null> {
      if (overrides.getTotp) return overrides.getTotp(itemId);
      return unlocked && items.has(itemId) ? { code: "123456", secondsRemaining: 15 } : null;
    },
    async checkFresh(): Promise<boolean> {
      result.freshChecks += 1;
      return overrides.checkFresh ? overrides.checkFresh() : unlocked;
    },
  };
  return result;
}

function policyWith(vault: ReturnType<typeof fakeFullVault>) {
  return new BackgroundPolicy({
    ownExtensionId: ownId,
    popupUrl,
    getActiveTab: async () => null,
    sendToDocument: async () => true,
    vault,
    associationStorage: createInMemoryAssociationStorage(),
  });
}

const goodPassword = () => [1, 2, 3, 4];

describe("independent unlock (D1)", () => {
  test("a successful unlock marks the session active and persists the account/origin association", async () => {
    const vault = fakeFullVault();
    const p = policyWith(vault);
    expect(p.session.locked).toBe(true);
    const response = await p.handlePopupMessage({ type: "unlock", accountId: "acct_1", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    expect(response).toEqual({ type: "unlocked" });
    expect(p.session.locked).toBe(false);
    expect(vault.unlockCalls).toBe(1);
    const state = await p.handlePopupMessage({ type: "get-state" }, popupSender);
    expect(state).toEqual({ type: "state", locked: false, unlockAvailable: true, savedAccount: { accountId: "acct_1", apiOrigin: "https://api.test" } });
  });

  test("a failed unlock (wrong password/account/origin) stays locked and reports generically", async () => {
    const vault = fakeFullVault({ unlock: async () => ({ ok: false, reason: "unlock-failed" }) });
    const p = policyWith(vault);
    const response = await p.handlePopupMessage({ type: "unlock", accountId: "acct_1", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    expect(response).toEqual({ type: "unlock-failed" });
    expect(p.session.locked).toBe(true);
  });

  test("an unlock request from a non-popup sender has no authority", async () => {
    const vault = fakeFullVault();
    const p = policyWith(vault);
    const contentSender = { id: ownId, url: "https://example.test", tab: { id: 1 }, frameId: 0 };
    const response = await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, contentSender);
    expect(response).toEqual({ type: "locked" });
    expect(vault.unlockCalls).toBe(0);
  });
});

describe("save/update (D3)", () => {
  test("saves a new item only once unlocked, and list-items reflects it", async () => {
    const vault = fakeFullVault();
    const p = policyWith(vault);
    await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    const saved = await p.handlePopupMessage({ type: "save-item", title: "Example", itemType: "login", username: "alice", password: [1, 2, 3] }, popupSender);
    expect(saved.type).toBe("saved");
    const items = await p.handlePopupMessage({ type: "list-items" }, popupSender);
    expect(items).toEqual({ type: "items", items: [{ itemId: (saved as { itemId: string }).itemId, title: "Example", type: "login", username: "alice", url: undefined }] });
  });

  test("save-item is refused while locked", async () => {
    const vault = fakeFullVault();
    const p = policyWith(vault);
    const response = await p.handlePopupMessage({ type: "save-item", title: "X", itemType: "note" }, popupSender);
    expect(response).toEqual({ type: "refused", reason: "unlock-unavailable" });
  });

  test("a validation failure is surfaced with its problems", async () => {
    // A schema-valid message (non-empty title) that still fails the vault
    // manager's own semantic validation (a login needs a username or a
    // password) — distinct from a message the schema itself would already
    // reject (e.g. an empty title), which never reaches the vault manager
    // at all and is refused generically instead (see the popup-message
    // schema tests in packages/extension-adapters/test).
    const vault = fakeFullVault({ saveItem: async () => ({ ok: false, reason: "validation", problems: ["A login needs a username or a password."] }) });
    const p = policyWith(vault);
    await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    const response = await p.handlePopupMessage({ type: "save-item", title: "Example", itemType: "login" }, popupSender);
    expect(response).toEqual({ type: "save-failed", reason: "validation", problems: ["A login needs a username or a password."] });
  });
});

describe("TOTP display (D3/D6)", () => {
  test("returns the current code only for a known item while unlocked", async () => {
    const vault = fakeFullVault();
    const p = policyWith(vault);
    await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    const saved = await p.handlePopupMessage({ type: "save-item", title: "GH", itemType: "totp-login", username: "a", password: [1], totpSecret: [2] }, popupSender);
    const totp = await p.handlePopupMessage({ type: "get-totp", itemId: (saved as { itemId: string }).itemId }, popupSender);
    expect(totp).toEqual({ type: "totp", code: "123456", secondsRemaining: 15 });
  });

  test("returns not-found for an unknown item", async () => {
    const vault = fakeFullVault();
    const p = policyWith(vault);
    await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    expect(await p.handlePopupMessage({ type: "get-totp", itemId: "missing" }, popupSender)).toEqual({ type: "refused", reason: "not-found" });
  });
});

describe("lifecycle (D5)", () => {
  test("explicit lock disposes the vault manager's own state without a network attempt", async () => {
    const vault = fakeFullVault();
    const p = policyWith(vault);
    await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    p.lock();
    expect(p.session.locked).toBe(true);
    expect(vault.isUnlocked()).toBe(false);
    expect(vault.lockCalls).toBe(1);
    expect(vault.logoutCalls).toBe(0);
  });

  test("logout attempts server revocation and then locks", async () => {
    const vault = fakeFullVault();
    const p = policyWith(vault);
    await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    const response = await p.handlePopupMessage({ type: "logout" }, popupSender);
    expect(response).toEqual({ type: "locked" });
    expect(p.session.locked).toBe(true);
    expect(vault.logoutCalls).toBe(1);
  });

  test("popup close locks and disposes vault manager state", async () => {
    const vault = fakeFullVault();
    const p = policyWith(vault);
    await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    p.lockFromPopupClose();
    expect(p.session.locked).toBe(true);
    expect(vault.lockCalls).toBe(1);
  });

  test("a fresh-check failure (401/network) during list-items locks the session", async () => {
    const vault = fakeFullVault({ checkFresh: async () => false });
    const p = policyWith(vault);
    await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    const response = await p.handlePopupMessage({ type: "list-items" }, popupSender);
    expect(response).toEqual({ type: "locked" });
  });

  test("a 5-minute popup-inactivity timeout locks even without any explicit action", async () => {
    let now = 0;
    const vault = fakeFullVault();
    const p = new BackgroundPolicy({
      ownExtensionId: ownId,
      popupUrl,
      now: () => now,
      getActiveTab: async () => null,
      sendToDocument: async () => true,
      vault,
      associationStorage: createInMemoryAssociationStorage(),
    });
    await p.handlePopupMessage({ type: "unlock", accountId: "a", apiOrigin: "https://api.test", password: goodPassword() }, popupSender);
    expect(p.session.locked).toBe(false);
    now += 300_001;
    const state = await p.handlePopupMessage({ type: "get-state" }, popupSender);
    expect(state).toMatchObject({ locked: true });
  });
});
