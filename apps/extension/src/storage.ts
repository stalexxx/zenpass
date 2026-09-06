/**
 * D1/D4 persistence: "Persist only the account/API association across
 * restarts — no wrapped-bundle cache, item cache, or offline unlock." This
 * module is the one place allowed to persist anything, and it persists
 * exactly two non-secret strings (accountId, apiOrigin) — never a
 * password, bearer token, wrapped key bundle, item, or TOTP seed. The
 * storage backend is injected so tests never touch a real browser API.
 */

export interface SavedAccount {
  accountId: string;
  apiOrigin: string;
}

export interface AssociationStorage {
  get(): Promise<SavedAccount | null>;
  set(value: SavedAccount): Promise<void>;
  clear(): Promise<void>;
}

const STORAGE_KEY = "zkpm.extension.account-association.v1";

function isSavedAccount(value: unknown): value is SavedAccount {
  if (typeof value !== "object" || value === null) return false;
  const record = value as Record<string, unknown>;
  return typeof record.accountId === "string" && record.accountId.length > 0 && record.accountId.length <= 256
    && typeof record.apiOrigin === "string" && record.apiOrigin.length > 0 && record.apiOrigin.length <= 512;
}

/** Minimal shape of `chrome.storage.local` / `browser.storage.local` this
 * module needs, so it can be exercised against a fake in tests without a
 * real browser runtime. */
export interface BrowserLocalStorageArea {
  get(keys: string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string[]): Promise<void>;
}

/** Wraps a browser's extension-storage local area. Stores only the
 * non-secret account/origin association; nothing else is ever written
 * through this module. */
export function createAssociationStorage(area: BrowserLocalStorageArea): AssociationStorage {
  return {
    async get() {
      const result = await area.get([STORAGE_KEY]);
      const value = result[STORAGE_KEY];
      return isSavedAccount(value) ? value : null;
    },
    async set(value: SavedAccount) {
      if (!isSavedAccount(value)) throw new Error("invalid account association");
      await area.set({ [STORAGE_KEY]: value });
    },
    async clear() {
      await area.remove([STORAGE_KEY]);
    },
  };
}

/** In-memory storage for tests and for any runtime without a storage API
 * (association is then simply not remembered across restarts — never a
 * fallback for secret data, since none is ever stored here). */
export function createInMemoryAssociationStorage(): AssociationStorage {
  let value: SavedAccount | null = null;
  return {
    async get() {
      return value;
    },
    async set(next: SavedAccount) {
      if (!isSavedAccount(next)) throw new Error("invalid account association");
      value = next;
    },
    async clear() {
      value = null;
    },
  };
}
