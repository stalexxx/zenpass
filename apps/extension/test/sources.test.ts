import { expect, test } from "bun:test";

/**
 * Storage/log inspection (T15/T19): the extension sources must not log
 * message contents or field values, and must persist nothing beyond the
 * one explicitly reviewed exception — the non-secret accountId/apiOrigin
 * association (ADR-0011 D1/D4: "Persist only the account/API association
 * across restarts"), which lives exclusively in `src/storage.ts` and is
 * wired from `src/background.ts` only through that module's typed
 * `createAssociationStorage`/`createInMemoryAssociationStorage` API — never
 * a raw `chrome.storage`/`browser.storage` call anywhere else, and never a
 * wrapped bundle, item, key, password, bearer token, or TOTP seed. This is
 * a static source check; runtime inspection is part of the browser E2E
 * evidence.
 */
const sources = [
  "src/content.ts",
  "src/popup.ts",
  "src/protocol.ts",
  "src/vault-manager.ts",
  "src/origin.ts",
  "src/item-codec.ts",
];
/** `src/background.ts` and `src/storage.ts` are deliberately excluded from
 * `sources` above — they are the two reviewed files allowed to reference a
 * storage API at all, and are checked by their own dedicated tests below
 * instead. */

const forbidden = [
  "localStorage",
  "sessionStorage",
  "indexedDB",
  "console.",
];

test("extension sources (other than background.ts/storage.ts) log nothing and never touch a storage API", async () => {
  for (const source of sources) {
    const text = await Bun.file(new URL(`../${source}`, import.meta.url).pathname).text();
    for (const pattern of [...forbidden, "chrome.storage", "browser.storage", "storage.local", "storage.sync", "storage.session"]) {
      expect(text.includes(pattern), `${source} must not use ${pattern}`).toBe(false);
    }
  }
});

test("background.ts references a storage API only by passing it to createAssociationStorage", async () => {
  const text = await Bun.file(new URL("../src/background.ts", import.meta.url).pathname).text();
  for (const pattern of forbidden) {
    expect(text.includes(pattern), `src/background.ts must not use ${pattern}`).toBe(false);
  }
  expect(text.includes("chrome.storage")).toBe(false);
  expect(text.includes("browser.storage")).toBe(false);
  // The only occurrence of the literal `storage.local` in this file is as
  // the argument to `createAssociationStorage` — never a raw
  // `.set(`/`.get(`/`.remove(` call on a storage object here.
  const occurrences = text.split("storage.local").length - 1;
  expect(occurrences).toBe(1);
  expect(text).toContain("createAssociationStorage(runtimeApi.storage.local)");
});

test("storage.ts persists only the {accountId, apiOrigin} association shape", async () => {
  const text = await Bun.file(new URL("../src/storage.ts", import.meta.url).pathname).text();
  for (const pattern of forbidden) {
    expect(text.includes(pattern), `src/storage.ts must not use ${pattern}`).toBe(false);
  }
  // The stored shape is exactly {accountId, apiOrigin} (see storage.test.ts
  // for the behavioral proof that nothing else is ever written).
  expect(text).toContain("interface SavedAccount");
  expect(text).toContain("accountId: string");
  expect(text).toContain("apiOrigin: string");
});

test("content script transports no credential values and captures no submits", async () => {
  const text = await Bun.file(new URL("../src/content.ts", import.meta.url).pathname).text();
  expect(text.includes('"save-submitted"')).toBe(false);
  expect(text.includes("addEventListener(\"submit\"")).toBe(false);
  expect(text.includes(".value")).toBe(false);
});
