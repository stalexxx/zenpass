import { expect, test } from "bun:test";

/**
 * Storage/log inspection (T15/T19): the extension sources must not persist
 * anything and must not log message contents or field values. This is a
 * static source check over the shipped sources; runtime inspection is part
 * of the post-C04-G1 browser E2E evidence.
 */
const sources = ["src/background.ts", "src/content.ts", "src/popup.ts", "src/protocol.ts"];

const forbidden = [
  "localStorage",
  "sessionStorage",
  "indexedDB",
  "storage.set",
  "storage.local",
  "storage.sync",
  "storage.session",
  "console.",
];

test("extension sources persist no state and log no message or field values", async () => {
  for (const source of sources) {
    const text = await Bun.file(new URL(`../${source}`, import.meta.url).pathname).text();
    for (const pattern of forbidden) {
      expect(text.includes(pattern), `${source} must not use ${pattern}`).toBe(false);
    }
  }
});

test("content script transports no credential values and captures no submits", async () => {
  const text = await Bun.file(new URL("../src/content.ts", import.meta.url).pathname).text();
  expect(text.includes('"save-submitted"')).toBe(false);
  expect(text.includes("addEventListener(\"submit\"")).toBe(false);
  expect(text.includes(".value")).toBe(false);
});
