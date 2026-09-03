import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { normalizeBitwardenJson } from "../src/bitwarden.ts";

const fixture = (name: string) => readFileSync(join(import.meta.dir, "fixtures", name), "utf8");

test("normalizes a well-formed Bitwarden JSON export", () => {
  const result = normalizeBitwardenJson(fixture("bitwarden.json"));
  expect(result.items).toHaveLength(2);
  expect(result.items[0]).toMatchObject({
    title: "Example",
    username: "alice",
    password: "hunter2",
    url: "https://example.com",
    otherUrls: ["https://m.example.com"],
    notes: "some note",
    folder: "Personal",
    source: "bitwarden",
  });
  expect(result.items[0].totp?.secret).toContain("otpauth://");
  // A secure-note-type item (no `login`) is preserved as a title/notes
  // record, not dropped and not given a fabricated password.
  expect(result.items[1]).toMatchObject({ title: "Secure note only", notes: "just text" });
  expect(result.items[1].password).toBeUndefined();
});

test("malformed/adversarial Bitwarden JSON never throws and reports issues", () => {
  const result = normalizeBitwardenJson(fixture("bitwarden-malformed.json"));
  expect(result.issues.length).toBeGreaterThan(0);
  // The non-object array entry and the nameless item are both skipped with
  // issues; only the "no login section" item has a title and survives.
  expect(result.items).toHaveLength(1);
});

test("invalid JSON syntax never throws, reported as an issue", () => {
  const result = normalizeBitwardenJson("{ not json");
  expect(result.items).toHaveLength(0);
  expect(result.issues[0].reason).toContain("invalid JSON");
});

test("non-Bitwarden-shaped JSON (e.g. an array) is rejected as an issue, not crashed on", () => {
  const result = normalizeBitwardenJson("[1,2,3]");
  expect(result.items).toHaveLength(0);
  expect(result.issues).toHaveLength(1);
});
