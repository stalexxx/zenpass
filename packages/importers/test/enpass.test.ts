import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { normalizeEnpassJson } from "../src/enpass.ts";

const fixture = (name: string) => readFileSync(join(import.meta.dir, "fixtures", name), "utf8");

test("normalizes a well-formed Enpass JSON export", () => {
  const result = normalizeEnpassJson(fixture("enpass.json"));
  expect(result.items).toHaveLength(2);
  expect(result.items[0]).toMatchObject({
    title: "Example",
    username: "alice",
    password: "hunter2",
    url: "https://example.com",
    notes: "an example note",
    totp: { secret: "JBSWY3DPEHPK3PXP" },
    source: "enpass",
  });
  expect(result.items[1]).toMatchObject({ title: "No fields at all" });
  expect(result.items[1].username).toBeUndefined();
});

test("malformed Enpass JSON never throws", () => {
  const result = normalizeEnpassJson('{ "items": [ 42, { "fields": "not-an-array" }, {} ] }');
  expect(result.items.length).toBeGreaterThanOrEqual(0);
  expect(result.issues.length).toBeGreaterThan(0);
});

test("invalid JSON syntax never throws", () => {
  const result = normalizeEnpassJson("not json at all");
  expect(result.items).toHaveLength(0);
  expect(result.issues[0].reason).toContain("invalid JSON");
});
