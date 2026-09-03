import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { normalizeCsv } from "../src/csv.ts";
import { ImportSizeError, MAX_INPUT_CHARS } from "../src/limits.ts";

const fixture = (name: string) => readFileSync(join(import.meta.dir, "fixtures", name), "utf8");

test("normalizes a well-formed generic CSV including quoted/embedded-newline fields", () => {
  const result = normalizeCsv(fixture("generic.csv"));
  expect(result.items).toHaveLength(2);
  expect(result.items[0]).toMatchObject({
    title: "Example Site",
    username: "alice",
    password: "hunter2",
    url: "https://example.com/login",
    notes: "first line\nsecond line",
    totp: { secret: "JBSWY3DPEHPK3PXP" },
    source: "csv",
  });
  expect(result.items[1]).toMatchObject({ title: "Quoted, Title", username: "bob", password: 'pa"ss' });
  expect(result.issues).toHaveLength(0);
});

test("malformed/adversarial CSV never throws and reports issues instead of crashing", () => {
  const result = normalizeCsv(fixture("generic-malformed.csv"));
  // Must not throw (implicit: reaching here). A row missing Password still
  // gets a title-only record; nothing is silently fabricated.
  expect(result.items.length).toBeGreaterThan(0);
  expect(result.items[0]).toMatchObject({ title: "NoValueForPassword", username: "someone" });
});

test("CSV with no recognizable header yields no items and one issue, not a guess", () => {
  const result = normalizeCsv("a,b,c\n1,2,3\n");
  expect(result.items).toHaveLength(0);
  expect(result.issues).toHaveLength(1);
});

test("oversized input is rejected before parsing", () => {
  expect(() => normalizeCsv("x".repeat(MAX_INPUT_CHARS + 1))).toThrow(ImportSizeError);
});

test("empty input yields no items and no crash", () => {
  const result = normalizeCsv("");
  expect(result.items).toHaveLength(0);
});
