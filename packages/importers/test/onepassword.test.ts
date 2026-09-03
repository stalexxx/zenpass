import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { normalizeOnePasswordCsv } from "../src/onepassword.ts";

const fixture = (name: string) => readFileSync(join(import.meta.dir, "fixtures", name), "utf8");

test("normalizes a 1Password classic CSV export", () => {
  const result = normalizeOnePasswordCsv(fixture("onepassword.csv"));
  expect(result.items).toHaveLength(1);
  expect(result.items[0]).toMatchObject({
    title: "Example",
    username: "alice",
    password: "hunter2",
    url: "https://example.com",
    notes: "an example note",
    source: "1password",
  });
});

test("malformed 1Password CSV never throws", () => {
  const result = normalizeOnePasswordCsv("Title,Website\nOnlyTitle\n");
  expect(result.items.length).toBeGreaterThanOrEqual(0);
});
