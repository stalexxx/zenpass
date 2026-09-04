import { expect, test } from "bun:test";
import { confirmFill, decideFill } from "../src/index.ts";

const candidate = { id: "item", title: "Entry", origin: "https://example.test" };
const safe = { pageUrl: "https://example.test/login", isTopFrame: true, formAction: "https://example.test/session", usernameVisible: true, passwordVisible: true };

test("offers only an exact HTTPS top-frame origin", () => {
  expect(decideFill(safe, [candidate])).toEqual({ allowed: true, candidates: [candidate] });
  expect(decideFill({ ...safe, pageUrl: "http://example.test" }, [candidate])).toEqual({ allowed: false, reason: "not-https" });
  expect(decideFill({ ...safe, pageUrl: "https://login.example.test", formAction: "https://login.example.test/session" }, [candidate])).toEqual({ allowed: false, reason: "no-exact-origin-match" });
  expect(decideFill({ ...safe, pageUrl: "https://example.test.attacker.invalid", formAction: "https://example.test.attacker.invalid/session" }, [candidate])).toEqual({ allowed: false, reason: "no-exact-origin-match" });
});

test("refuses frames, hidden fields, and cross-origin submissions", () => {
  expect(decideFill({ ...safe, isTopFrame: false }, [candidate])).toEqual({ allowed: false, reason: "not-top-frame" });
  expect(decideFill({ ...safe, passwordVisible: false }, [candidate])).toEqual({ allowed: false, reason: "hidden-field" });
  expect(decideFill({ ...safe, formAction: "https://attacker.invalid/collect" }, [candidate])).toEqual({ allowed: false, reason: "cross-origin-form" });
});

test("never treats a programmatic request as confirmation", () => {
  expect(confirmFill(false)).toEqual({ allowed: false, reason: "confirmation-required" });
  expect(confirmFill(true)).toEqual({ allowed: true });
});
