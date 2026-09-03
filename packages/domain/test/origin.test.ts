import { expect, test } from "bun:test";
import { matchOrigin, itemMatchesPageOrigin } from "../src/origin.ts";

test("exact match: same scheme, host, and port", () => {
  expect(matchOrigin("https://example.com", "https://example.com").matches).toBe(true);
});

test("exact match tolerates explicit default port on either side", () => {
  expect(matchOrigin("https://example.com:443", "https://example.com").matches).toBe(true);
  expect(matchOrigin("https://example.com", "https://example.com:443/login").matches).toBe(true);
});

test("scheme mismatch never matches", () => {
  const result = matchOrigin("http://example.com", "https://example.com");
  expect(result.matches).toBe(false);
  expect(result.reason).toBe("scheme-mismatch");
});

test("http page never matches an https-only recorded item", () => {
  expect(matchOrigin("https://example.com", "http://example.com").matches).toBe(false);
});

test("port mismatch never matches", () => {
  const result = matchOrigin("https://example.com:8443", "https://example.com:443");
  expect(result.matches).toBe(false);
  expect(result.reason).toBe("port-mismatch");
});

test("subdomain never matches its parent domain, in either direction", () => {
  expect(matchOrigin("https://app.example.com", "https://example.com").matches).toBe(false);
  expect(matchOrigin("https://example.com", "https://app.example.com").matches).toBe(false);
});

test("distinct subdomains of the same parent never match each other", () => {
  expect(matchOrigin("https://a.example.com", "https://b.example.com").matches).toBe(false);
});

test("look-alike / phishing domains never match: substring and suffix tricks fail", () => {
  expect(matchOrigin("https://example.com", "https://example.com.evil.tld").matches).toBe(false);
  expect(matchOrigin("https://example.com", "https://notexample.com").matches).toBe(false);
  expect(matchOrigin("https://example.com", "https://example-com.tld").matches).toBe(false);
  expect(matchOrigin("https://example.com", "https://xn--example-com.tld").matches).toBe(false);
});

test("unparseable input never matches (fails closed)", () => {
  expect(matchOrigin("not a url", "https://example.com").matches).toBe(false);
  expect(matchOrigin("https://example.com", "").matches).toBe(false);
  expect(matchOrigin("javascript:alert(1)", "https://example.com").matches).toBe(false);
});

test("itemMatchesPageOrigin matches if any recorded url matches", () => {
  expect(
    itemMatchesPageOrigin(["https://other.example", "https://example.com"], "https://example.com"),
  ).toBe(true);
  expect(itemMatchesPageOrigin(["https://other.example"], "https://example.com")).toBe(false);
  expect(itemMatchesPageOrigin([], "https://example.com")).toBe(false);
});
