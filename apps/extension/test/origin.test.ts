import { describe, expect, test } from "bun:test";
import { confirmApiOrigin, pinnedFetch } from "../src/origin.ts";

describe("confirmApiOrigin", () => {
  test("accepts a bare HTTPS origin, with or without a trailing slash", () => {
    expect(confirmApiOrigin("https://api.example.test")).toEqual({ origin: "https://api.example.test" });
    expect(confirmApiOrigin("https://api.example.test/")).toEqual({ origin: "https://api.example.test" });
    expect(confirmApiOrigin("https://api.example.test:8443")).toEqual({ origin: "https://api.example.test:8443" });
  });

  test("rejects plain HTTP", () => {
    expect(confirmApiOrigin("http://api.example.test")).toBeNull();
  });

  test("rejects URL credentials", () => {
    expect(confirmApiOrigin("https://user:pass@api.example.test")).toBeNull();
  });

  test("rejects query/fragment configuration", () => {
    expect(confirmApiOrigin("https://api.example.test?x=1")).toBeNull();
    expect(confirmApiOrigin("https://api.example.test#frag")).toBeNull();
  });

  test("rejects a non-root path", () => {
    expect(confirmApiOrigin("https://api.example.test/v1")).toBeNull();
  });

  test("rejects malformed/empty/oversized input", () => {
    expect(confirmApiOrigin("")).toBeNull();
    expect(confirmApiOrigin("not a url")).toBeNull();
    expect(confirmApiOrigin("https://" + "a".repeat(600) + ".test")).toBeNull();
  });
});

describe("pinnedFetch", () => {
  test("refuses a request URL outside the confirmed origin", async () => {
    const fetchImpl = pinnedFetch("https://api.example.test");
    await expect(fetchImpl("https://evil.invalid/x")).rejects.toThrow();
  });

  test("refuses a redirect response instead of following it", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(null, { status: 302, headers: { location: "https://evil.invalid/" } })) as typeof fetch;
    try {
      const fetchImpl = pinnedFetch("https://api.example.test");
      await expect(fetchImpl("https://api.example.test/health")).rejects.toThrow();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("passes through a normal same-origin response", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response("ok", { status: 200 })) as typeof fetch;
    try {
      const fetchImpl = pinnedFetch("https://api.example.test");
      const response = await fetchImpl("https://api.example.test/health");
      expect(response.status).toBe(200);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
