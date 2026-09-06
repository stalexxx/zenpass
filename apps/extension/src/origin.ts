/**
 * D1 independent-unlock origin confirmation (ADR-0011: "The configured API
 * must be an explicitly confirmed HTTPS origin, pinned per account
 * association. Reject URL credentials, query/fragment configuration,
 * cross-origin redirects, and API destinations supplied by page/content
 * messages."). This module only ever validates a popup-entered string; it
 * is never fed a value that originated from a content script or page.
 */

const MAX_ORIGIN_LENGTH = 512;

export type ConfirmedApiOrigin = { readonly origin: string };

/** Validates and normalizes a popup-entered API origin string. Accepts
 * only a bare HTTPS origin (optionally trailing slash) with no userinfo,
 * path (other than `/`), query, or fragment. Returns null for anything
 * else — including a bare hostname (ambiguous scheme), `http://`, or a
 * URL carrying extra configuration. */
export function confirmApiOrigin(input: string): ConfirmedApiOrigin | null {
  if (typeof input !== "string" || input.length === 0 || input.length > MAX_ORIGIN_LENGTH) return null;
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username !== "" || url.password !== "") return null;
  if (url.search !== "" || url.hash !== "") return null;
  if (url.pathname !== "" && url.pathname !== "/") return null;
  if (!url.hostname) return null;
  return { origin: url.origin };
}

/** Wraps `fetch` so every request is pinned to `origin` and never follows
 * a redirect (same-origin or cross-origin) — a redirect response is
 * treated as a hard failure rather than silently followed, since an
 * honest API never needs one for these routes and a malicious/compromised
 * network path redirecting to a different origin must not be trusted
 * transparently. */
export function pinnedFetch(origin: string): typeof fetch {
  return async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (!url.startsWith(origin)) {
      throw new Error("pinnedFetch: request URL is not within the confirmed API origin");
    }
    const response = await fetch(input, { ...init, redirect: "manual" });
    if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
      throw new Error("pinnedFetch: refusing to follow a redirect");
    }
    return response;
  };
}
