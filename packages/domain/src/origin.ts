// Origin matching for autofill (T06, docs/security/THREAT-MODEL.md:
// "Phishing/autofill exfiltration — exact origin matching; no HTTP
// autofill; confirmation for ambiguous/look-alike/cross-origin/new forms").
//
// This module is a pure function. It implements no UI and triggers no
// autofill itself; a later client task (C01) calls it to decide whether a
// stored item is eligible to be offered on the page currently open.
//
// Security invariants (deliberately conservative defaults):
//   - Matching is exact: scheme + hostname + port must all match. No
//     substring, prefix, suffix, or "same registrable domain" matching —
//     any of those are exactly what a look-alike/phishing domain can
//     satisfy (e.g. "example.com.evil.tld" or "not-example.com").
//   - Subdomains never match their parent, or each other. "app.example.com"
//     and "example.com" are different origins here, full stop. (A caller
//     that wants configurable subdomain trust can build it on top of this
//     function later — it is not this function's job to guess.)
//   - An item recorded only under an https origin never matches an http
//     page, even same host/port-normalized. An item recorded under http
//     matches only an http page (never silently upgraded to also match
//     https) — origins are compared as recorded, not coerced.
//   - A malformed/unparseable URL on either side never matches (fails
//     closed).

export type OriginMatchReason =
  | "exact"
  | "scheme-mismatch"
  | "host-mismatch"
  | "port-mismatch"
  | "unparseable";

export interface OriginMatchResult {
  matches: boolean;
  reason: OriginMatchReason;
}

interface ParsedOrigin {
  scheme: string;
  host: string;
  port: string;
}

const DEFAULT_PORTS: Record<string, string> = {
  "http:": "80",
  "https:": "443",
};

/** Parses a URL or bare origin string into scheme/host/port, or returns
 * null if it isn't a well-formed absolute URL. Ports are normalized to
 * their scheme default when omitted so "https://example.com" and
 * "https://example.com:443" compare equal, but no other normalization is
 * applied (host is lowercased per URL semantics only, never trimmed of
 * subdomains or otherwise rewritten). */
export function parseOrigin(input: string): ParsedOrigin | null {
  if (typeof input !== "string" || input.length === 0 || input.length > 4096) return null;
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (!url.hostname) return null;
  const scheme = url.protocol;
  const port = url.port || DEFAULT_PORTS[scheme] || "";
  return { scheme, host: url.hostname.toLowerCase(), port };
}

/** Decides whether `itemOrigin` (the origin recorded against a stored
 * item) is an exact match for `pageOrigin` (the origin of the page
 * currently requesting autofill). Strict default: identical scheme, host,
 * and port. Never true for a scheme, host, or port mismatch, and never
 * true if either input fails to parse as an absolute URL. */
export function matchOrigin(itemOrigin: string, pageOrigin: string): OriginMatchResult {
  const item = parseOrigin(itemOrigin);
  const page = parseOrigin(pageOrigin);
  if (!item || !page) return { matches: false, reason: "unparseable" };
  if (item.scheme !== page.scheme) return { matches: false, reason: "scheme-mismatch" };
  if (item.host !== page.host) return { matches: false, reason: "host-mismatch" };
  if (item.port !== page.port) return { matches: false, reason: "port-mismatch" };
  return { matches: true, reason: "exact" };
}

/** Convenience over an item's `url`/`otherUrls` list: true if any recorded
 * origin exactly matches the page origin. */
export function itemMatchesPageOrigin(
  itemUrls: readonly string[],
  pageOrigin: string,
): boolean {
  return itemUrls.some((u) => matchOrigin(u, pageOrigin).matches);
}
