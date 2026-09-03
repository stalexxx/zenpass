// Shared vocabulary for "one item from any password manager's export,
// before encryption". Import normalizers (packages/importers) produce
// these; a caller (a later client task, e.g. C01) is the one who owns the
// plaintext window and is responsible for encrypting a NormalizedItem
// (via packages/crypto-wasm) before it is ever persisted or transmitted.
//
// NOTHING in packages/domain or packages/importers may log, persist, or
// transmit a NormalizedItem or any field of it. It exists only as an
// in-memory intermediate shape.

/** A single TOTP secret carried by an imported item, if the source format
 * had one. `secret` is the raw base32 (or otherwise encoded, as the source
 * format stored it) secret string — never decoded/validated as a live OTP
 * here, that is out of scope for a normalizer. */
export interface NormalizedTotp {
  secret: string;
  /** otpauth-style algorithm/digits/period, when the source recorded them.
   * Left undefined when the source only carried the bare secret. */
  algorithm?: string;
  digits?: number;
  periodSeconds?: number;
}

/** Common intermediate item shape every importer normalizes into. All
 * fields except `title` are optional because source formats vary in what
 * they carry; a normalizer must never invent a value a source did not
 * provide. */
export interface NormalizedItem {
  title: string;
  username?: string;
  password?: string;
  /** The item's associated URL or origin, verbatim from the source
   * (not yet parsed/validated as an origin — see packages/domain's
   * origin-matching module for that). When a source lists multiple URLs,
   * the first is used here and the rest go in `otherUrls`. */
  url?: string;
  otherUrls?: string[];
  notes?: string;
  totp?: NormalizedTotp;
  /** Free-form source-provided grouping (folder/collection name), kept for
   * caller-side organization; never used for any security decision. */
  folder?: string;
  /** Which normalizer produced this record, for caller-side diagnostics. */
  source: "enpass" | "1password" | "bitwarden" | "csv";
}

/** Non-fatal problem encountered while normalizing one source record
 * (e.g. a row with no recognizable password field). Import functions
 * report these instead of silently dropping or crashing on adversarial
 * input (T16, docs/security/THREAT-MODEL.md). */
export interface NormalizeIssue {
  index: number;
  reason: string;
}

export interface NormalizeResult {
  items: NormalizedItem[];
  issues: NormalizeIssue[];
}
