// T16 (docs/security/THREAT-MODEL.md: "Malicious import/export file") —
// every normalizer in this package treats its input as adversarial:
// bounded size, no crash on malformed/truncated/oversized input, no
// partial silent writes (a normalizer either returns a NormalizeResult or
// throws before touching any output array — it never appends a
// half-built item and calls it done).

/** Hard ceiling on a raw import file's size in characters. Anything over
 * this is rejected outright rather than parsed — an import this large is
 * far outside any real password-manager export and is far more likely to
 * be a denial-of-service attempt than legitimate data. */
export const MAX_INPUT_CHARS = 25_000_000; // ~25 MB of text

/** Hard ceiling on the number of records a normalizer will emit from one
 * file. Extra records past this are dropped with a NormalizeIssue rather
 * than processed, to bound memory use against a crafted file containing
 * millions of trivial rows. */
export const MAX_ITEMS = 50_000;

/** Per-field length ceiling. Applied to every string field pulled out of
 * source data before it is placed on a NormalizedItem, so a single
 * pathological field (e.g. a multi-megabyte "notes" value) cannot blow up
 * downstream consumers (encryption, storage, UI rendering). Values over
 * this are truncated, not dropped — the record stays a usable partial
 * import and the truncation is recorded as an issue. */
export const MAX_FIELD_CHARS = 100_000;

export class ImportSizeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImportSizeError";
  }
}

export function assertInputSize(input: string): void {
  if (typeof input !== "string") {
    throw new ImportSizeError("import input must be a string");
  }
  if (input.length > MAX_INPUT_CHARS) {
    throw new ImportSizeError(
      `import input exceeds maximum size of ${MAX_INPUT_CHARS} characters`,
    );
  }
}

/** Truncates a possibly-oversized string field to MAX_FIELD_CHARS,
 * returning both the (possibly truncated) value and whether truncation
 * happened. Never throws. */
export function boundField(value: unknown): { value: string | undefined; truncated: boolean } {
  if (typeof value !== "string" || value.length === 0) return { value: undefined, truncated: false };
  if (value.length <= MAX_FIELD_CHARS) return { value, truncated: false };
  return { value: value.slice(0, MAX_FIELD_CHARS), truncated: true };
}
