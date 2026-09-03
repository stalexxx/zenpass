/**
 * Digest tool for crypto fixture authors.
 *
 * Prints the normalized-record digest for each fixture file given. With
 * --write, embeds/updates `provenance.normalizedRecordSha256` in place and
 * normalizes the file to 2-space JSON formatting.
 *
 * Usage:
 *   bun run src/digest-tool.ts [--write] <fixture.json> [more.json ...]
 *
 * The tool only computes structural digests; it performs no cryptographic
 * operation on fixture content and never prints byte material.
 */
import { normalizedRecordDigest, parseDigestField, type JsonValue } from "./normalize.ts";

const args = process.argv.slice(2);
const values = { write: args.filter((a) => a === "--write").length > 0 };
const positionals = args.filter((a) => !a.startsWith("--"));

if (positionals.length === 0) {
  console.error("usage: bun run src/digest-tool.ts [--write] <fixture.json> [...]");
  process.exit(1);
}

let failed = false;
for (const file of positionals) {
  const text = await Bun.file(file).text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch (cause) {
    console.error(`${file}: malformed JSON (${(cause as Error).message})`);
    failed = true;
    continue;
  }
  if (json === null || typeof json !== "object" || Array.isArray(json)) {
    console.error(`${file}: fixture root must be a JSON object`);
    failed = true;
    continue;
  }
  const record = json as { id?: unknown; provenance?: Record<string, unknown> };
  const digest = `sha256:${normalizedRecordDigest(json as JsonValue)}`;
  const id = typeof record.id === "string" ? record.id : "(no id)";
  console.log(`${file} ${id} ${digest}`);

  const existing = record.provenance?.normalizedRecordSha256;
  const parsed = typeof existing === "string" ? parseDigestField(existing) : { ok: false as const };
  const embedded = parsed.ok && `sha256:${parsed.hex}` === digest;
  if (!embedded) {
    if (values.write) {
      const provenance = (record.provenance ?? {}) as Record<string, unknown>;
      provenance.normalizedRecordSha256 = digest;
      record.provenance = provenance;
      await Bun.write(file, `${JSON.stringify(record, null, 2)}\n`);
      console.log(`${file}: digest embedded (--write)`);
    } else {
      console.log(`${file}: digest not embedded; rerun with --write to embed`);
    }
  }
}
process.exit(failed ? 1 : 0);
