import { readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { byteFieldLength, scanByteFields } from "./encodings.ts";
import { FIXTURE_FORMAT_REVISION, OPERATION_SET, TYPED_ERROR_SET } from "./constants.ts";
import { normalizedRecordDigest, parseDigestField, type JsonValue } from "./normalize.ts";
import { MANIFEST } from "./manifest.ts";

export type Fixture = Record<string, any> & { id: string };
export type Case = { caseId: string; operation: string; inputs: unknown; expected: { outcome: "pass" | "reject"; error?: string } };
export type Loaded = { fixtures: Fixture[]; cases: Case[]; manifestDigest: string };

const root = resolve(import.meta.dir, "../../..");
export const fixtureDir = join(root, "fixtures/crypto");

function fail(file: string, message: string): never { throw new Error(`${file}: ${message}`); }
function addCase(cases: Case[], seen: Set<string>, file: string, c: Case) {
  if (seen.has(c.caseId)) fail(file, `duplicate case id ${c.caseId}`);
  if (!OPERATION_SET.has(c.operation)) fail(file, `unknown operation ${c.operation}`);
  if (c.expected.outcome === "reject" && (!c.expected.error || !TYPED_ERROR_SET.has(c.expected.error))) fail(file, `reject case ${c.caseId} must name a typed error`);
  cases.push(c); seen.add(c.caseId);
}

function requiredLength(f: Fixture, file: string, path: string, n: number) {
  const parts = path.split("."); let v: any = f;
  for (const p of parts) v = v?.[p];
  const r = byteFieldLength(v); if (!r.ok) fail(file, `${path}: ${r.error}`);
  if (r.byteLength !== n) fail(file, `${path}: expected ${n} bytes`);
}

export async function loadFixtures(): Promise<Loaded> {
  const files = (await readdir(fixtureDir)).filter((f) => f.endsWith(".json")).sort();
  if (!files.length) throw new Error("fixtures/crypto: no JSON fixtures found");
  const fixtures: Fixture[] = []; const cases: Case[] = []; const seenIds = new Set<string>(); const seenCases = new Set<string>();
  for (const name of files) {
    const file = `fixtures/crypto/${name}`; let f: Fixture;
    const declaration = MANIFEST[name as keyof typeof MANIFEST];
    if (!declaration) fail(file, "fixture is not declared in manifest");
    try { f = JSON.parse(await Bun.file(join(fixtureDir, name)).text()); } catch { fail(file, "malformed JSON"); }
    if (!f || typeof f !== "object" || Array.isArray(f)) fail(file, "root must be an object");
    if (typeof f.id !== "string" || !f.id) fail(file, "id is required");
    if (seenIds.has(f.id)) fail(file, `duplicate fixture id ${f.id}`); seenIds.add(f.id); fixtures.push(f);
    for (const key of declaration.required) if (!(key in f)) fail(file, `manifest-required field '${key}' is missing`);
    const scan = scanByteFields(f); if (!scan.ok) fail(file, `${scan.path}: ${scan.error}`);
    if (!f.provenance || f.provenance.fixtureFormatRevision !== FIXTURE_FORMAT_REVISION || f.provenance.classification !== "test-only") fail(file, "provenance must declare fixture revision and test-only classification");
    const d = parseDigestField(f.provenance.normalizedRecordSha256); if (!d.ok || d.hex !== normalizedRecordDigest(f as JsonValue)) fail(file, "normalizedRecordSha256 does not match fixture");

    if (name === "aad-item-payload.json") {
      addCase(cases, seenCases, file, { caseId: `${f.id}:positive`, operation: "canonical-cbor", inputs: f.input, expected: { outcome: "pass" } });
      for (const n of f.nonCanonical ?? []) addCase(cases, seenCases, file, { caseId: `${f.id}:${n.case}`, operation: "canonical-cbor", inputs: n, expected: { outcome: "reject", error: n.error } });
    } else if (name === "kdf-parameters.json") {
      requiredLength(f, file, "parameters.salt", 16); if (f.parameters.outputLength !== 32) fail(file, "outputLength must be 32");
      addCase(cases, seenCases, file, { caseId: `${f.id}:positive`, operation: "canonical-cbor", inputs: f.parameters, expected: { outcome: "pass" } });
      for (const n of [...(f.canonicalReject ?? []), ...(f.negative ?? [])]) addCase(cases, seenCases, file, { caseId: `${f.id}:${n.case}`, operation: "canonical-cbor", inputs: n, expected: { outcome: "reject", error: n.error } });
    } else if (name === "envelope-malformed.json") {
      requiredLength(f, file, "validEnvelopeShape.nonce", 24); addCase(cases, seenCases, file, { caseId: `${f.id}:positive-structure`, operation: "envelope", inputs: f.validEnvelopeShape, expected: { outcome: "pass" } });
      for (const n of f.reject ?? []) addCase(cases, seenCases, file, { caseId: `${f.id}:${n.case}`, operation: "envelope", inputs: n, expected: { outcome: "reject", error: n.error } });
    } else if (name === "aead-xchacha20poly1305.json") {
      requiredLength(f, file, "key", 32); requiredLength(f, file, "nonce", 24); const ct = byteFieldLength(f.ciphertextTag); if (!ct.ok || ct.byteLength < 16) fail(file, "ciphertextTag must include a 16-byte tag");
      addCase(cases, seenCases, file, { caseId: `${f.id}:positive`, operation: "aead", inputs: f, expected: { outcome: "pass" } }); for (const n of f.negative ?? []) addCase(cases, seenCases, file, { caseId: `${f.id}:${n.case}`, operation: "aead", inputs: n, expected: { outcome: "reject", error: n.error } });
    } else if (name === "opaque-3dh-ristretto255.json") {
      addCase(cases, seenCases, file, { caseId: `${f.id}:positive`, operation: "opaque", inputs: f, expected: { outcome: "pass" } }); for (const n of f.negative ?? []) addCase(cases, seenCases, file, { caseId: `${f.id}:${n.case}`, operation: "opaque", inputs: n, expected: { outcome: "reject", error: n.error } });
    } else if (name === "recovery-semantics.json") {
      requiredLength(f, file, "recoveryKey", 32); requiredLength(f, file, "recoveryWrappedAccountKey.nonce", 24); const ct = byteFieldLength(f.recoveryWrappedAccountKey.ciphertext); if (!ct.ok || ct.byteLength !== 48) fail(file, "recovery placeholder must be 48 bytes"); if (f.ciphertextIsPlaceholder !== true) fail(file, "recovery ciphertext must be explicitly marked placeholder");
    } else fail(file, "fixture is not declared in manifest");
  }
  const manifestDigest = normalizedRecordDigest(cases as unknown as JsonValue);
  return { fixtures, cases, manifestDigest };
}
