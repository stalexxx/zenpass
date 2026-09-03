# crypto-fixtures

Dependency-free Bun harness for `crypto-envelope/v1` test fixtures
(`fixtures/crypto/`).

**Status: planning artifact for H01. H01 remains BLOCKED. This harness and its
outputs are not H01 evidence and approve nothing.**

## Boundary

Per `docs/security/H01-CRYPTO-FIXTURES-VERIFIER-PLAN.md`, this harness:

- consumes public, test-only fixture inputs and expected outcomes only;
- performs **structural, schema, and non-cryptographic checks** (encoding
  prefixes, sizes, bounds, uniqueness, case coverage, digests);
- relays cryptographic operations to a separately supplied **validator
  adapter** over a versioned line-oriented JSON protocol;
- never implements or performs any cryptographic operation itself;
- never imports `crates/crypto-core`, bindings, application code, or any
  production crypto implementation;
- adds no dependencies (Bun built-ins only).

All keys, nonces, passwords, and OPAQUE inputs in the fixtures are test-only.
Harness output never prints fixture byte material, plaintexts, passwords,
OPAQUE secrets, or recovery material — only fixture ids, operation names,
check names, pass/fail counts, and digests.

## Commands

```text
bun run --filter crypto-fixtures test:structure   # structural/schema checks only
bun run --filter crypto-fixtures test             # structure + validator adapter; FAILS CLOSED
bun run --filter crypto-fixtures test:unit        # harness self-tests (protocol plumbing)
```

`test` fails closed (non-zero exit) when no validator adapter is configured.
Configure the adapter with `CRYPTO_FIXTURES_ADAPTER` or `--adapter` (see
"Validator adapter" below).

## Fixture digests

Every fixture carries a `provenance` block with `normalizedRecordSha256`, the
SHA-256 of its normalized record (full JSON minus the digest field itself,
recursively sorted keys, no whitespace). The harness recomputes and
cross-checks it against the package manifest. Authors update digests with:

```text
bun run fixtures:digest -- --write ../../fixtures/crypto/<file>.json
```

The full adapter protocol, manifest format, and known coverage gaps are
documented in the sections below.

## Validator adapter

The adapter is an executable supplied by the reviewer; it is not bundled and
is never imported by this package. Set `CRYPTO_FIXTURES_ADAPTER` to its command
line (or pass `--adapter <command>`). The harness writes one JSON object per
line to stdin and expects one response object per line on stdout.

Every request has this shape and uses protocol version
`crypto-fixtures-adapter/1`:

```json
{"protocol":"crypto-fixtures-adapter/1","caseId":"...","operation":"canonical-cbor|envelope|aead|wrap|opaque","inputs":{},"expected":{"outcome":"pass"}}
```

The adapter must respond with exactly one record for every request:

```json
{"caseId":"...","operation":"...","outcome":"pass"}
{"caseId":"...","operation":"...","outcome":"reject","error":"NonCanonicalCbor"}
```

The harness rejects malformed JSON, unknown or duplicate case IDs, missing
cases, operation mismatches, unknown typed errors, non-zero adapter exits, and
outcomes/errors that differ from the fixture manifest. Adapter output is not
trusted as evidence until independently reviewed by H01.

## Manifest and structural rules

The loader declares every JSON file in `fixtures/crypto/` and maps it to the
operations above. IDs and case IDs are unique. All opaque byte fields use
lowercase even-length `hex:` or padded standard `b64:`; unknown prefixes are
rejected. Contract sizes (32-byte keys, 24-byte nonces, 16-byte tags, 16-byte
KDF salts, 32-byte KDF output, and 48-byte wrapped-key output) are checked
without decoding or performing cryptographic operations. Each fixture carries
test-only provenance and a normalized SHA-256 record digest.

## Known gaps and blockers

- **G-09 (recovery-wrap positive vector, blocked):**
  `fixtures/crypto/recovery-semantics.json` carries an explicitly marked
  48-byte structural placeholder (`ciphertextIsPlaceholder: true`), sized to
  the contract expectation (32-byte wrapped AccountKey + 16-byte tag). A real
  positive vector cannot be added in this rework: no authoritative external
  source exists for this contract-specific construction, and generating one
  would require an approved cryptographic implementation (library selection is
  H01/G-06 reviewer work). Routed to H01 as a blocker.
- **G-03 (wrap vectors):** no authoritative, reproducible source was found
  for the contract-specific AAD/key hierarchy construction. No wrap vector is
  claimed here; the gap remains explicit for H01. The recovery placeholder is
  likewise excluded from adapter cases.
- **Derived negatives:** tamper cases are declared behavioral expectations
  derived from a positive source vector; they are not claimed as authoritative
  source vectors.
