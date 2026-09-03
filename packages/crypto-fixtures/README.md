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

To be completed with the adapter protocol specification (G-01 delivery).

## Known gaps and blockers

To be completed (G-03 wrap vectors, G-09 recovery placeholder).
