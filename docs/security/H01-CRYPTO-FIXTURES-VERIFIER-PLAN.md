# H01 follow-up: crypto-fixtures verifier plan (G-01..G-05)

Status: **planning only; no vectors have been verified by this plan.**

## Purpose and boundary

This plan resolves the delivery gap, not the cryptographic design.  It makes
`bun run --filter crypto-fixtures test` a reproducible fixture harness and
defines the separately run evidence required for H01 independent validation.
It does not select a library, add a dependency, implement a cryptographic
primitive, modify `crypto-envelope/v1`, or approve any fixture.

The future harness is a test consumer of public, test-only inputs and expected
outputs.  It must not import `crates/crypto-core`, bindings, application code,
or a production crypto implementation.  It must not generate cryptographic
results.  A validator adapter, supplied by the reviewer or an independently
selected reference environment, performs cryptographic operations outside the
harness.  The adapter must be independently implemented from the Rust
crypto-core and must be recorded in ADR-0003 before its results count as H01
evidence.

Fixed keys, nonces, passwords, and OPAQUE inputs in these fixtures are
test-only.  No production vault data, credentials, recovery kits, or secrets
may be added.

## Required ownership and path change

The integrator must return A04 to `READY` and amend its dispatch scope before
assigning the rework.  The A04 crypto-spec agent owns G-01 through G-04 and
G-11; the human H01 reviewer owns G-05 evidence recording and its conclusion.

| Owner | Work | Exact allowed paths | Explicitly excluded |
|---|---|---|---|
| Integrator (before dispatch) | Amend the A04 task definition and status/DAG routing | `docs/tasks/A04.md`, `docs/plan/STATUS.md` | Contract, fixtures, implementation |
| A04 crypto-spec agent | Build the dependency-free Bun harness; add/correct public test vectors and negative cases | `packages/crypto-fixtures/**`, `fixtures/crypto/**` | `crates/crypto-core/**`, all application code, `docs/contracts/crypto-envelope-v1.md`, production dependencies and lockfiles |
| Human H01 reviewer | Choose and run an independent validator, review outputs, and record exact evidence/finding dispositions | `docs/security/H01-REVIEW-CHECKLIST.md`, `docs/decisions/ADR-0003-crypto-envelope-v1-approval.md` | Fixture mutation, production code, contract edits |

The A04 amendment must retain its existing allowed documentation paths and add
only `packages/crypto-fixtures/**` to the agent's implementation scope.  The
existing root workspace glob already includes `packages/*`; therefore no root
`package.json` change is needed for this package.  The task must state that
`bun`, not pnpm, is the sole package command.  It must also state that adding
a dependency, changing a fixture schema that changes normative meaning, or
changing the crypto contract is out of scope and requires a separately
approved decision.

## Harness deliverable (G-01)

Create workspace package `packages/crypto-fixtures/` named
`crypto-fixtures`, with a `test` script runnable as:

```text
bun run --filter crypto-fixtures test
```

The package uses Bun's built-in runtime and test facilities only.  Its stable
responsibilities are:

1. Load every declared JSON fixture from `fixtures/crypto/` by repository-root
   relative path, reject malformed JSON and unknown encoding prefixes, and
   report fixture id plus assertion name without echoing byte material.
2. Enforce the fixture manifest/schema: unique ids; `hex:` byte fields have
   even, lowercase hexadecimal; `b64:` fields use padded standard RFC 4648;
   required expected result and typed-error fields are present; and all
   positive/negative vector identifiers are unique.
3. Validate non-cryptographic invariants: sizes required by the frozen
   contract (key 32, nonce 24, AEAD tag 16, KDF salt 16/output 32), ciphertext
   length expectations, case coverage, and the exact typed error named for
   each negative vector.
4. Invoke a validator adapter through a versioned line-oriented JSON protocol
   for canonical-CBOR, AEAD, wrapping, and OPAQUE operations.  The harness
   checks only that the adapter response is well formed and matches the
   fixture's expected pass/fail result; it never performs the operation itself.
5. Provide two modes: `test:structure` for steps 1--3, and `test` for
   structure plus all adapters.  `test` fails closed if the configured adapter
   is absent, exits non-zero, omits a required case, returns an unknown case,
   or reports a result different from the fixture.  CI must run `test`, not
   only `test:structure`.

The adapter command is passed explicitly by environment variable or command
line documented in the package README; the plan intentionally does not name
the variable, executable, library, language, or version.  Harness output may
contain fixture ids, operation names, pass/fail counts, tool version, and a
digest of normalized result records.  It must not print test key bytes,
plaintexts, passwords, OPAQUE secrets, or recovery material.

## Fixture and adapter protocol

Before adding vectors, A04 defines a JSON fixture manifest in the package
documentation and tests it against all fixture files.  The manifest must map
each vector to one operation and require opaque byte fields to use the existing
`hex:`/`b64:` convention.  A normalized request contains only `caseId`,
`operation`, `inputs`, and `expected`; a response contains `caseId`,
`operation`, `outcome` (`pass` or `reject`), and for rejects the normative
typed error.  The response never carries plaintext or key material.  The
harness canonicalizes result records solely to calculate an evidence digest.

The protocol must support this matrix.  It is deliberately an adapter
interface, not a second crypto API.

| Operation | Positive evidence required | Negative evidence required |
|---|---|---|
| `canonical-cbor` | Decode then canonical re-encode equals supplied bytes; semantic map equals fixture fields | non-minimal integer (including G-11 regression), unordered keys, duplicate keys, indefinite lengths, tags, floats, and unknown outer keys reject as `NonCanonicalCbor` or `UnknownField` as applicable |
| `aead` | XChaCha20-Poly1305 encryption exactly equals supplied `ciphertext || tag`; decryption returns the fixture's declared test plaintext | one-byte changes in ciphertext, final tag byte, nonce, and AAD reject as `AuthenticationFailed` or `InvalidNonce`/`InvalidContext` as applicable |
| `wrap` | One vector for each `account-wrap`, `recovery-wrap`, `vault-wrap`, and `item-wrap`; each supplies wrapping key, 32-byte wrapped key, nonce, canonical AAD, exact output, and successful unwrap | wrong wrapping key, wrong kind, changed account/vault/item id, changed key version, changed nonce/ciphertext/tag all reject without returning key bytes |
| `opaque` | RFC 9807 Ristretto255 registration and login transcript vectors, with expected message bytes and successful client/server outcomes | tampered message/proof, mismatched password, wrong server record, and transcript/context substitution fail with only the contract's generic authentication outcome exposed |

For every fixture, A04 must add provenance metadata that identifies the source
standard section or generation procedure, fixture format revision, test-only
classification, and SHA-256 digest of the normalized vector record.  It must
not record a library name as fixture provenance.  If an official RFC vector
does not cover the contracted Ristretto255 profile or required operation, mark
that coverage gap explicitly and route it to H01; do not invent a transcript
format.

The current `kdf-parameters-01` encoding remains a known failing input until
A04 corrects it and adds the non-minimal-integer rejection regression.  The
current malformed and recovery placeholder ciphertexts must not be relabeled
as positive AEAD/wrapping vectors.  A recovery-wrap positive vector must be
48 bytes for a 32-byte wrapped AccountKey plus the 16-byte tag.

## Independent-validation procedure (G-05)

After A04's harness and vectors pass in its fixture-only environment, the
human reviewer performs this independent procedure.  It is separate from both
the Bun harness and future Rust implementation tests.

1. Select a reference validator that is independent of the Rust crypto-core
   and the fixture generator.  Record its executable/library identity,
   version, source, license, and invocation in ADR-0003.  This is evidence,
   not a library approval for production use.
2. Run the adapter-backed Bun command on a clean checkout with network access
   disabled after prerequisites are installed.  Save the command exit status,
   tool version, fixture-manifest digest, and normalized-result digest.
3. Independently inspect canonical CBOR byte equality and all canonical
   rejection cases, including the repaired G-11 regression.
4. Independently encrypt and decrypt every AEAD and wrapping positive vector,
   then run every declared tamper/context/key-kind negative case.
5. Run the OPAQUE vectors against the selected RFC 9807 Ristretto255-capable
   validator.  Confirm messages are processed by the standard profile rather
   than a repository-defined transcript.
6. Compare the result set exactly to the fixture manifest.  Any missing,
   additional, or different result is a finding; no partial pass can close
   G-05.
7. Append the tool details, commands, dates, digests, outcomes, and finding
   disposition to ADR-0003 and update the H01 checklist evidence map.  Only a
   human reviewer may conclude whether the evidence supports approval.

## Acceptance and handoff

A04 rework is ready for H01 only when `bun run --filter crypto-fixtures test`
passes with the independent adapter; all matrix rows have positive and required
negative vectors; G-11 is fixed with a regression; and the harness has no
production crypto dependency.  The H01 reviewer then repeats the independent
procedure and records evidence.  This plan neither changes the current
`PROPOSED` contract status nor clears G-01..G-05.
