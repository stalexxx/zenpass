# `crypto-envelope/v1` (normative)

Status: frozen — approved with findings in ADR-0003 on 2026-09-03. B01 must
complete the mandatory canonical-CBOR, vector, calibration, dependency, and
recovery-encoding follow-ups recorded in ADR-0003 F-2/F-3 before production
crypto delivery; changes to this v1 contract require v2 and renewed approval.
This is the byte-level contract for the Rust crypto-core and its WASM/UniFFI bindings.

## Fixed algorithms and sizes

| Purpose | Algorithm / encoding |
|---|---|
| Password KDF | Argon2id, RFC 9106, 32-byte output |
| AEAD and wrapping | XChaCha20-Poly1305 (IETF), 32-byte key, 24-byte nonce, 16-byte tag |
| Envelope | Deterministic/canonical CBOR (RFC 8949), definite lengths only |
| Binary API value | `b64:` + standard RFC 4648 base64 with padding |
| Authentication | OPAQUE, RFC 9807, vetted Ristretto255 profile |

No primitive, suite, nonce construction, or serialization may be substituted in
v1. A change requires v2, an ADR, new fixtures, and H01 approval.

## Key hierarchy

The client generates uniformly random 32-byte `AccountKey`, one random 32-byte
`VaultKey` per vault, and a fresh random 32-byte `ItemKey` per item. Keys are
never derived from identifiers or plaintext.

```text
master password --Argon2id--> UnlockKey
UnlockKey --wrap--> WrappedAccountKey
recovery key --wrap--> RecoveryWrappedAccountKey
AccountKey --wrap--> WrappedVaultKey
VaultKey --wrap--> WrappedItemKey
ItemKey --XChaCha20-Poly1305--> item plaintext
```

Wrappers have kinds `account-wrap`, `recovery-wrap`, `vault-wrap`, and
`item-wrap`. The recovery key is 32 random bytes; any printable code is a
display encoding only. No plaintext key is persisted or sent to the server.

## Domain separation and associated data

AEAD AAD is the canonical CBOR encoding of this map (integer keys in ascending
numeric order):

```text
{ 1: "crypto-envelope/v1", 2: accountId, 3: vaultId-or-null,
  4: itemId-or-null, 5: recordType, 6: keyVersion }
```

`recordType` is one of `account-wrap`, `recovery-wrap`, `vault-wrap`,
`item-wrap`, `item-payload`, or `export-manifest`. Null is permitted only where
the kind has no such identifier. Decryption rejects any context mismatch.

## Canonical envelope bytes

The outer envelope is a canonical CBOR map with exactly these integer keys:

```text
{ 1: "crypto-envelope/v1", 2: kind, 3: keyVersion, 4: nonce,
  5: ciphertext, 6: aad }
```

`kind` and `keyVersion` are text/integer values; `nonce`, `ciphertext`, and
`aad` are byte strings. `aad` must equal the bytes defined above. Maps sort by
encoded integer key; definite lengths are mandatory. Reject floating point,
tags, duplicate keys, indefinite strings/maps/arrays, and unknown outer keys.

AEAD output is `ciphertext || tag`, with the final 16 bytes as tag. Every
encryption uses 24 fresh OS-CSPRNG bytes; nonce reuse with the same key/context
is forbidden. Authentication is verified before returning plaintext. Payload is
canonical CBOR; sensitive fields remain inside it. Limits: 1 MiB per item and
64 KiB per wrapped key.

## Argon2id and unlock

The password wrapper stores this canonical CBOR parameter map:

```text
{ 1: "argon2id", 2: 19, 3: memoryKiB, 4: iterations,
  5: parallelism, 6: salt, 7: 32 }
```

Version 19 means Argon2 v1.3; salt is 16 random bytes and output length is 32.
The client calibrates on first setup for 500–1000 ms, with bounds
`memoryKiB >= 65536`, `iterations >= 3`, `parallelism >= 1`, and at most 25%
of reported physical memory. Parameters are persisted and never silently
weakened. Upgrading them creates a new password wrapper only.

## OPAQUE suite

Use the vetted RFC 9807 implementation, Ristretto255 profile, OPRF mode, and
the library's standard transcript, envelope, and proof encoding. Client sends
only OPAQUE messages over TLS; server stores an opaque registration record and
never receives password, UnlockKey, AccountKey, or recovery key. UI receives a
generic authentication failure. Library upgrades require vector verification
and an ADR; suite changes require H01 re-approval.

## Recovery reset and rotation

Account creation produces a recovery kit containing a display-only recovery code
and `RecoveryWrappedAccountKey`. The client requires a challenge confirmation
derived from the recovery key before marking the kit saved. Server stores only
the wrapped key and reset authorization material and cannot use it to decrypt.

Recovery locally unwraps AccountKey, derives a new UnlockKey from a new password,
creates a new password wrapper, then submits it through authenticated reset.
Successful reset revokes all sessions/devices, increments wrapper version, and
requires explicit re-enrollment. Missing both password and recovery kit is
permanent; support has no bypass.

Rotation is copy-on-write: create a new wrapper/version, verify local unwrap,
upload it, and delete the old wrapper only after a successful second unlock.
Item ciphertexts are not rewritten for password-wrapper rotation.

## Typed errors

Public errors are `InvalidEncoding`, `UnsupportedVersion`, `NonCanonicalCbor`,
`UnknownField`, `InvalidContext`, `InvalidNonce`, `AuthenticationFailed`,
`InvalidKdfParameters`, `KdfResourceLimit`, `InvalidKeyLength`,
`InvalidRecoveryKit`, `Locked`, and `Internal`. Errors contain no secret bytes or
raw parser details. UI must not distinguish wrong password from bad remote
credential material.

## Versioning and migration

`crypto-envelope/v1` is present in every envelope and AAD. v1 readers reject
unknown versions/fields. A future version uses a new string, fixtures, ADR, and
explicit migration. Migration is copy-on-write: decrypt old, validate, encrypt
new, verify new, then commit; old remains recoverable until completion. Unknown
payload fields may not be silently discarded.

## Fixtures

Files under `fixtures/crypto/` are language-neutral JSON. `hex:` is raw bytes;
`b64:` is transport encoding. Fixed keys/nonces are test-only. Implementations
must verify canonical CBOR bytes, AAD bytes, and negative cases before accepting
the format. The set covers canonicalization, context binding, malformed input,
KDF parameters, and recovery semantics.
