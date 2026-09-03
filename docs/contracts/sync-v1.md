# sync/v1

## Record

`itemId`, `vaultId`, `ciphertext`, `envelopeVersion`, `revision`, `deleted`, `createdAt`, `updatedAt`.

## Rules

- Mutations include `mutationId` and `baseRevision`.
- Matching `baseRevision` commits a new monotonic revision and change sequence.
- Mismatch returns `409 Conflict` containing both opaque versions.
- Deletes are tombstones; clients must be able to replay them after reconnect.
- Change feed uses an opaque cursor and is idempotent.
- The server never merges or decrypts ciphertext.

The machine-readable record, mutation, and change-page schemas are in `packages/contracts/schemas/`. The normative client/server transition rules are in [`packages/contracts/sync-state-machine.md`](../../packages/contracts/sync-state-machine.md). Fixtures and rejected examples are in `fixtures/contracts/`.
