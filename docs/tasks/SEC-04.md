# SEC-04: reject sync rollback and unauthenticated record metadata

Source: GitHub issue #4 (audit 2026-09-05, commit `95846a9`). Severity: High.
Threats: T02/T10.

Goal: `SyncEngine.pull` (`packages/sdk/src/sync-state-machine.ts`) and
`IndexedDBLocalRepository.putItem` (`apps/web/src/db/indexeddb-repository.ts`)
must stop unconditionally replacing local records and advancing the cursor.
A dishonest server can currently replay an old, cryptographically valid
ciphertext for the same `itemId` at a lower `revision` and the client accepts
it, including reviving a tombstoned (`deleted`) record, because AAD binds
`keyVersion` but not `revision`/`deleted`.

Dependencies: none (independent of C04). Owner: C02/B05 via integrator.

Allowed paths: `packages/sdk/src/`, `packages/sdk/test/`,
`apps/web/src/db/`, `apps/web/test/`, `docs/tasks/SEC-04.md`.

Forbidden paths: `crates/crypto-core/`, `docs/contracts/*/v1` (no contract/AAD
format rewrite without an ADR and human security approval — see below),
backend routes/migrations, extension code.

Required fix:

- Reject a pulled/applied record whose `revision` regresses relative to the
  currently stored local record for the same `(vaultId, itemId)`, and reject
  a same-revision record whose bytes differ from what is already stored.
- Validate the record's `vaultId` matches the vault being synced before
  ever calling `putItem`/advancing the cursor.
- Verify integrity before replacing local state or moving the cursor forward;
  a rejected record must produce a visible error, not a silent skip.
- Do not let the UI's `deleted` check run before decryption/authentication —
  tombstone status must be validated as part of the authenticated write path.
- If closing this fully requires an AAD/contract change (binding revision or
  deleted into the authenticated envelope), do not make that change yourself:
  stop, document the exact proposed field addition and its wire/versioning
  impact, and report it as a blocker for integrator-led ADR review. Ship the
  strongest fix possible under the existing frozen envelope first (revision
  monotonicity + vault-ownership + same-revision-byte-equality checks are all
  achievable without touching the envelope), and call out precisely what
  residual replay risk remains without the AAD change.
- Preserve existing local data and cursor position on any rejection (fail
  closed, not fail-forward).

Required tests (Bun, real `SyncEngine`/`InMemoryLocalRepository`/
`IndexedDBLocalRepository`, only the API double is synthetic): revision
rollback rejected; wrong-vault record rejected; same-revision replacement
with different bytes rejected; tampered `deleted` flag rejected; replay of an
old genuinely-valid ciphertext at a newly-claimed higher `revision` (state
the residual risk explicitly if the envelope can't fully rule this out
without an ADR); local data/cursor unchanged after a rejected pull.

Verification: `bun run --filter @zkpm/sdk test`, `bun run --filter @zkpm/web
test`, `bun run check:boundaries`.

Completion report format: Standard completion report (`docs/plan/INTEGRATOR.md`).
Reference GitHub issue #4; do not close it yourself — the integrator closes
issues after merge and verification.
