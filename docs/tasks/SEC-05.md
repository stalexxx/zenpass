# SEC-05: in-flight vault operations repopulate plaintext cache after lock

Source: GitHub issue #5 (audit 2026-09-05, commit `95846a9`). Severity: Medium.
Threats: T07/T19.

Goal: `VaultSession` (`apps/web/src/vault/vault-session.ts`) checks `unlocked`
only before its first `await`; `saveItem` then unconditionally calls
`itemCache.set(id, data)` after `sealItemPayload`/`enqueueEdit` resolve, even
if `lock()` ran in between. `lock()` clears the cache but does not invalidate
already-in-flight operations, so a slow save can repopulate plaintext into the
cache after the session is locked. `loadAllItemsIntoMemory` and
`resolveConflict` need the same check.

Dependencies: none. Owner: C01/C05 via integrator.

Allowed paths: `apps/web/src/vault/`, `apps/web/test/`, `docs/tasks/SEC-05.md`.

Forbidden paths: `crates/crypto-core/`, `packages/sdk/`, `docs/contracts/`,
backend, extension code.

Required fix:

- Introduce a monotonic generation/session token that increments on
  `lock()` and on account switch.
- Every method that awaits (`saveItem`, `loadAllItemsIntoMemory`,
  `resolveConflict`, and any other cache-writing async path) must capture the
  generation before its first await and re-check it after every await before
  writing plaintext into `itemCache` or returning cached data.
- If the generation changed, drop the result — but do not discard work that
  was already safely enqueued as ciphertext via `enqueueEdit` (the encrypted
  mutation queue is not what's being invalidated, only the plaintext cache
  write/return path).
- Cache reads while locked must also refuse to return data (the cache should
  already be empty post-lock, but add the check defensively for any residual
  in-flight write).
- A new unlocked session (e.g. after re-unlock or switching accounts) must
  never surface a previous session's cached plaintext.

Required tests: deterministic tests using controllable/deferred promises for
the crypto/sync doubles (matching the issue's repro shape) proving: lock
completing before a save/load/resolveConflict resolves leaves the plaintext
cache empty; a previous account's data never appears in a new session;
`debugMemoryState().itemCacheSize` is 0 immediately after lock even with an
operation in flight at lock time.

Verification: `bun run --filter @zkpm/web test`, `bun run check:boundaries`.

Completion report format: Standard completion report (`docs/plan/INTEGRATOR.md`).
Reference GitHub issue #5; do not close it yourself.
