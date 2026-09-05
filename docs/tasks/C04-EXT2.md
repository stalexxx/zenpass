# C04-EXT2: wire independent extension unlock, save/update, TOTP, and lifecycle

Goal: complete ADR-0011's approved work package 3. `apps/extension` is
currently locked-by-default with `vault: null` hardcoded in
`BackgroundPolicy`'s production wiring (`apps/extension/src/background.ts`) —
no unlock caller exists yet. C04-G1/G2 (bundle publication, device
enrollment) are merged; this task wires the extension background to
actually use them: independent OPAQUE login, key-bundle opening, popup
save/update, TOTP display/fill, and the full ADR-0011 D1–D6 lifecycle.

Dependencies: C04-G1 (merged), C04-EXT (merged, hardening baseline).
Read `docs/decisions/ADR-0011-c04-approval-packet.md` in full before writing
any code — it is the implementation authority, including the exact runtime
boundary table, the exact-origin/cancellation protocol, and the acceptance
criteria/evidence table. Also read `docs/tasks/C04.md`, `docs/tasks/C04-EXT.md`,
`docs/security/C04-E2E-REPORT.md` (what's already verified vs. still open),
and the existing `apps/extension/src/*.ts` and
`packages/extension-adapters/src/*.ts` code.

Allowed paths: `apps/extension/`, `packages/extension-adapters/`,
`tests/browser/`, `docs/security/C04-E2E-REPORT.md`, `docs/plan/STATUS.md`
(status line only), `docs/tasks/C04-EXT2.md`.

Forbidden paths: `crates/crypto-core/`, `docs/contracts/*/v1` (no contract
change — G1/G2's approved shapes are frozen), `packages/sdk/` (its
`AuthClient`/`ApiClient`/`account-bundle-codec` are already sufficient per
ADR-0011 — consume them, do not modify them; if you find them insufficient,
stop and report it as a blocker rather than widening scope), `apps/web/`,
`apps/backend/`, `packages/crypto-worker/`/`packages/crypto-wasm/` (reuse
existing exports only; widening them requires a separate scoped grant per
ADR-0011).

Required implementation (per ADR-0011 D1–D6 and the runtime boundary table):

- **D1 Independent unlock**: popup-driven OPAQUE login using the existing
  `packages/sdk` `AuthClient`. User provides accountId and an explicitly
  confirmed HTTPS API origin (reject URL credentials, query/fragment
  configuration, cross-origin redirects, and any origin supplied by a
  page/content message). Persist only the account/API association across
  restarts — no wrapped-bundle cache, item cache, or offline unlock (D4).
- **D2 Crypto hosting**: instantiate the existing `CryptoWorkerHost`/WASM
  adapter inside the background realm, privately owned — no new isolation
  primitive, no raw-key export to any UI surface.
- Key-bundle opening: after login, fetch the account's key bundle (G1's
  GET route via the SDK) and open it using the existing C01/C02 hierarchy
  and the background's private crypto host; implement the real
  `VaultCandidateSource` (`packages/extension-adapters` already defines the
  interface) backed by decrypted item metadata/fields, replacing the
  `vault: null` placeholder in `background.ts`'s production wiring.
- **D3 Fill/save authority**: keep the existing popup-only selection and
  one-use, document-bound exact-origin fill capability machinery (already
  implemented by C04-EXT) — do not reintroduce content-script fill or
  credential-bearing page-submit transport. Add popup-driven manual
  save/update of vault items (new items and edits), and separate popup
  actions for displaying/filling the current TOTP code. Seeds never leave
  the background; TOTP uses the existing native Web Crypto path only
  (ADR-0008 §3 / ADR-0011 D6) — no new cryptographic primitive.
- **D5 Lifetime and revocation**: background restart/eviction, explicit
  lock/logout, popup close, a 5-minute trusted-popup-inactivity timeout,
  and authentication failure/401 must all lock. Revalidate online before
  every secret release or mutation (a fresh authenticated check, at most
  30s apart while the popup is open, 5s network deadline); no offline
  cached-data fallback. A session-generation counter must invalidate
  in-flight work exactly like the existing capability/session-state
  machinery already does for fill.
- **D6**: extend the CSP only as already scoped (`wasm-unsafe-eval`); no
  broader eval/inline/remote-code permission, no offscreen document.
- Device binding: enroll each extension login as its own named device via
  G2's `bearer-session-v1` branch (already implemented server-side/SDK-side);
  refresh is serialized and rotates the one in-memory bearer token
  atomically, never retried on the old token after rotation.
- Chrome MV3 async messaging: use the documented callback/`return true`
  compatibility path (already the pattern in `background.ts`); a bounded
  JSON-compatible integer-byte-array encoding for password/edit buffers
  crossing runtime messaging, reconstructed and cleared on both sides.

Required tests (extend `apps/extension/test/`, `packages/extension-adapters/test/`):
strict schema/sender validation for the new popup message types (unlock,
save/update, TOTP display/fill); lock on every await boundary (session
generation checks) for the new async paths; popup close/restart/eviction/
timeout/401 all lock; refresh serialization and no-retry-on-old-token;
device enrollment via G2's bearer branch; storage/log inspection (no
plaintext vault data, keys, passwords, TOTP seeds ever persisted, logged,
or fixtured).

Required Chrome/Firefox real-browser E2E (extend `tests/browser/`, building
on the existing harness in `tests/browser/c04-extension-e2e.mjs` and
`https-fixture.mjs`): independent extension-side OPAQUE unlock against the
real backend + real WASM from a fresh extension profile (wrong
password/account/origin fail generically, no web-storage read); same-origin
fill succeeds and hostile-origin fill is refused; popup save/update
round-trips through the real API as ciphertext only; TOTP display/fill;
device revoke from a second client locks the already-open extension
session; lock/restart/timeout during an in-flight operation; record exact
Chrome/Firefox versions used. Update `docs/security/C04-E2E-REPORT.md`'s
"Known limitations" section to reflect what this task closes versus what
remains genuinely open — do not overwrite or delete the existing report's
prior verified findings, extend it.

Verification: `bun run --filter extension-adapters test` (or equivalent),
extension build for both manifests, `bun run check:boundaries`, the new
real-browser E2E harness run, and a re-run of the existing
`tests/browser/c04-extension-e2e.mjs` baseline to confirm no regression.

If anything here turns out to require a contract change, a wider
crypto/SDK/WASM export, or a scope decision ADR-0011 didn't already make
explicitly, STOP and report it as a blocker for integrator/human review
rather than making the call yourself — this is a security-sensitive
boundary and ADR-0011 was deliberately explicit about what is and isn't
authorized.

Completion report format: Standard completion report (`docs/plan/INTEGRATOR.md`).
Do not merge your own work, do not mark C04 MERGED yourself, do not edit
`docs/plan/STATUS.md`'s C04 row status (only note progress in your report;
the integrator updates STATUS.md after review).
