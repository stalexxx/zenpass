# D02-MVP: native Android client — independent unlock, vault CRUD, TOTP

Goal: a first working native Android client, mirroring the architecture
already proven for the browser extension (C04-EXT2): independent OPAQUE
login against the existing backend, key-bundle opening via the Rust crypto
core (through UniFFI/JNI instead of WASM), vault item list/save/update, and
TOTP display. This supersedes `docs/tasks/D02.md`'s React Native plan for
this first slice — human decision 2026-09-06: native Kotlin + Jetpack
Compose instead. Full D02 acceptance criteria (Secure Enclave-equivalent
Keystore-backed offline unlock, biometric prompt, Android Autofill Framework
integration, full sync/offline/recovery) remain out of scope for this MVP
and are follow-up tasks, exactly as C01 (web MVP) preceded C03/C04
(extension) and C05 (React migration).

**Human scope decision, 2026-09-06:** personal/dev-scope development may
proceed now without waiting on H02/full R01 (mirrors R01's own carve-out).
Play Store publication, and any claim that this is public-release-ready,
remain out of scope and blocked on H02.

Dependencies: B03 (crypto-ffi exists), B04 (OPAQUE/device/session API),
C04-G1 (key-bundle GET route, bearer-session-v1 device enrollment — already
merged and already proven against a real independent client by C04-EXT2).
Read `docs/decisions/ADR-0011-c04-approval-packet.md` in full and treat its
D1-D6 boundary model as the template to adapt for Android (it was written
for the browser extension, but the "independent OPAQUE login, background-
private crypto host, no plaintext persistence, fail-closed lifecycle"
shape applies directly here — cite it, adapt it, don't reinvent it). Also
read `apps/extension/src/vault-manager.ts` (the equivalent, already-shipped
TypeScript implementation of this exact flow against the same backend) as
the reference implementation to port the *shape* of, not the code itself.

Allowed paths: `apps/android/` (new), `crates/crypto-ffi/` (additive
UniFFI exports only, see below), `docs/tasks/D02-MVP.md`.

Forbidden paths: `crates/crypto-core/` (read-only — call its existing
functions from `crypto-ffi`, never add new cryptography or change existing
algorithms/parameters), `docs/contracts/*/v1` (no contract change; this
task consumes the existing REST API exactly as the extension does),
`packages/sdk/`, `apps/web/`, `apps/backend/`, `apps/extension/`.

## Required `crypto-ffi` additions (mechanical only, mirrors ADR-0007)

`crates/crypto-ffi/src/lib.rs` today exports only `unlock` (opens an
existing hierarchy), `seal_item_payload`/`open_item_payload`, `inspect`, and
`protocol_status` — it has no OPAQUE client operations and no account/
vault/item-key wrapping (hierarchy-creation) exports, because nothing has
needed them through this boundary yet. Add UniFFI-exported wrappers around
the *already-existing* `crypto_core::opaque` client functions
(`client_registration_start/finish`, `client_login_start/finish`) needed for
independent login — this mirrors ADR-0007's precedent ("added client-side
OPAQUE exports to `packages/crypto-wasm`, mechanical, no new cryptography")
exactly, just for the UniFFI boundary instead of wasm-bindgen. Do **not**
add `wrap_account_key_with_password`/hierarchy-creation exports in this
task — this MVP does not implement onboarding/registration on Android (see
scope below), so those exports are not needed yet; adding them
unrequested would be scope creep. If you find you need something from
`crypto-core` this task doesn't already list, stop and report it as a
blocker rather than deciding to export it yourself.

## Required implementation

Mirror ADR-0011's D1-D6 shape, adapted for a single-Activity Android app
(there is no background-service-worker/popup split here — the whole app is
one trusted process, closer to the *web* client's trust model than the
extension's):

- **Independent unlock (D1 analog)**: a login screen collects accountId,
  an explicitly confirmed HTTPS API origin (reuse the extension's exact
  validation rules: reject non-HTTPS, userinfo, query/fragment, ambiguous
  hostnames — port `apps/extension/src/origin.ts`'s logic to Kotlin), and
  the master password. OPAQUE login via the new `crypto-ffi` exports over
  OkHttp (or Ktor — your choice, justify it in the report) against the
  existing `/auth/opaque/login` route.
- **Device enrollment**: enroll via G2's `bearer-session-v1` branch
  (`POST /devices` with `{name, enrollmentMode: "bearer-session-v1"}`) on
  every login, exactly as the extension does — fail the whole unlock
  closed if this fails.
- **Key-bundle opening (D2 analog)**: `GET /account/key-bundle`, parse/
  validate the `AccountBundle` JSON exactly per its frozen spec
  (`docs/contracts/` — find and cite the exact schema; port the validation
  rules `apps/extension/src/../../../packages/sdk/src/account-bundle-codec.ts`
  already implements, do not invent a looser parser), open it via the new
  `crypto-ffi` OPAQUE-adjacent `unlock` export.
- **No plaintext persistence (D4 analog)**: only the non-secret account
  association (accountId + confirmed API origin) may be persisted, and
  only inside Android's `EncryptedSharedPreferences` (Jetpack Security
  Crypto library) backed by an Android Keystore-generated key — never a
  plain file, never plaintext `SharedPreferences`. No wrapped-bundle cache,
  item cache, or mutation queue survives process death; everything else
  lives in memory for the life of the unlocked session, exactly like the
  extension's background.
- **Vault list, save/update, TOTP (D3 analog)**: fetch the vault's change
  feed (`GET /vaults/:id/changes`), decrypt items in memory via
  `crypto-ffi`, list them in a Compose screen; save/update seals via
  `crypto-ffi` and pushes a `Mutation` (`baseRevision`, ciphertext-only) to
  the existing mutation route; TOTP display computes RFC 6238 codes from
  the decrypted seed in memory only (find and reuse or port the same
  approach `apps/extension`/`apps/web` already use — do not add a new TOTP
  dependency if `javax.crypto`'s `Mac`/`HmacSHA1` suffices, matching the
  existing native-crypto-only TOTP policy from ADR-0008 §3/ADR-0011 D6).
- **Lifecycle (D5 analog)**: lock on explicit user action, app process
  death/eviction (Android's normal lifecycle — do not fight it, rely on
  nothing surviving except the encrypted account-association prefs),
  and any 401/network authentication failure. A fresh authenticated check
  before every secret display/mutation, matching the extension's "at most
  30s apart, 5s network deadline, no offline fallback" rule — reuse those
  exact constants unless you have a concrete Android-specific reason not
  to (state it if so).
- No biometric prompt, no Android Autofill Framework integration, no
  offline/cached vault, no recovery-kit flow, no import/export in this MVP
  — all explicit follow-ups, matching D02.md's fuller acceptance criteria.

## Required tests

- Kotlin unit tests for: origin confirmation/validation logic (port of
  `origin.test.ts`'s cases), account-bundle parsing/validation (positive
  and negative cases mirroring the SDK's own fixtures), TOTP known-answer
  vectors (RFC 6238 Appendix B, same vectors already used elsewhere in this
  repo — reuse them, don't invent new ones), and lifecycle/lock-on-failure
  behavior with a fake API client.
- An integration test run against the **real backend** (the same
  `TEST_DATABASE_URL=postgres://pass:pass@127.0.0.1:5434/pass` Postgres
  instance and real running `apps/backend`, started the same way
  `apps/extension/test/vault-manager.integration.test.ts` does — read that
  file for the exact pattern of spinning up a real backend for a test) and
  the real `crypto-ffi` JNI library (built via `cargo build` for the host/
  emulator architecture — this dev machine's emulator is `arm64-v8a`,
  matching Apple Silicon hardware acceleration; do not test against a
  mocked crypto layer for this suite): unlock succeeds, wrong password
  fails generically, empty vault unlocks correctly, save/update round-trips
  and is verified ciphertext-only via a direct database check (mirror
  `vault-manager.integration.test.ts`'s exact verification style), TOTP
  correctness, device-revoke-from-a-second-client locks the app's session.
- A real on-emulator run: install the built APK on the `pass_dev` AVD
  (already running on this machine — `adb devices` should show
  `emulator-5554`), drive the actual login → unlock → view items → save →
  TOTP flow via UI Automator/Espresso or manual `adb shell input`-driven
  steps, and capture screenshots as evidence (mirror how
  `output/playwright/*.png` records browser evidence — save Android
  screenshots under `output/android/`).

## Verification

- `./gradlew :app:testDebugUnitTest` (or equivalent) for the Kotlin unit
  suite.
- `cargo build -p crypto-ffi --target aarch64-linux-android` (or the
  appropriate Rust Android target/cross toolchain — investigate what's
  already set up for this repo's cross-compilation, if anything, before
  assuming a fresh toolchain install; report exactly what was needed).
- The real-backend/real-crypto-ffi integration suite above.
- A real install + manual/automated run on the `pass_dev` emulator with
  screenshot evidence.
- `bun run check:boundaries` (confirm nothing outside `apps/android/`/
  `crates/crypto-ffi/` was touched).
- `cargo test --workspace` (confirm `crypto-ffi`'s additive changes don't
  break anything and its own tests, if any, pass).

## Completion report format

Standard completion report (`docs/plan/INTEGRATOR.md`). Report the exact
Rust Android cross-compilation setup used (target triple, NDK version, any
new build tooling installed) since this is likely new to this repository —
do not assume it silently worked without recording what you actually did.
State plainly what's verified vs. still open (biometric, autofill, offline,
recovery, import/export — all explicitly out of scope for this MVP, not
silently dropped). Do not touch `docs/plan/STATUS.md` — the integrator
updates it after review.
