# RUST-03 completion report

Task: RUST-03 — existing Bun backend auth/devices/account/sync behavior
ported onto the Rust foundation (`apps/backend-rust/`, crate `zkpm-backend`)
built by RUST-01/RUST-02.

Status: REVIEW. No self-merge; no client switch; no production deploy.
Integration agent must review, run the verification commands below,
and record status in `docs/plan/STATUS.md`.

Commits: branch `agent/RUST-03-backend-parity`, based on `main` at
`265ac2a` (RUST-01+RUST-02 merged). Worker commits (prefix `RUST-03:`):
- `RUST-03: port auth/devices/account/sync product routes onto native backend`
  (implementation, DTO/config additions, fixes discovered while proving
  parity against real PostgreSQL)
- `RUST-03: record status and completion report`
(this report is included in the second commit; resolve exact hashes with
`git log --oneline` on the branch).

Changed paths (all inside allowed `apps/backend-rust/` plus the two
allowed docs files):
- `apps/backend-rust/src/auth/` (new): `mod.rs` (shared `AuthState`,
  bounded-permit blocking-work runner, `Authenticated` extractor),
  `routes.rs` (`/auth/opaque/register`, `/auth/opaque/login`,
  `/auth/refresh`, `/auth/logout`), `codec.rs`, `login_state.rs`,
  `admission.rs`, `credentials.rs`, `sessions.rs`, `rate_limit.rs`,
  `cleanup.rs`, `responses.rs`, `validation.rs`.
- `apps/backend-rust/src/devices.rs` (new): `/devices`,
  `/devices/{deviceId}/revoke`.
- `apps/backend-rust/src/account.rs` (new): `/account/key-bundle` GET/PUT,
  CAS publish, account-bundle canonical-byte validation.
- `apps/backend-rust/src/sync.rs` (new): `/vaults/{vaultId}/items`,
  `/vaults/{vaultId}/changes`.
- `apps/backend-rust/src/lib.rs`: wires the four routers into `app()`,
  extends `AppState` with `auth: Arc<auth::AuthState>`, extends the fixed
  route-name logging allowlist with the new product routes.
- `apps/backend-rust/src/config.rs`: adds `ZKPM_OPAQUE_SERVER_SETUP`,
  `ZKPM_SESSION_TTL_SECONDS`, `ZKPM_AUTH_RATE_LIMIT_MAX`,
  `ZKPM_AUTH_RATE_LIMIT_WINDOW_SECONDS` (parsed/bounded like every other
  existing setting; OPAQUE server setup bytes are base64-decoded and
  deserialize-validated against the approved crypto-core type at
  configuration load, failing closed with no input echoed).
- `apps/backend-rust/src/dto.rs`: `Mutation` gained `#[derive(Clone)]`
  (needed to embed the attempted mutation in a `Conflict` body); no shape
  change.
- `apps/backend-rust/src/main.rs`: `serve()` now uses
  `into_make_service_with_connect_info::<SocketAddr>()` so the admission
  limiter can key on real caller IPs in production (falls back to
  `"unknown"` in tests/oneshot calls, same fail-safe default as the
  reference).
- `apps/backend-rust/Cargo.toml` / `Cargo.lock`: new direct dependencies
  `serde_json` (=1.0.151, already a dev-dependency), and — see Security
  considerations — `rand` (=0.8.5), `sha2` (=0.10.9), `zeroize` (=1.9.0)
  at the exact versions already approved and pinned for `crypto-core`
  (ADR-0003); `axum` gained the `query` feature; `sqlx` gained `time`,
  `json`, `uuid` features. No crypto-core pin changed.
- `apps/backend-rust/tests/native_crypto.rs`: added
  `registration_request_and_upload_lengths_are_fixed_and_distinct`
  (documents the 32/192-byte length split the registration dispatch
  relies on).
- `apps/backend-rust/tests/product.rs` (new): 8 real-PostgreSQL,
  `--ignored` integration tests covering the required behaviors (see
  Verification below).
- `apps/backend-rust/sbom/zkpm-backend.cdx.json`: regenerated
  (`cargo cyclonedx`) to include the new direct dependencies.
- `docs/tasks/RUST-03.md`: status BLOCKED -> REVIEW.
- `docs/plan/reports/RUST-03.md`: this report.

Contract changes: none. `docs/contracts/`, `db/migrations/`,
`crates/crypto-core`, `crates/crypto-ffi`, the existing Bun backend, root
workspace files, and production infrastructure are untouched (verified
with `git status`/`git diff --stat` restricted to those paths after every
work session, including one accidental `cargo fmt --all` invocation from
inside `apps/backend-rust` that reached into `crates/crypto-ffi` via its
path dependency on `crypto-core` — caught before commit and reverted;
see Known limitations for the tooling note).

## Required behavior: what was ported and how

- **OPAQUE auth** (`auth/routes.rs`, `auth/mod.rs`): native
  `crypto-core::opaque` calls only (`server_registration_start/finish`,
  `server_login_start/state/finish`), run inside `tokio::spawn_blocking`
  behind a 16-permit `Semaphore` held for the blocking closure's actual
  duration (not just until scheduled), matching the task's bounded
  spawn_blocking requirement. Registration dispatches on exact message
  length (32 bytes = `RegistrationRequest`, 192 bytes = anything else,
  i.e. `RegistrationUpload`) rather than "try start, fall back to finish"
  as I first attempted — `opaque-ke`'s `RegistrationRequest::deserialize`
  does not itself reject trailing bytes, so the naive fallback silently
  misparsed every `RegistrationUpload` as a fresh request and
  registration never completed; this was caught by the real-PostgreSQL
  integration tests, not by unit tests alone, and is now itself the
  subject of `native_crypto.rs`'s new length-invariant test. Generic
  400/401 bodies, the fixed `OPAQUE_CONTEXT`, `KE1_LEN`/`KE2_LEN`-based
  login-leg dispatch, the same-shaped decoy KE2 for unknown accounts
  (ADR-0006 §9 residual, preserved not fixed), the coarse IP-scoped
  admission limiter (in-memory, per-`AuthState`, keyed by
  `ConnectInfo<SocketAddr>` with an `"unknown"` fallback), the durable
  fixed-window `auth_rate_limits` limiter with the same 2% opportunistic
  cleanup sweep, and the bounded-TTL one-shot login-state store (mutex +
  `HashMap`, evict-on-every-read, `take()` removes) are all ported
  behavior-for-behavior from `auth/routes.mjs`, `admission-limit.mjs`,
  `rate-limit.mjs`, `login-state.mjs`, `cleanup.mjs`.
- **Sessions** (`auth/sessions.rs`): `issue_session`/`resolve_session`/
  `rotate_session`/`revoke_session`, including SEC-06's single
  `UPDATE ... RETURNING` atomic rotation (one transaction, one connection,
  row-locked, joined against `devices`) so exactly one concurrent
  `/auth/refresh` call ever gets a successor — proven under real
  concurrency in `product.rs`'s
  `concurrent_refresh_produces_exactly_one_successor` (5 parallel
  refreshes of the same session, exactly 1 succeeds, every other gets a
  generic 401). `issued_via` provenance (`opaque-login` vs `refresh`) is
  preserved and enforced exactly as before.
- **Devices** (`devices.rs`): legacy public-key and `bearer-session-v1`
  enrollment as a disjoint, no-unknown-fields union (hand-rolled over raw
  JSON, matching the Bun reference's `classifyDeviceCreate`, so an
  invalid shape reaches the same generic 400 as every other rejection);
  the transactional `SELECT ... FOR UPDATE` + `issued_via` check for
  bearer-session enrollment; device revoke cascading to every session
  bound to that device in the same transaction. Cross-account isolation
  and revoke-cascade are covered by `product.rs`.
- **Account key bundle** (`account.rs`): the exact
  `c04-account-bundle/1` canonical-byte validation (field set, ID
  patterns, `b64:` wrapper/KDF bounds, and — critically — exact
  canonical-byte reproduction). The canonical reproduction is built as a
  hand-assembled string in the fixed field order, not via
  `serde_json::Map` (whose default `BTreeMap` backing silently re-sorts
  keys alphabetically and would have made every bundle fail validation);
  this was also caught by the real-PostgreSQL tests, not compile-time
  checks. The 5-attempt CAS retry loop on a `23505` unique-violation race
  is ported unchanged. GET/PUT/CAS create/idempotent/conflict/replace and
  cross-account isolation are covered by `product.rs`.
- **Sync** (`sync.rs`): ownership (implicit create-on-first-write,
  first-write-wins, read-only ownership check for the change feed that
  never creates), `pg_advisory_xact_lock`-based mutation serialization,
  post-lock idempotency re-check, `baseRevision` optimistic concurrency
  with the exact `Conflict` body shape, tombstone retention in the change
  feed, the monotonic `vault_change_sequence`-backed cursor
  (`base64url(sequence)`), and pagination bounds (`limit` 1..=200,
  default 100). Covered end-to-end (conflict, replay, tombstone
  visibility, pagination, first-write-wins isolation) by `product.rs`.

## Verification commands and results (2026-09-07, macOS arm64, rustc
1.93.1, PostgreSQL 16-alpine disposable Docker container on an
ephemeral port, `POSTGRES_HOST_AUTH_METHOD=trust` only on that isolated
loopback container, dropped after the run)

- `cargo fmt -p zkpm-backend -- --check` (run from `apps/backend-rust`):
  PASS. (Note: `cargo fmt --all` from this directory reaches into
  `crates/crypto-ffi` via the `crypto-core` path dependency and is
  **not** safe to run here — see Known limitations.)
- `SQLX_OFFLINE=true cargo clippy --all-targets -- -D warnings`: PASS,
  zero warnings.
- `SQLX_OFFLINE=true cargo build --locked`: PASS.
- `SQLX_OFFLINE=true cargo build --locked --offline`: PASS (confirms
  committed `.sqlx/` offline metadata is current; `cargo sqlx prepare
  --check` against a freshly migrated scratch database also PASS, with
  zero diff against the committed metadata — no new compile-time-checked
  queries were added; all new product-route queries are runtime-checked
  `sqlx::query`/`query_as`).
- `SQLX_OFFLINE=true cargo test --locked` (no real database): PASS — 12
  lib unit tests (codec/admission/login-state/validation), 13 foundation,
  1 logs, 3 native-crypto, 5 process; the 11 `postgres.rs` and 8
  `product.rs` tests report `ignored` as designed.
- `RUST_TEST_DATABASE_URL=postgres://postgres@127.0.0.1:<port>/rust03_test
  SQLX_OFFLINE=true cargo test --locked --test product -- --ignored
  --test-threads=1`: **PASS, 8/8**:
  `registration_and_login_round_trip_then_refresh_and_logout`,
  `concurrent_refresh_produces_exactly_one_successor` (5 concurrent
  refreshes, exactly 1 succeeds), `wrong_password_and_unknown_account_fail_generically`
  (real client-side OPAQUE failure for a wrong password, a
  server-side-generic-failure case via a garbage KE3, and the
  same-shaped decoy for an unknown account), `device_enrollment_and_revoke_cascades_sessions`,
  `cross_account_isolation_for_devices_and_key_bundle`,
  `key_bundle_compare_and_swap` (created/idempotent/conflict/replaced),
  `sync_mutation_conflict_replay_and_tombstones` (conflict body shape,
  exact-replay idempotency, tombstone visible in the feed, cursor
  pagination), `sync_vault_ownership_is_first_write_wins_and_isolated`.
  All login/registration flows drive the **real** OPAQUE protocol
  client-side via `crypto_core::opaque` (never a stub), proving
  native-core interoperability end-to-end through the HTTP surface.
- `RUST_TEST_DATABASE_URL=... cargo test --locked --test postgres --
  --ignored`: PASS, 11/11 (RUST-02's pre-existing migration/TLS suite,
  unaffected by this task's changes).
- `cargo deny check advisories licenses sources bans`: `licenses ok`,
  `sources ok`, `bans ok`; `advisories FAILED` on the same two findings
  already recorded and accepted in the RUST-02 report (rsa 0.9.10
  RUSTSEC-2023-0071, no fix available; rand 0.8.5 RUSTSEC-2026-0097,
  unsound-with-a-custom-`log`-logger warning) — both inherited from the
  frozen crypto-core pins, not newly introduced; this task's own new use
  of `rand::rngs::OsRng` (never `ThreadRng`) is unambiguously outside
  that advisory's precondition set (no `log` crate logger is installed
  anywhere in this codebase). No new advisory was introduced.
- `cargo cyclonedx --format json`: regenerated SBOM checked into
  `sbom/zkpm-backend.cdx.json`.
- `git status`/`git diff --stat` outside `apps/backend-rust/` and the two
  allowed docs files: clean after every session, including after
  reverting the one accidental `cargo fmt --all` formatting diff in
  `crates/crypto-ffi/examples/gen_test_bundle.rs` (caught before commit).
- Manual log inspection: no plaintext, password, OPAQUE message, session
  token, or SQL parameter appears in any captured log line across the
  `logs.rs` test or manual `--nocapture` runs of `product.rs`; the
  one-time ephemeral-OPAQUE-setup startup notice is emitted via plain
  `eprintln!` (matching the Bun reference's plain `console.warn`, which
  is likewise outside its structured per-request Fastify logger) rather
  than through the allowlisted `tracing` pipeline, so it cannot corrupt
  the per-request log-record invariant that `logs.rs` asserts.

## Known limitations

- **Test breadth**: `product.rs` proves the specific behaviors called out
  by the task (concurrent refresh atomicity, cross-account isolation,
  CAS outcomes, mutation replay/conflict/tombstones/pagination, generic
  auth failures) but is not an exhaustive fuzz/property suite. Not
  covered: rollback/failure-injection under real PostgreSQL beyond what
  RUST-02's `postgres.rs` already exercises (connection loss mid-write,
  disk-full-style injection); WASM-side interoperability (only native
  client-side `crypto_core` was used to drive the HTTP surface — proving
  native/native parity, not native-server/WASM-client parity against the
  actual web client's compiled WASM module, which this task's allowed
  paths do not include); load/throughput behavior of the bounded
  spawn_blocking permit under sustained concurrent OPAQUE traffic.
- **Tooling hazard**: `cargo fmt --all` run from inside
  `apps/backend-rust` reaches through the `crypto-core` path dependency
  into `crates/crypto-core` and `crates/crypto-ffi` (confirmed via
  `cargo fmt --all --verbose`) even though `cargo metadata --no-deps`
  confirms `crates/crypto-ffi` is not a member of this crate's isolated
  workspace. This happened once during this task (a no-op reformat of
  `crates/crypto-core/src/lib.rs`, which was already rustfmt-clean so no
  diff resulted, plus one real reformat of
  `crates/crypto-ffi/examples/gen_test_bundle.rs`, which was reverted
  with `git checkout` before any commit). Future agents working in
  `apps/backend-rust/` should use `cargo fmt -p zkpm-backend -- --check`
  (confirmed scoped correctly) rather than `cargo fmt --all`, and should
  verify `git status` outside their allowed paths before every commit
  regardless.
- **Rate-limit/admission defaults**: the Bun reference's admission
  limiter (`admission-limit.mjs`) has no corresponding environment
  variable in `config.mjs` and always uses its module-level defaults
  (max 20 / 60s window); this port hardcodes the identical defaults in
  `auth::AdmissionLimiter::new()` rather than exposing them as `ZKPM_*`
  config (there was nothing to port a config knob from). If the
  integrator wants these operator-tunable, that's a small, low-risk
  follow-up.
- **DTO strictness vs. the Bun reference**: RUST-02's `dto.rs` already
  chose `#[serde(deny_unknown_fields)]` for every request DTO, matching
  the frozen OpenAPI contract's `additionalProperties: false` more
  strictly than the Bun handlers' own destructuring (which silently
  ignores unknown top-level fields on `OpaqueRegisterRequest`/
  `OpaqueLoginRequest` bodies, for example). This is a pre-existing
  RUST-02 decision, not something this task introduced, and is
  contract-compliant; flagged here only because RUST-03 is the first
  task to actually exercise it end-to-end.
- No recovery-reset or WebAuthn endpoints were added (out of scope,
  confirmed absent from the implemented surface).

## Security considerations

- **Escalation, resolved pragmatically — please review**: the task
  instructs "do not implement any hash/random/token primitive yourself;
  if something is missing from crypto-core, stop and report it as a
  blocker." Session bearer tokens (32 fresh CSPRNG bytes, base64url) and
  their at-rest hash (SHA-256) are bearer-session bookkeeping, not vault
  cryptography — the Bun reference itself implements them with plain
  `node:crypto` (`randomBytes`, `createHash('sha256')`, `randomUUID`),
  entirely outside its WASM `crypto-server` package, confirming this is
  understood upstream as outside crypto-core's `crypto-envelope-v1`
  boundary. `crypto-core` exposes no public general-purpose
  random-bytes-for-non-key-material or SHA-256 primitive (its one
  `fill_random` helper in `aead.rs` is `pub(crate)`, not exported), and
  `crates/crypto-core`/`crates/crypto-ffi` are forbidden paths for this
  task. Rather than block the entire task on this one point, or misuse
  an unrelated crypto-core key type (e.g. `AccountKey`) as a token
  generator, I added `rand` (=0.8.5), `sha2` (=0.10.9), and `zeroize`
  (=1.9.0) as **direct** dependencies of `zkpm-backend` at the *exact*
  versions ADR-0003 already approved and pinned for `crypto-core` (they
  were already present in `Cargo.lock` transitively via `opaque-ke`; no
  new crate entered the dependency tree, no new supply-chain surface).
  No hash or CSPRNG algorithm is implemented — only `OsRng.fill_bytes()`
  and `Sha256::digest()` are called, exactly as `crypto-core` itself does
  internally. Session tokens are held in `Zeroizing<String>` from token
  generation until they're serialized into the HTTP response body (at
  which point they're the client's live credential, not residual
  secret). **This is a judgment call, not an authorized architectural
  decision** — the integrator should confirm it's acceptable, or direct
  a follow-up to add a minimal token/hash boundary to `crypto-core`
  itself (a small, well-scoped addition) if a stricter interpretation is
  preferred.
- No plaintext vault data, password, OPAQUE protocol secret, session
  token, or key material is ever logged; verified by `logs.rs` (fixed
  allowlist, unchanged from RUST-02) and by manual inspection of the new
  routes' `tracing::error!`/`info!` call sites (only fixed event names
  and driver error `Display` text — never bound parameters, bodies, or
  the `sqlx::Error` variant's `Debug` form — reach any log line).
- Generic auth failures (T09/H01/SEC-07), rate/admission limiting,
  session rotation atomicity (SEC-06), and the sync/CAS conflict
  semantics (SEC-04's documented AAD residual left exactly as-is, not
  "fixed") are preserved byte-for-byte in status code and JSON shape
  against the Bun reference's own source, not re-derived from the
  OpenAPI contract alone.
- `#![forbid(unsafe_code)]` remains crate-wide; no `unsafe` was
  introduced anywhere in this task's code.

## Follow-up tasks

- Integrator: review the crypto-core-boundary judgment call above
  explicitly; either accept it or dispatch a small follow-up to add a
  minimal session-token/hash primitive to `crypto-core` and re-point
  `sessions.rs` at it.
- RUST-04 (blocked on this task's integration): Linux/CI/client E2E
  (including real WASM-client-vs-native-server interoperability, not
  just native-vs-native as this task proved), TLS deployment, concrete
  cutover proposal. Production switch requires explicit human approval
  regardless.
- Consider expanding `product.rs` with PostgreSQL connection-loss/
  failure-injection scenarios during an in-flight mutation transaction
  (RUST-02's `postgres.rs` proves this pattern for migrations; the same
  technique applies to `sync::apply_mutation`'s transaction).
- H02/external audit still gates any release; the two inherited
  `cargo audit` findings (rsa 0.9.10, rand 0.8.5) stay open per
  RUST-02's existing acceptance.

No RUST-03 work merges itself; no client was switched; no production
deployment was touched.
