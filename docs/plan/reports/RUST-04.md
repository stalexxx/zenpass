# RUST-04 completion report

Task: RUST-04 — Rust backend integration and cutover proposal (container
image, CI dependency/SBOM evidence, real-client E2E, backup/migration/
rollback rehearsals, and a concrete cutover runbook).

Status: REVIEW. This task produces a reviewed cutover **candidate**, not a
production switch. No production Compose/Caddy configuration was touched,
no traffic was switched, the Bun backend was not removed, and no
production/real mutating traffic was replayed against either backend. No
self-merge; no `docs/plan/STATUS.md` edit (integrator-owned).

Commits: branch `agent/RUST-04-cutover`, based on `main` at `eb5687c`
(RUST-01+RUST-02+RUST-03 merged). Worker commit(s) prefixed `RUST-04:`
(resolve exact hash with `git log --oneline` on the branch; this report is
included in the final commit).

Changed paths (all inside allowed paths):
- `infra/rust-backend/Dockerfile` (new): multi-stage build —
  `rust:1.93.1-slim-bookworm` builder (matches
  `apps/backend-rust/rust-toolchain.toml`), `debian:bookworm-slim` runtime,
  non-root `uid=10001`/`gid=10001`, `SQLX_OFFLINE=true cargo build --release
  --locked --bin zkpm-backend`, `ca-certificates` only, no shell utilities
  added, migrations embedded at compile time (`sqlx::migrate!`) so no
  runtime filesystem access to SQL files is needed.
- `infra/rust-backend/docker-compose.rust-backend.yml` (new): a parallel
  design overlay (`rust-migrate` + `rust-api` services) showing integration
  with the existing `infra/docker-compose.prod.yml` — same private
  `database` network (no published DB port), same `proxy` network for a
  future Caddy target, resource limits, and a CLI-subcommand healthcheck
  (no curl/wget in the slim runtime image). Validated with `docker compose
  -f infra/docker-compose.prod.yml -f
  infra/rust-backend/docker-compose.rust-backend.yml config` against the
  real base compose file (external networks pre-created for the dry run) —
  merges cleanly, no conflicts. **Not referenced by any file outside
  `infra/rust-backend/`.**
- `infra/rust-backend/RUNBOOK.md` (new): candidate artifacts, pre-cutover
  checklist, the actual traffic-switch step (explicitly deferred to a
  human editing the real `infra/Caddyfile` at execution time — not done by
  this task), acceptance criteria, in-flight OPAQUE login-state
  drain/invalidation behavior, rollback triggers/procedure, and an explicit
  "what this does NOT authorize" section.
- `tests/rust-backend/` (new): `helpers.ts` (spawns the real compiled
  `zkpm-backend` binary, disposable-database helpers); `client-e2e.test.ts`
  (real `packages/sdk` + real `packages/crypto-wasm` — the exact code
  apps/web/extension/desktop ship — driving register/login/device
  enrollment/key-bundle CAS and the two-device offline/reconnect/tombstone
  scenario over real HTTP against the real binary); `rollback-compat.test.ts`
  (bidirectional bearer-session compatibility between Bun and Rust on the
  same database — the "old-server rollback drill"); `migration-baseline.test.ts`
  (real Bun `migrate()` + real Rust `migrate` binary baseline-adoption and
  fresh-install compatibility, driven at the top level rather than only
  inside RUST-02's internal `postgres.rs` simulation); `backup-restore-rehearsal.test.ts`
  (runs the existing, unmodified `infra/backup.sh`/`infra/restore.sh`
  against a Rust-populated disposable database inside a version-matched
  `postgres:16-alpine` container).
- `.github/workflows/rust-backend.yml`: scoped the pre-existing `Format`
  step to `cargo fmt -p zkpm-backend -- --check` (RUST-03's report flagged
  `cargo fmt --all` from this directory as reaching into
  `crates/crypto-core`/`crates/crypto-ffi`); added a run of RUST-03's
  `product.rs` integration suite; added an SBOM regeneration
  drift-check job step (component name/version comparison, not a raw byte
  diff — see rationale in the workflow's own comments); added a
  `container-image` job that builds `infra/rust-backend/Dockerfile` on
  Linux CI and smoke-checks non-root/CLI; added a `client-e2e` job that
  runs the new `tests/rust-backend/` suite (excluding the
  Docker-network-dependent backup/restore rehearsal, which needs local
  rehearsal per the runbook) against a real GitHub Actions PostgreSQL
  service. Extended the path triggers to `infra/rust-backend/**` and
  `tests/rust-backend/**`.
- `apps/backend-rust/README.md`: fixed the same `cargo fmt --all` footgun
  in the documented Verify steps, added the `product.rs` test invocation,
  and a new "RUST-04" section pointing at the container/E2E/runbook
  artifacts.
- `docs/tasks/RUST-04.md`: status BLOCKED -> REVIEW.
- `docs/plan/reports/RUST-04.md`: this report.

Contract changes: none. `docs/contracts/`, `db/migrations/`,
`crates/crypto-core`, `crates/crypto-ffi`, the existing Bun backend, root
workspace files, and — critically — `infra/docker-compose.prod.yml` and
`infra/Caddyfile` (the actual production configuration) are untouched.

## Verification commands and results (2026-09-07, macOS arm64 dev machine;
rustc/cargo 1.93.1 via rustup for all `apps/backend-rust` commands; Docker
Desktop; disposable containers only, dropped after every run)

**Rust crate (no source changes made by this task, but re-verified clean
after the CI-workflow edits above):**
- `cargo fmt -p zkpm-backend -- --check`: PASS.
- `DATABASE_URL=postgres://postgres@127.0.0.1:<disposable>/rust04 cargo
  clippy --locked --all-targets -- -D warnings`: PASS, zero warnings.
- `env -u DATABASE_URL SQLX_OFFLINE=true cargo build --locked --offline`:
  PASS.
- `RUST_TEST_DATABASE_URL=... cargo test --locked --test product --
  --ignored --test-threads=1`: PASS, 8/8 (RUST-03's full product/parity
  suite, unaffected by this task).
- `cargo audit`: 1 vulnerability + 1 warning, both the same pre-accepted
  findings recorded in the RUST-02/RUST-03 reports (rsa 0.9.10
  RUSTSEC-2023-0071, no fix; rand 0.8.5 RUSTSEC-2026-0097 unsound-with-
  custom-logger warning, precondition not met anywhere in this codebase),
  inherited from frozen crypto-core pins. **No new advisory.**
- `cargo deny check advisories licenses sources bans`: `licenses ok`,
  `sources ok`, `bans ok`; `advisories FAILED` on the same two pre-accepted
  findings only.
- `cargo cyclonedx --format json`, then `jq '[.components[]|{name,version}]
  | sort'` on the regenerated file vs. the committed
  `sbom/zkpm-backend.cdx.json`: **identical component name/version sets**
  (276 crate dependencies; the raw files differ only in
  `serialNumber`/`timestamp`, which cargo-cyclonedx randomizes every run,
  and in the local `crypto-core` path-dependency's bom-ref/purl, which
  embeds this checkout's absolute path — neither indicates a real
  dependency change, which is why the CI check compares the parsed
  name/version list rather than the raw file). This is the RUST-01
  "unreviewed transitive closure" gap closed with real, repeatable,
  CI-enforced evidence rather than a one-time manual report.

**Container image (built and run for real, not just written):**
- `docker build -f infra/rust-backend/Dockerfile -t
  zkpm-backend:rust04-candidate .` from the repository root: PASS, 163MB
  final image, build time ~107s for a clean release compile.
  `sha256:92db55ba514da2363fa03e12671b5eb87965320cf4e27ad48e8b5edf5c978e86`
  (local build digest on this dev machine/checkout — see RUNBOOK.md
  Section 1 for why a real cutover must re-resolve this on the actual
  deployment/CI host).
- `docker run --rm --entrypoint id zkpm-backend:rust04-candidate`:
  `uid=10001(zkpm) gid=10001(zkpm) groups=10001(zkpm)` — non-root confirmed.
- `docker run --rm --entrypoint cat ... /etc/os-release`: Debian GNU/Linux
  12 (bookworm) confirmed.
- `docker run --rm zkpm-backend:rust04-candidate --version`: `zkpm-backend
  0.1.0`.
- **Production-posture network smoke test**: generated a real CA + signed
  server certificate (openssl, mirroring `apps/backend-rust/tests/postgres.rs`'s
  own technique), enabled TLS on a disposable `postgres:16-alpine`
  container on a private Docker bridge network (no host port needed for
  the app-to-DB leg), then ran the **actual built image** —
  `ZKPM_ENVIRONMENT=production`, `ZKPM_DATABASE_TLS=verify-full` with a
  mounted CA file, a real generated `ZKPM_OPAQUE_SERVER_SETUP`, no
  published container ports:
  - `zkpm-backend migrate`: exit 0, `migrate_complete` (5 migrations
    applied) over real verify-full TLS.
  - `zkpm-backend serve`: `server_started`; `docker exec ... zkpm-backend
    healthcheck` exit 0; a same-network `curlimages/curl` sidecar got
    `live=200` and `ready=200` from `rust-api:8080` with **no published
    host port on the API container** (`docker port` returned nothing).
  - `docker stop -t 15`: completed in ~0.1s (well under the 15s/10s-default
    shutdown budget), confirming bounded graceful shutdown under a real
    container runtime, not just `tests/process.rs`'s direct-subprocess
    simulation.

**Client E2E, rollback, migration-baseline, and backup/restore rehearsals**
(disposable `postgres:16-alpine` container, `RUST04_E2E=1` +
`RUST04_TEST_DATABASE_URL` + the real compiled `zkpm-backend` binary):
- `bun test tests/rust-backend` (backup/restore rehearsal additionally
  gated on `RUST04_BACKUP_RESTORE=1 RUST04_PG_NETWORK=... RUST04_PG_HOST=...`
  for its Docker-network-based version-matched pg_dump/pg_restore): **7/7
  PASS**, 31 `expect()` calls, re-run from a fully clean slate (no
  leftover scratch databases/containers) immediately before writing this
  report:
  - `client-e2e.test.ts` (2/2): real WASM `packages/crypto-wasm` +
    `packages/sdk` register/login/device-enrollment/key-bundle-CAS, and
    the same two-device offline/reconnect/tombstone scenario
    `tests/e2e/two-device-offline-reconnect.test.ts` proves against Bun —
    now proven against the real spawned Rust binary instead. This closes
    the specific gap the RUST-03 report flagged: only native
    Rust-client-vs-Rust-server OPAQUE was proven there; this is the actual
    WASM-client-vs-Rust-server path a real browser/extension/desktop
    client uses.
  - `rollback-compat.test.ts` (2/2): a bearer session minted by the real
    Rust binary is accepted by the Bun backend (`buildApp`, in-process) on
    the *same* database after Rust is fully stopped, and the mirror image
    (Bun-minted token accepted by Rust after Bun is fully stopped) — both
    directions proven end to end, not inferred from code reading. This is
    the required "old-server rollback drill," and it additionally shows a
    *forward* cutover preserves already-logged-in sessions too.
  - `migration-baseline.test.ts` (2/2): a database migrated by the real
    Bun `migrate.mjs` adopts cleanly into the Rust SQLx baseline with no
    DDL replay, the legacy `schema_migrations` table stays in sync, and
    Bun's own migrator re-run afterward is a no-op; a fresh database
    migrated only by the Rust binary is recognized as fully up to date by
    Bun's migrator with no error.
  - `backup-restore-rehearsal.test.ts` (1/1): the existing, **unmodified**
    `infra/backup.sh`/`infra/restore.sh` (run inside a version-matched
    `postgres:16-alpine` container after discovering the dev machine's
    local `pg_dump` is v14 and refuses to talk to the v16 test server —
    documented in the test file) round-tripped a database populated
    entirely through the real Rust binary (account + device row):
    restored row counts matched exactly.
- `git status`/`git diff --stat` outside the allowed paths: clean, checked
  after every session.

## Known limitations

- **Container digest is local, not registry-resolved**: this task has no
  registry credentials and was not authorized to push anywhere. The
  `container-image` CI job added to `.github/workflows/rust-backend.yml`
  builds and smoke-checks the same Dockerfile on Linux CI on every push/PR
  going forward, but a real cutover still needs a human to build (or pull
  from wherever CI/the deployment pipeline is configured to push) the
  actual candidate on the deployment host and record *that* digest — see
  RUNBOOK.md Section 1.
- **Backup/restore rehearsal needs Docker-network host/hostname env vars**
  (`RUST04_PG_NETWORK`/`RUST04_PG_HOST`) because it shells out to a
  version-matched `postgres:16-alpine` container to run `pg_dump`/
  `pg_restore` at the server's exact version (a mismatch fails hard, as
  discovered while writing this test — the dev machine only had Homebrew's
  `postgresql@14` client tools installed against a v16 server). This is
  why it's excluded from the `client-e2e` CI job (no clean way to name a
  GitHub Actions service container's network from within a job) and is
  instead a documented local-rehearsal step; it was run successfully on
  this dev machine as recorded above.
- **No production TLS certificate chain was tested** beyond the disposable
  CA/cert generated for this task's own container smoke test; the actual
  VPS's real TLS posture (Caddy-terminated, static self-signed cert per the
  R01 STATUS.md row, or eventually a real domain) is unaffected by any of
  this — the Rust backend's own DB-side TLS (`ZKPM_DATABASE_TLS`) is a
  separate concern from Caddy's edge TLS, and neither was changed.
- **No load/throughput/soak testing** of the bounded `spawn_blocking`
  OPAQUE permit or the concurrency limiter under sustained real traffic —
  RUST-02/03 already noted this gap; RUST-04 does not close it.
- **The single-image container test used a fresh, empty disposable
  database** — it did not additionally exercise a *populated* database
  under container-network TLS (that combination was covered separately:
  container/TLS smoke test used an empty DB; population/backup/restore/
  rollback used the host-networked binary directly, not the container
  image). A human rehearsing the real cutover should combine both — run
  the actual candidate *image* (not just the debug binary) through the
  backup/restore and rollback drills once more on the real deployment
  host, per RUNBOOK.md.
- **OPAQUE server setup handling in the compose overlay is intentionally
  incomplete**: `infra/rust-backend/docker-compose.rust-backend.yml`
  deliberately does not default `ZKPM_OPAQUE_SERVER_SETUP` (or any other
  `ZKPM_*` value) — a human must add the real values to
  `infra/.env.production` before ever running this overlay for real, and
  RUNBOOK.md Section 2 says so explicitly. This is a safety choice (fail
  closed on a missing value) rather than an oversight.
- **H02/external audit remains BLOCKED** (`docs/plan/STATUS.md`); the two
  inherited `cargo audit` findings (rsa 0.9.10, rand 0.8.5) stay open per
  RUST-02/RUST-03's existing acceptance. This task adds no new finding but
  also resolves none of the existing ones.

## Security considerations

- No cryptographic primitive, OPAQUE flow, session-token scheme, or
  frozen contract was changed by this task — all Rust source in
  `apps/backend-rust/src/` is untouched; every change is
  container/CI/test/documentation.
- The container runtime image runs as a dedicated non-root user
  (`uid=10001`), has no shell utilities beyond Debian slim's base plus
  `ca-certificates`, and exposes no ports beyond documentation (`EXPOSE
  8080`) — actual reachability is controlled entirely by the compose
  network topology in `infra/rust-backend/docker-compose.rust-backend.yml`
  (private `database` network, `proxy`-only for the API, no published DB
  port), matching the existing Bun `api`/`migrate` posture.
- `tests/rust-backend/` never logs or persists real credentials: the one
  password used in the backup-restore rehearsal is a fixed disposable
  string used only inside a throwaway database dropped at test end;
  registration/login always use freshly generated random account IDs and
  passwords (`node:crypto randomBytes`/`randomUUID`), never fixtures.
  `helpers.ts` never disables TLS/production checks *inside the shipped
  binary itself* — it uses `ZKPM_ENVIRONMENT=test` (loopback-only,
  documented fail-closed posture), matching how RUST-02/03's own test
  suites already run the binary; the separate container smoke test above
  exercised the actual `ZKPM_ENVIRONMENT=production` + verify-full TLS
  path once, directly.
- No production mutating traffic — real or synthetic-shadowed against both
  backends for comparison — was ever generated or replayed. Every register/
  login/sync operation in every new test runs against a freshly created,
  uniquely named, disposable scratch database, dropped in a `finally`
  block immediately afterward (mirroring `apps/backend-rust/tests/product.rs`'s
  own `TestDatabase` pattern).
- The rollback-compat finding (bearer sessions are valid across a Bun<->
  Rust switch on the same database) is a **security-relevant fact a human
  reviewer should confirm they're comfortable with**, not just an
  operational convenience: it means a cutover or rollback does not force
  reauthentication, which is good for availability but means an attacker
  who already holds a stolen bearer token is unaffected by which backend
  is currently serving traffic — exactly the same as today's Bun-only
  deployment (a bearer token is a bearer token regardless of which process
  validates it), so this is a restatement of an existing property, not a
  new exposure, but it is called out explicitly here per this task's
  "flag anything requiring human confirmation" instruction.

## Follow-up tasks (all require human decision before any real cutover —
see `infra/rust-backend/RUNBOOK.md` for the full procedure)

1. **Human release-owner decision to actually execute Phase 3** of the
   runbook (editing the real `infra/Caddyfile`) — explicitly out of scope
   for this task and not performed.
2. **Resolve and record a real candidate image digest** on the actual
   deployment host or CI/registry pipeline before cutover (this task's
   local build digest is informative, not the artifact to deploy).
3. **Confirm the OPAQUE-server-setup reuse plan** in RUNBOOK.md Section 0/2
   (same `OPAQUE_SERVER_SETUP` value must be present in the Rust backend's
   config as already exists in `infra/.env.production` for the Bun
   backend) before bringing up `rust-api` for real.
4. **Re-run the backup/restore + rollback rehearsal on the real deployment
   host** using the actual container image (not just the debug binary
   this task used for most of the E2E suite) once a human is ready to
   proceed, per the Known limitations note above.
5. H02 (external audit) remains `BLOCKED` and continues to gate any
   public-release claim; this task's personal/internal-deployment-scope
   candidate does not change that.

No production infrastructure, Bun backend, or client was touched, removed,
or switched by this task.
