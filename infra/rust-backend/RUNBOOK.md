# RUST-04 cutover runbook (reviewed candidate — production switch NOT authorized here)

This document is the concrete procedure a human release owner would follow
to switch the personal-deployment VPS (`docs/plan/STATUS.md` R01 row) from
the current Bun `apps/backend` to the Rust `apps/backend-rust`
(`zkpm-backend`) backend, or to roll back. **Writing this runbook is not
executing it.** No step below has been run against the real VPS; every
verification referenced was run against disposable, throwaway PostgreSQL
databases and containers, never production data, never real user traffic.
Actually performing Phase 3 (traffic switch) requires the release owner's
explicit authorization at execution time, per `docs/tasks/RUST-04.md` and
`AGENTS.md`.

## 0. Why this is believed safe to attempt at all

- **Schema identity**: `apps/backend-rust/migrations/` are byte-identical
  copies of `db/migrations/*.sql` (RUST-02). This task additionally proved,
  against real disposable databases (`tests/rust-backend/migration-baseline.test.ts`):
  a database already migrated by Bun adopts cleanly into the Rust SQLx
  baseline with no DDL replay, the legacy `schema_migrations` table stays in
  sync afterward, and a *fresh* database migrated only by the Rust binary is
  still recognized as fully up to date by Bun's own migrator. Either backend
  can be pointed at the same database at any time.
- **Session compatibility**: both backends mint bearer tokens the same way
  (32 CSPRNG bytes, base64url-no-pad, only the SHA-256 hash persisted —
  `apps/backend/src/auth/sessions.mjs` vs `apps/backend-rust/src/auth/sessions.rs`,
  confirmed identical in the RUST-03 report). This task proved, end to end
  against a real disposable database (`tests/rust-backend/rollback-compat.test.ts`):
  a session token minted by Rust is accepted by Bun on the same database, and
  a session minted by Bun is accepted by Rust. **A cutover or rollback does
  not force already-logged-in users to re-authenticate**, as long as the
  target backend is pointed at the same database and comes up before the
  token's TTL (`ZKPM_SESSION_TTL_SECONDS` / `SESSION_TTL_SECONDS`, default
  900s) expires.
- **OPAQUE server setup is the one thing that must NOT change**: it is
  per-account-registration-independent server key material — the value
  itself does not need to match between the two backends' processes for
  *already-registered* accounts to keep working, but a NEW registration or
  login always talks to whichever backend is currently serving traffic, so
  during any window where both backends might handle live registration/login
  requests, both must be configured with the **same**
  `OPAQUE_SERVER_SETUP` / `ZKPM_OPAQUE_SERVER_SETUP` value (the one already
  generated for the VPS in `infra/.env.production`) or new registrations
  created against one will fail OPAQUE login against the other. This
  runbook's traffic switch (Phase 3) is a single-writer cutover (Caddy sends
  100% of traffic to exactly one backend at a time), so this only matters if
  a human deviates into a blue/green dual-serving setup — not covered here.
- **Client compatibility**: `tests/rust-backend/client-e2e.test.ts` drives
  the real `packages/sdk` + real `packages/crypto-wasm` (the exact code
  apps/web, apps/extension and apps/desktop ship) over real HTTP against the
  actual compiled `zkpm-backend` binary — register, login, device
  enrollment, key-bundle CAS, and the same two-device offline/reconnect/
  tombstone scenario `tests/e2e/two-device-offline-reconnect.test.ts` proves
  against Bun. This closes the specific gap the RUST-03 report flagged
  ("only native Rust-client-vs-Rust-server was proven, not the actual
  WASM-client-vs-Rust-server path").
- **Container artifact**: `infra/rust-backend/Dockerfile` was built and run
  locally end to end (see Verification in `docs/plan/reports/RUST-04.md`):
  non-root (`uid=10001`), Debian bookworm-slim runtime, `--locked` release
  build, real verify-full TLS to a disposable PostgreSQL over a private
  Docker network (no published DB port), `/health/live` and `/health/ready`
  both 200, `zkpm-backend healthcheck` exit 0, and a bounded graceful
  `docker stop -t 15` well under the shutdown budget.
- **Backup/restore**: `tests/rust-backend/backup-restore-rehearsal.test.ts`
  ran the existing, unmodified `infra/backup.sh` / `infra/restore.sh`
  against a database populated entirely through the real Rust binary —
  proving the existing backup tooling needs no Rust-specific changes.

## 1. Candidate artifacts

| Artifact | Identity |
|---|---|
| Rust source commit | the exact commit this report's branch HEAD points to (`git log -1 --format=%H` on `agent/RUST-04-cutover`) |
| Container image | built from `infra/rust-backend/Dockerfile` at that commit. Local build in this task: `zkpm-backend:rust04-candidate`, image ID (content digest) `sha256:92db55ba514da2363fa03e12671b5eb87965320cf4e27ad48e8b5edf5c978e86`. **This is a local build digest, not a registry-pushed digest** — no image was pushed anywhere by this task (no registry credentials, no push authorized). Before a real cutover, a human must: build this same Dockerfile on the actual deployment host (or a registry-integrated CI runner — see the `container-image` job added to `.github/workflows/rust-backend.yml`), record the resulting digest, and use *that* digest (not this local one, which reflects this task's development machine and checkout path) as the pinned candidate. |
| Base images | builder `rust:1.93.1-slim-bookworm`; runtime `debian:bookworm-slim` (resolve and record their own digests at build time on the deployment host, since tag-to-digest mapping can change upstream — see `infra/rust-backend/Dockerfile`'s own pinning comment). |
| Rust toolchain | 1.93.1, pinned in `apps/backend-rust/rust-toolchain.toml`. |
| Migrations | `apps/backend-rust/migrations/0001..0005_*.sql`, byte-identical to `db/migrations/001..005_*.sql`. |
| SBOM | `apps/backend-rust/sbom/zkpm-backend.cdx.json` (CycloneDX; regenerated and diff-checked by CI, see `.github/workflows/rust-backend.yml`'s "SBOM regeneration drift check"). |
| Dependency/advisory state | 2 pre-accepted findings (RUSTSEC-2023-0071 `rsa` 0.9.10, RUSTSEC-2026-0097 `rand` 0.8.5), both inherited from frozen crypto-core pins, already accepted in the RUST-02/RUST-03 reports; no new advisory introduced by RUST-04. |

## 2. Pre-cutover checklist (a human executes this on the real VPS)

1. **Backup/restore point.** Run the *existing* `infra/backup.sh` against
   the live production database (`DATABASE_URL` unset, docker-compose-exec
   mode against `infra/docker-compose.prod.yml`, exactly as `pass-backup.timer`
   already does). Copy the resulting dump off-host (per the existing R01
   known limitation: nothing currently ships backups off the VPS
   automatically). This is the rollback point if Phase 3 needs to be
   reverted for any reason beyond a simple backend restart.
2. **Add the `ZKPM_*` environment block** to `infra/.env.production` (not
   committed — see `infra/.env.production.example`'s existing Bun-side
   names for the pattern). At minimum: `ZKPM_ENVIRONMENT=production`,
   `ZKPM_DATABASE_URL` (same Postgres, `ZKPM_DATABASE_TLS=verify-full` with
   a CA file if the real deployment terminates DB TLS, `disabled` if it's
   the same private Docker network posture as today), `ZKPM_CORS_ORIGINS`
   (same allowlist as the Bun `WEB_ORIGIN`), and **the same base64
   `OPAQUE_SERVER_SETUP` value already in use** — reusing the existing
   value, not generating a new one, is what keeps every existing account's
   OPAQUE credential valid after cutover.
3. **Build and tag the real candidate image** on the deployment host (or a
   trusted CI runner) from `infra/rust-backend/Dockerfile` at the exact
   commit under review. Record its digest in this file / the operational
   record before proceeding.
4. **Bring up `rust-migrate` (not `rust-api`) only**, using
   `infra/rust-backend/docker-compose.rust-backend.yml` layered on top of
   `infra/docker-compose.prod.yml`, against the **real** production
   database. Confirm it exits 0 and that Bun's own migrator, re-run once
   more afterward, still reports "up to date" (mirrors
   `tests/rust-backend/migration-baseline.test.ts`, now against the real
   schema instead of a disposable one). This step is forward-only and
   additive (adopts/records baseline checksums); it does not remove
   anything Bun needs.
5. **Bring up `rust-api` alongside the existing Bun `api`** (both running,
   Caddy still routing 100% of traffic to Bun). Confirm `rust-api`'s
   healthcheck passes and `/health/ready` returns 200 through the private
   network (no published port — verify with `docker exec rust-api
   zkpm-backend healthcheck` or a same-network sidecar, exactly as this
   task's own container smoke test did).

## 3. The switch itself (requires explicit human authorization to execute)

1. Edit `infra/Caddyfile`'s `reverse_proxy @api api:3000` to point at
   `rust-api:8080` instead (or swap the compose service name `rust-api`
   receives so the existing `api` alias resolves to it — either way, this
   is the one line that actually redirects traffic, and it is **not**
   edited by this task; only a human, at execution time, touches the real
   `infra/Caddyfile`). `docker compose restart caddy` (or `reload`, if
   Caddy's admin API is enabled) picks up the change without a Caddy
   downtime window.
2. **Acceptance criteria before declaring the switch complete:**
   - `/health/live` and `/health/ready` both 200 through the real public
     endpoint (same checks R01's STATUS.md row already describes for Bun).
   - A real login (real account, real OPAQUE, real WASM client — e.g. the
     already-deployed web client) succeeds against `rust-api`.
   - A real device-bound sync round trip (create/update/pull) succeeds.
   - No elevated error rate in `rust-api`'s structured logs for at least
     one full `ZKPM_SESSION_TTL_SECONDS` window (900s default) — long
     enough to observe both fresh logins and refresh-token rotations.
3. **Draining and in-flight login state:** the OPAQUE login-state store
   (bounded TTL, one-shot consumption — see ADR-0013 and the RUST-03
   report) is in-memory and per-process on *both* backends; it was never
   durable and never migrated across a restart even before this task. A
   switch drops any OPAQUE handshake that is *mid-flight* (client has sent
   KE1, server has not yet received KE3) at the instant Caddy's upstream
   changes — those clients see a failed login attempt and must retry from
   the start, exactly as they would after any ordinary backend restart.
   This is expected and acceptable: a login handshake takes well under a
   second, so the actual affected population is minimal, and the SDK's
   OPAQUE client-side code (used by every RUST-04-tested client path)
   already surfaces a login failure as a plain retryable error, not a
   crash. **Already-issued bearer sessions are not affected** (proven by
   `tests/rust-backend/rollback-compat.test.ts` — the DB-backed session
   table is what both backends check, not any in-process state).
4. Keep the Bun `api`/`migrate` services and image available and
   untouched (do not remove them) for at least one full observation window
   past the acceptance criteria above, per `docs/tasks/RUST-04.md`'s
   "Keep old backend available for approved rollback."

## 4. Rollback triggers and procedure

**Triggers** (any one is sufficient to roll back immediately):
- `/health/ready` returns non-200 for longer than the existing healthcheck
  retry budget (60s) after the switch.
- A real login, sync, or device-management request that succeeded against
  Bun fails against `rust-api` with anything other than the same documented
  generic failure Bun itself would also return for that input.
- Any log line containing plaintext, a raw SQL error, or secret material
  (the allowlisted-logging invariant `tests/logs.rs` / the RUST-03 manual
  log inspection already checks — a regression here is an immediate
  rollback trigger, not a "monitor and see").
- Elevated 5xx rate, resource exhaustion (OOM-killed container, sustained
  503 from the bounded-concurrency limiter), or any crash-loop.

**Procedure:**
1. Revert the one `infra/Caddyfile` line back to `api:3000` (or restore the
   original service-name mapping) and restart/reload Caddy. Because of the
   session-compatibility property proven in Section 0, users who logged in
   or refreshed while `rust-api` was live remain logged in against Bun —
   this is the same result `tests/rust-backend/rollback-compat.test.ts`
   demonstrated directly.
2. Stop `rust-api`/`rust-migrate` (`docker compose -f
   infra/docker-compose.prod.yml -f
   infra/rust-backend/docker-compose.rust-backend.yml stop rust-api
   rust-migrate`). Do not drop or alter the database — Rust's migration
   adoption is additive and does not remove anything Bun's own migrator
   needs.
3. If rollback was triggered by anything suggesting data corruption (not
   just an availability/error-rate regression), stop, do **not** attempt
   further live remediation, and restore from the Section 2 backup point
   into a fresh disposable database first to inspect it, exactly as
   `infra/restore.sh`'s own safety design assumes (never restore directly
   over a database with existing rows without deliberately passing
   `--force`).
4. Record the incident and root cause before attempting cutover again.

## 5. What this runbook explicitly does NOT authorize

- It does not authorize actually editing `infra/Caddyfile`,
  `infra/docker-compose.prod.yml`, `infra/.env.production`, or any other
  file outside `apps/backend-rust/`, `infra/rust-backend/`,
  `.github/workflows/rust-backend.yml`, `tests/rust-backend/`, or the two
  RUST-04 docs files — see `docs/tasks/RUST-04.md`'s Allowed paths.
- It does not authorize removing the Bun backend, its image, or its compose
  services.
- It does not authorize replaying real production mutating traffic against
  both backends for comparison, under any circumstance.
- It does not close H02 (external audit, still `BLOCKED`) or change the
  personal/internal-deployment-only scope of R01's human decision in
  `docs/plan/STATUS.md`. This runbook is scoped identically: personal/
  internal deployment cutover only, not a public-release decision.
