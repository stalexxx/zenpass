# R01-VPS-BACKUP: Backup/restore and minimal ops for the personal VPS deployment

Goal: Give the personal-VPS backend deployment (see
`docs/tasks/R01-VPS-DEPLOY.md`, delivered in parallel) a working,
documented, tested backup/restore path and minimal operational visibility
(health/log hygiene), building directly on the existing Q01 release-gate
evidence rather than inventing new mechanisms.

Scope note: This is the personal/internal-deployment slice of R01 authorized
by the human scope decision recorded in `docs/plan/STATUS.md` (2026-09-04).
It does not close R01, does not touch H02, and is not a public-release
deliverable. `docs/security/H02-RESIDUAL-RISK-ACCEPTANCE.md` is the
authorizing document.

Dependencies: Q01 (merged — read `docs/security/Q01-GATE-REPORT.md` and
`docs/runbooks/BACKUP-RECOVERY.md` first; do not re-derive the backup/restore
mechanism from scratch, extend the one already verified there), B02/B05
(merged migrations/backend).

Allowed paths: `infra/`, `docs/runbooks/`, `docs/tasks/R01-VPS-BACKUP.md`.
Coordinate with (but do not edit) `infra/docker-compose.prod.yml` /
`infra/Caddyfile` — a sibling task (`R01-VPS-DEPLOY`) owns those files; if you
need something from them, add it as a documented convention in the runbook
instead of editing those files, to avoid merge conflicts. It's fine to add
new files under `infra/` (e.g. `infra/backup.sh`).

Forbidden paths: `crates/`, `packages/crypto-*`, `docs/contracts/`,
`apps/backend/src/`, `apps/web`, `apps/extension`, `apps/desktop`.

Never log, persist, or transmit plaintext vault data, keys, passwords, or
TOTP secrets. A database backup is ciphertext by construction (the backend
never holds plaintext) — do not add any debug path that would dump decrypted
values.

## Required implementation

1. `infra/backup.sh`: a script that runs `pg_dump` (custom format, matching
   what `Q01-GATE-REPORT.md`'s dump-inspection harness already exercises)
   against the compose Postgres service, writes a timestamped, compressed
   dump to a configurable directory, and prunes dumps older than a
   configurable retention window (default suggestion: 14 daily + 8 weekly —
   pick something reasonable and document it, this is not a frozen policy).
2. `infra/restore.sh`: the inverse — restores a named dump into a target
   database, intended for use in a disaster-recovery drill or a fresh VPS.
   It must refuse to run against a database that already has data unless a
   `--force` flag is passed (avoid silent overwrite).
3. A cron or systemd-timer example (pick one, document both are possible) to
   run `infra/backup.sh` on a schedule, plus guidance for shipping the dump
   off-host (e.g., `rsync`/`rclone` to remote storage) — do not implement a
   specific cloud-storage integration, just document the extension point with
   a placeholder command.
4. Update `docs/runbooks/BACKUP-RECOVERY.md` with the concrete VPS commands:
   how to run a manual backup, how to schedule it, how to test a restore
   drill safely (into a throwaway database/container, never the live one),
   and how this relates to the isolated backup/restore evidence already
   produced by Q01 (`Q01_BACKUP_RESTORE=1`) — this task operationalizes that
   evidence for a real deployment, it does not replace it.
5. Minimal ops hygiene: confirm/document that `docker compose logs` for the
   `api` service does not emit vault plaintext or secrets (spot-check against
   the existing redaction tests referenced from B02/Q01), and add a short
   "what to monitor" section to the runbook (disk space for dump directory,
   `/health/ready`, Postgres connection count) without introducing any new
   telemetry/analytics dependency.

## Required tests / verification

- Run `infra/backup.sh` and `infra/restore.sh` end-to-end against a local
  throwaway Postgres (e.g. via `infra/docker-compose.yml`'s existing
  `postgres` service, not the production compose file) and confirm restored
  row counts/schema match the source. Show the exact commands and output in
  your report.
- `bun run test:security` still passes (you're not expected to touch it, but
  confirm no regression).
- If Docker/network access is unavailable in your sandbox for the live
  backup/restore run, say so explicitly instead of claiming it was verified,
  and describe exactly what a human should run to verify it themselves.

## Completion report format

Use the template in `docs/plan/INTEGRATOR.md` (`Task / Status / Commits /
Changed paths / Contract changes / Verification commands and results / Known
limitations / Security considerations / Follow-up tasks`).
