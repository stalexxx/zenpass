# Backup and recovery runbook

- Enable encrypted PostgreSQL backups and point-in-time recovery.
- Test restore into an isolated EU project before every release.
- Verify restored ciphertext, revisions, tombstones, cursors, and device revocations.
- Record restore duration and checksum results; do not export decrypted fixtures.
- Rotate server KMS credentials independently from user vault keys.

## Scope of this section

The bullets above are the general policy. This section operationalizes them
for the personal-VPS deployment (`R01-VPS-BACKUP`, see
`docs/plan/STATUS.md`'s 2026-09-04 scope decision and
`docs/security/H02-RESIDUAL-RISK-ACCEPTANCE.md`): concrete commands for a
single VPS running `infra/docker-compose.prod.yml`
(see `R01-VPS-DEPLOY`), using `infra/backup.sh` and `infra/restore.sh`.

It does not replace the isolated, CI-run backup/restore evidence already
produced by `Q01` (`Q01_BACKUP_RESTORE=1`, see `docs/security/Q01-GATE-REPORT.md`
and `tests/security/dump-restore.test.mjs`) — that harness proves the
mechanism (`pg_dump`/`pg_restore` custom format preserves opaque ciphertext,
revisions, and tombstones) in an ephemeral, disposable database on every CI
run. This runbook operationalizes that already-verified mechanism against a
real, persistent VPS deployment: scheduling it, retaining dumps, shipping
them off-host, and drilling a restore safely.

Both `infra/backup.sh` and `infra/restore.sh` support two ways of reaching
Postgres:

1. **`DATABASE_URL` set** — runs `pg_dump`/`pg_restore`/`psql` on the host
   against that URL. Use this against `infra/docker-compose.yml` (the dev
   stack, which exposes Postgres on `127.0.0.1:5434`) or any Postgres you can
   reach directly. Your host's `pg_dump` major version must be the same as,
   or newer than, the server's — if not, set `PG_DUMP`/`PG_RESTORE` (or
   `PSQL`) to an explicit compatible client binary.
2. **`DATABASE_URL` unset** — runs `pg_dump`/`pg_restore`/`psql` *inside* the
   Postgres service container via `docker compose exec`. This is the mode
   for the VPS: `infra/docker-compose.prod.yml` intentionally does not
   expose Postgres to the host (see `R01-VPS-DEPLOY`), and running inside
   the container guarantees the client matches the server version exactly.

## Manual backup on the VPS

```sh
cd /opt/pass   # wherever the repo is checked out on the VPS
COMPOSE_FILE=infra/docker-compose.prod.yml \
POSTGRES_SERVICE=postgres \
POSTGRES_DB=pass \
POSTGRES_USER=pass \
BACKUP_DIR=/var/backups/pass-vps \
./infra/backup.sh
```

This writes `/var/backups/pass-vps/pass-<UTC timestamp>.dump` (a `pg_dump`
custom-format archive — already compressed, no separate gzip step needed)
and prunes dumps outside the retention window. Default retention is **14
daily + 8 weekly** dumps (the most recent 14 dumps are always kept; older
ones are thinned to one per calendar week for up to 8 more weeks, then
deleted) — override with `RETENTION_DAILY`/`RETENTION_WEEKLY` if a different
policy is wanted; this is a starting point, not a frozen policy.

## Scheduling

Either a systemd timer or cron works; pick whichever this VPS already uses
for other scheduled jobs.

**systemd timer** (preferred — logs to `journalctl`, handles missed runs on
reboot via `Persistent=true`): example units are in `infra/systemd/`.

```sh
sudo cp infra/systemd/pass-backup.service infra/systemd/pass-backup.timer /etc/systemd/system/
# edit WorkingDirectory and the Environment= lines in pass-backup.service
# to match this VPS's checkout path and Postgres credentials
sudo systemctl daemon-reload
sudo systemctl enable --now pass-backup.timer
sudo systemctl list-timers pass-backup.timer   # confirm next run
journalctl -u pass-backup.service              # inspect past runs
```

**cron** (equivalent, simpler on hosts without systemd):

```
# /etc/cron.d/pass-backup — runs daily at 03:15 server time
15 3 * * * root cd /opt/pass && COMPOSE_FILE=infra/docker-compose.prod.yml POSTGRES_SERVICE=postgres POSTGRES_DB=pass POSTGRES_USER=pass BACKUP_DIR=/var/backups/pass-vps ./infra/backup.sh >> /var/log/pass-backup.log 2>&1
```

## Shipping dumps off-host

`BACKUP_DIR` is local disk — a VPS disk failure or compromise loses local
dumps too, so ship them to remote storage after each run. This task does not
implement a specific cloud-storage integration; wire up whichever remote
target the release owner controls, for example as a line appended to the
backup job:

```sh
# placeholder — replace <remote> with an actual configured rclone remote,
# or swap for `rsync -a /var/backups/pass-vps/ user@backup-host:/path/`
rclone sync /var/backups/pass-vps <remote>:pass-backups --min-age 1m
```

Dumps are ciphertext by construction (the backend never holds plaintext —
see `Q01-GATE-REPORT.md`), but treat the destination with the same access
control as any other backup of account/session data (device IDs, envelope
metadata, timestamps are visible even though vault contents are not).

## Restore drill

**Never restore into the live database.** Always drill into an isolated
database or a throwaway container first.

```sh
# 1. Bring up a disposable Postgres to drill into (do NOT use the prod
#    compose file's postgres service for this — use a separate instance,
#    e.g. the dev stack, or `docker run` a scratch postgres:16 container).
docker compose -f infra/docker-compose.yml up -d postgres

# 2. Restore the dump into an isolated database name, not the live "pass" DB.
docker exec <postgres-container> psql -U pass -d postgres -c 'CREATE DATABASE restore_drill;'
COMPOSE_FILE=infra/docker-compose.yml \
POSTGRES_SERVICE=postgres \
POSTGRES_DB=restore_drill \
POSTGRES_USER=pass \
./infra/restore.sh --dump /var/backups/pass-vps/pass-<timestamp>.dump

# 3. Verify: table list, row counts, and that ciphertext/revision/deleted
#    values round-tripped unchanged (they must — the backend never sees
#    plaintext, so a byte-for-byte match is the only thing to check, never
#    decrypt or inspect contents).
docker exec <postgres-container> psql -U pass -d restore_drill -c '\dt'
docker exec <postgres-container> psql -U pass -d restore_drill -c \
  "SELECT vault_id, item_id, revision, deleted, length(ciphertext) FROM vault_items;"

# 4. Tear down the drill database when done.
docker exec <postgres-container> psql -U pass -d postgres -c 'DROP DATABASE restore_drill WITH (FORCE);'
```

`infra/restore.sh` refuses to run if the target database already has rows in
`accounts`, `vaults`, or `vault_items` — this is the guard against silently
overwriting a live database. Pass `--force` only when you are certain (e.g.
restoring onto a genuinely fresh VPS with no data yet, or you've deliberately
decided to overwrite). Record restore duration and the row-count/checksum
comparison in the incident or release log per the general policy above.

This end-to-end path (backup a live-shaped database with a test row,
restore into an isolated database, confirm ciphertext/revision/deleted
match) was run manually during `R01-VPS-BACKUP` development; see that task's
completion report for the exact commands and output.

## Restoring onto a fresh VPS (disaster recovery)

Same as the drill above, except the target is the real `infra/docker-compose.prod.yml`
`postgres` service on a newly provisioned VPS, immediately after
`docker compose ... up -d postgres migrate` and before the `api` service has
ever taken production traffic (so `accounts`/`vaults`/`vault_items` are
still empty and `--force` is not needed):

```sh
COMPOSE_FILE=infra/docker-compose.prod.yml \
POSTGRES_SERVICE=postgres \
POSTGRES_DB=pass \
POSTGRES_USER=pass \
./infra/restore.sh --dump /path/to/pass-<timestamp>.dump
docker compose -f infra/docker-compose.prod.yml up -d
```

## What to monitor

No new telemetry/analytics dependency is introduced here — these are things
to check by hand or with plain shell/cron, not a new metrics pipeline:

- **Disk space for the dump directory** (`df -h /var/backups/pass-vps`) — a
  filling disk silently breaks backups; alerting on this is a cron one-liner
  (e.g. `df` threshold check) if the VPS doesn't already have one.
- **`/health/ready`** — the same endpoint the `api` container's Docker
  healthcheck already polls; `curl -f https://<DOMAIN>/health/ready` from
  outside confirms the whole path (reverse proxy → api → Postgres) is up.
- **Postgres connection count** — `docker compose exec postgres psql -U pass -d pass -c "SELECT count(*) FROM pg_stat_activity;"`
  compared against Postgres's `max_connections`, to catch a connection leak
  before it exhausts the pool.
- **Backup job success** — `journalctl -u pass-backup.service` (systemd) or
  the cron log file; a missed or failing backup is the thing this whole
  runbook exists to prevent.

## Log hygiene spot-check

`apps/backend/src/logger.mjs` configures Fastify's request logger (wired in
`apps/backend/src/app.mjs`) to redact `req.headers.authorization`,
`req.headers.cookie`, `req.body`, `res.headers["set-cookie"]`, and any
`password`/`masterPassword`/`recoveryKey`/`clientMessage`/`ciphertext`/`bundle`/`recoveryProof`
field wherever it appears in a logged object, replacing it with
`[REDACTED]`. This applies to every request the `api` service logs, so
`docker compose -f infra/docker-compose.prod.yml logs api` never emits
vault plaintext, bearer tokens, or session cookies — only method, URL,
status code, and request ID. This is covered by an existing automated test
(`apps/backend/test/logger.test.mjs`, run via `bun test`), re-confirmed
during `R01-VPS-BACKUP` development; see that task's completion report.

No debug path exists (and none should be added) that would log or dump
decrypted vault values — a database backup itself is ciphertext by
construction, and the API never holds plaintext to log in the first place.
