#!/usr/bin/env bash
# infra/backup.sh — dump the pass Postgres database to a timestamped,
# compressed pg_dump custom-format archive and prune old dumps.
#
# pg_dump's custom format (-Fc) is compressed by construction, so no
# separate gzip step is needed. A database dump is ciphertext by
# construction (the backend never holds plaintext) — this script never
# inspects, logs, or transforms dump contents.
#
# Two ways to reach Postgres:
#   1. DATABASE_URL set — runs pg_dump on the host against that URL. This is
#      the same invocation shape the Q01 test harness uses
#      (tests/security/dump-restore.test.mjs) and is the mode to use with
#      the dev stack (infra/docker-compose.yml exposes Postgres on the host).
#   2. DATABASE_URL unset — runs pg_dump *inside* the Postgres service
#      container via `docker compose exec`. This is the mode for a real VPS
#      deployment, where infra/docker-compose.prod.yml intentionally does
#      not expose Postgres to the host, and it also guarantees pg_dump's
#      version matches the server exactly.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: infra/backup.sh [-h|--help]

Environment variables:
  DATABASE_URL       postgres://user:pass@host:port/db — host pg_dump mode.
                      Unset to use docker-compose-exec mode instead.
  COMPOSE_FILE        compose file for docker-exec mode
                      (default: infra/docker-compose.prod.yml)
  POSTGRES_SERVICE    compose service name for Postgres (default: postgres)
  POSTGRES_DB         database name in docker-exec mode (default: pass)
  POSTGRES_USER       database user in docker-exec mode (default: pass)
  BACKUP_DIR          directory dumps are written to
                      (default: /var/backups/pass-vps)
  RETENTION_DAILY     most-recent daily dumps to always keep (default: 14)
  RETENTION_WEEKLY    additional weekly dumps to keep beyond the daily
                      window, one per calendar week (default: 8)
  PG_DUMP             pg_dump binary for host mode (default: pg_dump)
  DOCKER_COMPOSE      compose invocation for docker-exec mode
                      (default: "docker compose")

Writes BACKUP_DIR/pass-<UTC timestamp>.dump and prunes dumps outside the
retention window. Exits non-zero on any failure; never leaves a partial
dump at the final filename (dumps to a .partial file first, then renames).
EOF
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

BACKUP_DIR=${BACKUP_DIR:-/var/backups/pass-vps}
RETENTION_DAILY=${RETENTION_DAILY:-14}
RETENTION_WEEKLY=${RETENTION_WEEKLY:-8}
COMPOSE_FILE=${COMPOSE_FILE:-infra/docker-compose.prod.yml}
POSTGRES_SERVICE=${POSTGRES_SERVICE:-postgres}
POSTGRES_DB=${POSTGRES_DB:-pass}
POSTGRES_USER=${POSTGRES_USER:-pass}
PG_DUMP=${PG_DUMP:-pg_dump}
DOCKER_COMPOSE=${DOCKER_COMPOSE:-docker compose}
PREFIX="pass"

mkdir -p "$BACKUP_DIR"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
final="$BACKUP_DIR/${PREFIX}-${timestamp}.dump"
partial="${final}.partial"

echo "Starting backup -> $final"

if [[ -n "${DATABASE_URL:-}" ]]; then
  "$PG_DUMP" --format=custom --no-owner --no-privileges --file "$partial" --dbname "$DATABASE_URL"
else
  # shellcheck disable=SC2086
  $DOCKER_COMPOSE -f "$COMPOSE_FILE" exec -T "$POSTGRES_SERVICE" \
    pg_dump --format=custom --no-owner --no-privileges -U "$POSTGRES_USER" "$POSTGRES_DB" > "$partial"
fi

mv "$partial" "$final"
echo "Backup complete: $final ($(du -h "$final" | cut -f1))"

# --- retention pruning: keep the most recent RETENTION_DAILY dumps
# unconditionally, then one further dump per ISO calendar week (the most
# recent in that week) for up to RETENTION_WEEKLY additional weeks. Anything
# older than that is deleted. Ordering is derived from the filename's
# embedded timestamp (sortable, UTC), not filesystem mtime.

week_of() {
  local ymd=$1 # YYYYMMDD
  if date -u -d "${ymd}" +%G-%V >/dev/null 2>&1; then
    date -u -d "${ymd}" +%G-%V
  else
    date -u -j -f "%Y%m%d" "${ymd}" +%G-%V
  fi
}

daily_kept=0
weekly_kept=0
declare -A weeks_seen

while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  base="$(basename "$f" .dump)"
  ts="${base#"${PREFIX}"-}" # YYYYMMDDTHHMMSSZ
  ymd="${ts:0:8}"

  if (( daily_kept < RETENTION_DAILY )); then
    daily_kept=$((daily_kept + 1))
    continue
  fi

  week="$(week_of "$ymd")"
  if [[ -z "${weeks_seen[$week]:-}" && $weekly_kept -lt $RETENTION_WEEKLY ]]; then
    weeks_seen[$week]=1
    weekly_kept=$((weekly_kept + 1))
    continue
  fi

  echo "Pruning old backup: $f"
  rm -f -- "$f"
done < <(find "$BACKUP_DIR" -maxdepth 1 -name "${PREFIX}-*.dump" -print | sort -r)

echo "Retention: kept up to $RETENTION_DAILY daily + $RETENTION_WEEKLY weekly dumps in $BACKUP_DIR"
