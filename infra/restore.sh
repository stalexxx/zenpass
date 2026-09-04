#!/usr/bin/env bash
# infra/restore.sh — restore a pg_dump custom-format archive (as produced by
# infra/backup.sh) into a target Postgres database.
#
# Refuses to run against a database that already has rows in the pass
# schema's core tables unless --force is passed, to avoid silently
# clobbering a live database. Intended for disaster-recovery drills (restore
# into a throwaway database/container, never the live one — see
# docs/runbooks/BACKUP-RECOVERY.md) and for bootstrapping a fresh VPS from
# an existing dump.
#
# Same two-mode design as infra/backup.sh: DATABASE_URL set uses host
# pg_restore/psql; unset falls back to `docker compose exec` into the
# Postgres service container.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: infra/restore.sh --dump <path> [--force] [-h|--help]

Options:
  --dump <path>       path to a .dump file produced by infra/backup.sh (required)
  --force             restore even if the target database already has data
  -h, --help          show this help

Environment variables:
  DATABASE_URL        postgres://user:pass@host:port/db — host pg_restore mode.
                       Unset to use docker-compose-exec mode instead.
  COMPOSE_FILE         compose file for docker-exec mode
                       (default: infra/docker-compose.prod.yml)
  POSTGRES_SERVICE     compose service name for Postgres (default: postgres)
  POSTGRES_DB          database name in docker-exec mode (default: pass)
  POSTGRES_USER        database user in docker-exec mode (default: pass)
  PG_RESTORE           pg_restore binary for host mode (default: pg_restore)
  PSQL                 psql binary for host mode (default: psql)
  DOCKER_COMPOSE       compose invocation for docker-exec mode
                       (default: "docker compose")

Never targets the live production database directly from a drill — restore
into an isolated database/container and verify there first.
EOF
}

dump_path=""
force=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dump) dump_path=${2:?--dump requires a path}; shift 2 ;;
    --force) force=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$dump_path" ]]; then
  echo "error: --dump <path> is required" >&2
  usage >&2
  exit 2
fi
if [[ ! -f "$dump_path" ]]; then
  echo "error: dump file not found: $dump_path" >&2
  exit 2
fi

COMPOSE_FILE=${COMPOSE_FILE:-infra/docker-compose.prod.yml}
POSTGRES_SERVICE=${POSTGRES_SERVICE:-postgres}
POSTGRES_DB=${POSTGRES_DB:-pass}
POSTGRES_USER=${POSTGRES_USER:-pass}
PG_RESTORE=${PG_RESTORE:-pg_restore}
PSQL=${PSQL:-psql}
DOCKER_COMPOSE=${DOCKER_COMPOSE:-docker compose}

existing_row_check_sql="SELECT COALESCE((SELECT count(*) FROM accounts), 0) + COALESCE((SELECT count(*) FROM vaults), 0) + COALESCE((SELECT count(*) FROM vault_items), 0);"

count_existing_rows() {
  if [[ -n "${DATABASE_URL:-}" ]]; then
    "$PSQL" -tA "$DATABASE_URL" -c "
      DO \$\$ BEGIN
        IF to_regclass('public.accounts') IS NULL THEN
          RAISE EXCEPTION 'no schema';
        END IF;
      END \$\$;" >/dev/null 2>&1 || { echo 0; return; }
    "$PSQL" -tA "$DATABASE_URL" -c "$existing_row_check_sql" 2>/dev/null | tr -d '[:space:]'
  else
    # shellcheck disable=SC2086
    if ! $DOCKER_COMPOSE -f "$COMPOSE_FILE" exec -T "$POSTGRES_SERVICE" \
      psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA -c "SELECT to_regclass('public.accounts') IS NOT NULL;" 2>/dev/null | grep -q 't'; then
      echo 0
      return
    fi
    # shellcheck disable=SC2086
    $DOCKER_COMPOSE -f "$COMPOSE_FILE" exec -T "$POSTGRES_SERVICE" \
      psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA -c "$existing_row_check_sql" 2>/dev/null | tr -d '[:space:]'
  fi
}

rows="$(count_existing_rows || echo 0)"
rows="${rows:-0}"

if [[ "$rows" != "0" && "$force" -ne 1 ]]; then
  echo "error: target database already has data ($rows rows across accounts/vaults/vault_items)." >&2
  echo "Refusing to restore without --force. This is a safety check to prevent" >&2
  echo "silently overwriting a live database — restore into an isolated" >&2
  echo "database/container for a drill, or pass --force if you are certain." >&2
  exit 1
fi

echo "Restoring $dump_path (existing rows: $rows, force=$force)"

if [[ -n "${DATABASE_URL:-}" ]]; then
  "$PG_RESTORE" --no-owner --no-privileges --clean --if-exists --dbname "$DATABASE_URL" "$dump_path"
else
  # shellcheck disable=SC2086
  $DOCKER_COMPOSE -f "$COMPOSE_FILE" exec -T "$POSTGRES_SERVICE" \
    pg_restore --no-owner --no-privileges --clean --if-exists -U "$POSTGRES_USER" -d "$POSTGRES_DB" < "$dump_path"
fi

echo "Restore complete."
