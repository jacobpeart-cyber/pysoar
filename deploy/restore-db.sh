#!/usr/bin/env bash
# Restore a PySOAR PostgreSQL dump written by deploy/backup-db.sh.
#
# The dump is loaded into a NEW scratch database next to the live one and
# checked there first; the live database is not touched until the restored
# copy passes:
#
#   1. gzip integrity (gzip -t)
#   2. psql loads the whole dump with ON_ERROR_STOP (any SQL error aborts)
#   3. alembic_version holds exactly one revision, and that revision exists
#      in this checkout's alembic/versions (a dump from newer code than the
#      checkout is refused)
#   4. row counts: the restored database has tables and at least MIN_USERS
#      rows in users; counts of key tables are printed next to the live ones
#
# --verify-only stops there and drops the scratch database: the restore drill,
# safe to run against a live stack. Without it, the script then stops the
# application services, renames the live database to <db>_pre_restore_<stamp>
# (kept, never dropped by this script), renames the scratch copy to the live
# name in the same transaction, runs `alembic upgrade head`, starts the
# services again and waits for GET /api/v1/health.
#
# Usage: restore-db.sh [--verify-only] [--yes] [--no-migrate] DUMP.sql.gz
#
# Environment (defaults match docker-compose.yml):
#   PYSOAR_DIR         compose project directory          (/opt/pysoar)
#   MIN_USERS          minimum rows in users to accept    (1)
#   APP_SERVICES       stopped during the swap            (api worker scheduler flower)
#   PROXY_SERVICES     restarted after the swap           (frontend nginx)
#   HEALTH_TIMEOUT     seconds to wait for a healthy /api/v1/health (180)
set -euo pipefail

REPO="${PYSOAR_DIR:-/opt/pysoar}"
MIN_USERS="${MIN_USERS:-1}"
APP_SERVICES="${APP_SERVICES:-api worker scheduler flower}"
PROXY_SERVICES="${PROXY_SERVICES:-frontend nginx}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"

VERIFY_ONLY=0
ASSUME_YES=0
MIGRATE=1
DUMP=""
for arg in "$@"; do
    case "$arg" in
        --verify-only) VERIFY_ONLY=1 ;;
        --yes) ASSUME_YES=1 ;;
        --no-migrate) MIGRATE=0 ;;
        -h|--help) sed -n '2,34p' "$0"; exit 0 ;;
        -*) echo "unknown argument: $arg" >&2; exit 2 ;;
        *) [ -z "$DUMP" ] || { echo "only one dump file may be given" >&2; exit 2; }; DUMP="$arg" ;;
    esac
done
[ -n "$DUMP" ] || { echo "usage: restore-db.sh [--verify-only] [--yes] [--no-migrate] DUMP.sql.gz" >&2; exit 2; }

log() { printf '%s [restore-db] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

# Resolve the dump path before changing directory.
case "$DUMP" in /*) ;; *) DUMP="$PWD/$DUMP" ;; esac
[ -r "$DUMP" ] || die "cannot read $DUMP"
cd "$REPO"

# psql inside the postgres container, as the container's own superuser (the
# credentials come from the container environment, nothing is hard-coded).
# Arguments after the SQL-free options are passed through to psql.
pg() {
    docker compose exec -T postgres sh -c 'exec psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$@"' psql "$@"
}
# One value from a query: pg_value DB "SQL"
pg_value() {
    pg -d "$1" -At -c "$2"
}

LIVE_DB="$(docker compose exec -T postgres sh -c 'printf %s "$POSTGRES_DB"')"
[ -n "$LIVE_DB" ] || die "could not read POSTGRES_DB from the postgres container (is the stack up?)"
STAMP="$(date +%Y%m%d%H%M%S)"
SCRATCH="${LIVE_DB}_restore_${STAMP}"
OLD="${LIVE_DB}_pre_restore_${STAMP}"
SWAPPED=0

cleanup() {
    status=$?
    if [ "$SWAPPED" = 0 ] && [ -n "${SCRATCH_CREATED:-}" ]; then
        log "dropping scratch database $SCRATCH"
        pg -d postgres -c "DROP DATABASE IF EXISTS \"$SCRATCH\"" || log "WARNING: could not drop $SCRATCH; drop it by hand"
    fi
    exit "$status"
}
trap cleanup EXIT

# ------------------------------------------------------------ 1. integrity --
log "checking gzip integrity of $DUMP"
gzip -t "$DUMP" || die "$DUMP is not a valid gzip file"

# ----------------------------------------------------------------- 2. load --
log "creating scratch database $SCRATCH"
pg -d postgres -c "CREATE DATABASE \"$SCRATCH\""
SCRATCH_CREATED=1
log "loading the dump into $SCRATCH"
gunzip -c "$DUMP" | pg -d "$SCRATCH" >/dev/null || die "psql stopped on an error while loading the dump"

# --------------------------------------------------------------- 3. alembic --
has_alembic="$(pg_value "$SCRATCH" "SELECT count(*) FROM pg_tables WHERE schemaname = 'public' AND tablename = 'alembic_version'")"
[ "$has_alembic" = 1 ] || die "the restored database has no alembic_version table"
mapfile -t versions < <(pg_value "$SCRATCH" "SELECT version_num FROM alembic_version")
[ "${#versions[@]}" = 1 ] || die "alembic_version holds ${#versions[@]} rows (expected exactly 1): ${versions[*]:-none}"
restored_rev="${versions[0]}"

known_revs="$(sed -nE "s/^revision(: *str)? *= *['\"]([^'\"]+)['\"].*/\2/p" alembic/versions/*.py)"
down_revs="$(sed -nE "s/^down_revision[^=]*= *['\"]([^'\"]+)['\"].*/\1/p" alembic/versions/*.py)"
head_rev="$(comm -23 <(printf '%s\n' "$known_revs" | sort -u) <(printf '%s\n' "$down_revs" | sort -u) | paste -sd, -)"
printf '%s\n' "$known_revs" | grep -qxF "$restored_rev" \
    || die "restored revision $restored_rev is not in this checkout's alembic/versions (head $head_rev): check out the code the dump was taken with"
log "alembic revision of the dump: $restored_rev (this checkout's head: $head_rev)"

# ------------------------------------------------------------ 4. row counts --
tables="$(pg_value "$SCRATCH" "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"
[ "$tables" -gt 1 ] || die "the restored database has $tables table(s) in schema public"
users="$(pg_value "$SCRATCH" "SELECT count(*) FROM users")" || die "the restored database has no users table"
[ "$users" -ge "$MIN_USERS" ] || die "the restored database has $users row(s) in users (MIN_USERS=$MIN_USERS)"

count_or_dash() {
    pg_value "$1" "SELECT CASE WHEN to_regclass('public.$2') IS NULL THEN '-' ELSE (xpath('/row/c/text()', query_to_xml('SELECT count(*) AS c FROM public.$2', false, true, '')))[1]::text END"
}
log "tables in public: $tables"
printf '%-16s %12s %12s\n' "table" "restored" "live"
for t in organizations users alerts incidents audit_logs; do
    printf '%-16s %12s %12s\n' "$t" "$(count_or_dash "$SCRATCH" "$t")" "$(count_or_dash "$LIVE_DB" "$t" 2>/dev/null || echo '?')"
done
log "verification passed"

if [ "$VERIFY_ONLY" = 1 ]; then
    log "--verify-only: leaving $LIVE_DB untouched"
    exit 0
fi

# ----------------------------------------------------------------- 5. swap --
if [ "$ASSUME_YES" = 0 ]; then
    [ -t 0 ] || die "refusing to replace $LIVE_DB without a terminal; pass --yes"
    printf 'Replace database %s with the restored copy? The current one is kept as %s. [y/N] ' "$LIVE_DB" "$OLD"
    read -r answer
    [ "$answer" = y ] || [ "$answer" = Y ] || die "aborted; $LIVE_DB untouched"
fi

# shellcheck disable=SC2086 # service lists are word-split on purpose
{
    log "stopping $APP_SERVICES"
    docker compose stop $APP_SERVICES
    log "swapping databases: $LIVE_DB -> $OLD, $SCRATCH -> $LIVE_DB"
    pg -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname IN ('$LIVE_DB', '$SCRATCH') AND pid <> pg_backend_pid()" >/dev/null
    # Two renames in one statement string: psql sends it as one query, so
    # PostgreSQL runs both in a single implicit transaction.
    pg -d postgres -c "ALTER DATABASE \"$LIVE_DB\" RENAME TO \"$OLD\"; ALTER DATABASE \"$SCRATCH\" RENAME TO \"$LIVE_DB\""
    SWAPPED=1
    rollback_hint="to undo: docker compose stop $APP_SERVICES && docker compose exec -T postgres sh -c 'psql -U \"\$POSTGRES_USER\" -d postgres -c \"ALTER DATABASE $LIVE_DB RENAME TO ${LIVE_DB}_failed_restore_${STAMP}; ALTER DATABASE $OLD RENAME TO $LIVE_DB\"' && docker compose start $APP_SERVICES && docker compose restart $PROXY_SERVICES"

    if [ "$MIGRATE" = 1 ]; then
        log "running alembic upgrade head"
        docker compose run --rm --no-deps api alembic upgrade head \
            || die "alembic upgrade head failed; services left stopped. $rollback_hint"
    fi

    log "starting $APP_SERVICES"
    docker compose start $APP_SERVICES
    log "restarting $PROXY_SERVICES (they cache the api address)"
    docker compose restart $PROXY_SERVICES
}

# /api/v1/health answers 200 with "degraded" when Postgres or Redis is
# unreachable, so the body must say "healthy".
log "waiting up to ${HEALTH_TIMEOUT}s for GET /api/v1/health to report healthy"
deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
until body="$(docker compose exec -T api curl -fsS http://localhost:8000/api/v1/health 2>/dev/null)" \
        && [[ "$body" == *'"status":"healthy"'* ]]; do
    [ "$(date +%s)" -lt "$deadline" ] || die "the api did not report healthy in ${HEALTH_TIMEOUT}s. $rollback_hint"
    sleep 3
done
log "health: $body"
log "restore complete. alembic: $(pg_value "$LIVE_DB" "SELECT version_num FROM alembic_version")"
log "the previous database is kept as $OLD; once satisfied, drop it with: docker compose exec postgres sh -c 'dropdb -U \"\$POSTGRES_USER\" $OLD'"
log "$rollback_hint"
