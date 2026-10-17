#!/usr/bin/env bash
# Daily PostgreSQL backup with retention for the PySOAR production host.
#
# Replaces the root crontab one-liner that dumped every night into
# /opt/pysoar/backups with no retention, no integrity check and stderr sent to
# /dev/null (178 dumps / 8.3 GB by October 2026). Install as root:
#
#   0 2 * * * /opt/pysoar/deploy/backup-db.sh >> /var/log/pysoar-backup.log 2>&1
#
# Retention (all configurable through the environment):
#   daily    keep the newest KEEP_DAILY dumps (default 14)
#   weekly   keep Sunday dumps for KEEP_WEEKLY weeks (default 8)
#   monthly  keep 1st-of-month dumps for KEEP_MONTHLY months (default 12)
#   event    keep pre-* dumps (pre-deploy, pre-migration, ...) and the
#            pysoar_api_* dumps written by POST /api/v1/backup/create for
#            KEEP_EVENT_DAYS days (default 90)
#
# Sanity checks on the new dump (a failure exits 1 and prunes nothing):
#   MIN_BYTES             smaller dumps are failures (default 32768; an
#                         empty schema dumps to about 68 KB)
#   SHRINK_FLOOR_PERCENT  a dump smaller than this percentage of the newest
#                         previous daily dump is a failure (default 50); it
#                         is kept as <name>.sql.gz.suspect for inspection.
#                         ALLOW_SHRINK=1 accepts it (after a deliberate purge).
#
# Usage: backup-db.sh [--dry-run] [--prune-only]
set -euo pipefail

REPO="${PYSOAR_DIR:-/opt/pysoar}"
DIR="${BACKUP_DIR:-$REPO/backups}"
KEEP_DAILY="${KEEP_DAILY:-14}"
KEEP_WEEKLY="${KEEP_WEEKLY:-8}"
KEEP_MONTHLY="${KEEP_MONTHLY:-12}"
KEEP_EVENT_DAYS="${KEEP_EVENT_DAYS:-90}"
MIN_BYTES="${MIN_BYTES:-32768}"     # a dump smaller than 32 KiB is treated as a failure
SHRINK_FLOOR_PERCENT="${SHRINK_FLOOR_PERCENT:-50}"
ALLOW_SHRINK="${ALLOW_SHRINK:-0}"

DRY_RUN=0
PRUNE_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        --prune-only) PRUNE_ONLY=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

log() { printf '%s [backup-db] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
run() { if [ "$DRY_RUN" = 1 ]; then log "DRY-RUN: $*"; else "$@"; fi; }

# A database dump is as sensitive as the database: owner-only from the first
# byte written (umask), and the directory itself is closed to other users.
umask 077
mkdir -p "$DIR"
chmod 700 "$DIR"
cd "$REPO"

# ---------------------------------------------------------------- dump ----
if [ "$PRUNE_ONLY" = 0 ]; then
    stamp="$(date +%Y%m%d)"
    out="$DIR/pysoar_${stamp}.sql.gz"
    tmp="${out}.part"
    log "dumping to $out"
    if [ "$DRY_RUN" = 0 ]; then
        # Credentials come from the container's own environment; nothing is
        # hard-coded here.
        docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' | gzip -6 > "$tmp"
        gzip -t "$tmp"
        size=$(stat -c %s "$tmp")
        if [ "$size" -lt "$MIN_BYTES" ]; then
            log "ERROR: dump is only ${size} bytes; keeping the previous backup, removing the partial file"
            rm -f "$tmp"
            exit 1
        fi
        # A dump that suddenly shrinks (a wrong database, a truncated table,
        # a half-finished purge) must not quietly become the newest backup
        # and start pushing good ones out of retention.
        # Globs expand in sorted order, so the last match is the newest date.
        prev=""
        for f in "$DIR"/pysoar_[0-9]*.sql.gz; do [ -e "$f" ] && prev="$f"; done
        if [ -n "$prev" ] && [ "$ALLOW_SHRINK" != 1 ]; then
            prev_size=$(stat -c %s "$prev")
            if [ $((size * 100)) -lt $((prev_size * SHRINK_FLOOR_PERCENT)) ]; then
                mv -f "$tmp" "${out}.suspect"
                log "ERROR: dump is ${size} bytes, under ${SHRINK_FLOOR_PERCENT}% of $(basename "$prev") (${prev_size} bytes); kept as ${out}.suspect, nothing pruned. If the shrink is expected, rerun with ALLOW_SHRINK=1"
                exit 1
            fi
        fi
        mv -f "$tmp" "$out"
        log "ok: $(du -h "$out" | cut -f1)"
    fi
fi

# --------------------------------------------------------------- prune ----
# Dumps written by the old crontab line were world-readable; tighten them.
run find "$DIR" -maxdepth 1 -name '*.sql.gz' -perm /077 -exec chmod 600 {} +
today_epoch=$(date -d "$(date +%Y-%m-%d)" +%s)
deleted=0
kept=0
freed=0

# Daily dumps: pysoar_YYYYMMDD.sql.gz
mapfile -t dailies < <(ls -1 "$DIR"/pysoar_[0-9]*.sql.gz 2>/dev/null | sort -r)
idx=0
for f in "${dailies[@]}"; do
    idx=$((idx + 1))
    name=$(basename "$f")
    ymd=${name#pysoar_}; ymd=${ymd%%.*}
    if ! d_epoch=$(date -d "${ymd:0:4}-${ymd:4:2}-${ymd:6:2}" +%s 2>/dev/null); then
        log "skip (unparseable date): $name"; continue
    fi
    age_days=$(( (today_epoch - d_epoch) / 86400 ))
    dow=$(date -d "@$d_epoch" +%u)      # 7 = Sunday
    dom=$(date -d "@$d_epoch" +%d)
    keep=0
    [ "$idx" -le "$KEEP_DAILY" ] && keep=1
    [ "$dow" = 7 ] && [ "$age_days" -le $((KEEP_WEEKLY * 7)) ] && keep=1
    [ "$dom" = 01 ] && [ "$age_days" -le $((KEEP_MONTHLY * 31)) ] && keep=1
    if [ "$keep" = 1 ]; then
        kept=$((kept + 1))
    else
        freed=$((freed + $(stat -c %s "$f")))
        run rm -f -- "$f"
        deleted=$((deleted + 1))
    fi
done

# Event dumps: pre-<reason>-YYYYMMDD-HHMMSS.sql.gz, and the in-app dumps
# pysoar_api_YYYYMMDD-HHMMSS.sql.gz (POST /api/v1/backup/create).
for f in "$DIR"/pre-*.sql.gz "$DIR"/pysoar_api_*.sql.gz; do
    [ -e "$f" ] || continue
    name=$(basename "$f")
    if [[ "$name" =~ ([0-9]{8})-[0-9]{6}\.sql\.gz$ ]]; then
        ymd=${BASH_REMATCH[1]}
        d_epoch=$(date -d "${ymd:0:4}-${ymd:4:2}-${ymd:6:2}" +%s)
        age_days=$(( (today_epoch - d_epoch) / 86400 ))
        if [ "$age_days" -gt "$KEEP_EVENT_DAYS" ]; then
            freed=$((freed + $(stat -c %s "$f")))
            run rm -f -- "$f"
            deleted=$((deleted + 1))
            continue
        fi
    fi
    kept=$((kept + 1))
done

log "retention: kept $kept, deleted $deleted, freed $((freed / 1048576)) MiB; directory now $(du -sh "$DIR" | cut -f1)"
