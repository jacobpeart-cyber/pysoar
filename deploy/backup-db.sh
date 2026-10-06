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
#   event    keep pre-* dumps (pre-deploy, pre-migration, ...) for
#            KEEP_EVENT_DAYS days (default 90)
#
# Usage: backup-db.sh [--dry-run] [--prune-only]
set -euo pipefail

REPO="${PYSOAR_DIR:-/opt/pysoar}"
DIR="${BACKUP_DIR:-$REPO/backups}"
KEEP_DAILY="${KEEP_DAILY:-14}"
KEEP_WEEKLY="${KEEP_WEEKLY:-8}"
KEEP_MONTHLY="${KEEP_MONTHLY:-12}"
KEEP_EVENT_DAYS="${KEEP_EVENT_DAYS:-90}"
MIN_BYTES="${MIN_BYTES:-1048576}"   # a dump smaller than 1 MiB is treated as a failure

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

mkdir -p "$DIR"
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
        mv -f "$tmp" "$out"
        log "ok: $(du -h "$out" | cut -f1)"
    fi
fi

# --------------------------------------------------------------- prune ----
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

# Event dumps: pre-<reason>-YYYYMMDD-HHMMSS.sql.gz
for f in "$DIR"/pre-*.sql.gz; do
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
