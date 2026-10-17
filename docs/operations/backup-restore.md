# Backup and restore

For docker compose installs, `deploy/backup-db.sh` writes the database
backups and `deploy/restore-db.sh` restores them. Both run on the host, from
the compose directory, and reach the database through the `postgres`
container (`docker compose exec`), using that container's `POSTGRES_USER` and
`POSTGRES_DB`; neither holds a password. Kubernetes installs: see the end of
this page.

## What is and is not in a backup

`backup-db.sh` dumps the PostgreSQL database (all tenants, plain SQL from
`pg_dump`, gzip). Not in it, and needed for a full recovery:

| Item | Where | How to keep it |
|---|---|---|
| `.env` | compose directory | password manager. Without the same `ENCRYPTION_MASTER_KEY`, the integration credentials stored in a restored database cannot be decrypted. |
| uploads (case attachments, evidence) | volume `pysoar_pysoar-uploads` | volume archive, below |
| application data (STIG content, agent tokens) | volume `pysoar_pysoar-data` | volume archive, below |
| TLS certificate | `nginx/ssl/` | certbot re-issues it |

Redis holds the Celery queue and caches; it is not backed up.

Volume names are `<project>_<volume>`; the project is the compose directory's
name (`pysoar` for `/opt/pysoar`); `docker volume ls` lists them. To archive
and restore a volume with an image the stack already uses:

```sh
docker run --rm -v pysoar_pysoar-uploads:/v:ro -v "$PWD/backups:/b" postgres:15-alpine \
  tar czf "/b/pysoar-uploads-$(date +%Y%m%d).tgz" -C /v .
docker run --rm -v pysoar_pysoar-uploads:/v -v "$PWD/backups:/b:ro" postgres:15-alpine \
  tar xzf /b/pysoar-uploads-YYYYMMDD.tgz -C /v
```

Copy `backups/` off the host as well: a backup on the same disk as the
database does not survive losing the host.

## Backup: `deploy/backup-db.sh`

```text
deploy/backup-db.sh [--dry-run] [--prune-only]
```

Writes `backups/pysoar_YYYYMMDD.sql.gz` (mode 600, directory mode 700),
checks it with `gzip -t`, refuses a dump smaller than `MIN_BYTES`, then
prunes. One file per day: a second run on the same day replaces that day's
file. Install it for root:

```sh
0 2 * * * /opt/pysoar/deploy/backup-db.sh >> /var/log/pysoar-backup.log 2>&1
```

| Variable | Default | Meaning |
|---|---|---|
| `PYSOAR_DIR` | `/opt/pysoar` | compose directory |
| `BACKUP_DIR` | `$PYSOAR_DIR/backups` | where dumps go |
| `KEEP_DAILY` | `14` | newest daily dumps kept |
| `KEEP_WEEKLY` | `8` | weeks of Sunday dumps kept |
| `KEEP_MONTHLY` | `12` | months of 1st-of-month dumps kept |
| `KEEP_EVENT_DAYS` | `90` | days `pre-*-YYYYMMDD-HHMMSS.sql.gz` dumps are kept |
| `MIN_BYTES` | `1048576` | smaller dumps are treated as failures |

A new install's dump is smaller than the 1 MiB default (68 KB for an empty
schema in the drill below), so set `MIN_BYTES` lower in the crontab line until
the database has grown, or every run fails.

`--dry-run` prints what pruning would delete without dumping or deleting;
`--prune-only` skips the dump.

Ad-hoc dumps before risky work (an upgrade, a restore) use the event name
pattern so retention keeps them:

```sh
(umask 077; docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  | gzip > "backups/pre-upgrade-$(date +%Y%m%d-%H%M%S).sql.gz")
```

## Restore

`deploy/restore-db.sh`:

```text
deploy/restore-db.sh [--verify-only] [--yes] [--no-migrate] DUMP.sql.gz
```

1. `gzip -t` on the dump.
2. Creates a scratch database `<db>_restore_<stamp>` next to the live one and
   loads the dump with `psql -v ON_ERROR_STOP=1`; any SQL error stops it.
3. Checks the restored copy: `alembic_version` holds exactly one revision,
   and that revision is a file in this checkout's `alembic/versions` (a dump
   from newer code than the checkout is refused: check out the matching
   version first).
4. Checks row counts: more than one table in `public`, and at least
   `MIN_USERS` (default 1) rows in `users`. Prints the counts of
   `organizations`, `users`, `alerts`, `incidents` and `audit_logs` in the
   restored copy next to the live database.

`--verify-only` ends here and drops the scratch database. Otherwise it asks
for confirmation (or takes `--yes`; without a terminal it requires `--yes`),
then:

5. stops `api worker scheduler flower`, ends the remaining connections, and
   renames the live database to `<db>_pre_restore_<stamp>` and the scratch
   copy to the live name in one transaction;
6. runs `docker compose run --rm --no-deps api alembic upgrade head` (skip with
   `--no-migrate`), so an older dump is brought to the checkout's schema;
7. starts the services, restarts `frontend nginx`, and waits up to
   `HEALTH_TIMEOUT` seconds (180) for `/api/v1/health` to say `healthy`.

Any failure before step 5 drops the scratch database and leaves the live one
untouched. A failure after it leaves the services stopped and prints the undo
command. The previous database is never dropped by the script; it prints the
`dropdb` command for when you are satisfied, and the undo command:

```sh
docker compose stop api worker scheduler flower && \
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d postgres -c "ALTER DATABASE pysoar RENAME TO pysoar_failed_restore_<stamp>; ALTER DATABASE pysoar_pre_restore_<stamp> RENAME TO pysoar"' && \
docker compose start api worker scheduler flower && docker compose restart frontend nginx
```

The scratch copy lives in the same Postgres instance, so the disk needs room
for a second copy of the database while the script runs.

Other variables: `PYSOAR_DIR` (default `/opt/pysoar`), `APP_SERVICES`
(default `api worker scheduler flower`), `PROXY_SERVICES` (default
`frontend nginx`).

## The restore drill

A backup that has never been restored is not known to work. Monthly, and
after any change to the backup set-up, run against the live stack:

```sh
cd /opt/pysoar
deploy/restore-db.sh --verify-only "backups/pysoar_$(date +%Y%m%d).sql.gz"
```

It exits 0 and prints `verification passed` with the row counts when the
dump restores; the live database is not touched. Compare the restored counts
with the live ones (the live side has grown since the dump was taken). Record
the date, dump name and result.

A full drill (swap included) belongs on a separate host or project, not on
production: copy the compose directory (code, `.env`, `alembic/`), start
`postgres redis api worker scheduler` there, and run
`deploy/restore-db.sh --yes` with `PYSOAR_DIR` pointing at the copy.

### Drill record: 2026-10-17 (Docker Desktop 29.2.1, Windows, Git Bash)

Throwaway compose project `pcdrill` in the session scratch directory:
`postgres:15-alpine`, `redis:7-alpine`, and `api`, `worker`, `scheduler` from a
backend image built from commit 587325f with `src/` and `alembic/`
bind-mounted, `.env` as in the compose install guide (`APP_ENV=production`).
`MSYS_NO_PATHCONV=1` and `COMPOSE_PROJECT_NAME=pcdrill` were set for Git Bash;
the scripts were run unmodified from `deploy/`.

1. `docker compose run --rm --no-deps api alembic upgrade head` on the empty
   database: 210 tables created, stamped `038`. The api started and created
   the first administrator (1 row in `users`).
2. `PYSOAR_DIR=<drill dir> MIN_BYTES=1 bash deploy/backup-db.sh`: wrote
   `pysoar_20261017.sql.gz` (68 KB, `gzip -t` passed).
3. Created a marker table `drill_marker_after_backup` in the live database.
4. `restore-db.sh --verify-only` on the dump: exit 0, revision `038`,
   211 tables, `users` 1, scratch database dropped, live database unchanged.
5. `APP_SERVICES="api worker scheduler" PROXY_SERVICES=redis restore-db.sh --yes`
   on the dump: exit 0, databases swapped, `alembic upgrade head` a no-op,
   health `healthy`; the marker table was gone from `pysoar` and present in
   `pysoar_pre_restore_<stamp>`.
6. Refusals, each exit 1 with the scratch database dropped and the live one
   untouched: a truncated dump (`gzip -t`), a dump whose `alembic_version`
   was edited to `999` (unknown revision), a dump with an SQL error injected
   (`ON_ERROR_STOP`), `MIN_USERS=2`, and a run without `--yes` and without a
   terminal.
7. A dump whose `alembic_version` was edited to `037`: restored, and
   `alembic upgrade head` ran `037 -> 038`; health `healthy`.
8. The printed undo command, run as printed: the previous database was back
   under its name and the api reported `healthy`.
9. After a database password change (`ALTER USER`, new `DATABASE_URL`,
   `docker compose up -d`): backup and full restore repeated, both exit 0.

Not covered by the drill: the full `docker-compose.yml` (nginx, frontend,
flower, the fixed container names), a Linux host, dumps of a populated
production-size database, and restores across major PostgreSQL versions.

## The application's `/api/v1/backup` routes

The application's own backup routes (`POST /api/v1/backup/create`,
`POST /api/v1/backup/restore`, platform superusers only) call `pg_dump` and
`psql` inside the api container. The backend image does not contain them
(it installs `libpq5` only), so `create` falls back to a metadata-only file
whose note says so, and `restore` cannot restore a database. Use the scripts
above.

## Kubernetes

`backup-db.sh` and `restore-db.sh` drive docker compose and do not apply.
Use the managed database's snapshots and point-in-time recovery, and back up
the chart's data claim (`<release>-data`) with your storage provider's
tooling. The same checks apply after a restore: one row in `alembic_version`
that the deployed code knows, a plausible `users` count, then a
`helm upgrade` so the migration hook brings the schema to head. None of this
has been run on a cluster.
