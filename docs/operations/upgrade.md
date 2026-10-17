# Upgrading PySOAR

Every upgrade has the same shape: back up, move the code and images to the
new version, apply the database migrations **before** the new code serves
requests, restart, check the version. Skipping the migrations is the failure
seen in production on 2026-06-15: new code against an old schema crash-loops
the api at `create_first_admin` (`UndefinedColumnError`).

Install guides: [compose](../install/compose.md),
[Kubernetes](../install/kubernetes.md). Backups:
[backup-restore.md](backup-restore.md).

## docker compose

Run from the compose directory (`/opt/pysoar` on the production host).

### 1. Note what is running

```sh
git describe --tags --always
docker compose exec api curl -fsS http://localhost:8000/api/v1/health
```

Read the release notes of every version between the running one and the
target (GitHub release page; see [RELEASING.md](../releases/RELEASING.md)).

### 2. Back up and check the backup

```sh
(umask 077; docker compose exec -T postgres sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  | gzip > "backups/pre-upgrade-$(date +%Y%m%d-%H%M%S).sql.gz")
deploy/restore-db.sh --verify-only backups/pre-upgrade-YYYYMMDD-HHMMSS.sql.gz
```

The file name pattern `pre-<reason>-YYYYMMDD-HHMMSS.sql.gz` is the one
`deploy/backup-db.sh` keeps for `KEEP_EVENT_DAYS` (90 days). `--verify-only`
loads the dump into a scratch database, checks its alembic revision and row
counts, and drops the scratch copy; the live database is not touched.

### 3. Move the code

To a release tag:

```sh
git fetch --tags origin
git checkout vX.Y.Z
```

To the tip of `main` (how the production host is deployed today):

```sh
git fetch origin main
git reset --hard origin/main
```

`git reset --hard` discards local changes to tracked files in the checkout.
`.env`, `backups/`, `frontend/dist/` and `nginx/ssl/*.pem` are untracked and
are not affected.

### 4. Move the images

Released images (set `PYSOAR_IMAGE_TAG=X.Y.Z` in `.env` first):

```sh
docker compose pull api worker scheduler flower frontend
```

Or build from the checkout:

```sh
PYSOAR_COMMIT=$(git rev-parse HEAD) docker compose build
```

A build is needed whenever `requirements.txt` or a Dockerfile changed; the
`./src` bind mount carries Python code changes but not new dependencies.

### 5. Stop the application, migrate, start

```sh
docker compose stop api worker scheduler flower
docker compose run --rm --no-deps api alembic upgrade head
docker compose up -d
docker compose restart frontend nginx
```

Stopping first keeps the old code from running against the new schema while
the migration runs. `docker compose up -d` starts the stopped containers with
a fresh process (so the bind-mounted code is re-read) and recreates any whose
image or configuration changed. `frontend` and `nginx` are restarted because
they hold the api container's address.

If `alembic upgrade head` fails, nothing has started on the new code: fix the
cause and run it again, or roll back (below).

### 6. Refresh the web UI files

`./frontend/dist` on the host is what nginx serves, not the copy inside the
frontend image. Replace it from the new frontend image and restart both
containers that mount it **before** deleting the old directory (the running
containers keep the old directory's inode; deleting it first leaves nginx an
empty root and it answers 403):

```sh
rm -rf frontend/dist.new && mkdir frontend/dist.new
docker create --name pysoar-dist ghcr.io/jacobpeart-cyber/pysoar-frontend:X.Y.Z   # or :local after a build
docker cp pysoar-dist:/usr/share/nginx/html/. frontend/dist.new/
docker rm pysoar-dist
mv frontend/dist frontend/dist.old && mv frontend/dist.new frontend/dist
docker compose restart frontend nginx
rm -rf frontend/dist.old
```

### 7. Check

```sh
docker compose ps
docker compose exec api curl -fsS http://localhost:8000/api/v1/health
docker compose exec -T postgres sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT version_num FROM alembic_version"'
```

The health response must say `healthy` with the new `version` and `commit`
(`commit` is `unknown` for a build without `PYSOAR_COMMIT`), and the alembic
revision must be the newest file in `alembic/versions/`. Then load the UI
from outside the host and confirm the page loads.

### Rolling back

The revisions' `downgrade()` functions are not exercised by any test or
procedure, so this guide does not use `alembic downgrade`. Roll back by
restoring the pre-upgrade dump with the old code:

```sh
git checkout vPREVIOUS                      # the tag noted in step 1
# set PYSOAR_IMAGE_TAG back in .env and pull, or rebuild
deploy/restore-db.sh backups/pre-upgrade-YYYYMMDD-HHMMSS.sql.gz
```

then refresh `frontend/dist` from the old image (step 6). Data written
between the backup and the rollback is lost; the database it replaces is
kept as `pysoar_pre_restore_<stamp>` (see
[backup-restore.md](backup-restore.md#restore)).

## Behaviour changes to check before upgrading

Read these together with the release notes. Each one is pinned by a test.

### Upgrading past `cc1d6d8`: database password rule, side-effect actions need an administrator

- **A production `DATABASE_URL` must carry a random password**: the api
  refuses to start when it is empty, the bundled default `pysoar`, shorter
  than 12 characters or contains a weak word (`validate_production_secrets()`
  in `src/core/config.py`). The bundled `postgres` service was created with
  the literal `pysoar` before this release. Change it first
  (compose.md, "Changing the database password"), then upgrade.
  `docker-compose.yml` now reads `POSTGRES_PASSWORD` from `.env` for the first
  initialisation of a new data volume; an existing volume is unaffected.
- **Side-effect connector actions need an administrator** through
  `POST /api/v1/integrations/installed/{id}/actions/{action_id}/execute`
  (403 `approval_required` otherwise). Analysts keep read-only actions.
  Playbooks are unaffected.
- **Sentinel incident and playbook ids are scoped**: `update_incident` takes
  an incident id (or its ARM path inside the configured workspace) and
  `run_playbook` a Logic App name (or its ARM path in the configured
  subscription); any other ARM resource is refused.

### Upgrading past `67e0c3c`: in-app backups and the backup script

- **Rebuild or pull the backend image.** It now carries `pg_dump`
  (`postgresql-client-15`, from apt.postgresql.org, so a build needs network
  access to that host). `POST /api/v1/backup/create` writes a real dump
  into `/app/backups`, which `docker-compose.yml` now mounts from the host's
  `./backups`; with an old image it answers 503 and writes nothing (it no
  longer writes a metadata-only JSON file). Pinned by
  `tests/unit/test_backup_routes.py`.
- **`./backups` must belong to uid 999** (the image's `pysoar` user) for that
  route: `sudo chown 999 /opt/pysoar/backups`. root's nightly
  `deploy/backup-db.sh` keeps working either way. Until then the route
  answers 500 and says the directory is not writable.
- **`POST /api/v1/backup/restore` always answers 409**
  (`restore_not_supported_in_app`); use `deploy/restore-db.sh`.
  `GET /api/v1/backup/status` no longer returns `auto_backup_enabled` or
  `retention_days` (they were constants, not configuration) and now returns
  `pg_dump_available`. Pinned by `tests/unit/test_backup_routes.py`.
- **`deploy/backup-db.sh`**: `MIN_BYTES` defaults to 32768 instead of 1 MiB,
  and a dump under `SHRINK_FLOOR_PERCENT` (50) of the newest previous daily
  dump now fails the run (kept as `.suspect`, nothing pruned). After a
  deliberate large purge, run it once with `ALLOW_SHRINK=1`. Drilled (see
  [backup-restore.md](backup-restore.md)), not covered by an automated test.

### Upgrading past `8d844c0` (0.9.0)

- **`FIRST_ADMIN_PASSWORD` must be set to a random value in production**, even
  when the first administrator already exists. The production check now refuses
  the code default `changeme123` and any value containing `change`, `default`,
  `password`, `secret`, `admin`, `test`, `example` or `placeholder`
  (`validate_production_secrets()` in `src/core/config.py`); before, only the
  entropy was checked and an unset variable passed. An install that never set
  it will not start after the upgrade: add a random value to `.env`
  (`python3 -c 'import secrets; print(secrets.token_urlsafe(24))'`). The value
  is only read while the `users` table is empty.
- **`DATABASE_SSL_MODE` now reaches the database connection** (`00a0d45`). It
  was validated and ignored before, so an install that set `require` or
  `verify-full` against a server without TLS (the bundled `postgres` service
  has none) was connecting in clear and will now fail to connect. Set it to
  `disable` for the bundled service, or enable TLS on the server; a `ssl=` or
  `sslmode=` parameter in `DATABASE_URL` overrides the setting.
- **The simulation agent is no longer seeded in production** (`bb7b805`)
  unless `SIM_AGENT_SEED_ENABLED=true`. An agent enrolled by an earlier version
  keeps its token and keeps working; nothing is removed. New production
  installs get no simulation agent unless the variable is set.
- Host-built images no longer contain the host's `.env` or key files
  (`.dockerignore`); no action, but rebuild the images so the old copies are
  replaced.

## Kubernetes

Not yet exercised on a cluster (the chart is render-validated only; see
[kubernetes.md](../install/kubernetes.md)). What the chart does:

1. Take a snapshot of the managed database (provider tooling; the compose
   scripts do not apply).
2. Set `image.backend.tag` and `image.frontend.tag` (or `digest`) to the new
   version, then:

   ```sh
   helm upgrade pysoar deploy/helm/pysoar -n pysoar -f my-values.yaml --wait --timeout 15m
   ```

   The `pysoar-migrate` pre-upgrade hook Job runs `alembic upgrade head` with
   the new backend image before any Deployment changes. If it fails, the
   upgrade stops with the old pods still running; read
   `kubectl -n pysoar logs job/pysoar-migrate`.
3. Check `curl -s http://127.0.0.1:8000/api/v1/health` through
   `kubectl -n pysoar port-forward svc/pysoar-api 8000:8000`.

`helm rollback` restores the previous manifests and images but does not run
the migration hook (it is `pre-install,pre-upgrade` only) and does not undo
migrations. Rolling back across a schema change means restoring the
pre-upgrade database snapshot as well.
