# Installing PySOAR with docker compose

This guide covers `docker-compose.yml` at the repository root, the file the
production host runs. `docker-compose.prod.yml` and `docker-compose.dev.yml`
also exist; they are not covered here and have not been checked against the
current code.

Every variable named below is in the generated
[environment reference](environment.md). Kubernetes: see
[kubernetes.md](kubernetes.md).

## What the stack runs

| Service | Image | Role |
|---|---|---|
| `nginx` | `nginx:1.25-alpine` | TLS edge on host ports 80, 443 and 8443. Port 80 serves `/.well-known/acme-challenge/` from `./nginx/certbot` and redirects everything else to HTTPS. Config: `nginx/nginx.conf`. |
| `frontend` | `ghcr.io/jacobpeart-cyber/pysoar-frontend:${PYSOAR_IMAGE_TAG:-local}` | nginx serving the web UI. No host port. |
| `api` | `ghcr.io/jacobpeart-cyber/pysoar-backend:${PYSOAR_IMAGE_TAG:-local}` | FastAPI on port 8000 (internal), plus the SIEM syslog receiver on host port 5514 UDP and TCP. |
| `worker` | backend image | Celery worker, `PYSOAR_DB_POOL=null`, 1536 MB memory limit. |
| `scheduler` | backend image | Celery beat, `PYSOAR_DB_POOL=null`. |
| `flower` | backend image | Celery monitoring on port 5555 (internal). |
| `postgres` | `postgres:15-alpine` | Database, volume `pysoar-postgres`. No host port. |
| `redis` | `redis:7-alpine` | Cache and Celery broker, password from `REDIS_PASSWORD`. No host port. |
| `prometheus`, `grafana` | `prom/prometheus:v2.50.1`, `grafana/grafana:10.3.1` | Metrics. Grafana publishes host port 3000. |
| `agent` | `python:3.11-alpine` | The simulation endpoint agent. It waits until the api has written a token to `/app/data/agent/`, which the api does only when `SIM_AGENT_SEED_ENABLED` is true or `APP_ENV` is not `production`. With `APP_ENV=production` and the variable unset it keeps waiting and does nothing. |

The api, worker and scheduler bind-mount `./src` (and the api also
`./alembic`, and `./backups` at `/app/backups` for the in-app backup route)
from the host, and `frontend` and `nginx` bind-mount `./frontend/dist`. The code that runs is whatever the host checkout holds, so
the checkout and the image tag must match (see
[RELEASING.md](../releases/RELEASING.md#docker-compose-and-image-tags)).

Host ports to firewall: 80 and 443 (public), 8443 (a second HTTPS port on
the same nginx), 5514 UDP/TCP (syslog senders only), 3000 (Grafana; restrict
it to operators).

## Prerequisites

- Linux host with Docker Engine and the compose plugin (`docker compose`).
  `deploy/server-setup.sh` installs them on Ubuntu 22.04.
- Git, `openssl` (and `python3` if you write `.env` by hand; both are used
  only to generate random values).
- A DNS name for the host, and a certificate for it (step 4).

## 1. Get the code

```sh
git clone https://github.com/jacobpeart-cyber/pysoar.git /opt/pysoar
cd /opt/pysoar
git checkout v0.9.0      # a release tag; or stay on main to build from source
```

`git tag` lists the releases. If none is listed, no release has been cut yet:
stay on `main` and build the images yourself (step 3).

## The short path: two scripts

Steps 2, 3, 6 and 7 are scripted. From the checkout, after step 1:

```sh
bash deploy/configure-env.sh https://soar.example.com you@example.org
# step 4 (TLS certificate) and step 5 (web UI files), then:
bash deploy/start-production.sh
```

`deploy/configure-env.sh <public URL> <admin email>` writes `.env` with exactly
the keys of step 2: fresh random values from `openssl rand` (drawn again in
the rare case one contains a word the production check refuses),
`DATABASE_SSL_MODE=disable` and `DATABASE_URL` with the `pysoar` password
the bundled postgres service is created with (change it afterwards, below),
the Redis password in all three Redis URLs, `PYSOAR_PUBLIC_URL` from the
first argument and `CORS_ORIGINS=[]`. The file is mode 600. It refuses an
admin address on a special-use domain (`.local`, `.test`, `.invalid`, ...),
which the sign-in form would reject. It refuses to overwrite an existing
`.env`; with `--force` it replaces it and keeps the old one as
`.env.replaced-<stamp>` (mode 600). It does not modify `docker-compose.yml`
and prints no secret: it prints the path and the command that reads
`FIRST_ADMIN_PASSWORD` from the file. `PYSOAR_DIR` (default `/opt/pysoar`)
names the compose directory.

`deploy/start-production.sh [--no-build] [--systemd]` then, in order:
refuses to continue without `.env`, the compose plugin, the certificate in
`nginx/ssl/` and `frontend/dist/index.html`; creates `backups/` (mode 700);
pulls the release images when `PYSOAR_IMAGE_TAG` is set in `.env`, otherwise
builds them from the checkout (`--no-build` skips both); runs the api's
production checks and the sign-in form's check of `FIRST_ADMIN_EMAIL` in a
throwaway api container and stops, with nothing started, if any fails
(field names and messages are printed, never values); then runs step 6
(`up -d postgres redis`, `alembic upgrade head`, `up -d`, restart of
`frontend` and `nginx`) and waits up to `HEALTH_TIMEOUT` seconds (180) for
`/api/v1/health` to say `healthy`. `--systemd` also installs
`/etc/systemd/system/pysoar.service`, which runs `docker compose up -d` in
the compose directory at boot. Running it again on an installed system
applies only missing migrations; for upgrades use
[upgrade.md](../operations/upgrade.md), which backs up first.

`backups/` must belong to uid 999, the `pysoar` user of the backend image,
for `POST /api/v1/backup/create` to write there; run as root, the script
chowns it, otherwise it prints the `chown` command. root (the nightly
`deploy/backup-db.sh`) writes it either way.

The steps below are the same procedure by hand.

## 2. Write `.env`

docker compose reads `.env` twice: to fill `${...}` in `docker-compose.yml`
(`REDIS_PASSWORD`, `GRAFANA_ADMIN_PASSWORD`, `PYSOAR_IMAGE_TAG`, ...) and,
through `env_file:`, as the environment of the api, worker, scheduler and
flower. Do not start from `.env.example`: it is a development file (SQLite
database, Redis on `localhost`, `APP_ENV=development`) and does not work
inside the compose network.

Create `/opt/pysoar/.env` with mode 600 and these keys. Generate each random
value separately; the comments say how.

```sh
# Production mode: arms the production checks (environment.md, "Production").
APP_ENV=production
DEBUG=false

# The bundled postgres service. docker-compose.yml creates role and database
# pysoar with POSTGRES_PASSWORD when the data volume is first initialised
# (see "Changing the database password" below for an existing database).
# In production the password must be random: not pysoar, not shorter than
# 12 characters, no weak word.  python3 -c 'import secrets; print(secrets.token_urlsafe(24))'
# The service has no TLS and is reachable only on the compose network, so
# DATABASE_SSL_MODE is disable; in production the setting must be require,
# verify-full or disable or no backend process starts.
POSTGRES_PASSWORD=
DATABASE_URL=postgresql+asyncpg://pysoar:POSTGRES_PASSWORD_HERE@postgres:5432/pysoar
DATABASE_SSL_MODE=disable

# Redis: docker-compose.yml starts redis with --requirepass ${REDIS_PASSWORD}.
# Use the same value in the three URLs.  python3 -c 'import secrets; print(secrets.token_urlsafe(24))'
REDIS_PASSWORD=
REDIS_URL=redis://:REDIS_PASSWORD_HERE@redis:6379/0
CELERY_BROKER_URL=redis://:REDIS_PASSWORD_HERE@redis:6379/1
CELERY_RESULT_BACKEND=redis://:REDIS_PASSWORD_HERE@redis:6379/2

# Two different values:  python3 -c 'import secrets; print(secrets.token_urlsafe(64))'
SECRET_KEY=
JWT_SECRET_KEY=

# Encrypts stored integration credentials. Losing it makes them unreadable.
#   openssl rand -base64 32
ENCRYPTION_MASTER_KEY=

# The first administrator, created when the users table is empty. The account
# must change its password at first login.
#   python3 -c 'import secrets; print(secrets.token_urlsafe(24))'
FIRST_ADMIN_EMAIL=
FIRST_ADMIN_PASSWORD=

# Required by docker-compose.yml for the grafana service.
GRAFANA_ADMIN_PASSWORD=

# The URL users reach PySOAR on. Used in notification links and phishing-
# simulation tracking; unset, the code falls back to the PySOAR project's own
# host, which is wrong for your deployment.
PYSOAR_PUBLIC_URL=https://soar.example.com

# The UI calls the API on the same origin, so no extra CORS origin is needed.
CORS_ORIGINS=[]
```

Replace `REDIS_PASSWORD_HERE` with the `REDIS_PASSWORD` value (the URLs are
read literally; compose does not substitute inside `env_file`). Keep a copy
of `.env` in your password manager: `SECRET_KEY`, `JWT_SECRET_KEY` and
`ENCRYPTION_MASTER_KEY` cannot be recovered from the running system.

Optional keys (integration API keys, SMTP, LLM defaults, OT discovery
ranges, ...) are listed in [environment.md](environment.md).

What the api checks at start with `APP_ENV=production` (it exits otherwise):
`SECRET_KEY` and `JWT_SECRET_KEY` must be high-entropy and must not contain
words such as `change`, `secret` or `password`; `ENCRYPTION_MASTER_KEY` must
be set to base64 of 32 bytes; `FIRST_ADMIN_PASSWORD` must pass the same
entropy and weak-word checks, so the code default `changeme123` is refused.

`deploy/configure-env.sh` (above) writes this same file.

## 3. Get the images

Either pull a release (the checkout must be on the same tag):

```sh
echo PYSOAR_IMAGE_TAG=0.9.0 >> .env
docker compose pull api worker scheduler flower frontend
```

The ghcr.io packages may be private; `docker login ghcr.io` first (see
[RELEASING.md](../releases/RELEASING.md#pulling-the-images)).

Or build from the checkout (images are tagged `:local`):

```sh
PYSOAR_COMMIT=$(git rev-parse HEAD) docker compose build
```

The backend build context is the repository root; `.dockerignore` keeps
`.env`, `.env.*` (except `.env.example`), key and certificate files,
`nginx/ssl/` and logs out of it, so a host-built image does not carry the
host's secrets. Images from the release workflow are built from a clean
checkout.

## 4. TLS certificate

nginx reads `nginx/ssl/fullchain.pem` and `nginx/ssl/privkey.pem` and does not
start without them. The HTTPS server block names `pysoar.it.com`, but as the
only server on 443 it answers for any host name.

For an evaluation install, a self-signed certificate:

```sh
bash nginx/ssl/generate-self-signed.sh soar.example.com
```

For Let's Encrypt, start the stack (step 6) with a temporary self-signed
certificate so nginx serves the ACME webroot on port 80, then:

```sh
sudo certbot certonly --webroot -w /opt/pysoar/nginx/certbot -d soar.example.com \
  --deploy-hook /opt/pysoar/deploy/certbot-deploy-hook.sh
```

The hook copies the certificate into `nginx/ssl/` and restarts nginx; certbot
runs it on every renewal. Run by hand, without certbot's `RENEWED_LINEAGE`,
it looks for the `pysoar.it.com` lineage only, and it chowns the files to
`ubuntu` unless `PYSOAR_OWNER` is set.

## 5. The web UI files

`frontend` and `nginx` serve `./frontend/dist` from the host. If it is
missing, Docker creates it empty and the UI is blank. Fill it from the
frontend image you pulled or built (use the same tag, `local` for a build):

```sh
mkdir -p frontend/dist
docker create --name pysoar-dist ghcr.io/jacobpeart-cyber/pysoar-frontend:0.9.0
docker cp pysoar-dist:/usr/share/nginx/html/. frontend/dist/
docker rm pysoar-dist
```

or build it with Node 20: `npm --prefix frontend ci && npm --prefix frontend run build`.

## 6. Create the schema, then start

The schema must exist before the api starts. The api's start-up
(`init_db()` in `src/core/database.py`) creates missing tables without an
`alembic_version` row; `alembic upgrade head` on such a database replays the
revision chain from 001 against tables that already exist instead of taking
the empty-database path. If that has happened, stamp the revision that
matches the schema by hand (`alembic stamp <rev>`) before upgrading.

```sh
docker compose up -d postgres redis
docker compose run --rm --no-deps api alembic upgrade head
docker compose up -d
```

On an empty database, `alembic upgrade head` builds every table from the
models and stamps the head revision (`alembic/env.py`); it prints
`empty database; created N tables from the models and stamped <rev>`.

## 7. Check it

```sh
docker compose ps
docker compose exec api curl -fsS http://localhost:8000/api/v1/health
curl -fsS https://soar.example.com/api/v1/health     # add -k for a self-signed certificate
```

`/api/v1/health` returns `{"status": "healthy", "version": ..., "commit": ...}`.
`degraded` means the api cannot reach Postgres or Redis. `commit` is `unknown`
for a build without `PYSOAR_COMMIT`.

Sign in at `https://soar.example.com/` as `FIRST_ADMIN_EMAIL` with
`FIRST_ADMIN_PASSWORD`; you are asked to change the password. There are no
other accounts and no demo data.

## 8. Backups

Install the nightly backup before anything else depends on the system; see
[backup-restore.md](../operations/backup-restore.md). Upgrades:
[upgrade.md](../operations/upgrade.md).

## Changing the database password

The `postgres` role is created with `POSTGRES_PASSWORD` from `.env` (default
`pysoar` when unset, for installs that predate the variable), and only when
the data volume is first initialised: changing `.env` later does not change
an existing role. The service is not published on a host port. To change
the password of an existing database:

```sh
docker compose exec postgres psql -U pysoar -d pysoar -c "ALTER USER pysoar WITH PASSWORD 'NEW_PASSWORD'"
# put NEW_PASSWORD into DATABASE_URL in .env, then recreate the backend containers:
docker compose up -d api worker scheduler flower
docker compose restart frontend nginx
```

`docker compose up -d` recreates the containers whose `env_file` content
changed. `deploy/backup-db.sh` and `deploy/restore-db.sh` connect inside the
postgres container and are not affected by the change.

## Verification record

On 2026-10-17, on Docker Desktop 29.2.1 (Windows), a throwaway compose project
with the `postgres`, `redis`, `api`, `worker` and `scheduler` services of this
file (a backend image built from commit 587325f, `./src` and `./alembic`
bind-mounted) and a `.env` written as in step 2 was used to run step 6,
step 7's in-container health check, and the database password change above.
`alembic upgrade head` built 210 tables and stamped `038`; the api started
with `APP_ENV=production` and reported `healthy`; after the password change
the recreated api reported `healthy` and queried the database. nginx,
frontend, TLS, Grafana and the public URL were not part of that run, because
the full file uses fixed container names that were already in use on that
machine.

Later the same day the two scripts were run, unmodified, from `deploy/` (Git
Bash, `MSYS_NO_PATHCONV=1`, `COMPOSE_PROJECT_NAME=h1drill`, `PYSOAR_DIR`
pointing at a throwaway directory) against a compose file with the same
`postgres`, `redis`, `api`, `worker` and `scheduler` services, a backend image
built from the working tree at 67e0c3c with this change's Dockerfile
(`postgresql-client-15`), and `src/` and `alembic/` exported from 67e0c3c plus
the new `src/api/v1/endpoints/backup.py` bind-mounted over the image's copy:

1. `configure-env.sh https://soar.drill.example.org ops@example.org` wrote
   `.env` with every key of step 2 and printed no secret. Without arguments,
   with an existing `.env` and with an `.invalid` address it exited non-zero
   and wrote nothing. Mode 600, `--force` (old file kept as
   `.env.replaced-<stamp>`, mode 600) and the refusals of a `ftp://` URL and of
   a malformed address were checked by running the script in a Linux container
   (`alpine:3.20` with bash and openssl), since NTFS does not show POSIX modes.
2. `start-production.sh` with `DATABASE_SSL_MODE=prefer`, with
   `FIRST_ADMIN_PASSWORD=changeme123` and with an `.invalid` admin address (an
   earlier run had installed one, which then could not sign in; that is why
   both scripts now check it): each stopped at the production check, exit 1,
   with no container started.
3. `start-production.sh` with the written `.env`: exit 0; `alembic upgrade
   head` built 210 tables and stamped `038`; the api ran with
   `APP_ENV=production` and reported `healthy`; the first administrator
   existed with `is_superuser` and `force_password_change` set. Signing in
   returned 403 `Password change required` with a limited token, the limited
   token was refused by `POST /api/v1/backup/create`, and after the change the
   new password signed in.
4. As that administrator, `POST /api/v1/backup/create` wrote
   `pysoar_api_<stamp>.sql.gz` (67 KB, `pg_dump` 15.19) into the host's
   `backups/`; `deploy/restore-db.sh --verify-only` restored it (revision
   `038`, 211 tables, `users` 1). `POST /api/v1/backup/restore` answered 409.

Not run: `--systemd` (no systemd on that machine), the image pull path,
nginx, frontend, flower, TLS, Grafana, and the uid-999 ownership of
`backups/` on a Linux host (Docker Desktop bind mounts do not enforce it; the
script printed its `chown` note). The worker and scheduler there used the
image's default health check, which probes port 8000 and so reports them
unhealthy; `docker-compose.yml` gives them their own checks. The full
`docker-compose.yml` was not used because its fixed container names were in
use on that machine.
