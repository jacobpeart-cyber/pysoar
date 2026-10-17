#!/usr/bin/env bash
# First start of a docker compose install, in the order of
# docs/install/compose.md (steps 3, 6 and 7):
#
#   1. checks: .env and docker-compose.yml exist, the compose plugin is
#      installed, nginx's certificate and the web UI files are in place
#      (when the compose file has those services)
#   2. images: pulled when PYSOAR_IMAGE_TAG is set in .env, otherwise built
#      from the checkout (skip with --no-build)
#   3. the production checks the api runs at start, and the sign-in form's
#      check of FIRST_ADMIN_EMAIL, run once in a throwaway api container so
#      a bad .env stops here, before anything is started
#   4. docker compose up -d postgres redis
#   5. docker compose run --rm --no-deps api alembic upgrade head
#   6. docker compose up -d, then restart frontend and nginx
#   7. waits for GET /api/v1/health to report "healthy" and prints the URL
#
# Usage: start-production.sh [--no-build] [--systemd]
#
#   --no-build   use the images already present (no pull, no build)
#   --systemd    also install /etc/systemd/system/pysoar.service, which runs
#                `docker compose up -d` in this directory at boot (needs root
#                or sudo). The containers' `restart: unless-stopped` policy
#                already brings them back when Docker starts; the unit makes
#                the start explicit and ordered after the network.
#
# Environment:
#   PYSOAR_DIR       compose directory                           (/opt/pysoar)
#   HEALTH_TIMEOUT   seconds to wait for a healthy /api/v1/health (180)
#
# Re-running it on an installed system is safe: alembic applies only missing
# revisions and `up -d` recreates only changed containers. For upgrades use
# docs/operations/upgrade.md (it backs up first and stops the api before
# migrating).
set -euo pipefail

REPO="${PYSOAR_DIR:-/opt/pysoar}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-180}"
BUILD=1
SYSTEMD=0
for arg in "$@"; do
    case "$arg" in
        --no-build) BUILD=0 ;;
        --systemd) SYSTEMD=1 ;;
        -h|--help) sed -n '2,34p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

log() { printf '%s [start-production] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
die() { log "ERROR: $*"; exit 1; }

[ -d "$REPO" ] || die "$REPO does not exist (set PYSOAR_DIR to the compose directory)"
cd "$REPO"

# ------------------------------------------------------------- 1. checks --
[ -f docker-compose.yml ] || die "$REPO/docker-compose.yml not found"
[ -f .env ] || die "$REPO/.env not found; write it with deploy/configure-env.sh or by hand (docs/install/compose.md, step 2)"
docker compose version >/dev/null 2>&1 || die "the docker compose plugin is not installed ('docker compose version' failed)"

env_value() { sed -n "s/^$1=//p" .env | tail -n 1; }

mapfile -t SERVICES < <(docker compose config --services)
has_service() { local s; for s in "${SERVICES[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1; }
has_service api || die "docker-compose.yml has no api service"

if has_service nginx; then
    { [ -s nginx/ssl/fullchain.pem ] && [ -s nginx/ssl/privkey.pem ]; } \
        || die "nginx/ssl/fullchain.pem and privkey.pem are missing; nginx does not start without them (docs/install/compose.md, step 4)"
fi
if has_service frontend || has_service nginx; then
    [ -f frontend/dist/index.html ] \
        || die "frontend/dist/index.html is missing; the UI would be blank (docs/install/compose.md, step 5)"
fi

# Dumps written by deploy/backup-db.sh and by POST /api/v1/backup/create.
# The api writes as the image's pysoar user, so the directory must belong to
# that uid (root, which runs backup-db.sh from cron, can write it regardless).
mkdir -p backups
chmod 700 backups

# ------------------------------------------------------------- 2. images --
if [ "$BUILD" = 1 ]; then
    tag="$(env_value PYSOAR_IMAGE_TAG)"
    if [ -n "$tag" ]; then
        pull=()
        for s in api worker scheduler flower frontend; do has_service "$s" && pull+=("$s"); done
        log "pulling release images for PYSOAR_IMAGE_TAG=$tag: ${pull[*]}"
        docker compose pull "${pull[@]}"
    else
        commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
        log "building images from the checkout (commit $commit)"
        PYSOAR_COMMIT="$commit" docker compose build
    fi
fi

api_uid="$(docker compose run --rm --no-deps -T api id -u | tr -d '\r')"
if [ "$(stat -c %u backups)" != "$api_uid" ]; then
    if [ "$(id -u)" = 0 ]; then
        chown "$api_uid" backups
        log "backups/ now belongs to uid $api_uid (the api container's user)"
    else
        log "NOTE: backups/ is not owned by uid $api_uid (the api container's user); POST /api/v1/backup/create cannot write there until you run: sudo chown $api_uid $REPO/backups"
    fi
fi

# ------------------------------------------------- 3. production checks --
log "checking .env against the api's production checks"
docker compose run --rm --no-deps -T api python -c '
import sys
from pydantic import EmailStr, TypeAdapter, ValidationError
try:
    from src.core.config import settings
except ValidationError as exc:
    # Field name and message only: the input value may be a secret.
    for err in exc.errors():
        print("  - %s: %s" % (".".join(str(x) for x in err["loc"]), err["msg"]))
    sys.exit(1)
problems = settings.validate_production_secrets()
# The sign-in form (LoginRequest.email) uses the same validator.
try:
    TypeAdapter(EmailStr).validate_python(settings.first_admin_email)
except ValueError as exc:
    problems.append("FIRST_ADMIN_EMAIL %r cannot sign in: %s" % (settings.first_admin_email, exc.errors()[0]["msg"]))
for p in problems:
    print("  - " + p)
if not settings.is_production:
    print("  - APP_ENV is %r, not production" % settings.app_env)
    sys.exit(1)
sys.exit(1 if problems else 0)
' || die ".env fails the checks listed above; nothing was started"

# ---------------------------------------------- 4-6. migrate, then start --
log "starting postgres and redis"
docker compose up -d postgres redis
log "applying database migrations (alembic upgrade head)"
docker compose run --rm --no-deps api alembic upgrade head
log "starting every service"
docker compose up -d
proxies=()
for s in frontend nginx; do has_service "$s" && proxies+=("$s"); done
if [ "${#proxies[@]}" -gt 0 ]; then
    log "restarting ${proxies[*]} (they cache the api address)"
    docker compose restart "${proxies[@]}"
fi

# ------------------------------------------------------------ 7. health --
# /api/v1/health answers 200 with "degraded" when Postgres or Redis is
# unreachable, so the body must say "healthy".
log "waiting up to ${HEALTH_TIMEOUT}s for GET /api/v1/health to report healthy"
deadline=$(( $(date +%s) + HEALTH_TIMEOUT ))
until body="$(docker compose exec -T api curl -fsS http://localhost:8000/api/v1/health 2>/dev/null)" \
        && [[ "$body" == *'"status":"healthy"'* ]]; do
    [ "$(date +%s)" -lt "$deadline" ] || die "the api did not report healthy in ${HEALTH_TIMEOUT}s; see: docker compose logs api"
    sleep 3
done
log "health: $body"

# ----------------------------------------------------------- systemd unit --
if [ "$SYSTEMD" = 1 ]; then
    docker_bin="$(command -v docker)"
    SUDO=""
    [ "$(id -u)" = 0 ] || SUDO="sudo"
    log "installing /etc/systemd/system/pysoar.service ($docker_bin compose, in $REPO)"
    $SUDO tee /etc/systemd/system/pysoar.service >/dev/null <<EOF
[Unit]
Description=PySOAR (docker compose in $REPO)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$REPO
ExecStart=$docker_bin compose up -d
ExecStop=$docker_bin compose stop
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable pysoar.service
fi

url="$(env_value PYSOAR_PUBLIC_URL)"
log "PySOAR is running: ${url:-PYSOAR_PUBLIC_URL is not set in .env}"
log "sign in as $(env_value FIRST_ADMIN_EMAIL) with FIRST_ADMIN_PASSWORD from .env; the password must be changed at first login"
log "next: install the nightly backup (docs/operations/backup-restore.md)"
