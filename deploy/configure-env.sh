#!/usr/bin/env bash
# Write the production .env for the docker compose install.
#
# Writes exactly the keys of docs/install/compose.md, step 2, with fresh random
# values, for the bundled postgres and redis services of docker-compose.yml.
# It never prints a secret: it prints the file's path and the command that
# reads the first administrator's password from it.
#
# Usage: configure-env.sh [--force] PUBLIC_URL ADMIN_EMAIL
#
#   PUBLIC_URL    the URL users reach PySOAR on, e.g. https://soar.example.com
#                 (written as PYSOAR_PUBLIC_URL)
#   ADMIN_EMAIL   the first administrator's sign-in address (FIRST_ADMIN_EMAIL)
#   --force       replace an existing .env; the old file is kept next to it as
#                 .env.replaced-<stamp> (mode 600). Without --force an existing
#                 .env is never touched: its SECRET_KEY, JWT_SECRET_KEY and
#                 ENCRYPTION_MASTER_KEY cannot be recovered once overwritten.
#
# Environment:
#   PYSOAR_DIR    compose directory (/opt/pysoar)
#
# Requires openssl. docker-compose.yml is not modified. POSTGRES_PASSWORD is
# random and docker-compose.yml creates the role with it on the FIRST start;
# an already initialised database keeps its password (ALTER USER as in
# docs/install/compose.md, "Changing the database password", then --force).
set -euo pipefail

REPO="${PYSOAR_DIR:-/opt/pysoar}"
FORCE=0
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --force) FORCE=1 ;;
        -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
        -*) echo "unknown argument: $arg" >&2; exit 2 ;;
        *) ARGS+=("$arg") ;;
    esac
done
if [ "${#ARGS[@]}" -ne 2 ]; then
    echo "usage: configure-env.sh [--force] PUBLIC_URL ADMIN_EMAIL" >&2
    exit 2
fi
PUBLIC_URL="${ARGS[0]%/}"
ADMIN_EMAIL="${ARGS[1]}"

die() { echo "configure-env: ERROR: $*" >&2; exit 1; }

case "$PUBLIC_URL" in
    https://?*|http://?*) ;;
    *) die "PUBLIC_URL must start with https:// (or http://): $PUBLIC_URL" ;;
esac
[[ "$ADMIN_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] || die "ADMIN_EMAIL is not an email address: $ADMIN_EMAIL"
# The sign-in form validates the address with email-validator, which refuses
# special-use domains; an administrator created with one could never sign in.
case "${ADMIN_EMAIL##*.}" in
    arpa|invalid|local|localhost|onion|test)
        die "ADMIN_EMAIL ends in .${ADMIN_EMAIL##*.}, a special-use domain the sign-in form refuses: $ADMIN_EMAIL" ;;
esac
[ -d "$REPO" ] || die "$REPO does not exist (set PYSOAR_DIR to the compose directory)"
[ -f "$REPO/docker-compose.yml" ] || die "$REPO/docker-compose.yml not found (set PYSOAR_DIR to the compose directory)"
command -v openssl >/dev/null || die "openssl is required"

ENV_FILE="$REPO/.env"
if [ -e "$ENV_FILE" ] && [ "$FORCE" = 0 ]; then
    die "$ENV_FILE already exists; not overwriting it (pass --force to replace it; the old file is kept)"
fi

# The production checks (validate_production_secrets() in src/core/config.py)
# refuse a secret containing one of these words, in any case. A random value
# contains one by chance about once in tens of thousands; draw again if so.
WEAK_WORDS="change default password secret admin test example placeholder"

# URL-safe random string from N random bytes (the same alphabet as Python's
# secrets.token_urlsafe(N)).
token() {
    local value word
    while :; do
        value="$(openssl rand -base64 "$1" | tr -d '\n=' | tr '+/' '-_')"
        for word in $WEAK_WORDS; do
            case "${value,,}" in *"$word"*) continue 2 ;; esac
        done
        printf '%s' "$value"
        return 0
    done
}

REDIS_PASSWORD="$(token 24)"
DB_PASSWORD="$(token 24)"
SECRET_KEY="$(token 64)"
JWT_SECRET_KEY="$(token 64)"
while [ "$JWT_SECRET_KEY" = "$SECRET_KEY" ]; do JWT_SECRET_KEY="$(token 64)"; done
ENCRYPTION_MASTER_KEY="$(openssl rand -base64 32 | tr -d '\n')"
FIRST_ADMIN_PASSWORD="$(token 24)"
GRAFANA_ADMIN_PASSWORD="$(token 24)"

umask 077
TMP="$(mktemp "$REPO/.env.new.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

cat > "$TMP" <<EOF
# PySOAR production settings, written by deploy/configure-env.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Keys and meaning: docs/install/compose.md (step 2) and docs/install/environment.md.
# Keep a copy in your password manager: SECRET_KEY, JWT_SECRET_KEY and
# ENCRYPTION_MASTER_KEY cannot be recovered from the running system.

APP_ENV=production
DEBUG=false

# The bundled postgres service: docker-compose.yml creates role and database
# pysoar with POSTGRES_PASSWORD when the data volume is first initialised
# (an existing database keeps its password: compose.md, "Changing the
# database password"). No TLS on the compose network.
POSTGRES_PASSWORD=$DB_PASSWORD
DATABASE_URL=postgresql+asyncpg://pysoar:$DB_PASSWORD@postgres:5432/pysoar
DATABASE_SSL_MODE=disable

# docker-compose.yml starts redis with --requirepass \${REDIS_PASSWORD}.
REDIS_PASSWORD=$REDIS_PASSWORD
REDIS_URL=redis://:$REDIS_PASSWORD@redis:6379/0
CELERY_BROKER_URL=redis://:$REDIS_PASSWORD@redis:6379/1
CELERY_RESULT_BACKEND=redis://:$REDIS_PASSWORD@redis:6379/2

SECRET_KEY=$SECRET_KEY
JWT_SECRET_KEY=$JWT_SECRET_KEY

# Encrypts stored integration credentials. Losing it makes them unreadable.
ENCRYPTION_MASTER_KEY=$ENCRYPTION_MASTER_KEY

# The first administrator, created when the users table is empty; the account
# must change its password at first login.
FIRST_ADMIN_EMAIL=$ADMIN_EMAIL
FIRST_ADMIN_PASSWORD=$FIRST_ADMIN_PASSWORD

GRAFANA_ADMIN_PASSWORD=$GRAFANA_ADMIN_PASSWORD

PYSOAR_PUBLIC_URL=$PUBLIC_URL

# The UI calls the API on the same origin.
CORS_ORIGINS=[]
EOF
chmod 600 "$TMP"

if [ -e "$ENV_FILE" ]; then
    OLD="$REPO/.env.replaced-$(date +%Y%m%d%H%M%S)"
    mv "$ENV_FILE" "$OLD"
    chmod 600 "$OLD"
    echo "configure-env: the previous .env is kept as $OLD (mode 600); delete it once nothing needs its keys"
fi
mv "$TMP" "$ENV_FILE"
trap - EXIT

echo "configure-env: wrote $ENV_FILE (mode 600)"
echo "configure-env: first administrator: $ADMIN_EMAIL; read the initial password with:"
echo "    grep '^FIRST_ADMIN_PASSWORD=' $ENV_FILE | cut -d= -f2-"
echo "configure-env: copy $ENV_FILE into your password manager, then run deploy/start-production.sh"
