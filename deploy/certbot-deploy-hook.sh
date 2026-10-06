#!/usr/bin/env bash
# certbot deploy hook for the PySOAR production host.
#
# Installed on the host via:
#   certbot certonly --webroot -w /opt/pysoar/nginx/certbot -d pysoar.it.com \
#       --deploy-hook /opt/pysoar/deploy/certbot-deploy-hook.sh
# After that, `certbot renew` (systemd certbot.timer) runs this automatically
# whenever a renewal actually produces a new certificate.
#
# The nginx container does not read /etc/letsencrypt directly; it mounts
# ./nginx/ssl:/etc/nginx/ssl:ro and expects fullchain.pem + privkey.pem there.
# This hook copies the renewed lineage into that directory, checks that nginx
# accepts the new files, and restarts the container so it picks them up.
set -euo pipefail

# certbot sets RENEWED_LINEAGE when it calls the hook. When run by hand, fall
# back to the newest lineage directory (the webroot switch on 2026-10-06
# created pysoar.it.com-0001 and the old standalone lineage was deleted).
LINEAGE="${RENEWED_LINEAGE:-$(ls -d /etc/letsencrypt/live/pysoar.it.com* 2>/dev/null | sort | tail -n 1)}"
REPO="${PYSOAR_DIR:-/opt/pysoar}"
SSL_DIR="${REPO}/nginx/ssl"
OWNER="${PYSOAR_OWNER:-ubuntu}"

log() { printf '[certbot-deploy-hook] %s\n' "$*"; }

for f in fullchain.pem privkey.pem; do
    [ -r "${LINEAGE}/${f}" ] || { log "missing ${LINEAGE}/${f}"; exit 1; }
done

install -m 0644 -o "${OWNER}" -g "${OWNER}" "${LINEAGE}/fullchain.pem" "${SSL_DIR}/fullchain.pem"
install -m 0640 -o "${OWNER}" -g "${OWNER}" "${LINEAGE}/privkey.pem" "${SSL_DIR}/privkey.pem"
log "installed $(openssl x509 -in "${SSL_DIR}/fullchain.pem" -noout -enddate)"

# Validate before restarting so a bad file cannot take the proxy down.
if docker exec pysoar-nginx nginx -t >/dev/null 2>&1; then
    docker compose -f "${REPO}/docker-compose.yml" restart nginx >/dev/null
    log "nginx restarted"
else
    log "nginx -t rejected the new configuration; container left running on the old certificate"
    exit 1
fi
