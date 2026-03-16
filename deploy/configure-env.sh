#!/bin/bash
# PySOAR Production Environment Configuration
# Run this once after server-setup.sh to generate a production .env
# Usage: bash configure-env.sh [server-ip-or-domain]

set -e

PYSOAR_DIR="/opt/pysoar"
SERVER_HOST="${1:-$(curl -s ifconfig.me)}"

echo "Configuring PySOAR for: $SERVER_HOST"

# Generate strong random secrets
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
JWT_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(64))")
DB_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

cat > "$PYSOAR_DIR/.env" << EOF
# PySOAR Production Configuration
# Generated on $(date)

APP_NAME=PySOAR
APP_ENV=production
DEBUG=false

SECRET_KEY=$SECRET_KEY
JWT_SECRET_KEY=$JWT_SECRET_KEY

HOST=0.0.0.0
PORT=8000
WORKERS=2

DATABASE_URL=postgresql+asyncpg://pysoar:${DB_PASSWORD}@postgres:5432/pysoar
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

FIRST_ADMIN_EMAIL=admin@pysoar.local
FIRST_ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")

CORS_ORIGINS=["http://${SERVER_HOST}","https://${SERVER_HOST}"]

LOG_LEVEL=INFO
LOG_FORMAT=json
RATE_LIMIT_PER_MINUTE=60
EOF

# Also update docker-compose postgres password to match
sed -i "s/POSTGRES_PASSWORD=pysoar/POSTGRES_PASSWORD=${DB_PASSWORD}/" "$PYSOAR_DIR/docker-compose.yml" 2>/dev/null || true

echo ""
echo "============================================"
echo "  .env written to $PYSOAR_DIR/.env"
echo "============================================"
echo ""
echo "  Admin login credentials:"
grep "FIRST_ADMIN_EMAIL\|FIRST_ADMIN_PASSWORD" "$PYSOAR_DIR/.env"
echo ""
echo "  SAVE THESE CREDENTIALS - they won't be shown again."
echo ""
echo "  Access PySOAR at: http://$SERVER_HOST"
echo ""
