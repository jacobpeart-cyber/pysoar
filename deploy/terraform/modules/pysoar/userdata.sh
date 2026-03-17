#!/bin/bash
# PySOAR Bootstrap Script
# Runs on first boot of the EC2 instance

set -e
exec > /var/log/pysoar-init.log 2>&1

echo "=== PySOAR Bootstrap Started ==="

# Update system
apt-get update -qq
apt-get upgrade -y -qq

# Install Docker
apt-get install -y -qq ca-certificates curl gnupg
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -qq
apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Install Docker Compose
curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m)" \
  -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Add ubuntu user to docker group
usermod -aG docker ubuntu

# Install Git
apt-get install -y -qq git

# Clone PySOAR
mkdir -p /opt/pysoar
git clone ${pysoar_repo} /opt/pysoar
chown -R ubuntu:ubuntu /opt/pysoar

# Write production .env
cat > /opt/pysoar/.env << EOF
APP_NAME=PySOAR
APP_ENV=production
DEBUG=false

SECRET_KEY=${secret_key}
JWT_SECRET_KEY=${jwt_secret_key}

HOST=0.0.0.0
PORT=8000
WORKERS=2

DATABASE_URL=postgresql+asyncpg://pysoar:${db_password}@postgres:5432/pysoar
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/1
CELERY_RESULT_BACKEND=redis://redis:6379/2

JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

FIRST_ADMIN_EMAIL=${admin_email}
FIRST_ADMIN_PASSWORD=${admin_password}

CORS_ORIGINS=${cors_origins}

LOG_LEVEL=INFO
LOG_FORMAT=json
RATE_LIMIT_PER_MINUTE=60
EOF

chown ubuntu:ubuntu /opt/pysoar/.env
chmod 600 /opt/pysoar/.env

# Start PySOAR
cd /opt/pysoar
docker-compose up -d

# Set up systemd service for auto-start on reboot
cat > /etc/systemd/system/pysoar.service << 'SYSTEMD'
[Unit]
Description=PySOAR SOAR Platform
Requires=docker.service
After=docker.service network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/pysoar
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable pysoar

echo "=== PySOAR Bootstrap Complete ==="
