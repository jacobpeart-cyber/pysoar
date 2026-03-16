#!/bin/bash
# PySOAR Production Start Script
# Builds and starts all containers, sets up systemd auto-start
# Usage: bash start-production.sh

set -e

PYSOAR_DIR="/opt/pysoar"
cd "$PYSOAR_DIR"

if [ ! -f ".env" ]; then
  echo "ERROR: .env not found. Run configure-env.sh first."
  exit 1
fi

echo "[1/3] Building containers (this takes ~5 minutes first time)..."
docker-compose build

echo "[2/3] Starting PySOAR..."
docker-compose up -d

echo "[3/3] Setting up systemd service for auto-start on reboot..."
sudo tee /etc/systemd/system/pysoar.service > /dev/null << 'EOF'
[Unit]
Description=PySOAR SOAR Platform
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/pysoar
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable pysoar

echo ""
echo "============================================"
echo "  PySOAR is running!"
echo "============================================"
echo ""
SERVER_IP=$(curl -s ifconfig.me)
echo "  URL:    http://$SERVER_IP"
echo "  Status: docker-compose ps"
echo ""
echo "  Auto-starts on every server reboot."
echo ""
