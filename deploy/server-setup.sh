#!/bin/bash
# PySOAR Server Setup Script
# Run this ONCE on a fresh Ubuntu 22.04 server (Oracle Cloud ARM)
# Usage: bash server-setup.sh

set -e

echo "=========================================="
echo "  PySOAR Server Setup"
echo "=========================================="

# Update system
echo "[1/6] Updating system packages..."
sudo apt-get update -qq
sudo apt-get upgrade -y -qq

# Install Docker
echo "[2/6] Installing Docker..."
sudo apt-get install -y -qq ca-certificates curl gnupg lsb-release

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update -qq
sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Add current user to docker group (no sudo needed)
sudo usermod -aG docker $USER

# Enable Docker to start on boot
sudo systemctl enable docker
sudo systemctl start docker

# Install Docker Compose standalone (v2)
echo "[3/6] Installing Docker Compose..."
sudo curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$(uname -m)" \
  -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install Git
echo "[4/6] Installing Git..."
sudo apt-get install -y -qq git

# Clone PySOAR
echo "[5/6] Cloning PySOAR repository..."
cd /opt
sudo git clone https://github.com/$(git config --global user.name 2>/dev/null || echo "YOUR_GITHUB_USERNAME")/pysoar.git || {
  echo ""
  echo "  NOTE: Automatic clone failed (no GitHub URL configured)."
  echo "  You will need to upload the code manually - see deploy instructions."
  echo ""
}

# Configure firewall (Oracle Linux requires both ufw AND iptables rules)
echo "[6/6] Configuring firewall..."
sudo apt-get install -y -qq ufw
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw --force enable

# Oracle Cloud also blocks ports at the network level via iptables
# This rule allows HTTP/HTTPS through Oracle's default iptables chains
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT 6 -m state --state NEW -p tcp --dport 443 -j ACCEPT
sudo netfilter-persistent save 2>/dev/null || sudo apt-get install -y iptables-persistent

echo ""
echo "=========================================="
echo "  Setup complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Upload your PySOAR code to /opt/pysoar"
echo "     (or fix the GitHub clone above)"
echo "  2. Run: bash /opt/pysoar/deploy/configure-env.sh"
echo "  3. Run: bash /opt/pysoar/deploy/start-production.sh"
echo ""
echo "  IMPORTANT: Log out and back in for docker group to take effect."
echo ""
