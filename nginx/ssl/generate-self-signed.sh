#!/bin/bash
# Generate self-signed SSL certificate for development/testing
# For production, use Let's Encrypt with certbot

set -e

DOMAIN="${1:-pysoar.local}"
DAYS=365
DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Generating self-signed certificate for: $DOMAIN"

openssl req -x509 -nodes -days $DAYS -newkey rsa:2048 \
  -keyout "$DIR/privkey.pem" \
  -out "$DIR/fullchain.pem" \
  -subj "/C=US/ST=State/L=City/O=PySOAR/OU=Security/CN=$DOMAIN" \
  -addext "subjectAltName=DNS:$DOMAIN,DNS:*.${DOMAIN},IP:127.0.0.1"

echo "Certificate generated:"
echo "  Certificate: $DIR/fullchain.pem"
echo "  Private key: $DIR/privkey.pem"
echo ""
echo "For production, use Let's Encrypt:"
echo "  certbot certonly --webroot -w /var/www/certbot -d yourdomain.com"
echo "  cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem $DIR/"
echo "  cp /etc/letsencrypt/live/yourdomain.com/privkey.pem $DIR/"
