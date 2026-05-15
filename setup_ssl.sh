#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  SafetyMonitor — Script d'installation TLS/SSL automatique
#  Usage : sudo bash setup_ssl.sh votre-domaine.com
# ═══════════════════════════════════════════════════════════════

set -e

DOMAIN=${1:-""}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Couleurs ──────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

echo -e "${BOLD}═══════════════════════════════════════════════${NC}"
echo -e "${BOLD}  SafetyMonitor — Setup TLS/SSL${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════${NC}"

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Usage : sudo bash setup_ssl.sh votre-domaine.com${NC}"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Ce script doit être lancé en root (sudo)${NC}"
    exit 1
fi

echo -e "${BLUE}[1/5]${NC} Installation Nginx + Certbot..."
apt-get update -qq
apt-get install -y nginx certbot python3-certbot-nginx

echo -e "${BLUE}[2/5]${NC} Configuration Nginx pour $DOMAIN..."
# Remplace le domaine dans la config
sed "s/votre-domaine\.com/$DOMAIN/g" "$SCRIPT_DIR/nginx_safetymonitor.conf" \
    > /etc/nginx/sites-available/safetymonitor

# Active la config
ln -sf /etc/nginx/sites-available/safetymonitor /etc/nginx/sites-enabled/safetymonitor
rm -f /etc/nginx/sites-enabled/default

# Crée le dossier pour le challenge Let's Encrypt
mkdir -p /var/www/certbot

# Test config nginx
nginx -t
systemctl reload nginx

echo -e "${BLUE}[3/5]${NC} Génération certificat Let's Encrypt pour $DOMAIN..."
certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" \
    --non-interactive --agree-tos --register-unsafely-without-email \
    --redirect

echo -e "${BLUE}[4/5]${NC} Mise à jour .env..."
ENV_FILE="$SCRIPT_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    cp "$SCRIPT_DIR/.env.example" "$ENV_FILE"
fi

# Active FORCE_HTTPS et configure les certs dans .env
sed -i "s/FORCE_HTTPS=0/FORCE_HTTPS=1/" "$ENV_FILE"
# Ajoute SSL_CERT et SSL_KEY si pas déjà présents
grep -q "SSL_CERT=" "$ENV_FILE" || echo "SSL_CERT=/etc/letsencrypt/live/$DOMAIN/fullchain.pem" >> "$ENV_FILE"
grep -q "SSL_KEY="  "$ENV_FILE" || echo "SSL_KEY=/etc/letsencrypt/live/$DOMAIN/privkey.pem"   >> "$ENV_FILE"

echo -e "${BLUE}[5/5]${NC} Renouvellement automatique (cron)..."
# Renouvellement auto certbot tous les 12h
(crontab -l 2>/dev/null; echo "0 */12 * * * certbot renew --quiet && systemctl reload nginx") | crontab -

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "${GREEN}  ✅ TLS/SSL configuré avec succès !${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
echo -e "   Domaine  : ${BOLD}https://$DOMAIN${NC}"
echo -e "   Cert     : /etc/letsencrypt/live/$DOMAIN/"
echo -e "   Renouvellement : automatique (cron)"
echo ""
echo -e "${YELLOW}  Prochaine étape : python app.py${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════${NC}"
