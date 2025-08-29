#!/usr/bin/env bash
# Interactive Mail Stack Installer: Mailcow | Poste.io | Mailu
# Target OS: Debian/Ubuntu (apt based)
# Run as root: sudo bash install-mail-stack.sh

set -euo pipefail

# ------------------ Utility Functions ------------------
log()  { printf "\n[INFO] %s\n" "$*"; }
warn() { printf "\n[WARN] %s\n" "$*"; }
err()  { printf "\n[ERR ] %s\n" "$*" >&2; }
ask()  { printf "[Q] %s " "$*"; }

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    err "Please run as root (sudo)."
    exit 1
  fi
}

check_cmd() { command -v "$1" >/dev/null 2>&1; }

install_packages() {
  if check_cmd apt; then
    apt update -y
    DEBIAN_FRONTEND=noninteractive apt install -y "$@"
  else
    err "Only Debian/Ubuntu (apt) supported."
    exit 1
  fi
}

install_docker() {
  if check_cmd docker && docker info >/dev/null 2>&1; then
    log "Docker already installed."
    return
  fi
  log "Installing Docker and Compose plugin..."
  install_packages ca-certificates curl gnupg lsb-release git docker.io docker-compose-plugin
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker
  fi
}

random_password() {
  tr -dc 'A-Za-z0-9!@#%^*()-_=+' < /dev/urandom | head -c 20; echo
}

wait_for_file() {
  file=$1
  timeout=${2:-60}
  waited=0
  while [ ! -s "$file" ] && [ $waited -lt $timeout ]; do
    sleep 2
    waited=$((waited+2))
  done
  [ -s "$file" ]
}

# ------------------ Input Gathering ------------------
interactive_inputs() {
  echo
  log "Choose stack:"
  echo "  1) Mailcow (feature-rich, recommended)"
  echo "  2) Poste.io (fastest single container)"
  echo "  3) Mailu (lightweight modular)"
  while :; do
    ask "Enter choice [1-3]:"
    read -r choice
    case "$choice" in
      1) STACK="mailcow"; break ;;
      2) STACK="poste";   break ;;
      3) STACK="mailu";   break ;;
      *) warn "Invalid choice." ;;
    esac
  done

  ask "Primary domain (example.com):"
  read -r MAIL_DOMAIN
  [ -z "$MAIL_DOMAIN" ] && { err "Domain cannot be empty."; exit 1; }

  ask "Hostname/FQDN (default: mail.${MAIL_DOMAIN}):"
  read -r MAIL_HOST
  [ -z "$MAIL_HOST" ] && MAIL_HOST="mail.${MAIL_DOMAIN}"

  ask "Let's Encrypt notification email (optional):"
  read -r LE_EMAIL
  [ -z "$LE_EMAIL" ] && LE_EMAIL=""

  ask "Timezone (default: UTC):"
  read -r TZ
  [ -z "$TZ" ] && TZ="UTC"

  ask "Generate restrictive SPF automatically? [Y/n]:"
  read -r ANSWER
  case "$ANSWER" in
    [Nn]*) GEN_SPF="no" ;;
    *)     GEN_SPF="yes" ;;
  esac

  ask "DMARC report addresses (comma-separated or empty):"
  read -r DMARC_RUA_INPUT
  if [ -n "$DMARC_RUA_INPUT" ]; then
    OLDIFS=$IFS
    IFS=','; set -- $DMARC_RUA_INPUT; IFS=$OLDIFS
    DMARC_RUAS=("$@")
  else
    DMARC_RUAS=()
  fi

  ask "Initial mailbox local part (default: admin):"
  read -r INIT_LOCAL
  [ -z "$INIT_LOCAL" ] && INIT_LOCAL="admin"

  ask "Initial mailbox password (blank = autogenerate):"
  read -r INIT_PASS
  if [ -z "$INIT_PASS" ]; then
    INIT_PASS=$(random_password)
    AUTOGEN_PASS="yes"
  else
    AUTOGEN_PASS="no"
  fi

  export STACK MAIL_DOMAIN MAIL_HOST LE_EMAIL TZ GEN_SPF INIT_LOCAL INIT_PASS AUTOGEN_PASS
  export DMARC_RUAS
}

# ------------------ DNS Guidance ------------------
generate_dns_base() {
  ip4=$(curl -4 -s https://ifconfig.co || true)
  ip6=$(curl -6 -s https://ifconfig.co || true)

  echo "==== DNS RECORDS TO ADD ===="
  echo "A    ${MAIL_HOST}.    ${ip4:-YOUR_IPV4}"
  [ -n "$ip6" ] && echo "AAAA ${MAIL_HOST}.    ${ip6}"
  echo "MX   ${MAIL_DOMAIN}.  10 ${MAIL_HOST}."
  if [ "$GEN_SPF" = "yes" ]; then
    echo "SPF (TXT ${MAIL_DOMAIN}.): \"v=spf1 a:${MAIL_HOST%.} mx ~all\""
  else
    echo "SPF: e.g. \"v=spf1 a mx ~all\""
  fi
  echo "DMARC (TXT _dmarc.${MAIL_DOMAIN}.):"
  rua_list=""
  for addr in "${DMARC_RUAS[@]:-}"; do
    trimmed=$(echo "$addr" | xargs)
    [ -n "$trimmed" ] && rua_list="${rua_list},mailto:${trimmed}"
  done
  rua_list=${rua_list#,}
  DMARC_VAL="v=DMARC1; p=quarantine"
  [ -n "$rua_list" ] && DMARC_VAL="${DMARC_VAL}; rua=${rua_list}"
  echo "  \"${DMARC_VAL}\""
  echo "TLS-RPT (optional TXT _smtp._tls.${MAIL_DOMAIN}.): \"v=TLSRPTv1; rua=mailto:tlsrpt@${MAIL_DOMAIN}\""
  echo "MTA-STS (optional TXT _mta-sts.${MAIL_DOMAIN}.): \"v=STSv1; id=$(date +%Y%m%d)\""
  echo
}

# ------------------ Deploy Mailcow ------------------
deploy_mailcow() {
  log "Deploying Mailcow..."
  install_docker
  mkdir -p /opt
  if [ ! -d /opt/mailcow-dockerized ]; then
    git clone https://github.com/mailcow/mailcow-dockerized /opt/mailcow-dockerized
  fi
  cd /opt/mailcow-dockerized

  if [ ! -f mailcow.conf ]; then
    log "Generating mailcow.conf..."
    MAILCOW_HOSTNAME="$MAIL_HOST" ./generate_config.sh <<EOF
$MAIL_HOST
EOF
  fi

  # Set timezone & ACME email
  if grep -q '^TZ=' mailcow.conf; then
    sed -i "s|^TZ=.*|TZ=${TZ}|" mailcow.conf
  else
    echo "TZ=${TZ}" >> mailcow.conf
  fi
  if [ -n "$LE_EMAIL" ]; then
    if grep -q '^ACME_CONTACT=' mailcow.conf; then
      sed -i "s|^ACME_CONTACT=.*|ACME_CONTACT=${LE_EMAIL}|" mailcow.conf
    else
      echo "ACME_CONTACT=${LE_EMAIL}" >> mailcow.conf
    fi
  fi

  docker compose pull
  docker compose up -d
  log "Waiting for services..."
  sleep 30

  PHPFPM=$(docker ps --filter "name=php-fpm-mailcow" --format '{{.ID}}' | head -n1 || true)
  if [ -n "$PHPFPM" ]; then
    MAILBOX="${INIT_LOCAL}@${MAIL_DOMAIN}"
    PASS_HASH=$(docker exec "$PHPFPM" doveadm pw -s BLF-CRYPT -p "$INIT_PASS")
    docker exec "$PHPFPM" php /var/www/html/helper-scripts/create_domain.php "$MAIL_DOMAIN" || true
    docker exec "$PHPFPM" php /var/www/html/helper-scripts/create_mailbox.php "$MAIL_DOMAIN" "$MAILBOX" "$PASS_HASH" 2048 "Admin User" || true
    docker exec "$PHPFPM" php /var/www/html/helper-scripts/generate_dkim.php "$MAIL_DOMAIN" 2048 || true
  else
    warn "php-fpm-mailcow container not found; skipping automatic domain/mailbox."
  fi

  DKIM_FILE="/opt/mailcow-dockerized/data/dkim/${MAIL_DOMAIN}.dkim"
  DKIM_CONTENT=""
  DKIM_SELECTOR="dkim"
  if wait_for_file "$DKIM_FILE" 60; then
    DKIM_CONTENT=$(grep -v '-----' "$DKIM_FILE" | tr -d ' \n\r\t')
  else
    warn "DKIM key not ready yet."
  fi

  log "Mailcow deployed at https://${MAIL_HOST}"
  echo "Initial mailbox: ${INIT_LOCAL}@${MAIL_DOMAIN}"
  echo "Password: ${INIT_PASS} $([ "$AUTOGEN_PASS" = "yes" ] && echo '(autogenerated)')"
  echo
  generate_dns_base
  if [ -n "$DKIM_CONTENT" ]; then
    echo "DKIM (TXT ${DKIM_SELECTOR}._domainkey.${MAIL_DOMAIN}.):"
    echo "  v=DKIM1; k=rsa; p=${DKIM_CONTENT}"
  else
    echo "DKIM: View later in UI (Configuration -> ARC/DKIM Keys)."
  fi
}

# ------------------ Deploy Poste.io ------------------
deploy_poste() {
  log "Deploying Poste.io..."
  install_docker
  mkdir -p /opt/poste-data
  docker run -d \
    --name poste \
    --restart=always \
    -h "$MAIL_HOST" \
    -p 25:25 -p 80:80 -p 443:443 \
    -p 110:110 -p 143:143 -p 465:465 -p 587:587 -p 993:993 -p 995:995 \
    -v /opt/poste-data:/data \
    -e "HTTPS=ON" \
    analogic/poste.io >/dev/null

  log "Waiting for initial bootstrap..."
  sleep 25
  warn "Finish setup in browser (wizard creates admin & domain)."
  echo "Open: https://${MAIL_HOST}"
  echo
  generate_dns_base
  echo "DKIM: Enable in domain settings inside Poste.io UI."
}

# ------------------ Deploy Mailu ------------------
deploy_mailu() {
  log "Deploying Mailu..."
  install_docker
  mkdir -p /opt/mailu
  cd /opt/mailu
  if [ ! -f docker-compose.yml ]; then
    git clone https://github.com/Mailu/Mailu . >/dev/null 2>&1 || true
  fi

  cat > .env <<EOF
VERSION=master
SECRET_KEY=$(random_password)
DOMAIN=${MAIL_DOMAIN}
HOSTNAMES=${MAIL_HOST}
POSTMASTER=postmaster
TLS_FLAVOR=letsencrypt
ADMIN=${INIT_LOCAL}@${MAIL_DOMAIN}
PASSWORD=${INIT_PASS}
TZ=${TZ}
WEBMAIL=roundcube
ANTIVIRUS=disabled
EOF

  if [ ! -f docker-compose.yml ] || ! grep -q "mailu" docker-compose.yml; then
    curl -fsSL https://raw.githubusercontent.com/Mailu/Mailu/master/docker-compose.yml -o docker-compose.yml
  fi

  docker compose pull
  docker compose up -d

  log "Waiting for services..."
  sleep 35

  DKIM_FILE="/opt/mailu/dkim/${MAIL_DOMAIN}.pem"
  DKIM_CONTENT=""
  DKIM_SELECTOR="mailu"
  if wait_for_file "$DKIM_FILE" 90; then
    DKIM_CONTENT=$(grep -v '-----' "$DKIM_FILE" | tr -d ' \n\r\t')
  else
    warn "DKIM not yet generated (enable in admin UI if needed)."
  fi

  log "Mailu deployed."
  echo "Admin UI: https://${MAIL_HOST}/admin"
  echo "Webmail : https://${MAIL_HOST}/webmail"
  echo "User    : ${INIT_LOCAL}@${MAIL_DOMAIN}"
  echo "Password: ${INIT_PASS} $([ "$AUTOGEN_PASS" = "yes" ] && echo '(autogenerated)')"
  echo
  generate_dns_base
  if [ -n "$DKIM_CONTENT" ]; then
    echo "DKIM (TXT ${DKIM_SELECTOR}._domainkey.${MAIL_DOMAIN}.):"
    echo "  v=DKIM1; k=rsa; p=${DKIM_CONTENT}"
  else
    echo "DKIM: After generation, view ${DKIM_FILE}"
  fi
}

# ------------------ Main ------------------
main() {
  require_root
  interactive_inputs
  log "Summary:"
  echo "  Stack:      $STACK"
  echo "  Domain:     $MAIL_DOMAIN"
  echo "  Hostname:   $MAIL_HOST"
  echo "  Timezone:   $TZ"
  echo "  Init user:  ${INIT_LOCAL}@${MAIL_DOMAIN}"
  echo "  Autogen pw: $AUTOGEN_PASS"
  echo
  ask "Proceed? [Y/n]:"
  read -r PROCEED
  case "$PROCEED" in
    [Nn]*) err "Aborted."; exit 1 ;;
  esac

  case "$STACK" in
    mailcow) deploy_mailcow ;;
    poste)   deploy_poste ;;
    mailu)   deploy_mailu ;;
    *) err "Unknown stack '$STACK'"; exit 1 ;;
  esac

  log "Post-install checklist:"
  echo "  1. Add DNS records above (A/AAAA, MX, SPF, DKIM, DMARC)."
  echo "  2. Set reverse DNS (PTR) to ${MAIL_HOST}."
  echo "  3. Test at https://www.mail-tester.com"
  echo "  4. Configure backups."
  echo "  5. Monitor logs: docker compose logs -f (Mailcow/Mailu) or docker logs -f poste"
  echo
  log "Done."
}

main "$@"
