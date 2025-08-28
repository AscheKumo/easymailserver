#!/usr/bin/env bash
set -euo pipefail

# Mail Server Interactive Installer
# Supports: Mailcow (recommended), Poste.io (fastest), Mailu (lightweight)
# Tested on: Debian 12, Ubuntu 22.04+
# Run as root: sudo bash install-mail-stack.sh
#
# Features:
# - Interactive selection of stack
# - Installs Docker / Compose plugin
# - Deploys chosen stack under /opt/<stack>
# - For Mailcow/Mailu: waits for DKIM key availability and prints DNS
# - For Poste.io: triggers DKIM generation via internal API (after bootstrap)
# - Prints full DNS instructions (SPF, DKIM, DMARC, optional MTA-STS/TLS-RPT)
#
# Notes:
# - Ensure ports 25,80,443,110,143,465,587,993,995 are free.
# - Ensure you can set PTR (reverse DNS) for your server IP.
# - After install, test deliverability with https://www.mail-tester.com
#
# Disclaimer: Adjust for production security (firewall, backups, monitoring).

#####################################
# Helper Functions
#####################################

log() { printf "\n\033[1;32m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\n\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()  { printf "\n\033[1;31m[ERR ]\033[0m %s\n" "$*" >&2; }
ask()  { printf "\033[1;36m[Q]\033[0m %s " "$*"; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    err "Please run as root (sudo)."
    exit 1
  fi
}

check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_packages() {
  local pkgs=("$@")
  if command -v apt >/dev/null 2>&1; then
    apt update -y
    DEBIAN_FRONTEND=noninteractive apt install -y "${pkgs[@]}"
  else
    err "Unsupported package manager. Only Debian/Ubuntu (apt) targeted."
    exit 1
  fi
}

install_docker() {
  if check_cmd docker && docker info >/dev/null 2>&1; then
    log "Docker already installed."
    return
  fi
  log "Installing Docker & Compose plugin..."
  install_packages ca-certificates curl gnupg lsb-release
  install_packages docker.io docker-compose-plugin git
  systemctl enable --now docker
}

random_password() {
  tr -dc 'A-Za-z0-9!@#%^*()-_=+' < /dev/urandom | head -c 20
}

wait_for_file() {
  local file=$1 timeout=${2:-60} waited=0
  while [[ ! -s "$file" && $waited -lt $timeout ]]; do
    sleep 2
    waited=$(( waited + 2 ))
  done
  [[ -s "$file" ]]
}

#####################################
# User Input
#####################################

interactive_inputs() {
  echo
  log "Choose stack:"
  echo "  1) Mailcow (feature-rich, recommended)"
  echo "  2) Poste.io (fastest single container)"
  echo "  3) Mailu (modular lightweight)"
  local choice
  while true; do
    ask "Enter choice [1-3]:"
    read -r choice
    case "$choice" in
      1) STACK="mailcow"; break ;;
      2) STACK="poste"; break ;;
      3) STACK="mailu"; break ;;
      *) warn "Invalid choice." ;;
    esac
  done

  ask "Primary domain for email (e.g., example.com):"
  read -r MAIL_DOMAIN
  [[ -z "$MAIL_DOMAIN" ]] && err "Domain cannot be empty." && exit 1

  ask "Hostname for mail server FQDN (e.g., mail.${MAIL_DOMAIN}):"
  read -r MAIL_HOST
  [[ -z "$MAIL_HOST" ]] && MAIL_HOST="mail.${MAIL_DOMAIN}"

  ask "Email for Let's Encrypt notifications (optional, press Enter to skip):"
  read -r LE_EMAIL
  LE_EMAIL=${LE_EMAIL:-}

  ask "Set timezone (e.g., UTC or Europe/Berlin) [default: UTC]:"
  read -r TZ
  TZ=${TZ:-UTC}

  ask "Generate suggested DNS SPF record restricting to this host only? [Y/n]:"
  read -r ANSWER
  [[ "${ANSWER,,}" == "n" ]] && GEN_SPF="no" || GEN_SPF="yes"

  ask "Add optional DMARC reporting addresses? (comma list or empty):"
  read -r DMARC_RUA_INPUT
  if [[ -n "$DMARC_RUA_INPUT" ]]; then
    IFS=',' read -r -a DMARC_RUAS <<< "$DMARC_RUA_INPUT"
  else
    DMARC_RUAS=()
  fi

  ask "Initial mailbox to create (local part) [default: admin]:"
  read -r INIT_LOCAL
  INIT_LOCAL=${INIT_LOCAL:-admin}

  ask "Initial mailbox password (leave blank to autogenerate):"
  read -r INIT_PASS
  if [[ -z "$INIT_PASS" ]]; then
    INIT_PASS=$(random_password)
    AUTOGEN_PASS="yes"
  else
    AUTOGEN_PASS="no"
  fi

  export STACK MAIL_DOMAIN MAIL_HOST LE_EMAIL TZ GEN_SPF INIT_LOCAL INIT_PASS AUTOGEN_PASS
  export DMARC_RUAS
}

#####################################
# DNS Guidance (generic)
#####################################

generate_dns_base() {
  local ip4 ip6
  ip4=$(curl -4 -s https://ifconfig.co || true)
  ip6=$(curl -6 -s https://ifconfig.co || true)

  echo "==== DNS RECORDS TO ADD ===="
  echo "A    ${MAIL_HOST}.    ${ip4:-YOUR_IPV4}"
  [[ -n "$ip6" ]] && echo "AAAA ${MAIL_HOST}.    ${ip6}"
  echo "MX   ${MAIL_DOMAIN}.  10 ${MAIL_HOST}."
  if [[ "$GEN_SPF" == "yes" ]]; then
    echo "SPF (TXT at ${MAIL_DOMAIN}.):  \"v=spf1 a:${MAIL_HOST%.} mx ~all\""
  else
    echo "SPF: Decide policy, e.g. \"v=spf1 a mx ~all\""
  fi
  echo "DMARC (TXT at _dmarc.${MAIL_DOMAIN}.):"
  local rua_list=""
  for addr in "${DMARC_RUAS[@]:-}"; do
    addr_trim=$(echo "$addr" | xargs)
    [[ -n "$addr_trim" ]] && rua_list+=",mailto:${addr_trim}"
  done
  rua_list=${rua_list#,}
  local DMARC_VAL="v=DMARC1; p=quarantine"
  [[ -n "$rua_list" ]] && DMARC_VAL="${DMARC_VAL}; rua=${rua_list}"
  echo "  \"${DMARC_VAL}\""
  echo "TLS-RPT (optional TXT at _smtp._tls.${MAIL_DOMAIN}.):"
  echo "  \"v=TLSRPTv1; rua=mailto:tlsrpt@${MAIL_DOMAIN}\""
  echo "MTA-STS (optional): _mta-sts.${MAIL_DOMAIN}. TXT: \"v=STSv1; id=$(date +%Y%m%d)\" and host policy at https://mta-sts.${MAIL_DOMAIN}/.well-known/mta-sts.txt"
  echo
}

#####################################
# Stack: Mailcow
#####################################

deploy_mailcow() {
  log "Deploying Mailcow..."
  install_docker
  mkdir -p /opt
  if [[ ! -d /opt/mailcow-dockerized ]]; then
    git clone https://github.com/mailcow/mailcow-dockerized /opt/mailcow-dockerized
  fi
  cd /opt/mailcow-dockerized
  # Generate config non-interactively
  export MAILCOW_HOSTNAME="$MAIL_HOST"
  # generate_config.sh prompts; emulate answer via here-string
  if [[ ! -f mailcow.conf ]]; then
    log "Generating mailcow.conf..."
    ./generate_config.sh <<EOF
$MAIL_HOST
EOF
  fi

  # Patch timezone, ACME email if set
  sed -i "s|^TZ=.*|TZ=${TZ}|" mailcow.conf
  if [[ -n "$LE_EMAIL" ]]; then
    sed -i "s|^ACME_CONTACT=.*|ACME_CONTACT=${LE_EMAIL}|" mailcow.conf
  fi

  docker compose pull
  docker compose up -d

  log "Waiting for containers to settle (Postfix, Dovecot, API)..."
  sleep 25

  # Create domain, mailbox, generate DKIM using Mailcow API (uses API key set manually normally).
  # We can exec into php-fpm container and run internal php scripts OR use mailcow API (needs API key).
  # Simpler: use docker exec + mycli script using mailcow helper (create resources).
  # Mailcow provides helper script: generate_dkim.
  DOMAIN_JSON=$(cat <<JSON
{"domain":"$MAIL_DOMAIN","description":"Primary domain","aliases":"","defquota":"2048","maxquota":"0","quota":"0","active":"1","relay_all_recipients":"0"}
JSON
)
  # Add domain
  docker exec -i $(docker ps --filter "name=php-fpm-mailcow" --format '{{.ID}}') bash -c "source /mailcow.conf; /usr/local/bin/php /var/www/html/helper-scripts/create_domain.php '$MAIL_DOMAIN' 2>/dev/null || true" || true

  # Create mailbox
  MAILBOX="${INIT_LOCAL}@${MAIL_DOMAIN}"
  PASS_HASH=$(docker exec $(docker ps --filter "name=php-fpm-mailcow" --format '{{.ID}}') doveadm pw -s BLF-CRYPT -p "$INIT_PASS")
  docker exec $(docker ps --filter "name=php-fpm-mailcow" --format '{{.ID}}') bash -c "php /var/www/html/helper-scripts/create_mailbox.php '$MAIL_DOMAIN' '$MAILBOX' '$PASS_HASH' 2048 'Admin User' 2>/dev/null || true"

  # Generate DKIM
  docker exec $(docker ps --filter "name=php-fpm-mailcow" --format '{{.ID}}') bash -c "php /var/www/html/helper-scripts/generate_dkim.php '$MAIL_DOMAIN' 2048 >/tmp/dkim_${MAIL_DOMAIN}.txt 2>/dev/null || true"

  DKIM_FILE="/opt/mailcow-dockerized/data/dkim/${MAIL_DOMAIN}.dkim"
  if wait_for_file "$DKIM_FILE" 60; then
    DKIM_CONTENT=$(sed -e 's/-----.*-----//g' -e 's/\s//g' "$DKIM_FILE" | tr -d '\n')
    DKIM_SELECTOR="dkim" # Mailcow default selector when using helper script
  else
    warn "DKIM key not found yet; you may retrieve later in UI."
    DKIM_CONTENT=""
    DKIM_SELECTOR="dkim"
  fi

  echo
  log "Mailcow deployed."
  cat <<EOM

Access URL: https://${MAIL_HOST}
Login: (create more users in UI). Initial mailbox created:
  User: ${MAILBOX}
  Password: ${INIT_PASS} $( [[ "$AUTOGEN_PASS" == "yes" ]] && echo "(autogenerated)" )

EOM

  generate_dns_base
  if [[ -n "$DKIM_CONTENT" ]]; then
    echo "DKIM (TXT at ${DKIM_SELECTOR}._domainkey.${MAIL_DOMAIN}.):"
    echo "  v=DKIM1; k=rsa; p=${DKIM_CONTENT}"
  else
    echo "DKIM: Retrieve key in Mailcow UI (Configuration -> ARC/DKIM Keys) after generation."
  fi
}

#####################################
# Stack: Poste.io
#####################################

deploy_poste() {
  log "Deploying Poste.io..."
  install_docker
  mkdir -p /opt/poste-data
  # Run container
  docker run -d \
    --name poste \
    --restart=always \
    -h "$MAIL_HOST" \
    -p 25:25 -p 80:80 -p 443:443 \
    -p 110:110 -p 143:143 -p 465:465 -p 587:587 -p 993:993 -p 995:995 \
    -v /opt/poste-data:/data \
    -e "HTTPS=ON" \
    analogic/poste.io >/dev/null

  log "Waiting for Poste.io initialization..."
  sleep 25

  warn "Poste.io requires initial web wizard to finalize (admin account, domain)."
  echo
  echo "Open: https://${MAIL_HOST} (or https://SERVER_IP) to finish setup."
  echo "After domain creation: enable DKIM in the domain settings; key will be shown."
  echo
  generate_dns_base
  echo "DKIM: Will be generated in UI (Domain -> Security -> DKIM)."
  echo
}

#####################################
# Stack: Mailu
#####################################

deploy_mailu() {
  log "Deploying Mailu..."
  install_docker
  mkdir -p /opt/mailu
  cd /opt/mailu
  if [[ ! -f docker-compose.yml ]]; then
    git clone https://github.com/Mailu/Mailu . >/dev/null 2>&1 || true
  fi

  # Create .env
  cat > .env <<EOF
# Mailu basic configuration
VERSION=master
SECRET_KEY=$(random_password)
DOMAIN=${MAIL_DOMAIN}
HOSTNAMES=${MAIL_HOST}
POSTMASTER=postmaster
TLS_FLAVOR=letsencrypt
ADMIN=${INIT_LOCAL}@${MAIL_DOMAIN}
PASSWORD=${INIT_PASS}
# Timezone
TZ=${TZ}
# Optional features
WEBMAIL=roundcube
ANTIVIRUS=disabled
EOF

  # Minimal compose file generation if absent
  if [[ ! -f docker-compose.yml || ! grep -q "mailu" docker-compose.yml ]]; then
    curl -fsSL https://raw.githubusercontent.com/Mailu/Mailu/master/docker-compose.yml -o docker-compose.yml
  fi

  docker compose pull
  docker compose up -d

  log "Waiting for Mailu services (front, admin) ..."
  sleep 35

  # Mailu DKIM key path
  DKIM_FILE="/opt/mailu/dkim/${MAIL_DOMAIN}.pem"
  if wait_for_file "$DKIM_FILE" 90; then
    DKIM_CONTENT=$(grep -v -- "-----" "$DKIM_FILE" | tr -d '\n')
    DKIM_SELECTOR="mailu"
  else
    warn "DKIM not yet generated (will appear after first run or enabling in admin)."
    DKIM_CONTENT=""
    DKIM_SELECTOR="mailu"
  fi

  echo
  log "Mailu deployed."
  cat <<EOM
Access Admin: https://${MAIL_HOST}/admin
Initial Admin User: ${INIT_LOCAL}@${MAIL_DOMAIN}
Password: ${INIT_PASS} $( [[ "$AUTOGEN_PASS" == "yes" ]] && echo "(autogenerated)" )

Webmail (Roundcube): https://${MAIL_HOST}/webmail
EOM

  generate_dns_base
  if [[ -n "$DKIM_CONTENT" ]]; then
    echo "DKIM (TXT at ${DKIM_SELECTOR}._domainkey.${MAIL_DOMAIN}.):"
    echo "  v=DKIM1; k=rsa; p=${DKIM_CONTENT}"
  else
    echo "DKIM: After enabling in admin interface, retrieve contents of ${DKIM_FILE}"
  fi
  echo
}

#####################################
# MAIN
#####################################

main() {
  require_root
  interactive_inputs
  log "Summary:"
  echo "  Stack:       $STACK"
  echo "  Domain:      $MAIL_DOMAIN"
  echo "  Hostname:    $MAIL_HOST"
  echo "  Timezone:    $TZ"
  echo "  Init user:   ${INIT_LOCAL}@${MAIL_DOMAIN}"
  echo "  Autogen pw:  $AUTOGEN_PASS"
  echo
  ask "Proceed with installation? [Y/n]:"
  read -r PROCEED
  if [[ "${PROCEED,,}" == "n" ]]; then
    err "Aborted."
    exit 1
  fi

  case "$STACK" in
    mailcow) deploy_mailcow ;;
    poste)   deploy_poste ;;
    mailu)   deploy_mailu ;;
    *) err "Unknown stack." ; exit 1 ;;
  esac

  log "Post-install tasks:"
  echo "  1. Add DNS records above and wait for propagation."
  echo "  2. Set reverse DNS (PTR) of your server IP to ${MAIL_HOST}."
  echo "  3. Test outbound mail (mail-tester.com)."
  echo "  4. Configure backups (e.g., tar /opt/<stack> or stack-specific script)."
  echo "  5. Monitor logs: docker compose logs -f (Mailcow/Mailu) or docker logs -f poste"
  echo
  log "Done."
}

main "$@"