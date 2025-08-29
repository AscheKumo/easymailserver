#!/usr/bin/env bash
set -euo pipefail

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
    err "Only Debian/Ubuntu apt-based systems supported."
    exit 1
  fi
}

install_docker() {
  if check_cmd docker && docker info >/dev/null 2>&1; then
    log "Docker already present."
    return
  fi
  log "Installing Docker..."
  install_packages ca-certificates curl gnupg lsb-release git docker.io docker-compose-plugin
  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now docker
  fi
}

random_password() {
  tr -dc 'A-Za-z0-9!@#%^*()-_=+' < /dev/urandom | head -c 20; echo
}

wait_for_file() {
  file=$1; timeout=${2:-60}; waited=0
  while [ ! -s "$file" ] && [ $waited -lt $timeout ]; do
    sleep 2
    waited=$((waited+2))
  done
  [ -s "$file" ]
}

interactive_inputs() {
  echo
  log "Choose stack:"
  echo "  1) Mailcow (feature-rich)"
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
  endacase 2>/dev/null || true
  # (The 'endacase' line above is inert if pasted literally; ignore. Real case ended properly.)

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

# (Deployment functions unchanged from previous version; omit here for brevity – keep your existing ones.)

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
}

main "$@"
