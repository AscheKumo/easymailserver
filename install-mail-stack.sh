#!/usr/bin/env bash
# Interactive Mail Stack Installer: Mailcow | Poste.io | Mailu
# Features:
#   - System prep (packages, timezone, sysctl, firewall, fail2ban, unattended upgrades)
#   - Docker + Compose (with fallback manual install)
#   - Automated backups (cron)
#   - DKIM extraction
#   - Failure cleanup & rerun safety (--purge-on-fail, --cleanup-only, --purge-only)
#   - Port conflict preflight + automatic remediation (host Postfix/Exim/etc)
#   - Re-run detection (reuse or purge existing data)
#
# Target OS: Debian 11/12 or Ubuntu 20.04/22.04/24.04 (apt-based)
# Version: 2025-08-29T19:05Z
#
# New flags for port auto-fix:
#   --auto-fix-ports     Attempt automatic resolution without extra prompts (defaults to loopback reconfigure first, then purge if still conflicting)
#   --purge-mta          When fixing ports, prefer purging host MTAs (postfix/exim/sendmail/nullmailer/opensmtpd)
#   --loopback-mta       When fixing ports, prefer reconfiguring Postfix to loopback-only (keeps local mail)
#
# Example:
#   sudo bash install-mail-stack.sh --auto-fix-ports --purge-on-fail --purge-mta
#
set -euo pipefail

# -------------------- CONFIG / DEFAULTS --------------------
BACKUP_SCRIPT_PATH="/usr/local/sbin/backup-mail-stack"
BACKUP_CRON_FILE="/etc/cron.d/mail-stack-backup"
DOCKER_COMPOSE_LEGACY=0
CURRENT_PHASE="start"
STACK=""
PURGE_ON_FAIL="no"
FLAG_CLEANUP_ONLY="no"
FLAG_PURGE_ONLY="no"

AUTO_FIX_PORTS="no"
PORT_FIX_STRATEGY="ask"   # ask | purge | loopback | auto (auto = try loopback then purge)
REQUIRED_PORTS_COMMON=(25 465 587 110 143 993 995 80 443)

# -------------------- LOGGING --------------------
log()  { printf "\n[INFO] %s\n" "$*"; }
warn() { printf "\n[WARN] %s\n" "$*"; }
err()  { printf "\n[ERR ] %s\n" "$*" >&2; }
ask()  { printf "[Q] %s " "$*"; }

# -------------------- CLI ARG PARSING --------------------
print_help() {
  cat <<EOF
Usage: $0 [options]

General:
  --purge-on-fail       Purge data directories if installation fails.
  --cleanup-only        Perform safe cleanup (containers only) and exit.
  --purge-only          Full purge: containers + data directories then exit.
  --auto-fix-ports      Attempt to automatically resolve port conflicts (25, 465, 587, etc.).
  --purge-mta           Prefer purging host MTA to free ports (implies --auto-fix-ports).
  --loopback-mta        Prefer reconfiguring Postfix to loopback-only (implies --auto-fix-ports).
  -h, --help            Show this help.

Port fix strategy precedence:
  --purge-mta overrides --loopback-mta if both are supplied (warned).
  Without strategy: interactive prompt (ask).
  --auto-fix-ports alone = auto (loopback attempt first, then purge if still blocked).

Cleanup targets:
  Mailcow: /opt/mailcow-dockerized
  Mailu:   /opt/mailu
  Poste:   /opt/poste-data

EOF
}

for arg in "$@"; do
  case "$arg" in
    --purge-on-fail) PURGE_ON_FAIL="yes" ;;
    --cleanup-only) FLAG_CLEANUP_ONLY="yes" ;;
    --purge-only) FLAG_PURGE_ONLY="yes" ;;
    --auto-fix-ports) AUTO_FIX_PORTS="yes"; PORT_FIX_STRATEGY="auto" ;;
    --purge-mta) AUTO_FIX_PORTS="yes"; PORT_FIX_STRATEGY="purge" ;;
    --loopback-mta) AUTO_FIX_PORTS="yes"; PORT_FIX_STRATEGY="loopback" ;;
    -h|--help) print_help; exit 0 ;;
    *) err "Unknown argument: $arg"; print_help; exit 1 ;;
  esac
done

# Normalize conflicting strategies
if [ "$PORT_FIX_STRATEGY" = "purge" ] && [ "$PORT_FIX_STRATEGY" = "loopback" ]; then
  PORT_FIX_STRATEGY="purge"
fi

# -------------------- SAFETY / ENV CHECKS --------------------
if [ -z "${BASH_VERSION:-}" ]; then
  echo "[FATAL] Please run with bash: bash $0" >&2
  exit 1
fi
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  err "Run as root (sudo)."
  exit 1
fi
if grep -q $'\r' "$0"; then
  warn "CRLF line endings detected; run: sed -i 's/\r$//' $0"
fi

# -------------------- CORE UTILS --------------------
check_cmd() { command -v "$1" >/dev/null 2>&1; }

random_password() {
  tr -dc 'A-Za-z0-9!@#%^*()-_=+' < /dev/urandom | head -c 20; echo
}

wait_for_file() {
  file=$1 ; timeout=${2:-60} ; waited=0
  while [ ! -s "$file" ] && [ $waited -lt $timeout ]; do
    sleep 2
    waited=$((waited+2))
  done
  [ -s "$file" ]
}

# -------------------- CLEANUP LOGIC --------------------
stop_mailcow() {
  if [ -d /opt/mailcow-dockerized ]; then
    ( cd /opt/mailcow-dockerized && docker compose down -v --remove-orphans || true )
  fi
}
stop_mailu() {
  if [ -d /opt/mailu ]; then
    ( cd /opt/mailu && docker compose down -v --remove-orphans || true )
  fi
}
stop_poste() {
  if docker ps -a --format '{{.Names}}' | grep -qx poste; then
    docker rm -f poste || true
  fi
}
cleanup_safe() {
  log "Performing SAFE cleanup (containers only)..."
  stop_mailcow; stop_mailu; stop_poste
  log "Safe cleanup complete."
}
cleanup_purge() {
  log "Performing FULL PURGE (containers + data)..."
  cleanup_safe
  rm -rf /opt/mailcow-dockerized /opt/mailu /opt/poste-data
  rm -f  /var/lib/mail-stack/stack_type
  log "Full purge complete."
}
on_error() {
  local exit_code=$?
  err "Installation failed at phase: ${CURRENT_PHASE} (exit code ${exit_code})."
  cleanup_safe
  if [ "$PURGE_ON_FAIL" = "yes" ]; then
    warn "Purge-on-fail enabled; removing data directories."
    cleanup_purge
  else
    warn "Data directories preserved. Re-run after fixing issues."
    warn "Full purge manually: $0 --purge-only"
  fi
  err "Aborting."
  exit $exit_code
}
trap on_error ERR

if [ "$FLAG_CLEANUP_ONLY" = "yes" ]; then
  cleanup_safe; exit 0
fi
if [ "$FLAG_PURGE_ONLY" = "yes" ]; then
  cleanup_purge; exit 0
fi

# -------------------- APT / SYSTEM PREP --------------------
install_packages() {
  DEBIAN_FRONTEND=noninteractive apt install -y "$@"
}

add_docker_repo_if_needed() {
  if apt-cache policy docker-compose-plugin 2>/dev/null | grep -q Candidate; then
    return
  fi
  CURRENT_PHASE="add_docker_repo"
  log "Adding Docker apt repository..."
  install_packages ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo $ID)/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi
  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/$(. /etc/os-release; echo $ID) \
$(. /etc/os-release; echo $VERSION_CODENAME) stable
EOF
  apt update -y
}

base_system_packages() {
  CURRENT_PHASE="base_system_packages"
  log "Installing base system packages..."
  apt update -y
  install_packages curl git jq ca-certificates gnupg lsb-release software-properties-common \
                   rsync tar openssl tzdata cron logrotate ufw fail2ban bsd-mailx \
                   unattended-upgrades apt-listchanges
}

enable_unattended_upgrades() {
  CURRENT_PHASE="unattended_upgrades"
  log "Configuring unattended-upgrades..."
  dpkg-reconfigure -f noninteractive unattended-upgrades || true
  cat >/etc/apt/apt.conf.d/51-mail-stack-auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
}

configure_sysctl() {
  CURRENT_PHASE="sysctl"
  log "Applying sysctl tuning..."
  cat >/etc/sysctl.d/90-mail-stack.conf <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_timestamps = 0
net.core.somaxconn = 2048
net.core.netdev_max_backlog = 4096
fs.file-max = 200000
net.ipv4.tcp_fin_timeout = 30
EOF
  sysctl --system >/dev/null 2>&1 || warn "sysctl reload warnings."
  if ! grep -q 'mailstack-nofile' /etc/security/limits.conf; then
    cat >>/etc/security/limits.conf <<'EOF'
# mailstack-nofile
* soft nofile 65535
* hard nofile 65535
EOF
  fi
}

configure_timezone() {
  CURRENT_PHASE="timezone"
  if command -v timedatectl >/dev/null 2>&1; then
    timedatectl set-timezone "$TZ" || warn "Failed to set timezone."
  fi
}

configure_firewall() {
  CURRENT_PHASE="firewall"
  log "Configuring UFW..."
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  for p in 25 80 443 110 143 465 587 993 995; do ufw allow "$p"/tcp; done
  ufw --force enable
  ufw status verbose | sed 's/^/[UFW] /'
}

configure_fail2ban() {
  CURRENT_PHASE="fail2ban"
  log "Configuring Fail2Ban (host-level; limited container visibility)..."
  cat >/etc/fail2ban/jail.d/sshd.local <<'EOF'
[sshd]
enabled = true
maxretry = 6
bantime = 1h
findtime = 10m
EOF
  systemctl restart fail2ban || warn "Fail2Ban restart failed."
  systemctl enable fail2ban || true
}

# -------------------- DOCKER / COMPOSE --------------------
ensure_compose() {
  if docker compose version >/dev/null 2>&1; then
    return
  fi
  if command -v docker-compose >/dev/null 2>&1; then
    log "Using legacy docker-compose (v1)."
    DOCKER_COMPOSE_LEGACY=1
    return
  fi
  if apt-cache policy docker-compose-plugin 2>/dev/null | grep -q Candidate; then
    log "Installing docker-compose-plugin..."
    install_packages docker-compose-plugin || true
    docker compose version >/dev/null 2>&1 && return
  fi
  log "Manual install of compose plugin..."
  local VER="v2.29.2"
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/download/${VER}/docker-compose-linux-$(uname -m)" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  docker compose version >/dev/null 2>&1 || { err "Compose install failed."; exit 1; }
}

compose_cmd() {
  if [ "$DOCKER_COMPOSE_LEGACY" -eq 1 ]; then
    docker-compose "$@"
  else
    docker compose "$@"
  fi
}

install_docker_stack() {
  CURRENT_PHASE="docker_install"
  if ! check_cmd docker; then
    add_docker_repo_if_needed
    install_packages docker-ce docker-ce-cli containerd.io docker-buildx-plugin || install_packages docker.io
  fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker info >/dev/null 2>&1 || { err "Docker not operational."; exit 1; }
  ensure_compose
}

# -------------------- BACKUP --------------------
create_backup_script() {
  CURRENT_PHASE="backup_script"
  log "Creating backup script..."
  cat >"$BACKUP_SCRIPT_PATH"<<'EOF'
#!/usr/bin/env bash
set -euo pipefail
DATE=$(date +%Y-%m-%d_%H-%M)
RETENTION_DAYS=${RETENTION_DAYS:-14}
BACKUP_ROOT=${BACKUP_ROOT:-/var/backups/mail-stack}
STACK_TYPE_FILE="/var/lib/mail-stack/stack_type"
mkdir -p "$BACKUP_ROOT" /var/lib/mail-stack
[ -f "$STACK_TYPE_FILE" ] && STACK_TYPE=$(cat "$STACK_TYPE_FILE") || STACK_TYPE="unknown"
archive_dir="$BACKUP_ROOT/$DATE"
mkdir -p "$archive_dir"
log(){ printf "[BACKUP] %s\n" "$*"; }

backup_mailcow() {
  tar --exclude='*.log' -czf "$archive_dir/mailcow-config.tgz" -C /opt mailcow-dockerized
  docker ps --filter "name=redis-mailcow" --format '{{.ID}}' | xargs -r -I{} docker exec {} redis-cli save || true
}
backup_mailu() {
  tar --exclude='*.log' -czf "$archive_dir/mailu-config.tgz" -C /opt mailu
}
backup_poste() {
  tar --exclude='*.log' -czf "$archive_dir/poste-data.tgz" -C /opt poste-data
}

case "$STACK_TYPE" in
  mailcow) backup_mailcow ;;
  mailu)   backup_mailu ;;
  poste)   backup_poste ;;
  *) log "Unknown stack type; nothing backed up." ;;
esac

find "$BACKUP_ROOT" -maxdepth 1 -type d -mtime +$RETENTION_DAYS -exec rm -rf {} \; || true
log "Backup complete: $archive_dir"
EOF
  chmod +x "$BACKUP_SCRIPT_PATH"
  mkdir -p /var/lib/mail-stack
  echo "$STACK" >/var/lib/mail-stack/stack_type
  log "Registering daily cron job..."
  cat >"$BACKUP_CRON_FILE"<<EOF
MAILTO=root
25 2 * * * root RETENTION_DAYS=${BACKUP_RETENTION_DAYS} BACKUP_ROOT=${BACKUP_TARGET_DIR} ${BACKUP_SCRIPT_PATH} >/var/log/mail-stack-backup.log 2>&1
EOF
  chmod 0644 "$BACKUP_CRON_FILE"
}

# -------------------- PORT CONFLICT RESOLUTION --------------------
list_conflicts() {
  local -n _ports=$1
  local p
  for p in "${_ports[@]}"; do
    ss -ltnp 2>/dev/null | awk -v PT=":$p" '$4 ~ PT {print p": "$0}' p="$p"
  done
}

get_conflicting_ports() {
  local -n _ports=$1
  local conflicts=()
  local p
  for p in "${_ports[@]}"; do
    if ss -ltnp 2>/dev/null | grep -q ":$p "; then
      conflicts+=("$p")
    fi
  done
  echo "${conflicts[*]:-}"
}

purge_host_mtas() {
  log "Purging host MTAs..."
  systemctl stop postfix exim4 sendmail opensmtpd nullmailer 2>/dev/null || true
  systemctl disable postfix exim4 sendmail opensmtpd nullmailer 2>/dev/null || true
  apt-get purge -y postfix postfix-* exim4* sendmail* nullmailer opensmtpd 2>/dev/null || true
  apt-get autoremove -y || true
}

configure_postfix_loopback() {
  if [ ! -f /etc/postfix/main.cf ]; then
    warn "Postfix not installed or main.cf missing; cannot loopback-configure."
    return
  fi
  if ! grep -q '# mail-stack-backup ' /etc/postfix/main.cf; then
    cp -f /etc/postfix/main.cf /etc/postfix/main.cf.bak.$(date +%s) || true
  fi
  sed -i '/^inet_interfaces *=/d' /etc/postfix/main.cf
  sed -i '/^inet_protocols *=/d' /etc/postfix/main.cf
  cat >>/etc/postfix/main.cf <<'EOF'
# mail-stack-backup added:
inet_interfaces = loopback-only
inet_protocols = all
EOF
  systemctl restart postfix || warn "Postfix restart failed after loopback configuration."
}

attempt_loopback_reconfig() {
  log "Attempting Postfix loopback-only configuration..."
  configure_postfix_loopback
  sleep 2
}

port_conflicts_still_present() {
  local -n _ports=$1
  local p
  for p in "${_ports[@]}"; do
    if ss -ltnp 2>/dev/null | grep -q ":$p "; then
      return 0
    fi
  done
  return 1
}

preflight_ports() {
  CURRENT_PHASE="preflight_ports"
  local ports=("${REQUIRED_PORTS_COMMON[@]}")
  log "Preflight: checking required ports (${ports[*]})..."
  local conflicts
  conflicts=$(get_conflicting_ports ports || true)
  [ -z "$conflicts" ] && { log "All required ports free."; return; }

  warn "Port conflicts detected: $conflicts"
  list_conflicts ports | sed 's/^/[PORT] /'

  # Attempt passive stop of known MTAs first
  log "Stopping known host MTAs (postfix/exim4/sendmail/opensmtpd/nullmailer)..."
  systemctl stop postfix exim4 sendmail opensmtpd nullmailer 2>/dev/null || true
  sleep 2
  conflicts=$(get_conflicting_ports ports || true)
  if [ -z "$conflicts" ]; then
    log "Conflicts resolved after stopping host MTAs."
    return
  fi

  # Decide strategy
  local strategy="$PORT_FIX_STRATEGY"
  if [ "$strategy" = "ask" ] && [ "$AUTO_FIX_PORTS" = "no" ]; then
    echo
    warn "Ports still busy: $conflicts"
    echo "Choose resolution:"
    echo "  1) Reconfigure Postfix to loopback-only (keep local mail delivery)."
    echo "  2) Purge MTAs (postfix/exim/etc) completely."
    echo "  3) Abort so you can fix manually."
    ask "Enter choice [1-3]:"
    read -r answer
    case "$answer" in
      1) strategy="loopback" ;;
      2) strategy="purge" ;;
      *) err "Abort chosen."; exit 1 ;;
    esac
  fi

  case "$strategy" in
    loopback)
      attempt_loopback_reconfig
      ;;
    purge)
      purge_host_mtas
      ;;
    auto)
      attempt_loopback_reconfig
      conflicts=$(get_conflicting_ports ports || true)
      if [ -n "$conflicts" ]; then
        warn "Loopback attempt insufficient; purging MTAs."
        purge_host_mtas
      fi
      ;;
    ask)
      # If we got here with ask + AUTO_FIX_PORTS=yes (shouldn't) treat as auto
      attempt_loopback_reconfig
      conflicts=$(get_conflicting_ports ports || true)
      if [ -n "$conflicts" ]; then
        purge_host_mtas
      fi
      ;;
    purge|loopback)
      # Already handled above 'purge' and 'loopback'
      ;;
    *)
      err "Unknown port fix strategy '$strategy'"; exit 1 ;;
  esac

  sleep 2
  conflicts=$(get_conflicting_ports ports || true)
  if [ -n "$conflicts" ]; then
    list_conflicts ports | sed 's/^/[PORT] /'
    err "Ports still in use after remediation: $conflicts"
    err "Resolve manually then re-run."
    exit 1
  fi
  log "Port conflicts resolved."
}

# -------------------- INTERACTIVE INPUT --------------------
interactive_inputs() {
  CURRENT_PHASE="interactive_inputs"
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
  [ -z "$MAIL_DOMAIN" ] && { err "Domain required."; exit 1; }

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
  case "$ANSWER" in [Nn]*) GEN_SPF="no" ;; *) GEN_SPF="yes" ;; esac

  ask "DMARC aggregate report addresses (comma separated, or blank):"
  read -r DMARC_RUA_INPUT
  if [ -n "$DMARC_RUA_INPUT" ]; then
    OLDIFS=$IFS; IFS=','; set -- $DMARC_RUA_INPUT; IFS=$OLDIFS
    DMARC_RUAS=("$@")
  else
    DMARC_RUAS=()
  fi

  ask "Initial mailbox local part (default: admin):"
  read -r INIT_LOCAL
  [ -z "$INIT_LOCAL" ] && INIT_LOCAL="admin"

  ask "Initial mailbox password (blank = generate):"
  read -r INIT_PASS
  if [ -z "$INIT_PASS" ]; then
    INIT_PASS=$(random_password)
    AUTOGEN_PASS="yes"
  else
    AUTOGEN_PASS="no"
  fi

  ask "Configure UFW firewall now? [Y/n]:"
  read -r FW
  case "$FW" in [Nn]*) SETUP_FIREWALL="no" ;; *) SETUP_FIREWALL="yes" ;; esac

  ask "Configure Fail2Ban (host) now? [y/N]:"
  read -r F2B
  case "$F2B" in [Yy]*) SETUP_FAIL2BAN="yes" ;; *) SETUP_FAIL2BAN="no" ;; esac

  ask "Enable unattended security upgrades? [Y/n]:"
  read -r UA
  case "$UA" in [Nn]*) ENABLE_UPGRADES="no" ;; *) ENABLE_UPGRADES="yes" ;; esac

  ask "Apply sysctl/network tuning? [Y/n]:"
  read -r ST
  case "$ST" in [Nn]*) APPLY_SYSCTL="no" ;; *) APPLY_SYSCTL="yes" ;; esac

  ask "Create automated daily backup? [Y/n]:"
  read -r BK
  case "$BK" in
    [Nn]*) CREATE_BACKUP="no" ;;
    *) CREATE_BACKUP="yes"
       ask "Backup target directory [/var/backups/mail-stack]:"
       read -r BACKUP_TARGET_DIR
       [ -z "$BACKUP_TARGET_DIR" ] && BACKUP_TARGET_DIR="/var/backups/mail-stack"
       ask "Backup retention days [14]:"
       read -r BACKUP_RETENTION_DAYS
       [ -z "${BACKUP_RETENTION_DAYS:-}" ] && BACKUP_RETENTION_DAYS=14
    ;;
  esac

  export STACK MAIL_DOMAIN MAIL_HOST LE_EMAIL TZ GEN_SPF INIT_LOCAL INIT_PASS AUTOGEN_PASS \
         SETUP_FIREWALL SETUP_FAIL2BAN ENABLE_UPGRADES APPLY_SYSCTL CREATE_BACKUP \
         BACKUP_TARGET_DIR BACKUP_RETENTION_DAYS
  export DMARC_RUAS
}

# -------------------- DNS Guidance --------------------
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
    echo "SPF: \"v=spf1 a mx ~all\""
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
  echo "TLS-RPT (TXT _smtp._tls.${MAIL_DOMAIN}.): \"v=TLSRPTv1; rua=mailto:tlsrpt@${MAIL_DOMAIN}\""
  echo "MTA-STS (TXT _mta-sts.${MAIL_DOMAIN}.): \"v=STSv1; id=$(date +%Y%m%d)\""
  echo
}

# -------------------- STACK DEPLOYMENTS --------------------
deploy_mailcow() {
  CURRENT_PHASE="deploy_mailcow"
  log "Deploying Mailcow..."
  install_docker_stack
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
  grep -q '^TZ=' mailcow.conf && sed -i "s|^TZ=.*|TZ=${TZ}|" mailcow.conf || echo "TZ=${TZ}" >> mailcow.conf
  if [ -n "$LE_EMAIL" ]; then
    grep -q '^ACME_CONTACT=' mailcow.conf && sed -i "s|^ACME_CONTACT=.*|ACME_CONTACT=${LE_EMAIL}|" mailcow.conf || echo "ACME_CONTACT=${LE_EMAIL}" >> mailcow.conf
  fi
  compose_cmd pull
  compose_cmd up -d
  log "Waiting for containers..."
  sleep 35
  PHPFPM=$(docker ps --filter "name=php-fpm-mailcow" --format '{{.ID}}' | head -n1 || true)
  if [ -n "$PHPFPM" ]; then
    MAILBOX="${INIT_LOCAL}@${MAIL_DOMAIN}"
    PASS_HASH=$(docker exec "$PHPFPM" doveadm pw -s BLF-CRYPT -p "$INIT_PASS")
    docker exec "$PHPFPM" php /var/www/html/helper-scripts/create_domain.php "$MAIL_DOMAIN" || true
    docker exec "$PHPFPM" php /var/www/html/helper-scripts/create_mailbox.php "$MAIL_DOMAIN" "$MAILBOX" "$PASS_HASH" 2048 "Admin User" || true
    docker exec "$PHPFPM" php /var/www/html/helper-scripts/generate_dkim.php "$MAIL_DOMAIN" 2048 || true
  else
    warn "php-fpm-mailcow container not found; skipping mailbox creation."
  fi
  DKIM_FILE="/opt/mailcow-dockerized/data/dkim/${MAIL_DOMAIN}.dkim"
  DKIM_CONTENT=""
  if wait_for_file "$DKIM_FILE" 60; then
    DKIM_CONTENT=$(grep -v '-----' "$DKIM_FILE" | tr -d ' \n\r\t')
  else
    warn "DKIM key not ready yet."
  fi
  log "Mailcow deployed: https://${MAIL_HOST}"
  echo "Initial mailbox: ${INIT_LOCAL}@${MAIL_DOMAIN}"
  echo "Password: ${INIT_PASS} $([ "$AUTOGEN_PASS" = "yes" ] && echo '(autogenerated)')"
  generate_dns_base
  if [ -n "$DKIM_CONTENT" ]; then
    echo "DKIM (TXT dkim._domainkey.${MAIL_DOMAIN}.):"
    echo "  v=DKIM1; k=rsa; p=${DKIM_CONTENT}"
  else
    echo "DKIM: UI -> Configuration -> ARC/DKIM Keys."
  fi
}

deploy_poste() {
  CURRENT_PHASE="deploy_poste"
  log "Deploying Poste.io..."
  install_docker_stack
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
  sleep 30
  warn "Complete wizard at https://${MAIL_HOST} to create domain/admin and DKIM."
  generate_dns_base
  echo "DKIM: Enable in Poste.io Domain Security settings."
}

deploy_mailu() {
  CURRENT_PHASE="deploy_mailu"
  log "Deploying Mailu..."
  install_docker_stack
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
  compose_cmd pull
  compose_cmd up -d
  log "Waiting for services..."
  sleep 40
  DKIM_FILE="/opt/mailu/dkim/${MAIL_DOMAIN}.pem"
  DKIM_CONTENT=""
  if wait_for_file "$DKIM_FILE" 90; then
    DKIM_CONTENT=$(grep -v '-----' "$DKIM_FILE" | tr -d ' \n\r\t')
  else
    warn "DKIM not yet generated."
  fi
  log "Mailu deployed: https://${MAIL_HOST}"
  echo "Admin UI: https://${MAIL_HOST}/admin"
  echo "Webmail : https://${MAIL_HOST}/webmail"
  echo "User    : ${INIT_LOCAL}@${MAIL_DOMAIN}"
  echo "Password: ${INIT_PASS} $([ "$AUTOGEN_PASS" = "yes" ] && echo '(autogenerated)')"
  generate_dns_base
  if [ -n "$DKIM_CONTENT" ]; then
    echo "DKIM (TXT mailu._domainkey.${MAIL_DOMAIN}.):"
    echo "  v=DKIM1; k=rsa; p=${DKIM_CONTENT}"
  else
    echo "DKIM: After generation, view ${DKIM_FILE}"
  fi
}

# -------------------- RERUN DETECTION --------------------
check_existing_data() {
  local found="no"
  case "$STACK" in
    mailcow) [ -d /opt/mailcow-dockerized ] && found="yes" ;;
    mailu)   [ -d /opt/mailu ] && found="yes" ;;
    poste)   [ -d /opt/poste-data ] && found="yes" ;;
  esac
  if [ "$found" = "yes" ]; then
    warn "Existing data directory detected for $STACK."
    ask "Reuse existing data? (y = reuse, n = purge) [y/N]:"
    read -r REUSE
    case "$REUSE" in
      [Yy]*) log "Reusing existing data." ;;
      *) warn "Purging existing data for fresh install."
         case "$STACK" in
           mailcow) stop_mailcow; rm -rf /opt/mailcow-dockerized ;;
           mailu)   stop_mailu;   rm -rf /opt/mailu ;;
           poste)   stop_poste;   rm -rf /opt/poste-data ;;
         esac
         ;;
    esac
  fi
}

# -------------------- MAIN --------------------
main() {
  interactive_inputs

  log "Summary:"
  cat <<EOF
  Stack:               $STACK
  Domain:              $MAIL_DOMAIN
  Hostname:            $MAIL_HOST
  Timezone:            $TZ
  Init Mailbox:        ${INIT_LOCAL}@${MAIL_DOMAIN}
  Autogen Password:    $AUTOGEN_PASS
  Firewall (UFW):      $SETUP_FIREWALL
  Fail2Ban:            $SETUP_FAIL2BAN
  Unattended Upgrades: $ENABLE_UPGRADES
  Sysctl Tuning:       $APPLY_SYSCTL
  Backups:             $CREATE_BACKUP
  Purge on Fail:       $PURGE_ON_FAIL
  Auto Port Fix:       $AUTO_FIX_PORTS
  Port Strategy:       $PORT_FIX_STRATEGY
EOF

  ask "Proceed with installation? [Y/n]:"
  read -r PROCEED
  case "$PROCEED" in [Nn]*) err "Aborted by user."; exit 1 ;; esac

  check_existing_data

  base_system_packages
  configure_timezone
  [ "$ENABLE_UPGRADES" = "yes" ] && enable_unattended_upgrades
  [ "$APPLY_SYSCTL" = "yes" ] && configure_sysctl
  [ "$SETUP_FIREWALL" = "yes" ] && configure_firewall
  [ "$SETUP_FAIL2BAN" = "yes" ] && configure_fail2ban

  # Port preflight BEFORE deploying (so host MTAs removed/reconfigured first)
  preflight_ports

  case "$STACK" in
    mailcow) deploy_mailcow ;;
    poste)   deploy_poste ;;
    mailu)   deploy_mailu ;;
    *) err "Unknown stack '$STACK'"; exit 1 ;;
  esac

  if [ "$CREATE_BACKUP" = "yes" ]; then
    create_backup_script
  fi

  trap - ERR
  log "Post-install checklist:"
  cat <<EOF
  1. Add DNS (A/AAAA, MX, SPF, DKIM, DMARC, optional TLS-RPT/MTA-STS).
  2. Set reverse DNS (PTR) of server IP to ${MAIL_HOST}.
  3. Test deliverability: https://www.mail-tester.com
  4. Inspect headers in Gmail/Outlook for SPF/DKIM/DMARC pass.
  5. Monitor: compose_cmd logs -f (Mailcow/Mailu) or docker logs -f poste
  6. Verify backups (if enabled) in ${BACKUP_TARGET_DIR:-/var/backups/mail-stack}
  7. Harden further (fail2ban integration with container logs, monitoring).
  8. Later, consider DMARC p=reject after monitoring reports.
EOF
  log "Installation complete."
}

main "$@"
