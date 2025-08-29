#!/usr/bin/env bash
###############################################################################
# Interactive Mail Stack Installer: Mailcow | Poste.io | Mailu
#
# Features / Guarantees:
#  - Robust, fault-tolerant end-to-end installer for self-hosted mail stacks
#  - System preparation (packages, timezone, sysctl tuning, firewall, fail2ban,
#    unattended upgrades, resource limits)
#  - Docker + Compose (automatic fallback to manual compose plugin install)
#  - Automatic port conflict detection & remediation (loopback postfix or purge)
#  - Safe re-run capability; detection & optional purge of prior data
#  - Automatic mailbox & DKIM creation (Mailcow / Mailu) with retries & readiness
#  - Poste.io readiness checks (container & HTTP bootstrap)
#  - Automated backup script + cron (configurable retention)
#  - Clean failure handling with traps, optional purge-on-fail
#  - Final ALWAYS prints login + concrete DNS records (with actual DKIM if available)
#  - Debug mode (DEBUG=1) for full trace logging to /var/log/mail-stack-installer.log
#  - Safe execution wrapper prevents transient failures from aborting entire run
#
# Usage Examples:
#   sudo bash install-mail-stack.sh
#   sudo bash install-mail-stack.sh --auto-fix-ports --purge-on-fail
#   sudo DEBUG=1 bash install-mail-stack.sh --purge-mta
#
# Flags:
#   --purge-on-fail      Purge data if installation fails
#   --cleanup-only       Stop/remove containers (keep data) then exit
#   --purge-only         Full purge: containers + data directories then exit
#   --auto-fix-ports     Auto-resolve required port conflicts (loopback then purge)
#   --purge-mta          Force purge MTAs to free ports (implies --auto-fix-ports)
#   --loopback-mta       Reconfigure Postfix loopback-only (implies --auto-fix-ports)
#   -h / --help          Show help
#
# Environment Overrides:
#   DEBUG=1              Enable verbose trace to log file
#
# Target OS: Debian 11/12 or Ubuntu 20.04/22.04/24.04 (apt-based)
#
# Version: 2025-08-29T21:00Z
###############################################################################
set -euo pipefail

# -------------------- GLOBAL CONFIG / DEFAULTS --------------------
BACKUP_SCRIPT_PATH="/usr/local/sbin/backup-mail-stack"
BACKUP_CRON_FILE="/etc/cron.d/mail-stack-backup"
DOCKER_COMPOSE_LEGACY=0
CURRENT_PHASE="start"
STACK=""
PURGE_ON_FAIL="no"
FLAG_CLEANUP_ONLY="no"
FLAG_PURGE_ONLY="no"
AUTO_FIX_PORTS="no"
PORT_FIX_STRATEGY="ask"          # ask|purge|loopback|auto
REQUIRED_PORTS_COMMON=(25 465 587 110 143 993 995 80 443)
FINAL_DKIM_SELECTOR=""
FINAL_DKIM_VALUE=""
ipv4_cache=""
ipv6_cache=""
DEBUG="${DEBUG:-0}"
LOG_FILE="/var/log/mail-stack-installer.log"

# -------------------- LOGGING --------------------
if [ "$DEBUG" = "1" ]; then
  mkdir -p "$(dirname "$LOG_FILE")"
  exec > >(tee -a "$LOG_FILE") 2>&1
  set -x
fi
log()  { printf "\n[INFO] %s\n" "$*"; }
warn() { printf "\n[WARN] %s\n" "$*"; }
err()  { printf "\n[ERR ] %s\n" "$*"; }
ask()  { printf "[Q] %s " "$*"; }

# -------------------- HELP / ARG PARSE --------------------
print_help() {
  cat <<EOF
Usage: $0 [options]

General Options:
  --purge-on-fail       Purge data directories if installation fails
  --cleanup-only        Stop/remove containers only; keep data; then exit
  --purge-only          Stop/remove containers and delete data directories; exit
  --auto-fix-ports      Auto-resolve port conflicts (loopback attempt then purge)
  --purge-mta           Prefer purging host MTAs to free ports (forces auto-fix)
  --loopback-mta        Prefer reconfiguring Postfix to loopback-only (forces auto-fix)
  -h, --help            Show this help

Environment:
  DEBUG=1               Enable verbose tracing & logging

Port Strategy precedence: purge > loopback > auto > ask
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

# -------------------- SAFETY CHECKS --------------------
[ -z "${BASH_VERSION:-}" ] && { echo "[FATAL] Run with bash" >&2; exit 1; }
[ "${EUID:-$(id -u)}" -ne 0 ] && { err "Run as root (sudo)."; exit 1; }
grep -q $'\r' "$0" && warn "CRLF line endings detected; run: sed -i 's/\r$//' $0"

# -------------------- UTILS --------------------
check_cmd()         { command -v "$1" >/dev/null 2>&1; }
random_password()   { tr -dc 'A-Za-z0-9!@#%^*()-_=+' < /dev/urandom | head -c 20; echo; }
wait_for_file() {
  local file=$1 timeout=${2:-60} waited=0
  while [ ! -s "$file" ] && [ $waited -lt $timeout ]; do sleep 2; waited=$((waited+2)); done
  [ -s "$file" ]
}
safe_exec() {
  local desc="$1"; shift
  if ! "$@"; then
    warn "Step failed (continuing): $desc (command: $*)"
    return 1
  fi
  return 0
}
wait_for_container() {
  local name_sub="$1" timeout="${2:-180}" waited=0 id=""
  log "Waiting for container '$name_sub' (timeout ${timeout}s)..."
  while [ $waited -lt $timeout ]; do
    id=$(docker ps --filter "name=$name_sub" --format '{{.ID}}' | head -n1 || true)
    if [ -n "$id" ]; then
      local health
      health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}unknown{{end}}' "$id" 2>/dev/null || echo "unknown")
      case "$health" in
        healthy) log "Container '$name_sub' healthy."; echo "$id"; return 0 ;;
        starting|unknown)
          # not ready yet; continue
          ;;
      esac
    fi
    sleep 3
    waited=$((waited+3))
  done
  warn "Container '$name_sub' not healthy/ready after ${timeout}s."
  return 1
}
wait_for_http() {
  # wait_for_http host port path timeout
  local host=$1 port=$2 path=$3 timeout=${4:-120} waited=0
  log "Waiting for HTTP readiness on https://${host}:${port}${path} (timeout ${timeout}s)..."
  while [ $waited -lt $timeout ]; do
    if curl -k -fsS --max-time 5 "https://${host}:${port}${path}" >/dev/null 2>&1; then
      log "HTTP endpoint responded."
      return 0
    fi
    sleep 4
    waited=$((waited+4))
  done
  warn "HTTP endpoint not responding after ${timeout}s."
  return 1
}

# -------------------- CLEANUP / FAILURE HANDLING --------------------
stop_mailcow() { [ -d /opt/mailcow-dockerized ] && (cd /opt/mailcow-dockerized && compose_cmd down -v --remove-orphans || true); }
stop_mailu()   { [ -d /opt/mailu ] && (cd /opt/mailu && compose_cmd down -v --remove-orphans || true); }
stop_poste()   { docker ps -a --format '{{.Names}}' | grep -qx poste && docker rm -f poste || true; }

cleanup_safe() {
  log "SAFE cleanup (containers only)..."
  stop_mailcow
  stop_mailu
  stop_poste
  log "Safe cleanup completed."
}
cleanup_purge() {
  log "FULL PURGE (containers + data)..."
  cleanup_safe
  rm -rf /opt/mailcow-dockerized /opt/mailu /opt/poste-data
  rm -f /var/lib/mail-stack/stack_type
  log "Full purge completed."
}
on_error() {
  local code=$?
  err "Installation failed at phase: $CURRENT_PHASE (exit code $code)"
  cleanup_safe
  if [ "$PURGE_ON_FAIL" = "yes" ]; then
    warn "purge-on-fail active: deleting data directories."
    cleanup_purge
  else
    warn "Data preserved. Re-run after fixing issues (or use --purge-only)."
  fi
  # Try to print partial summary if we at least collected some inputs
  if [ -n "${MAIL_DOMAIN:-}" ] && [ -n "${MAIL_HOST:-}" ]; then
    warn "Printing partial DNS/login summary (some values may be missing due to early failure)."
    summarize_dns_records || true
  fi
  exit $code
}
trap on_error ERR

[ "$FLAG_CLEANUP_ONLY" = "yes" ] && { cleanup_safe; exit 0; }
[ "$FLAG_PURGE_ONLY" = "yes" ] && { cleanup_purge; exit 0; }

# -------------------- APT / SYSTEM PREP --------------------
install_packages() { DEBIAN_FRONTEND=noninteractive apt install -y "$@"; }

add_docker_repo_if_needed() {
  apt-cache policy docker-compose-plugin 2>/dev/null | grep -q Candidate && return
  CURRENT_PHASE="add_docker_repo"
  log "Adding Docker repository..."
  install_packages ca-certificates curl gnupg lsb-release
  install -m 0755 -d /etc/apt/keyrings
  [ -f /etc/apt/keyrings/docker.gpg ] || curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo $ID)/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  cat >/etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release; echo $ID) $(. /etc/os-release; echo $VERSION_CODENAME) stable
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
  log "Configuring unattended upgrades..."
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
  grep -q mailstack-nofile /etc/security/limits.conf || cat >>/etc/security/limits.conf <<'EOF'
# mailstack-nofile
* soft nofile 65535
* hard nofile 65535
EOF
}

configure_timezone() {
  CURRENT_PHASE="timezone"
  command -v timedatectl >/dev/null 2>&1 && timedatectl set-timezone "$TZ" || true
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
}

configure_fail2ban() {
  CURRENT_PHASE="fail2ban"
  log "Configuring Fail2Ban..."
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
  if docker compose version >/dev/null 2>&1; then return; fi
  if command -v docker-compose >/dev/null 2>&1; then
    log "Using legacy docker-compose v1"
    DOCKER_COMPOSE_LEGACY=1
    return
  fi
  apt-cache policy docker-compose-plugin 2>/dev/null | grep -q Candidate && {
    log "Installing docker-compose-plugin..."
    install_packages docker-compose-plugin || true
    docker compose version >/dev/null 2>&1 && return
  }
  log "Manual compose plugin install..."
  local VER="v2.29.2"
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/download/${VER}/docker-compose-linux-$(uname -m)" -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  docker compose version >/dev/null 2>&1 || { err "Compose install failed"; exit 1; }
}
compose_cmd() { if [ "$DOCKER_COMPOSE_LEGACY" -eq 1 ]; then docker-compose "$@"; else docker compose "$@"; fi; }

install_docker_stack() {
  CURRENT_PHASE="docker_install"
  if ! check_cmd docker; then
    add_docker_repo_if_needed
    install_packages docker-ce docker-ce-cli containerd.io docker-buildx-plugin || install_packages docker.io
  fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker info >/dev/null 2>&1 || { err "Docker not operational"; exit 1; }
  ensure_compose
}

# -------------------- BACKUP --------------------
create_backup_script() {
  CURRENT_PHASE="backup_script"
  log "Creating backup script + cron..."
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
backup_mailcow(){ tar --exclude='*.log' -czf "$archive_dir/mailcow-config.tgz" -C /opt mailcow-dockerized; docker ps --filter "name=redis-mailcow" --format '{{.ID}}' | xargs -r -I{} docker exec {} redis-cli save || true; }
backup_mailu(){   tar --exclude='*.log' -czf "$archive_dir/mailu-config.tgz"   -C /opt mailu; }
backup_poste(){   tar --exclude='*.log' -czf "$archive_dir/poste-data.tgz"     -C /opt poste-data; }
case "$STACK_TYPE" in
  mailcow) backup_mailcow ;;
  mailu)   backup_mailu ;;
  poste)   backup_poste ;;
  *) log "Unknown stack type; skipping." ;;
esac
find "$BACKUP_ROOT" -maxdepth 1 -type d -mtime +$RETENTION_DAYS -exec rm -rf {} \; || true
log "Backup complete: $archive_dir"
EOF
  chmod +x "$BACKUP_SCRIPT_PATH"
  mkdir -p /var/lib/mail-stack
  echo "$STACK" >/var/lib/mail-stack/stack_type
  cat >"$BACKUP_CRON_FILE"<<EOF
MAILTO=root
25 2 * * * root RETENTION_DAYS=${BACKUP_RETENTION_DAYS} BACKUP_ROOT=${BACKUP_TARGET_DIR} ${BACKUP_SCRIPT_PATH} >/var/log/mail-stack-backup.log 2>&1
EOF
  chmod 0644 "$BACKUP_CRON_FILE"
}

# -------------------- PORT CONFLICT RESOLUTION --------------------
purge_host_mtas() {
  log "Purging host MTAs..."
  systemctl stop postfix exim4 sendmail opensmtpd nullmailer 2>/dev/null || true
  systemctl disable postfix exim4 sendmail opensmtpd nullmailer 2>/dev/null || true
  apt-get purge -y postfix postfix-* exim4* sendmail* nullmailer opensmtpd 2>/dev/null || true
  apt-get autoremove -y || true
}
configure_postfix_loopback() {
  [ -f /etc/postfix/main.cf ] || { warn "Postfix main.cf not found"; return; }
  sed -i '/^inet_interfaces *=/d;/^inet_protocols *=/d' /etc/postfix/main.cf
  cat >>/etc/postfix/main.cf <<'EOF'
# mail-stack added
inet_interfaces = loopback-only
inet_protocols = all
EOF
  systemctl restart postfix || warn "Postfix restart failed"
}
ports_busy() {
  for p in "${REQUIRED_PORTS_COMMON[@]}"; do
    ss -ltnp 2>/dev/null | grep -q ":$p " && return 0
  done
  return 1
}
conflicts_list() {
  for p in "${REQUIRED_PORTS_COMMON[@]}"; do
    ss -ltnp 2>/dev/null | grep -q ":$p " && ss -ltnp | awk -v PT=":$p" '$4 ~ PT {print p": "$0}'
  done
}
preflight_ports() {
  CURRENT_PHASE="preflight_ports"
  log "Preflight: checking required ports..."
  ports_busy || { log "All required ports free."; return; }
  warn "Port conflicts detected:"
  conflicts_list | sed 's/^/[PORT] /'
  log "Stopping known MTAs..."
  systemctl stop postfix exim4 sendmail opensmtpd nullmailer 2>/dev/null || true
  sleep 2
  ports_busy || { log "Conflicts cleared after stopping MTAs."; return; }
  local strategy="$PORT_FIX_STRATEGY"
  if [ "$strategy" = "ask" ] && [ "$AUTO_FIX_PORTS" = "no" ]; then
    echo "Resolution options:"
    echo "  1) Reconfigure Postfix loopback-only"
    echo "  2) Purge MTAs"
    echo "  3) Abort"
    ask "Choice [1-3]:"
    read -r ans
    case "$ans" in
      1) strategy="loopback" ;;
      2) strategy="purge" ;;
      *) err "Aborted by user"; exit 1 ;;
    esac
  fi
  case "$strategy" in
    loopback) configure_postfix_loopback ;;
    purge) purge_host_mtas ;;
    auto)
      configure_postfix_loopback
      sleep 2
      ports_busy && { warn "Loopback insufficient; purging MTAs."; purge_host_mtas; }
      ;;
    *) ;;
  esac
  sleep 2
  ports_busy && { err "Ports still busy after remediation."; conflicts_list | sed 's/^/[PORT] /'; exit 1; }
  log "Port conflicts resolved."
}

# -------------------- INTERACTIVE INPUTS --------------------
interactive_inputs() {
  CURRENT_PHASE="interactive_inputs"
  echo
  log "Choose stack:"
  echo "  1) Mailcow (feature-rich)"
  echo "  2) Poste.io (single container)"
  echo "  3) Mailu (modular lightweight)"
  while :; do
    ask "Enter choice [1-3]:"
    read -r c
    case "$c" in
      1) STACK="mailcow"; break ;;
      2) STACK="poste";   break ;;
      3) STACK="mailu";   break ;;
      *) warn "Invalid choice." ;;
    esac
  done
  ask "Primary domain (example.com):"; read -r MAIL_DOMAIN; [ -z "$MAIL_DOMAIN" ] && { err "Domain required"; exit 1; }
  ask "Hostname/FQDN (default: mail.${MAIL_DOMAIN}):"; read -r MAIL_HOST; [ -z "$MAIL_HOST" ] && MAIL_HOST="mail.${MAIL_DOMAIN}"
  ask "Let's Encrypt notification email (optional):"; read -r LE_EMAIL; [ -z "$LE_EMAIL" ] && LE_EMAIL=""
  ask "Timezone (default: UTC):"; read -r TZ; [ -z "$TZ" ] && TZ="UTC"
  ask "Generate restrictive SPF automatically? [Y/n]:"; read -r a; case "$a" in [Nn]*) GEN_SPF="no";; *) GEN_SPF="yes";; esac
  ask "DMARC aggregate report addresses (comma separated, blank = none):"; read -r DMARC_RUA_INPUT
  if [ -n "$DMARC_RUA_INPUT" ]; then OLDIFS=$IFS; IFS=','; set -- $DMARC_RUA_INPUT; IFS=$OLDIFS; DMARC_RUAS=("$@"); else DMARC_RUAS=(); fi
  ask "Initial mailbox local part (default: admin):"; read -r INIT_LOCAL; [ -z "$INIT_LOCAL" ] && INIT_LOCAL="admin"
  ask "Initial mailbox password (blank = generate):"; read -r INIT_PASS
  if [ -z "$INIT_PASS" ]; then INIT_PASS=$(random_password); AUTOGEN_PASS="yes"; else AUTOGEN_PASS="no"; fi
  ask "Configure UFW firewall? [Y/n]:"; read -r FW; case "$FW" in [Nn]*) SETUP_FIREWALL="no";; *) SETUP_FIREWALL="yes";; esac
  ask "Configure Fail2Ban? [y/N]:"; read -r F2B; case "$F2B" in [Yy]*) SETUP_FAIL2BAN="yes";; *) SETUP_FAIL2BAN="no";; esac
  ask "Enable unattended security upgrades? [Y/n]:"; read -r UA; case "$UA" in [Nn]*) ENABLE_UPGRADES="no";; *) ENABLE_UPGRADES="yes";; esac
  ask "Apply sysctl/network tuning? [Y/n]:"; read -r ST; case "$ST" in [Nn]*) APPLY_SYSCTL="no";; *) APPLY_SYSCTL="yes";; esac
  ask "Create automated daily backup? [Y/n]:"; read -r BK
  if [ "$BK" = "n" ] || [ "$BK" = "N" ]; then
    CREATE_BACKUP="no"
  else
    CREATE_BACKUP="yes"
    ask "Backup target directory [/var/backups/mail-stack]:"; read -r BACKUP_TARGET_DIR; [ -z "$BACKUP_TARGET_DIR" ] && BACKUP_TARGET_DIR="/var/backups/mail-stack"
    ask "Backup retention days [14]:"; read -r BACKUP_RETENTION_DAYS; [ -z "${BACKUP_RETENTION_DAYS:-}" ] && BACKUP_RETENTION_DAYS=14
  fi
  export STACK MAIL_DOMAIN MAIL_HOST LE_EMAIL TZ GEN_SPF INIT_LOCAL INIT_PASS AUTOGEN_PASS \
         SETUP_FIREWALL SETUP_FAIL2BAN ENABLE_UPGRADES APPLY_SYSCTL CREATE_BACKUP \
         BACKUP_TARGET_DIR BACKUP_RETENTION_DAYS
  export DMARC_RUAS
}

# -------------------- DNS PREPARATION --------------------
collect_ips() {
  ipv4_cache=$(curl -4 -s https://ifconfig.co || true)
  ipv6_cache=$(curl -6 -s https://ifconfig.co || true)
  [ -z "$ipv4_cache" ] && ipv4_cache="YOUR_IPV4"
}
build_dmarc_value() {
  local rua_list="" cleaned
  for addr in "${DMARC_RUAS[@]:-}"; do
    cleaned=$(echo "$addr" | xargs)
    [ -n "$cleaned" ] && rua_list="${rua_list},mailto:${cleaned}"
  done
  rua_list=${rua_list#,}
  local val="v=DMARC1; p=quarantine"
  [ -n "$rua_list" ] && val="${val}; rua=${rua_list}"
  echo "$val"
}
generate_spf_record() {
  if [ "$GEN_SPF" = "yes" ]; then
    echo "v=spf1 a:${MAIL_HOST%.} mx ~all"
  else
    echo "v=spf1 a mx ~all"
  fi
}

summarize_dns_records() {
  collect_ips
  local SPF_VAL DMARC_VAL TLSRPT_VAL MTASTS_VAL DKIM_HOST DKIM_VAL AUTOCONFIG_HOST AUTODISC_HOST
  SPF_VAL=$(generate_spf_record)
  DMARC_VAL=$(build_dmarc_value)
  TLSRPT_VAL="v=TLSRPTv1; rua=mailto:tlsrpt@${MAIL_DOMAIN}"
  MTASTS_VAL="v=STSv1; id=$(date +%Y%m%d)"
  AUTOCONFIG_HOST="autoconfig.${MAIL_DOMAIN}"
  AUTODISC_HOST="autodiscover.${MAIL_DOMAIN}"

  if [ -n "$FINAL_DKIM_VALUE" ]; then
    DKIM_HOST="${FINAL_DKIM_SELECTOR}._domainkey.${MAIL_DOMAIN}."
    DKIM_VAL="v=DKIM1; k=rsa; p=${FINAL_DKIM_VALUE}"
  else
    case "$STACK" in
      mailcow) DKIM_HOST="dkim._domainkey.${MAIL_DOMAIN}."; DKIM_VAL="<pending – check Mailcow UI>" ;;
      mailu)   DKIM_HOST="mailu._domainkey.${MAIL_DOMAIN}."; DKIM_VAL="<pending – after Mailu DKIM generation>" ;;
      poste)   DKIM_HOST="(poste selector)._domainkey.${MAIL_DOMAIN}."; DKIM_VAL="<create in Poste.io UI after wizard>" ;;
    esac
  fi

  cat <<EOF

================= LOGIN & ACCESS DETAILS =================
Stack:              $STACK
Primary Domain:     $MAIL_DOMAIN
Mail Hostname:      $MAIL_HOST
Initial Mailbox:    ${INIT_LOCAL}@${MAIL_DOMAIN}
Password:           $INIT_PASS $([ "$AUTOGEN_PASS" = "yes" ] && echo "(autogenerated)")
Web / Admin:
  Mailcow: https://${MAIL_HOST}          (login with mailbox above)
  Mailu:   https://${MAIL_HOST}/admin   (admin UI) | https://${MAIL_HOST}/webmail
  Poste:   https://${MAIL_HOST}         (complete wizard first)

Docker Helpers:
  List:        docker ps
  Logs (stack): cd /opt/${STACK} && compose_cmd logs -f    # Mailcow/Mailu
  Logs (Poste): docker logs -f poste

================= REQUIRED DNS RECORDS =================
; Zone-file style examples (adjust TTLs as desired)

${MAIL_HOST}.              300 IN A      ${ipv4_cache}
EOF
  [ -n "$ipv6_cache" ] && echo "${MAIL_HOST}.              300 IN AAAA   ${ipv6_cache}"
  cat <<EOF
${MAIL_DOMAIN}.            300 IN MX 10  ${MAIL_HOST}.
${MAIL_DOMAIN}.            300 IN TXT    "${SPF_VAL}"
${DKIM_HOST}      300 IN TXT    "${DKIM_VAL}"
_dmarc.${MAIL_DOMAIN}.     300 IN TXT    "${DMARC_VAL}"
_smtp._tls.${MAIL_DOMAIN}. 300 IN TXT    "${TLSRPT_VAL}"
_mta-sts.${MAIL_DOMAIN}.   300 IN TXT    "${MTASTS_VAL}"
autoconfig.${MAIL_DOMAIN}. 300 IN CNAME  ${MAIL_HOST}.
autodiscover.${MAIL_DOMAIN}. 300 IN CNAME ${MAIL_HOST}.
_autodiscover._tcp.${MAIL_DOMAIN}. 300 IN SRV 0 0 443 ${MAIL_HOST}.

PTR / Reverse DNS:
  Set the PTR (reverse DNS) of ${ipv4_cache} to ${MAIL_HOST}

================= POST-INSTALL CHECKLIST ================
1. Wait for DNS propagation (dig MX ${MAIL_DOMAIN}).
2. Test at https://www.mail-tester.com
3. Send test emails to Gmail / Outlook, verify SPF/DKIM/DMARC pass.
4. If backups enabled, confirm contents of ${BACKUP_TARGET_DIR:-/var/backups/mail-stack}.
5. After a week of monitoring DMARC reports, consider p=reject.
6. Update images periodically: compose_cmd pull && compose_cmd up -d (Mailcow/Mailu).
7. Rotate DKIM keys annually (UI) and update DNS.

================= TROUBLESHOOTING SHORTCUTS =============
Check ports: ss -ltnp | egrep ':(25|465|587|110|143|993|995|80|443)\\s'
Mail queue (Postfix container example):
  docker exec -it \$(docker ps --filter "name=postfix" --format '{{.ID}}' | head -n1) postqueue -p
Force ACME retry (Mailcow): cd /opt/mailcow-dockerized && ./helper-scripts/renew_certs.sh

=========================================================

EOF
}

# -------------------- STACK DEPLOYMENTS --------------------
deploy_mailcow() {
  CURRENT_PHASE="deploy_mailcow"
  log "Deploying Mailcow..."
  install_docker_stack
  mkdir -p /opt
  [ -d /opt/mailcow-dockerized ] || git clone https://github.com/mailcow/mailcow-dockerized /opt/mailcow-dockerized
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

  log "Waiting for core containers..."
  local php_id=""
  php_id=$(wait_for_container "php-fpm-mailcow" 240 || true)
  if [ -z "$php_id" ]; then
    warn "php-fpm-mailcow not fully ready; skipping auto mailbox steps."
  else
    local mailbox="${INIT_LOCAL}@${MAIL_DOMAIN}"
    safe_exec "Create domain" docker exec "$php_id" php /var/www/html/helper-scripts/create_domain.php "$MAIL_DOMAIN"
    local pass_hash=""
    for i in 1 2 3 4 5; do
      pass_hash=$(docker exec "$php_id" doveadm pw -s BLF-CRYPT -p "$INIT_PASS" 2>/dev/null || true)
      [ -n "$pass_hash" ] && break
      sleep 6
    done
    if [ -z "$pass_hash" ]; then
      warn "Could not generate password hash; mailbox creation may fail."
    else
      safe_exec "Create mailbox" docker exec "$php_id" php /var/www/html/helper-scripts/create_mailbox.php "$MAIL_DOMAIN" "$mailbox" "$pass_hash" 2048 "Admin User"
    fi
    for i in 1 2 3; do
      safe_exec "Generate DKIM" docker exec "$php_id" php /var/www/html/helper-scripts/generate_dkim.php "$MAIL_DOMAIN" 2048 && break
      sleep 15
    done
  fi
  local dkim_file="/opt/mailcow-dockerized/data/dkim/${MAIL_DOMAIN}.dkim"
  if wait_for_file "$dkim_file" 120; then
    FINAL_DKIM_SELECTOR="dkim"
    FINAL_DKIM_VALUE=$(grep -v '-----' "$dkim_file" | tr -d ' \n\r\t')
  else
    warn "Mailcow DKIM key not yet available."
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
  # Wait for container presence
  wait_for_container "poste" 180 || warn "Poste container not ready - continuing"
  # HTTP readiness (web wizard)
  wait_for_http "$MAIL_HOST" 443 "/" 240 || warn "Poste HTTPS endpoint not responding yet."
  # DKIM generated only after wizard + domain config
  FINAL_DKIM_SELECTOR=""
  FINAL_DKIM_VALUE=""
  log "Poste deployed (complete web wizard at https://${MAIL_HOST})."
}

deploy_mailu() {
  CURRENT_PHASE="deploy_mailu"
  log "Deploying Mailu..."
  install_docker_stack
  mkdir -p /opt/mailu
  cd /opt/mailu
  [ -f docker-compose.yml ] || git clone https://github.com/Mailu/Mailu . >/dev/null 2>&1 || true
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

  log "Waiting for Mailu key containers..."
  wait_for_container "front" 240 || warn "Mailu front not ready"
  wait_for_container "admin" 240 || warn "Mailu admin not ready"

  # DKIM key file appears after initial generation (may take time)
  local dkim_file="/opt/mailu/dkim/${MAIL_DOMAIN}.pem"
  if wait_for_file "$dkim_file" 180; then
    FINAL_DKIM_SELECTOR="mailu"
    FINAL_DKIM_VALUE=$(grep -v '-----' "$dkim_file" | tr -d ' \n\r\t')
  else
    warn "Mailu DKIM key not yet available."
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
    warn "Existing data for $STACK detected."
    ask "Reuse existing data? (y=reuse / n=purge) [y/N]:"
    read -r R
    case "$R" in
      [Yy]*) log "Reusing existing data." ;;
      *)
        warn "Purging existing data for fresh install..."
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
  Debug Mode:          $DEBUG
EOF
  ask "Proceed with installation? [Y/n]:"; read -r P; case "$P" in [Nn]*) err "Aborted"; exit 1;; esac

  check_existing_data
  base_system_packages
  configure_timezone
  [ "$ENABLE_UPGRADES" = "yes" ] && enable_unattended_upgrades
  [ "$APPLY_SYSCTL" = "yes" ] && configure_sysctl
  [ "$SETUP_FIREWALL" = "yes" ] && configure_firewall
  [ "$SETUP_FAIL2BAN" = "yes" ] && configure_fail2ban
  preflight_ports

  case "$STACK" in
    mailcow) deploy_mailcow ;;
    poste)   deploy_poste ;;
    mailu)   deploy_mailu ;;
    *) err "Unknown stack '$STACK'"; exit 1 ;;
  esac

  if [ "$CREATE_BACKUP" = "yes" ]; then create_backup_script; fi

  # Success: disable error trap to avoid cleanup on later manual commands
  trap - ERR

  summarize_dns_records
  log "Installation complete."
}

main "$@"
