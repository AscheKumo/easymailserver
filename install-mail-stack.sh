#!/usr/bin/env bash
###############################################################################
# Interactive Mail Stack Installer: Mailcow | Poste.io | Mailu
# Ultra-Robust Edition (enhanced)
#
# See previous explanations above. This version fixes:
#  - Empty container ID docker exec attempts ("page not found")
#  - diag-only unbound TZ
#  - Extra diagnostics for php-fpm-mailcow readiness failures
###############################################################################
set -euo pipefail

# -------------------- GLOBALS / DEFAULTS --------------------
BACKUP_SCRIPT_PATH="/usr/local/sbin/backup-mail-stack"
BACKUP_CRON_FILE="/etc/cron.d/mail-stack-backup"
DOCKER_COMPOSE_LEGACY=0
CURRENT_PHASE="start"
STACK=""
PURGE_ON_FAIL="no"
FLAG_CLEANUP_ONLY="no"
FLAG_PURGE_ONLY="no"
AUTO_FIX_PORTS="no"
PORT_FIX_STRATEGY="ask"
REQUIRED_PORTS_COMMON=(25 465 587 110 143 993 995 80 443)
FINAL_DKIM_SELECTOR=""
FINAL_DKIM_VALUE=""
ipv4_cache=""
ipv6_cache=""
DEBUG="${DEBUG:-0}"
LOG_FILE="/var/log/mail-stack-installer.log"
LONG_WAIT="no"
SKIP_MAILBOX="no"
SKIP_DKIM="no"
FAST_MODE="no"
DIAG_ONLY="no"
PARTIAL_FAILURE="no"

BASE_WAIT_PHP=240
BASE_WAIT_OTHER=240
BASE_WAIT_HTTP=240
BASE_WAIT_DKIM=180

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

# -------------------- DEFAULTS SETTER --------------------
set_defaults() {
  : "${TZ:=UTC}"
  : "${MAIL_DOMAIN:=example.com}"
  : "${MAIL_HOST:=mail.${MAIL_DOMAIN}}"
  : "${INIT_LOCAL:=admin}"
  : "${INIT_PASS:=<unset>}"
  : "${AUTOGEN_PASS:=no}"
  : "${GEN_SPF:=yes}"
  : "${LE_EMAIL:=}"
  : "${CREATE_BACKUP:=no}"
  : "${BACKUP_TARGET_DIR:=/var/backups/mail-stack}"
  : "${BACKUP_RETENTION_DAYS:=14}"
  : "${SETUP_FIREWALL:=no}"
  : "${SETUP_FAIL2BAN:=no}"
  : "${ENABLE_UPGRADES:=no}"
  : "${APPLY_SYSCTL:=no}"
  : "${DMARC_RUAS:=}"
}
set_defaults

adjust_timeouts() {
  if [ "$LONG_WAIT" = "yes" ]; then
    BASE_WAIT_PHP=$((BASE_WAIT_PHP*2))
    BASE_WAIT_OTHER=$((BASE_WAIT_OTHER*2))
    BASE_WAIT_HTTP=$((BASE_WAIT_HTTP*2))
    BASE_WAIT_DKIM=$((BASE_WAIT_DKIM*2))
  fi
  if [ "$FAST_MODE" = "yes" ]; then
    BASE_WAIT_PHP=120
    BASE_WAIT_OTHER=120
    BASE_WAIT_HTTP=90
    BASE_WAIT_DKIM=90
  fi
}
adjust_timeouts

# -------------------- HELP / ARG PARSE --------------------
print_help() {
  cat <<EOF
Usage: $0 [options]
  --purge-on-fail   Purge data if install fails
  --cleanup-only    Stop/remove containers (keep data) then exit
  --purge-only      Stop/remove containers + delete data then exit
  --auto-fix-ports  Auto remediate port conflicts
  --purge-mta       Prefer purge of host MTAs (forces auto-fix)
  --loopback-mta    Prefer loopback Postfix (forces auto-fix)
  --long-wait       Double readiness timeouts
  --no-mailbox      Skip mailbox creation
  --skip-dkim       Skip DKIM generation
  --diag-only       Only diagnostics + summary (must pick stack)
  --fast            Shorten waits (dev mode)
  -h, --help        Help
Env:
  DEBUG=1           Verbose trace logging
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
    --long-wait) LONG_WAIT="yes"; adjust_timeouts ;;
    --no-mailbox) SKIP_MAILBOX="yes" ;;
    --skip-dkim) SKIP_DKIM="yes" ;;
    --diag-only) DIAG_ONLY="yes" ;;
    --fast) FAST_MODE="yes"; adjust_timeouts ;;
    -h|--help) print_help; exit 0 ;;
    *) err "Unknown argument: $arg"; print_help; exit 1 ;;
  esac
done

# -------------------- SAFETY --------------------
[ -z "${BASH_VERSION:-}" ] && { echo "[FATAL] Run with bash" >&2; exit 1; }
[ "${EUID:-$(id -u)}" -ne 0 ] && { err "Run as root (sudo)."; exit 1; }
grep -q $'\r' "$0" && warn "CRLF line endings detected."

# -------------------- UTILITIES --------------------
check_cmd(){ command -v "$1" >/dev/null 2>&1; }
random_password(){ tr -dc 'A-Za-z0-9!@#%^*()-_=+' < /dev/urandom | head -c 20; echo; }
wait_for_file(){
  local f=$1 t=${2:-60} w=0
  while [ ! -s "$f" ] && [ $w -lt $t ]; do sleep 2; w=$((w+2)); done
  [ -s "$f" ]
}
safe_exec(){
  local desc="$1"; shift
  if ! "$@"; then
    warn "Step failed (continuing): $desc"
    return 1
  fi
  return 0
}
debug_container(){
  local cid="$1"
  [ -z "$cid" ] && { warn "debug_container called with empty ID"; return; }
  docker inspect "$cid" --format 'Name={{.Name}} State={{.State.Status}} Health={{if .State.Health}}{{.State.Health.Status}}{{end}} RestartCount={{.RestartCount}}' 2>/dev/null || true
}
wait_for_container(){
  local name_sub="$1" timeout="${2:-240}" waited=0 id="" health=""
  log "Waiting for container matching '$name_sub' (timeout ${timeout}s)..."
  while [ $waited -lt $timeout ]; do
    id=$(docker ps --filter "name=$name_sub" --format '{{.ID}}' | head -n1 || true)
    if [ -n "$id" ]; then
      # Check if container is running first
      local state=$(docker inspect --format='{{.State.Status}}' "$id" 2>/dev/null || echo "unknown")
      if [ "$state" != "running" ]; then
        if (( waited % 30 == 0 )); then
          log "Container '$name_sub' state=$state, waiting..."
          debug_container "$id"
        fi
        sleep 3
        waited=$((waited+3))
        continue
      fi
      
      health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" 2>/dev/null || echo "unknown")
      case "$health" in
        healthy)
          log "Container '$name_sub' healthy."
          debug_container "$id"
          echo "$id"
          return 0
          ;;
        starting)
          if (( waited % 30 == 0 )); then
            log "Still waiting: '$name_sub' health=$health (starting)"
            debug_container "$id"
          fi
          ;;
        none|unknown)
          # For containers without health checks, check if basic services are responding
          if docker exec "$id" test -f /var/www/html/helper-scripts/create_domain.php 2>/dev/null; then
            log "Container '$name_sub' ready (no health check, but files accessible)."
            echo "$id"
            return 0
          fi
          if (( waited % 30 == 0 )); then
            log "Still waiting: '$name_sub' health=$health (checking services)"
            debug_container "$id"
          fi
          ;;
        unhealthy)
          warn "Container '$name_sub' unhealthy, continuing to wait..."
          debug_container "$id"
          ;;
      esac
    else
      if (( waited % 30 == 0 )); then
        log "No container found matching '$name_sub'"
        docker ps --filter "name=$name_sub" || true
      fi
    fi
    sleep 3
    waited=$((waited+3))
  done
  warn "Container '$name_sub' not ready after ${timeout}s."
  [ -n "$id" ] && debug_container "$id"
  return 1
}

docker_exec_guard(){
  # Usage: docker_exec_guard <container_id> <desc> <cmd...>
  local cid="$1"; shift
  local desc="$1"; shift
  if [ -z "$cid" ]; then
    warn "Skip '$desc': container ID empty."
    return 1
  fi
  if ! docker ps --format '{{.ID}}' | grep -q "^$cid\$"; then
    warn "Skip '$desc': container $cid no longer running."
    return 1
  fi
  
  # Add a small delay to ensure container is fully ready
  sleep 2
  
  # Try the command with retries for better reliability
  local attempts=3
  for attempt in $(seq 1 $attempts); do
    if docker exec "$cid" "$@"; then
      return 0
    else
      local exit_code=$?
      warn "docker exec attempt $attempt/$attempts failed for '$desc': $* (exit code: $exit_code)"
      
      if [[ "$*" == *"php"* ]] || [[ "$*" == *"doveadm"* ]]; then
        warn "Potential root cause: service inside container not fully initialized yet."
      fi
      
      if [ $attempt -lt $attempts ]; then
        log "Retrying in 10 seconds..."
        sleep 10
      else
        warn "All $attempts attempts failed for '$desc'"
        return $exit_code
      fi
    fi
  done
}

wait_for_http(){
  local host=$1 port=$2 path=$3 timeout=${4:-240} waited=0
  log "Waiting for HTTPS readiness at https://${host}:${port}${path} (timeout ${timeout}s)..."
  while [ $waited -lt $timeout ]; do
    if curl -k -fsS --max-time 6 "https://${host}:${port}${path}" >/dev/null 2>&1; then
      log "HTTP endpoint responded."
      return 0
    fi
    sleep 5
    waited=$((waited+5))
  done
  warn "HTTP endpoint not responding after ${timeout}s."
  return 1
}

# -------------------- CLEANUP / FAILURE --------------------
stop_mailcow(){ [ -d /opt/mailcow-dockerized ] && (cd /opt/mailcow-dockerized && compose_cmd down -v --remove-orphans || true); }
stop_mailu(){ [ -d /opt/mailu ] && (cd /opt/mailu && compose_cmd down -v --remove-orphans || true); }
stop_poste(){ docker ps -a --format '{{.Names}}' | grep -qx poste && docker rm -f poste || true; }
cleanup_safe(){ log "SAFE cleanup (containers only)"; stop_mailcow; stop_mailu; stop_poste; }
cleanup_purge(){ log "FULL PURGE"; cleanup_safe; rm -rf /opt/mailcow-dockerized /opt/mailu /opt/poste-data; rm -f /var/lib/mail-stack/stack_type; }

on_error(){
  local code=$?
  err "Installation failed at phase: $CURRENT_PHASE (exit $code)"
  cleanup_safe
  [ "$PURGE_ON_FAIL" = "yes" ] && { warn "Purging due to --purge-on-fail"; cleanup_purge; }
  PARTIAL_FAILURE="yes"
  trap - ERR
  
  # Always show DNS records even on failure if we have domain info
  if [ -n "$MAIL_DOMAIN" ] && [ -n "$MAIL_HOST" ]; then
    warn "Installation failed, but here are the DNS records you'll need:"
    summarize_dns_records "FAILURE - PARTIAL DNS INFO"
  fi
  
  exit $code
}
trap on_error ERR

[ "$FLAG_CLEANUP_ONLY" = "yes" ] && { cleanup_safe; exit 0; }
[ "$FLAG_PURGE_ONLY" = "yes" ] && { cleanup_purge; exit 0; }

# -------------------- APT / PREP --------------------
install_packages(){ DEBIAN_FRONTEND=noninteractive apt install -y "$@"; }
add_docker_repo_if_needed(){
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
base_system_packages(){
  CURRENT_PHASE="base_system_packages"
  log "Installing base system packages..."
  apt update -y
  install_packages curl git jq ca-certificates gnupg lsb-release software-properties-common \
                   rsync tar openssl tzdata cron logrotate ufw fail2ban bsd-mailx \
                   unattended-upgrades apt-listchanges
}
enable_unattended_upgrades(){
  CURRENT_PHASE="unattended_upgrades"
  log "Configuring unattended upgrades..."
  dpkg-reconfigure -f noninteractive unattended-upgrades || true
  cat >/etc/apt/apt.conf.d/51-mail-stack-auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
}
configure_sysctl(){
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
configure_timezone(){ CURRENT_PHASE="timezone"; command -v timedatectl >/dev/null 2>&1 && timedatectl set-timezone "$TZ" || true; }
configure_firewall(){
  CURRENT_PHASE="firewall"
  log "Configuring UFW..."
  ufw --force reset
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow 22/tcp
  for p in 25 80 443 110 143 465 587 993 995; do ufw allow "$p"/tcp; done
  ufw --force enable
}
configure_fail2ban(){
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
ensure_compose(){
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
compose_cmd(){ if [ "$DOCKER_COMPOSE_LEGACY" -eq 1 ]; then docker-compose "$@"; else docker compose "$@"; fi; }

docker_api_sanity(){
  CURRENT_PHASE="docker_api_sanity"
  if ! docker version >/dev/null 2>&1; then
    err "Docker not responding."
    exit 1
  fi
}

install_docker_stack(){
  CURRENT_PHASE="docker_install"
  if ! check_cmd docker; then
    add_docker_repo_if_needed
    install_packages docker-ce docker-ce-cli containerd.io docker-buildx-plugin || install_packages docker.io
  fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker_api_sanity
  ensure_compose
}

# -------------------- BACKUP --------------------
create_backup_script(){
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

# -------------------- PORT CONFLICTS --------------------
purge_host_mtas(){
  log "Purging host MTAs..."
  systemctl stop postfix exim4 sendmail opensmtpd nullmailer 2>/dev/null || true
  systemctl disable postfix exim4 sendmail opensmtpd nullmailer 2>/dev/null || true
  apt-get purge -y postfix postfix-* exim4* sendmail* nullmailer opensmtpd 2>/dev/null || true
  apt-get autoremove -y || true
}
configure_postfix_loopback(){
  [ -f /etc/postfix/main.cf ] || { warn "Postfix not installed"; return; }
  sed -i '/^inet_interfaces *=/d;/^inet_protocols *=/d' /etc/postfix/main.cf
  cat >>/etc/postfix/main.cf <<'EOF'
# mail-stack loopback-only
inet_interfaces = loopback-only
inet_protocols = all
EOF
  systemctl restart postfix || warn "Postfix restart failed"
}
ports_busy(){
  for p in "${REQUIRED_PORTS_COMMON[@]}"; do
    ss -ltnp 2>/dev/null | grep -q ":$p " && return 0
  done
  return 1
}
conflicts_list(){
  for p in "${REQUIRED_PORTS_COMMON[@]}"; do
    if ss -ltnp 2>/dev/null | grep -q ":$p "; then
      ss -ltnp | awk -v PT=":$p" -v P="$p" '$4 ~ PT {print P": "$0}'
    fi
  done
  return 0
}
preflight_ports(){
  CURRENT_PHASE="preflight_ports"
  log "Checking required ports..."
  ports_busy || { log "All ports free."; return; }
  warn "Conflicts detected:"; conflicts_list | sed 's/^/[PORT] /'
  systemctl stop postfix exim4 sendmail opensmtpd nullmailer 2>/dev/null || true
  sleep 2
  ports_busy || { log "Conflicts cleared after stopping MTAs."; return; }
  local strategy="$PORT_FIX_STRATEGY"
  if [ "$strategy" = "ask" ] && [ "$AUTO_FIX_PORTS" = "no" ]; then
    echo "Port remediation:"
    echo "  1) Postfix loopback-only"
    echo "  2) Purge MTAs"
    echo "  3) Abort"
    ask "Choice [1-3]:"; read -r ans
    case "$ans" in
      1) strategy="loopback" ;;
      2) strategy="purge" ;;
      *) err "Aborted"; exit 1 ;;
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
  esac
  sleep 2
  ports_busy && { err "Ports still in use."; conflicts_list | sed 's/^/[PORT] /'; exit 1; }
  log "Ports OK."
}

# -------------------- INTERACTIVE / DIAG INPUTS --------------------
interactive_inputs(){
  CURRENT_PHASE="interactive_inputs"
  if [ "$DIAG_ONLY" = "yes" ]; then
    echo; log "Diagnostic mode: choose stack:"
    echo "  1) Mailcow  2) Poste.io  3) Mailu"
    while :; do
      ask "Choice [1-3]:"; read -r c
      case "$c" in
        1) STACK="mailcow"; break ;;
        2) STACK="poste"; break ;;
        3) STACK="mailu"; break ;;
        *) warn "Invalid choice." ;;
      esac
    done
    set_defaults
    return
  fi

  echo
  log "Choose stack:"
  echo "  1) Mailcow  2) Poste.io  3) Mailu"
  while :; do
    ask "Enter choice [1-3]:"; read -r c
    case "$c" in
      1) STACK="mailcow"; break ;;
      2) STACK="poste";   break ;;
      3) STACK="mailu";   break ;;
      *) warn "Invalid."; ;;
    esac
  done
  ask "Primary domain (example.com):"; read -r MAIL_DOMAIN; [ -z "$MAIL_DOMAIN" ] && { err "Domain required"; exit 1; }
  ask "Hostname/FQDN (default: mail.${MAIL_DOMAIN}):"; read -r MAIL_HOST; [ -z "$MAIL_HOST" ] && MAIL_HOST="mail.${MAIL_DOMAIN}"
  ask "Let's Encrypt notification email (optional):"; read -r LE_EMAIL; [ -z "$LE_EMAIL" ] && LE_EMAIL=""
  ask "Timezone (default: UTC):"; read -r TZ; [ -z "$TZ" ] && TZ="UTC"
  ask "Generate restrictive SPF automatically? [Y/n]:"; read -r a; case "$a" in [Nn]*) GEN_SPF="no";; *) GEN_SPF="yes";; esac
  ask "DMARC aggregate report addresses (comma separated, blank=none):"; read -r DMARC_RUA_INPUT
  if [ -n "$DMARC_RUA_INPUT" ]; then OLDIFS=$IFS; IFS=','; set -- $DMARC_RUA_INPUT; IFS=$OLDIFS; DMARC_RUAS=("$@"); else DMARC_RUAS=(); fi
  ask "Initial mailbox local part (default: admin):"; read -r INIT_LOCAL; [ -z "$INIT_LOCAL" ] && INIT_LOCAL="admin"
  if [ "$SKIP_MAILBOX" = "no" ]; then
    ask "Initial mailbox password (blank = generate):"; read -r INIT_PASS
    if [ -z "$INIT_PASS" ]; then INIT_PASS=$(random_password); AUTOGEN_PASS="yes"; else AUTOGEN_PASS="no"; fi
  else
    INIT_PASS="<skipped>"
    AUTOGEN_PASS="no"
  fi
  ask "Configure UFW firewall? [Y/n]:"; read -r FW; case "$FW" in [Nn]*) SETUP_FIREWALL="no";; *) SETUP_FIREWALL="yes";; esac
  ask "Configure Fail2Ban? [y/N]:"; read -r F2B; case "$F2B" in [Yy]*) SETUP_FAIL2BAN="yes";; *) SETUP_FAIL2BAN="no";; esac
  ask "Enable unattended upgrades? [Y/n]:"; read -r UA; case "$UA" in [Nn]*) ENABLE_UPGRADES="no";; *) ENABLE_UPGRADES="yes";; esac
  ask "Apply sysctl/network tuning? [Y/n]:"; read -r ST; case "$ST" in [Nn]*) APPLY_SYSCTL="no";; *) APPLY_SYSCTL="yes";; esac
  ask "Create automated daily backup? [Y/n]:"; read -r BK
  if [[ "$BK" =~ ^[Nn]$ ]]; then
    CREATE_BACKUP="no"
  else
    CREATE_BACKUP="yes"
    ask "Backup target directory [/var/backups/mail-stack]:"; read -r BACKUP_TARGET_DIR; [ -z "$BACKUP_TARGET_DIR" ] && BACKUP_TARGET_DIR="/var/backups/mail-stack"
    ask "Backup retention days [14]:"; read -r BACKUP_RETENTION_DAYS; [ -z "${BACKUP_RETENTION_DAYS:-}" ] && BACKUP_RETENTION_DAYS=14
  fi
  set_defaults
}

# -------------------- DNS PREPARATION --------------------
collect_ips(){
  ipv4_cache=$(curl -4 -s https://ifconfig.co || true)
  ipv6_cache=$(curl -6 -s https://ifconfig.co || true)
  [ -z "$ipv4_cache" ] && ipv4_cache="YOUR_IPV4"
}
build_dmarc_value(){
  local rua_list="" cleaned
  for addr in "${DMARC_RUAS[@]:-}"; do cleaned=$(echo "$addr" | xargs); [ -n "$cleaned" ] && rua_list="${rua_list},mailto:${cleaned}"; done
  rua_list=${rua_list#,}
  local v="v=DMARC1; p=quarantine"
  [ -n "$rua_list" ] && v="${v}; rua=${rua_list}"
  echo "$v"
}
generate_spf_record(){ [ "$GEN_SPF" = "yes" ] && echo "v=spf1 a:${MAIL_HOST%.} mx ~all" || echo "v=spf1 a mx ~all"; }

summarize_dns_records(){
  local status_banner="${1:-SUCCESS}"
  collect_ips
  local SPF_VAL DMARC_VAL DKIM_HOST DKIM_VAL
  SPF_VAL=$(generate_spf_record)
  DMARC_VAL=$(build_dmarc_value)
  if [ -n "$FINAL_DKIM_VALUE" ]; then
    DKIM_HOST="${FINAL_DKIM_SELECTOR}._domainkey.${MAIL_DOMAIN}."
    DKIM_VAL="v=DKIM1; k=rsa; p=${FINAL_DKIM_VALUE}"
  else
    case "$STACK" in
      mailcow) DKIM_HOST="dkim._domainkey.${MAIL_DOMAIN}."; DKIM_VAL="<pending - UI>" ;;
      mailu)   DKIM_HOST="mailu._domainkey.${MAIL_DOMAIN}."; DKIM_VAL="<pending - generate>" ;;
      poste)   DKIM_HOST="(poste selector)._domainkey.${MAIL_DOMAIN}."; DKIM_VAL="<wizard>" ;;
    esac
  fi

  echo
  echo "================= INSTALL SUMMARY (${status_banner}) ================="
  echo "Stack:          $STACK"
  echo "Domain:         $MAIL_DOMAIN"
  echo "Host:           $MAIL_HOST"
  echo "Mailbox:        ${INIT_LOCAL}@${MAIL_DOMAIN}"
  echo "Password:       $INIT_PASS $([ "$AUTOGEN_PASS" = "yes" ] && echo '(autogenerated)')"
  echo "Mailbox Auto:   $([ "$SKIP_MAILBOX" = 'yes' ] && echo 'SKIPPED' || echo 'ATTEMPTED')"
  echo "DKIM Auto:      $([ "$SKIP_DKIM" = 'yes' ] && echo 'SKIPPED' || echo 'ATTEMPTED')"
  [ "$PARTIAL_FAILURE" = "yes" ] && echo "[!] Some steps failed. See diagnostics above."

  cat <<EOF

DNS RECORDS (example):
${MAIL_HOST}.              300 IN A      ${ipv4_cache}
EOF
  [ -n "$ipv6_cache" ] && echo "${MAIL_HOST}.              300 IN AAAA   ${ipv6_cache}"
  cat <<EOF
${MAIL_DOMAIN}.            300 IN MX 10  ${MAIL_HOST}.
${MAIL_DOMAIN}.            300 IN TXT    "${SPF_VAL}"
${DKIM_HOST}      300 IN TXT    "${DKIM_VAL}"
_dmarc.${MAIL_DOMAIN}.     300 IN TXT    "${DMARC_VAL}"
_smtp._tls.${MAIL_DOMAIN}. 300 IN TXT    "v=TLSRPTv1; rua=mailto:tlsrpt@${MAIL_DOMAIN}"
_mta-sts.${MAIL_DOMAIN}.   300 IN TXT    "v=STSv1; id=$(date +%Y%m%d)"
autoconfig.${MAIL_DOMAIN}. 300 IN CNAME  ${MAIL_HOST}.
autodiscover.${MAIL_DOMAIN}. 300 IN CNAME ${MAIL_HOST}.
_autodiscover._tcp.${MAIL_DOMAIN}. 300 IN SRV 0 0 443 ${MAIL_HOST}.

PTR: Set reverse DNS of ${ipv4_cache} to ${MAIL_HOST}

Web / Admin:
  Mailcow: https://${MAIL_HOST}
  Mailu:   https://${MAIL_HOST}/admin (webmail: /webmail)
  Poste:   https://${MAIL_HOST}

Post-Install Quick Checks:
  mail-tester.com, Gmail/Outlook headers, backups at ${BACKUP_TARGET_DIR:-/var/backups/mail-stack}.

======================================================================
EOF
}

# -------------------- DIAGNOSTICS --------------------
diagnose_mailcow(){
  echo "--- Mailcow Diagnostics ---"
  (cd /opt/mailcow-dockerized 2>/dev/null && compose_cmd ps || echo "mailcow dir missing")
  for svc in php-fpm-mailcow postfix-mailcow mysql-mailcow redis-mailcow dovecot-mailcow; do
    echo "--- Last 80 lines: $svc ---"
    (cd /opt/mailcow-dockerized 2>/dev/null && compose_cmd logs --tail=80 "$svc" 2>/dev/null || echo "No logs")
  done
}
diagnose_mailu(){
  echo "--- Mailu Diagnostics ---"
  (cd /opt/mailu 2>/dev/null && compose_cmd ps || echo "mailu dir missing")
  for svc in front admin smtp imap redis; do
    echo "--- Last 80 lines: $svc ---"
    (cd /opt/mailu 2>/dev/null && compose_cmd logs --tail=80 "$svc" 2>/dev/null || echo "No logs")
  done
}
diagnose_poste(){
  echo "--- Poste Diagnostics ---"
  docker ps -a --format '{{.Names}}\t{{.Status}}' | grep poste || echo "poste missing"
  echo "--- Last 80 lines poste ---"
  docker logs --tail=80 poste 2>/dev/null || echo "No logs"
}

run_diagnostics_for_stack(){
  case "$STACK" in
    mailcow) diagnose_mailcow ;;
    mailu)   diagnose_mailu ;;
    poste)   diagnose_poste ;;
  esac
}

# -------------------- DEPLOYMENTS --------------------
deploy_mailcow(){
  CURRENT_PHASE="deploy_mailcow"
  install_docker_stack
  mkdir -p /opt
  [ -d /opt/mailcow-dockerized ] || git clone https://github.com/mailcow/mailcow-dockerized /opt/mailcow-dockerized
  cd /opt/mailcow-dockerized
  if [ ! -f mailcow.conf ]; then
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
  # Wait a bit for containers to start
  sleep 15
  
  local php_id=""
  php_id=$(wait_for_container "php-fpm-mailcow" "$BASE_WAIT_PHP" || true)
  if [ -z "$php_id" ]; then
    warn "php-fpm-mailcow not ready; attempting alternative approach..."
    # Try to find container by a different method
    php_id=$(docker ps --filter "name=php-fpm-mailcow" --format '{{.ID}}' | head -n1 || true)
    if [ -n "$php_id" ]; then
      log "Found php-fpm-mailcow container: $php_id"
      # Check if we can at least connect to it
      if docker exec "$php_id" ls /var/www/html/helper-scripts/ >/dev/null 2>&1; then
        log "php-fpm-mailcow accessible, proceeding with setup..."
      else
        warn "php-fpm-mailcow not accessible; skipping auto setup."
        php_id=""
      fi
    fi
  fi

  if [ -z "$php_id" ]; then
    warn "Cannot proceed with automatic mailbox/domain setup."
    warn "You can complete setup manually via the web interface at https://${MAIL_HOST}"
    PARTIAL_FAILURE="yes"
  else
    # Proceed with automated setup
    if [ "$SKIP_MAILBOX" = "no" ]; then
      local mailbox="${INIT_LOCAL}@${MAIL_DOMAIN}"
      log "Creating domain $MAIL_DOMAIN..."
      if docker_exec_guard "$php_id" "Create domain" php /var/www/html/helper-scripts/create_domain.php "$MAIL_DOMAIN"; then
        log "Domain creation succeeded."
      else
        warn "Domain creation failed - may already exist or container not ready."
        PARTIAL_FAILURE="yes"
      fi
      
      log "Creating mailbox $mailbox..."
      local pass_hash=""
      for i in {1..6}; do
        pass_hash=$(docker exec "$php_id" doveadm pw -s BLF-CRYPT -p "$INIT_PASS" 2>/dev/null || true)
        [ -n "$pass_hash" ] && break
        log "Waiting for doveadm to be ready (attempt $i/6)..."
        sleep 8
      done
      if [ -z "$pass_hash" ]; then
        warn "Password hash generation failed - doveadm not ready."
        PARTIAL_FAILURE="yes"
      else
        if docker_exec_guard "$php_id" "Create mailbox" php /var/www/html/helper-scripts/create_mailbox.php "$MAIL_DOMAIN" "$mailbox" "$pass_hash" 2048 "Admin User"; then
          log "Mailbox creation succeeded."
        else
          warn "Mailbox creation failed."
          PARTIAL_FAILURE="yes"
        fi
      fi
    fi

    if [ "$SKIP_DKIM" = "no" ]; then
      log "Generating DKIM key..."
      for i in {1..4}; do
        if docker_exec_guard "$php_id" "Generate DKIM" php /var/www/html/helper-scripts/generate_dkim.php "$MAIL_DOMAIN" 2048; then
          log "DKIM generation succeeded."
          break
        else
          warn "DKIM generation attempt $i/4 failed."
          sleep 15
        fi
      done
    fi
  fi

  # Try to get DKIM regardless of whether automated setup worked
  local dkim_file="/opt/mailcow-dockerized/data/dkim/${MAIL_DOMAIN}.dkim"
  if [ "$SKIP_DKIM" = "no" ] && wait_for_file "$dkim_file" "$BASE_WAIT_DKIM"; then
    FINAL_DKIM_SELECTOR="dkim"
    FINAL_DKIM_VALUE=$(grep -v '-----' "$dkim_file" | tr -d ' \n\r\t')
    log "DKIM key extracted successfully."
  else
    if [ "$SKIP_DKIM" = "no" ]; then
      warn "Mailcow DKIM not available automatically."
      warn "You can generate it manually via the web interface at https://${MAIL_HOST}"
    fi
  fi
}

deploy_poste(){
  CURRENT_PHASE="deploy_poste"
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
    analogic/poste.io >/dev/null || { PARTIAL_FAILURE="yes"; return; }
  wait_for_container "poste" "$BASE_WAIT_OTHER" || PARTIAL_FAILURE="yes"
  wait_for_http "$MAIL_HOST" 443 "/" "$BASE_WAIT_HTTP" || PARTIAL_FAILURE="yes"
}

deploy_mailu(){
  CURRENT_PHASE="deploy_mailu"
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
  wait_for_container "front" "$BASE_WAIT_OTHER" || PARTIAL_FAILURE="yes"
  wait_for_container "admin" "$BASE_WAIT_OTHER" || PARTIAL_FAILURE="yes"
  if [ "$SKIP_DKIM" = "no" ]; then
    local dkim_file="/opt/mailu/dkim/${MAIL_DOMAIN}.pem"
    if wait_for_file "$dkim_file" "$BASE_WAIT_DKIM"; then
      FINAL_DKIM_SELECTOR="mailu"
      FINAL_DKIM_VALUE=$(grep -v '-----' "$dkim_file" | tr -d ' \n\r\t')
    else
      warn "Mailu DKIM not ready."
      PARTIAL_FAILURE="yes"
    fi
  fi
}

# -------------------- RERUN DATA CHECK --------------------
check_existing_data(){
  local found="no"
  case "$STACK" in
    mailcow) [ -d /opt/mailcow-dockerized ] && found="yes" ;;
    mailu)   [ -d /opt/mailu ] && found="yes" ;;
    poste)   [ -d /opt/poste-data ] && found="yes" ;;
  esac
  [ "$found" = "no" ] && return
  warn "Existing $STACK data found."
  ask "Reuse existing data? (y=reuse / n=purge) [y/N]:"; read -r R
  case "$R" in
    [Yy]*) log "Reusing data." ;;
    *)
      warn "Purging existing data..."
      case "$STACK" in
        mailcow) stop_mailcow; rm -rf /opt/mailcow-dockerized ;;
        mailu)   stop_mailu;   rm -rf /opt/mailu ;;
        poste)   stop_poste;   rm -rf /opt/poste-data ;;
      esac
      ;;
  esac
}

# -------------------- MAIN --------------------
main(){
  interactive_inputs

  log "Summary:"
  cat <<EOF
  Stack:               $STACK
  Domain:              $MAIL_DOMAIN
  Hostname:            $MAIL_HOST
  Timezone:            $TZ
  Mailbox Auto:        $([ "$SKIP_MAILBOX" = "yes" ] && echo 'SKIPPED' || echo 'ENABLED')
  DKIM Auto:           $([ "$SKIP_DKIM" = "yes" ] && echo 'SKIPPED' || echo 'ENABLED')
  Firewall (UFW):      $SETUP_FIREWALL
  Fail2Ban:            $SETUP_FAIL2BAN
  Upgrades:            $ENABLE_UPGRADES
  Sysctl Tuning:       $APPLY_SYSCTL
  Backups:             $CREATE_BACKUP
  Port Strategy:       $PORT_FIX_STRATEGY
  Long Wait:           $LONG_WAIT
  Fast Mode:           $FAST_MODE
  Debug Mode:          $DEBUG
  Diag Only:           $DIAG_ONLY
EOF

  if [ "$DIAG_ONLY" = "yes" ]; then
    run_diagnostics_for_stack
    summarize_dns_records "DIAGNOSTICS ONLY"
    exit 0
  fi

  ask "Proceed with installation? [Y/n]:"; read -r P; [[ "$P" =~ ^[Nn]$ ]] && { err "Aborted"; exit 1; }

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

  [ "$CREATE_BACKUP" = "yes" ] && create_backup_script

  [ "$PARTIAL_FAILURE" = "yes" ] && run_diagnostics_for_stack

  trap - ERR
  local status="SUCCESS"
  if [ "$PARTIAL_FAILURE" = "yes" ]; then
    status="COMPLETED WITH WARNINGS"
    warn "Some automated setup steps failed. You may need to complete setup manually."
    warn "Visit the web interface: https://${MAIL_HOST}"
  fi
  summarize_dns_records "$status"
  log "Installation process finished."
  
  if [ "$PARTIAL_FAILURE" = "yes" ]; then
    echo
    warn "IMPORTANT: Even though some automation failed, the email server should be accessible."
    warn "Complete the setup via the web interface and generate DKIM keys there if needed."
    warn "The DNS records above are still correct and should be configured in your DNS."
  fi
}

main "$@"
