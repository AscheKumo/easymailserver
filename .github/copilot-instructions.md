# Mail Stack Installer

This repository contains an interactive bash script that installs one of three self-hosted mail server solutions: Mailcow, Poste.io, or Mailu. The script handles Docker installation, mail server deployment, DNS configuration generation, and optional system hardening.

Always reference these instructions first and fallback to search or bash commands only when you encounter unexpected information that does not match the info here.

## Working Effectively

### Bootstrap and validate the repository:
- Run syntax check: `bash -n install-mail-stack.sh` - takes <1 second
- Check script permissions: `chmod +x install-mail-stack.sh` if needed
- Test help functionality: `./install-mail-stack.sh --help` - displays usage information
- Verify system dependencies: `which curl git jq docker` - all should be available

### System Requirements (CRITICAL - validate these before proceeding):
- **Root access required**: Script must run as root via `sudo`
- **Debian/Ubuntu system**: Uses `apt` package manager exclusively
- **Internet access**: Downloads Docker, mail stack repositories, container images
- **Public IPv4 address**: Required for proper mail server operation
- **Domain with DNS control**: Needed to configure MX, SPF, DKIM, DMARC records
- **Open ports**: 25, 465, 587, 110, 143, 993, 995, 80, 443
- **Clean server**: No conflicting mail services (Postfix, Exim, etc.)

### Core Operations (with measured timings):

**NEVER CANCEL these operations - they are time-sensitive**:
- Docker installation: `install_docker_stack()` - **TIMEOUT: 300+ seconds**
- Mail stack deployment: **TIMEOUT: 900+ seconds (15+ minutes)**
  - Git repository clones: 1-5 seconds each
  - Container image pulls: 5-20 seconds per image
  - Container startup: 240+ seconds (4+ minutes) - **NEVER CANCEL**
  - Service readiness: 240+ seconds additional - **NEVER CANCEL**

### Script execution modes:
- **Interactive mode**: `sudo ./install-mail-stack.sh` - prompts for configuration
- **Diagnostic mode**: `sudo MAIL_DOMAIN=example.com STACK=mailcow ./install-mail-stack.sh --diag-only`
- **Help mode**: `./install-mail-stack.sh --help` - no root required
- **Debug mode**: `sudo DEBUG=1 ./install-mail-stack.sh` - verbose logging to `/var/log/mail-stack-installer.log`

### Pre-execution validation:
Always run these checks before executing the main script:
- `docker --version && docker compose version` - verify Docker is functional
- `systemctl status docker` - ensure Docker daemon is running  
- `ss -tlnp | grep -E ':(25|80|443|465|587|993|995):'` - check for port conflicts
- `df -h` - ensure adequate disk space (5GB+ recommended)

## Validation

### Manual testing scenarios (REQUIRED after any changes):
1. **Script integrity**: 
   - `bash -n install-mail-stack.sh` - syntax validation
   - `./install-mail-stack.sh --help` - help display
2. **Root requirements**:
   - `./install-mail-stack.sh` without sudo - should fail with error message
   - `sudo ./install-mail-stack.sh` - should prompt for configuration
3. **Diagnostic mode**:
   - `sudo MAIL_DOMAIN=test.example.com STACK=mailcow ./install-mail-stack.sh --diag-only`
   - Should complete without hanging and display DNS records
4. **Container operations** (if Docker available):
   - `docker ps` - verify no conflicting containers
   - `docker pull analogic/poste.io` - test image availability
5. **Environment variables**:
   - Test with various combinations: `TZ=UTC`, `DEBUG=1`, `FAST_MODE=yes`

### Expected timing benchmarks:
- **CRITICAL**: Default container wait times: 240 seconds (4 minutes)
- **CRITICAL**: DKIM generation wait: 180 seconds (3 minutes) 
- **CRITICAL**: Full deployment: 10-20 minutes depending on mail stack
- Container image pulls: 5-20 seconds per image
- Git repository clones: 1-5 seconds
- Docker command execution: <1 second

### Validation commands that ALWAYS work:
- `bash -n install-mail-stack.sh` - syntax check (no root needed)
- `./install-mail-stack.sh --help` - display help (no root needed)
- `grep -n "BASE_WAIT" install-mail-stack.sh` - show timeout values
- `docker --version && docker compose version` - verify Docker functionality

## Common Tasks

### Troubleshooting commands:
- Check script logs: `sudo tail -f /var/log/mail-stack-installer.log`
- Container status: `sudo docker ps -a`
- Docker logs: `sudo docker logs <container-name>`
- Port conflicts: `sudo ss -tlnp | grep :<port>`
- System resources: `df -h && free -h`

### Environment configuration:
Set these environment variables before running for non-interactive operation:
```bash
export MAIL_DOMAIN=example.com
export MAIL_HOST=mail.example.com
export STACK=mailcow  # or poste or mailu
export TZ=UTC
export SKIP_MAILBOX=no
export SKIP_DKIM=no
```

### Repository structure:
```
.
├── README-mail-stack.md     # User documentation
├── FIX_DOCUMENTATION.md     # Issue resolution history
└── install-mail-stack.sh    # Main installation script (946 lines)
```

### Key script functions and timeouts:
- `wait_for_container()` - 240+ second timeout, **NEVER CANCEL**
- `wait_for_http()` - 240+ second timeout for web interface readiness  
- `wait_for_file()` - 180+ second timeout for DKIM generation
- `docker_exec_guard()` - 3 retry attempts with 10-second delays
- Container readiness checks use Docker health checks when available

### DNS record generation:
The script ALWAYS generates DNS records even if container setup fails:
- MX record pointing to mail hostname
- SPF record with default policy
- DKIM record (if key generated successfully)  
- DMARC record with quarantine policy
- A/AAAA records for mail hostname

## Timing and Cancellation Warnings

**CRITICAL TIMEOUT SETTINGS**:
- Set bash timeout to 1800+ seconds (30+ minutes) for full deployment
- Container operations: minimum 300+ seconds timeout
- Never use default 120-second timeouts - they WILL cause failures
- If script appears hung, wait minimum 5 minutes before investigating

**NEVER CANCEL these operations**:
- Docker container pulls and startups
- Mail service initialization (can take 4+ minutes)
- DKIM key generation (up to 3 minutes)
- SSL certificate provisioning
- Database initialization

## Error Handling

### Common failure modes:
1. **Port conflicts**: Script detects and offers remediation
2. **Container readiness timeout**: Script continues with partial setup
3. **DKIM generation failure**: Manual generation required via web interface
4. **Docker daemon issues**: Restart with `sudo systemctl restart docker`

### Recovery procedures:
- Cleanup: `sudo ./install-mail-stack.sh --cleanup-only`
- Full purge: `sudo ./install-mail-stack.sh --purge-only`  
- Force container restart: `sudo docker restart <container-name>`
- Manual DKIM: Generate via web interface after deployment

**ALWAYS** complete manual verification by accessing the web interface at `https://mail.yourdomain.com` and testing mail functionality after deployment completes.