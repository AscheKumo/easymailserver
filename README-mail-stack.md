# Mail Stack Installer

This repository/script provides an interactive Bash installer for one of three self-hosted mail solutions:

| Stack   | Pros | Cons | Use Case |
|---------|------|------|----------|
| Mailcow | Feature-rich (Rspamd, SOGo, UI), open source | Heavier, more containers | Long-term multi-domain |
| Poste.io | Fastest single container, simple UI | Core not fully FOSS, less granular control | Quick start / lab |
| Mailu   | Modular, lighter, flexible | Less "appliance-like" than Mailcow | Tinkerers wanting modularity |

## Quick Start

```bash
curl -O https://yourhost/install-mail-stack.sh
sudo bash install-mail-stack.sh
```

Answer the prompts. The script:
1. Installs Docker & Compose.
2. Clones and configures selected stack.
3. Creates initial domain/mailbox (Mailcow/Mailu).
4. Generates (or fetches) DKIM key where possible.
5. Prints DNS records to add.

## Requirements
- Clean public IPv4 (and optionally IPv6)
- Ability to set reverse DNS (PTR) to `mail.yourdomain`
- Open ports: 25,80,443,110,143,465,587,993,995
- Debian/Ubuntu host (root access)
- Domain registrar access for DNS edits

## DNS Essentials
- A/AAAA: mail host -> server IP(s)
- MX: domain -> mail host
- SPF: v=spf1 a mx ~all
- DKIM: Provided after install
- DMARC: v=DMARC1; p=quarantine; rua=mailto:you@domain
- (Optional) TLS-RPT, MTA-STS

## Testing
- Outbound: https://www.mail-tester.com
- TLS: `testssl.sh mail.example.com:25`
- IMAP login: `openssl s_client -connect mail.example.com:993`

## Backups
- Mailcow: use helper scripts (`./helper-scripts/backup_and_restore.sh`)
- Poste.io: archive `/opt/poste-data`
- Mailu: backup `/opt/mailu` volumes + DB

## Updates
- Mailcow: `docker compose pull && docker compose up -d`
- Poste.io: `docker pull analogic/poste.io && docker stop poste && docker rm poste && <re-run docker run>`
- Mailu: `docker compose pull && docker compose up -d`

## Security Hardening (after baseline)
- Enable firewall (ufw) allowing needed ports.
- Fail2Ban (Mailcow integrates), else add container or host-level.
- Rotate DKIM annually (add new selector, update DNS, remove old).
- Enforce strong auth; consider enabling 2FA in webmail if supported.

## Troubleshooting
| Symptom | Check |
|---------|-------|
| Can't send | Port 25 blocked by provider? Logs: `docker logs postfix-mailcow` or stack equivalent |
| Auth fails | Correct full email as username, port 587 (submission) or 465 |
| Spam classification high | Ensure SPF/DKIM/DMARC pass, warm-up IP |
| DKIM missing | Wait for generation; ensure container not restarting |

## License
Script provided as-is (MIT style). Review security implications before production use.