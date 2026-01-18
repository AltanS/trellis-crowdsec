# Trellis CrowdSec

Ansible role to install and configure [CrowdSec](https://crowdsec.net/) Security Engine for [Trellis](https://roots.io/trellis/) WordPress deployments.

Replaces fail2ban and ferm with a modern, community-driven intrusion detection and prevention system.

## Features

- Installs CrowdSec Security Engine and nftables Firewall Bouncer
- Trellis-aware log acquisition (per-site nginx logs)
- Automatic migration from fail2ban/ferm
- IP whitelists (integrates with Trellis `ip_whitelist`)
- Import existing blocked IPs as CrowdSec decisions
- WordPress-specific attack detection via Hub collections
- Custom scenario support

## Requirements

- Ansible 2.10+
- Ubuntu 20.04/22.04/24.04 or Debian 11/12
- Trellis-based WordPress deployment (or compatible nginx setup)

## Installation

```yaml
# galaxy.yml
roles:
  - name: trellis-crowdsec
    src: https://github.com/AltanS/trellis-crowdsec
    version: v0.1.1  # or 'main' for latest
```

Then install:

```bash
ansible-galaxy install -r galaxy.yml
```

### Add to server.yml

```yaml
# server.yml
roles:
  - { role: common, tags: [common] }
  - { role: trellis-crowdsec, tags: [crowdsec, security] }
  # Comment out legacy roles:
  # - { role: fail2ban, tags: [fail2ban] }
  # - { role: ferm, tags: [ferm] }
```

## Configuration

**Zero configuration required** - just add the role to `server.yml` and run provisioning. No changes to `group_vars` needed.

Out of the box, you get:
- WordPress, nginx, and SSH protection via CrowdSec Hub collections
- Trellis log paths (`/srv/www/*/logs/*.log`)
- nftables firewall bouncer
- Localhost whitelisted (`127.0.0.0/8`)

### Optional Overrides

Add to `group_vars/all/security.yml` only if you need to customize:

```yaml
# Whitelist additional IPs (extends the default 127.0.0.0/8)
ip_whitelist:
  - 127.0.0.0/8
  - 203.0.113.50      # Office IP
  - 198.51.100.0/24   # VPN range

# Block specific IPs permanently
blocked_ips:
  - 192.0.2.100
  - 198.51.100.50

# Enroll in CrowdSec Console for centralized dashboard
crowdsec_console_token: "your-enrollment-token"

# Disable CrowdSec without removing the role
crowdsec_enabled: false
```

### CrowdSec Console

Enroll in [CrowdSec Console](https://app.crowdsec.net/) for a centralized dashboard to monitor all your servers.

### Custom Scenarios

Port fail2ban filters or add custom detection:

```yaml
crowdsec_custom_scenarios:
  - name: wordpress-admin-exploit
    description: "Detect WordPress admin exploitation"
    type: leaky
    filter: "evt.Meta.http_path contains '/wp-login.php' and evt.Meta.http_args contains 'lostpassword'"
    groupby: evt.Meta.source_ip
    capacity: 1
    leakspeed: 24h
    blackhole: 24h
    labels:
      service: wordpress
      type: exploit
      remediation: true
```

### Handling HTTP Probing False Positives

The `http-probing` scenario bans IPs that hit 10+ paths returning 404/403/400. This causes false positives on WordPress REST APIs where 404 means "resource not found" (normal behavior).

**Option 1: Exclude 404s (Recommended)**

Keep probing detection but exclude 404 responses:

```yaml
# Detect probing on 403/400 only, ignore 404s
crowdsec_http_probing_exclude_404: true
```

**Option 2: Disable http-probing entirely**

```yaml
crowdsec_scenarios_remove:
  - crowdsecurity/http-probing
```

## Variables Reference

### Trellis Integration Variables

| Variable        | Default         | Description                    |
| --------------- | --------------- | ------------------------------ |
| `ip_whitelist`  | `[127.0.0.0/8]` | IPs to never block             |
| `blocked_ips`   | `[]`            | IPs to permanently block       |

### CrowdSec Variables

| Variable                            | Default                              | Description                       |
| ----------------------------------- | ------------------------------------ | --------------------------------- |
| `crowdsec_enabled`                  | `true`                               | Master switch                     |
| `crowdsec_disable_legacy`           | `true`                               | Stop fail2ban/ferm                |
| `crowdsec_flush_legacy_rules`       | `false`                              | Flush iptables (use with caution) |
| `crowdsec_collections`              | See defaults                         | Hub collections to install        |
| `crowdsec_parsers`                  | `[]`                                 | Additional parsers                |
| `crowdsec_scenarios`                | `[]`                                 | Additional scenarios              |
| `crowdsec_scenarios_remove`         | `[]`                                 | Scenarios to remove               |
| `crowdsec_http_probing_exclude_404` | `false`                              | Exclude 404s from http-probing    |
| `crowdsec_acquisition`              | Trellis paths                        | Log file acquisition              |
| `crowdsec_firewall_bouncer_enabled` | `true`                               | Install firewall bouncer          |
| `crowdsec_firewall_bouncer_package` | `crowdsec-firewall-bouncer-nftables` | Bouncer package                   |
| `crowdsec_whitelists`               | `{{ ip_whitelist }}`                 | Derived from ip_whitelist         |
| `crowdsec_import_blocked_ips`       | `true`                               | Import blocked IPs as decisions   |
| `crowdsec_blocked_ips`              | `{{ blocked_ips }}`                  | Derived from blocked_ips          |
| `crowdsec_blocked_ips_duration`     | `87600h`                             | Block duration (10 years)         |
| `crowdsec_console_token`            | `""`                                 | Console enrollment token          |
| `crowdsec_custom_scenarios`         | `[]`                                 | Custom scenario definitions       |

## Useful Commands

```bash
# Service status
sudo cscli metrics
sudo cscli alerts list
sudo cscli decisions list

# Check log acquisition
sudo cscli metrics show acquisition

# View active bans
sudo cscli decisions list --type ban

# Manually ban an IP
sudo cscli decisions add --ip 1.2.3.4 --duration 24h --reason "Manual ban"

# Unban an IP
sudo cscli decisions delete --ip 1.2.3.4

# Unban all IPs banned by a specific scenario
sudo cscli decisions delete --scenario crowdsecurity/http-probing

# Check collections
sudo cscli collections list
sudo cscli hub list
```

## Migration from fail2ban

1. Add this role to `galaxy.yml` and install
2. Add role to `server.yml` (before or after commenting fail2ban/ferm)
3. Configure `blocked_ips` to import existing blocks (optional)
4. Run provisioning: `ansible-playbook server.yml -e env=production --tags=crowdsec`
5. Verify: `sudo cscli metrics` shows log processing
6. After confirming, set `crowdsec_flush_legacy_rules: true` to clean up iptables

## Uninstall / Reverting to fail2ban

To remove CrowdSec and restore fail2ban/ferm:

1. Update `server.yml` to disable CrowdSec and re-enable legacy roles:

```yaml
roles:
  - { role: common, tags: [common] }
  # - { role: trellis-crowdsec, tags: [crowdsec, security] }
  - { role: fail2ban, tags: [fail2ban] }
  - { role: ferm, tags: [ferm] }
```

2. Stop and remove CrowdSec on the server:

```bash
# SSH into your server, then:
sudo systemctl stop crowdsec crowdsec-firewall-bouncer
sudo systemctl disable crowdsec crowdsec-firewall-bouncer
sudo apt purge crowdsec crowdsec-firewall-bouncer-nftables
sudo nft flush ruleset  # Clear nftables rules
```

3. Re-provision to restore fail2ban/ferm:

```bash
ansible-playbook server.yml -e env=production --tags=fail2ban,ferm
```

4. Verify fail2ban is running:

```bash
sudo fail2ban-client status
sudo ferm --check /etc/ferm/ferm.conf
```

## License

MIT

## Author

Created for Trellis WordPress deployments.
