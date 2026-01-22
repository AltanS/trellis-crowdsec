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
- Built-in scenarios for common attack patterns (enabled by default)
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
    version: v0.3.0  # or 'main' for latest
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
- Built-in scenarios for actuator probes, debug fuzzing, scanner user agents, and SSRF callbacks
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

### Built-in Scenarios

This role includes four built-in scenarios that are **enabled by default** to protect against common attack patterns. All parameters are configurable.

#### Scenario Parameters Explained

| Parameter | Description |
| --------- | ----------- |
| `capacity` | Number of events allowed before triggering (bucket size). Lower = more sensitive. |
| `leakspeed` | How fast the bucket drains. `1m` = 1 event drains per minute. Faster = more tolerant. |
| `blackhole` | Cooldown after triggering before the scenario can fire again for the same IP. |
| `ban` | How long the IP is banned when the scenario triggers. |

#### Actuator Probe Detection

Detects probing for Spring Boot actuator endpoints (`/actuator`, `/heapdump`) which expose sensitive application data.

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `crowdsec_scenario_actuator_probe` | `true` | Enable/disable scenario |
| `crowdsec_scenario_actuator_probe_capacity` | `3` | Requests before triggering |
| `crowdsec_scenario_actuator_probe_leakspeed` | `1m` | Drain rate |
| `crowdsec_scenario_actuator_probe_blackhole` | `5m` | Cooldown between alerts |
| `crowdsec_scenario_actuator_probe_ban` | `24h` | Ban duration |

#### Debug Endpoint Fuzzing

Detects probing for debug endpoints and error parameters (`/debug`, `?error=`, `?stacktrace=`, `?exception=`).

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `crowdsec_scenario_debug_fuzzing` | `true` | Enable/disable scenario |
| `crowdsec_scenario_debug_fuzzing_capacity` | `5` | Requests before triggering |
| `crowdsec_scenario_debug_fuzzing_leakspeed` | `30s` | Drain rate |
| `crowdsec_scenario_debug_fuzzing_blackhole` | `10m` | Cooldown between alerts |
| `crowdsec_scenario_debug_fuzzing_ban` | `12h` | Ban duration |

#### Custom Bad User Agent Detection

Supplements the Hub's `http-bad-user-agent` scenario (500+ auto-updated patterns) with **immediate blocking** for the most egregious scanner user agents. The Hub scenario triggers after 2 requests; this triggers immediately on first match.

Detected agents: ffuf, sqlmap, nikto, nuclei, gobuster, dirbuster, wpscan, Team Anon Force, Mozlila, Moz111a

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `crowdsec_scenario_custom_bad_user_agent` | `true` | Enable/disable scenario |
| `crowdsec_scenario_custom_bad_user_agent_ban` | `168h` | Ban duration (7 days) |

#### SSRF Callback Detection

Detects Server-Side Request Forgery (SSRF) attempts using callback domains to exfiltrate data or confirm vulnerabilities. These domains are used by security testing tools for out-of-band detection.

Detected domains: burpcollaborator.net, oastify.com, interact.sh, canarytokens.com, requestbin.net, webhook.site, *.oast.*

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `crowdsec_scenario_ssrf_callback` | `true` | Enable/disable scenario |
| `crowdsec_scenario_ssrf_callback_ban` | `168h` | Ban duration (7 days) |

#### Disabling Scenarios

```yaml
# Disable specific built-in scenarios
crowdsec_scenario_actuator_probe: false
crowdsec_scenario_debug_fuzzing: false
crowdsec_scenario_custom_bad_user_agent: false
crowdsec_scenario_ssrf_callback: false
```

### Ban Durations

Ban durations are configured via CrowdSec profiles. This role deploys a custom `profiles.yaml` with sensible defaults.

```yaml
# Default ban duration for CrowdSec Hub scenarios (ssh-bf, http-probing, etc.)
crowdsec_ban_duration_default: "4h"

# Override built-in scenario ban durations
crowdsec_scenario_actuator_probe_ban: "24h"
crowdsec_scenario_debug_fuzzing_ban: "12h"
crowdsec_scenario_custom_bad_user_agent_ban: "168h"  # 7 days
crowdsec_scenario_ssrf_callback_ban: "168h"          # 7 days
```

Duration format: `30m` (minutes), `4h` (hours), `7d` (days)

## Variables Reference

### Trellis Integration Variables

| Variable        | Default         | Description                    |
| --------------- | --------------- | ------------------------------ |
| `ip_whitelist`  | `[127.0.0.0/8]` | IPs to never block             |
| `blocked_ips`   | `[]`            | IPs to permanently block       |

### CrowdSec Variables

| Variable                            | Default       | Description                       |
| ----------------------------------- | ------------- | --------------------------------- |
| `crowdsec_enabled`                  | `true`        | Master switch                     |
| `crowdsec_disable_legacy`           | `true`        | Stop fail2ban/ferm                |
| `crowdsec_flush_legacy_rules`       | `false`       | Flush iptables (use with caution) |
| `crowdsec_collections`              | See defaults  | Hub collections to install        |
| `crowdsec_parsers`                  | `[]`          | Additional parsers                |
| `crowdsec_scenarios`                | `[]`          | Additional scenarios              |
| `crowdsec_scenarios_remove`         | `[]`          | Scenarios to remove               |
| `crowdsec_http_probing_exclude_404` | `false`       | Exclude 404s from http-probing    |
| `crowdsec_ban_duration_default`     | `4h`          | Default ban for Hub scenarios     |
| `crowdsec_acquisition`              | Trellis paths | Log file acquisition              |
| `crowdsec_firewall_bouncer_enabled` | `true`        | Install firewall bouncer          |
| `crowdsec_blocked_ips_duration`     | `87600h`      | Block duration (10 years)         |
| `crowdsec_console_token`            | `""`          | Console enrollment token          |
| `crowdsec_custom_scenarios`         | `[]`          | Custom scenario definitions       |

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
