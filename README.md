# Trellis CrowdSec

> **⚠️ Warning:** This role modifies firewall rules and security services. Misconfiguration can lock you out of your server. Ensure you have out-of-band access (console, KVM, recovery mode) before deploying. Test on staging first. The author assumes no responsibility for lost access, downtime, or any damages resulting from use of this role.

Ansible role to install and configure [CrowdSec](https://crowdsec.net/) Security Engine for [Trellis](https://roots.io/trellis/) WordPress deployments.

Replaces fail2ban and ferm with a modern, community-driven intrusion detection and prevention system.

## Why CrowdSec over fail2ban + ferm?

| | fail2ban + ferm | CrowdSec |
|---|---|---|
| **Threat intelligence** | Local only - learns from attacks on your server | Community blocklists - benefit from attacks seen across 200k+ servers |
| **Detection** | Regex-based jail configs | Behavioral analysis with parsers and scenarios |
| **Firewall** | iptables (legacy) | nftables (modern, faster, better syntax) |
| **False positives** | Common with aggressive configs | Reputation-aware, whitelists good actors (Googlebot, etc.) |
| **Updates** | Manual filter maintenance | Auto-updated Hub with community scenarios |
| **Dashboard** | CLI only | Free web console for multi-server monitoring |

## Requirements

- Ansible 2.10+
- Ubuntu 20.04/22.04/24.04 or Debian 11/12
- Trellis-based WordPress deployment (or compatible nginx setup)

## Installation

### 1. Add to galaxy.yml

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

### 2. Update server.yml

```yaml
# server.yml
roles:
  - { role: common, tags: [common] }
  - { role: trellis-crowdsec, tags: [crowdsec, security] }
  # Comment out legacy roles:
  # - { role: fail2ban, tags: [fail2ban] }
  # - { role: ferm, tags: [ferm] }
```

### What the role does during provisioning

When you run provisioning, this role automatically handles the migration:

1. **Stops and disables fail2ban** - If `/etc/fail2ban` exists, the fail2ban service is stopped and disabled. The package is not removed.

2. **Stops and disables ferm** - If `/etc/ferm` exists, the ferm service is stopped and disabled. The package is not removed.

3. **Installs CrowdSec** - Adds the official CrowdSec repository and installs the Security Engine.

4. **Installs nftables firewall bouncer** - Registers with the CrowdSec LAPI to enforce blocking decisions.

5. **Configures log acquisition** - Points CrowdSec at Trellis log paths (`/srv/www/*/logs/*.log`).

6. **Installs Hub collections** - WordPress, nginx, SSH, and HTTP security scenarios.

**Note:** iptables rules from ferm remain active until you explicitly flush them (see below).

### 3. Run provisioning

```bash
ansible-playbook server.yml -e env=production --tags=crowdsec
```

### 4. Verify CrowdSec is working

```bash
# SSH into server
sudo cscli metrics                    # Should show log processing
sudo cscli decisions list             # Active bans
sudo cscli bouncers list              # Should show firewall-bouncer
```

### 5. Flush legacy iptables rules (optional)

After confirming CrowdSec is working, you can flush the old iptables rules from ferm:

```yaml
# group_vars/all/security.yml
crowdsec_flush_legacy_rules: true
```

Then re-provision. This runs `iptables -F` to clear legacy rules. Only do this after confirming CrowdSec's nftables bouncer is active.

### Migration variables

| Variable | Default | Description |
|----------|---------|-------------|
| `crowdsec_disable_legacy` | `true` | Stop and disable fail2ban/ferm services |
| `crowdsec_flush_legacy_rules` | `false` | Flush iptables rules (run `iptables -F`) |

## Uninstall / Reverting to fail2ban

To remove CrowdSec and restore fail2ban/ferm:

### 1. Update server.yml

```yaml
roles:
  - { role: common, tags: [common] }
  # - { role: trellis-crowdsec, tags: [crowdsec, security] }
  - { role: fail2ban, tags: [fail2ban] }
  - { role: ferm, tags: [ferm] }
```

### 2. Remove CrowdSec from the server

```bash
# SSH into your server
sudo systemctl stop crowdsec crowdsec-firewall-bouncer
sudo systemctl disable crowdsec crowdsec-firewall-bouncer
sudo apt purge crowdsec crowdsec-firewall-bouncer-nftables
sudo nft flush ruleset  # Clear nftables rules
```

### 3. Re-provision to restore fail2ban/ferm

```bash
ansible-playbook server.yml -e env=production --tags=fail2ban,ferm
```

### 4. Verify

```bash
sudo fail2ban-client status
sudo ferm --check /etc/ferm/ferm.conf
```

## Features

- Installs CrowdSec Security Engine and nftables Firewall Bouncer
- Trellis-aware log acquisition (per-site nginx logs)
- Automatic migration from fail2ban/ferm
- IP whitelists (integrates with Trellis `ip_whitelist`)
- Import existing blocked IPs as CrowdSec decisions
- WordPress-specific attack detection via Hub collections
- Built-in scenarios for common attack patterns (enabled by default)
- Custom scenario support

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

### Community Collections

CrowdSec Hub provides community-maintained collections that bundle parsers and scenarios for specific applications. This role installs a curated set by default.

**Default collections:**

| Collection | Description |
|------------|-------------|
| `crowdsecurity/linux` | Linux system log parsing |
| `crowdsecurity/nginx` | Nginx access/error log parsing |
| `crowdsecurity/sshd` | SSH brute-force detection |
| `crowdsecurity/base-http-scenarios` | HTTP probing, crawling, bad user-agents |
| `crowdsecurity/http-cve` | Known CVE exploitation attempts |
| `crowdsecurity/wordpress` | WordPress-specific attacks (xmlrpc, wp-login brute-force) |
| `crowdsecurity/whitelist-good-actors` | Whitelist Googlebot, Bingbot, etc. |

**Adding community collections:**

Browse available collections at [CrowdSec Hub](https://hub.crowdsec.net/browse/#collections). To add collections, override `crowdsec_collections` in `group_vars/all/security.yml`:

```yaml
# Add to your existing defaults
crowdsec_collections:
  # Default collections (keep these)
  - crowdsecurity/linux
  - crowdsecurity/nginx
  - crowdsecurity/sshd
  - crowdsecurity/base-http-scenarios
  - crowdsecurity/http-cve
  - crowdsecurity/wordpress
  - crowdsecurity/whitelist-good-actors
  # Additional collections
  - crowdsecurity/postfix        # Mail server protection
  - crowdsecurity/mysql          # MySQL/MariaDB protection
  - crowdsecurity/iptables       # If using iptables logs
```

**Removing collections:**

To remove a default collection, override the list without it:

```yaml
crowdsec_collections:
  - crowdsecurity/linux
  - crowdsecurity/nginx
  - crowdsecurity/sshd
  - crowdsecurity/base-http-scenarios
  - crowdsecurity/http-cve
  # Removed: crowdsecurity/wordpress (not using WordPress)
  - crowdsecurity/whitelist-good-actors
```

**Adding individual scenarios or parsers:**

If you only need specific scenarios/parsers (not full collections):

```yaml
# Add individual scenarios
crowdsec_scenarios:
  - crowdsecurity/http-sqli      # SQL injection detection

# Add individual parsers
crowdsec_parsers:
  - crowdsecurity/geoip-enrich   # Add geolocation to alerts
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
cscli metrics
cscli alerts list
cscli decisions list

# Check log acquisition
cscli metrics show acquisition

# View active bans
cscli decisions list --type ban

# Manually ban an IP
cscli decisions add --ip 1.2.3.4 --duration 24h --reason "Manual ban"

# Unban an IP
cscli decisions delete --ip 1.2.3.4

# Unban all IPs banned by a specific scenario
cscli decisions delete --scenario crowdsecurity/http-probing

# Check collections
cscli collections list
cscli hub list
```

## License

MIT

## Author

[AltanS](https://github.com/AltanS)
