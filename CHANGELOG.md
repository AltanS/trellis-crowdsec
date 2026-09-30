# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.9.8] - 2026-09-30

### Fixed
- Web scope: a Hub HTTP scenario (`crowdsecurity/http-probing`, `http-cve`, ...) or a
  stack's custom HTTP scenario fell through to `default_ip_remediation` and got
  `type: ban` on ALL ports. One false-positive alert dropped every packet from the
  source, including SSH and the Tailscale UDP transport, so the tailnet whitelist
  never saw the connection (klaracase prod, 2026-09-29). With
  `crowdsec_web_scope_http_bans: true` the catch-all now emits `web-ban` (80/443).

### Added
- `ssh_scenarios` profile, ahead of the catch-all when web scope is on: scenarios
  whose name starts with a prefix in `crowdsec_ssh_scenario_prefixes` (default
  `crowdsecurity/ssh-`) keep the all-ports `ban`. Add a prefix for any other
  non-HTTP scenario a stack installs.

### Verified
- Log replay on crowdsec v1.8.1: http-probing -> `web-ban`, ssh-bf / ssh-slow-bf ->
  `ban`. The same replay on the v0.9.7 profiles gave http-probing `ban`.

## [0.9.7] - 2026-07-21

### Fixed
- Idempotency: `Install CrowdSec collections` (and the sibling scenarios/parsers
  installs) no longer report `changed` on a converged host. cscli 1.7.x prints the
  no-op notice ("Nothing to install or remove.") to **stdout** with an empty stderr,
  and refuses tainted items via a "tainted"/"overwrite" **stderr** warning — the old
  `changed_when` only inspected stderr for "already"/"overwrite", so an already-installed
  clean collection was misreported as changed every run. The guard now recognises the
  stdout no-op and the tainted-refusal signals (old stderr markers kept for pre-1.7 cscli).
- Idempotency + correctness: `Remove http-probing override when disabled` is now
  symlink-aware. The Hub's own `http-probing` scenario lives at the same path as a
  symlink that `cscli collections install` (re)creates; deleting it tainted the owning
  collection, silently removed real protection, and produced a per-run
  remove→reload→re-enable churn ping-pong. The task now stats first and only removes a
  regular-file override (never the Hub symlink).

### Changed
- Removed the non-standard `galaxy_info.version` key from `meta/main.yml` — role
  versions are carried by git tags (consumed via `requirements.yml`), and current
  ansible-lint's meta schema rejects the field (was failing the production profile).

## [0.9.1] - 2026-03-19

### Fixed
- Bouncer race condition: stop bouncer immediately after `apt install` (before API key is configured) to prevent it running with wrong credentials from the package auto-start
- Replace `ExecStartPost` agent drop-in with `PartOf=crowdsec.service` bouncer drop-in — systemd natively restarts/stops the bouncer when the agent restarts, avoiding double-restart race conditions with stale netlink handles
- Add post-start nftables verification: the play now fails loudly if the bouncer's `ip crowdsec` table doesn't appear within 10 seconds, preventing silent enforcement failures
- Clean up legacy `ExecStartPost` drop-in from prior deploys

## [0.9.0] - 2026-03-15

### Added
- Bouncer auto-restart on agent restart — deploys a systemd drop-in (`ExecStartPost`) that restarts `crowdsec-firewall-bouncer` whenever the CrowdSec agent starts. Prevents stale/empty nftables sets after OOM recovery or agent updates.
- `aggressive-crawl` scenario — WordPress-compatible crawl detection that replaces the Hub's broken `http-crawl-non_statics` scenario. The Hub scenario uses `distinct: "evt.Parsed.file_name"` which is always empty for WordPress pretty permalink URLs ending in `/`, collapsing all requests into one bucket entry. This scenario uses `distinct: "evt.Meta.http_path"` instead. Capacity 40, leakspeed 5s. Catches fast scrapers in ~5 seconds. Excludes Ahrefs crawlers.
- `sustained-crawl` scenario — slow-but-persistent scraper detection. No `distinct` filter; counts all non-static GET/HEAD requests. Capacity 120, leakspeed 10s. Catches coordinated scraper clusters doing 25-40 req/min per IP within 3-6 minutes. Excludes Ahrefs crawlers.
- Four new scanner user agents to `custom-bad-user-agent`: `depconf_deep_scanner`, `getodin.com`, `cypex.ai/scanning`, `onlyscans.com`

### Changed
- Default ban duration (`crowdsec_ban_duration_default`) increased from `4h` to `24h` — persistent scrapers and SSRF probers were observed running 14+ hours continuously, outlasting the previous default

### Fixed
- `ssrf-callback` scenario: added `evil.com` to both `http_args` and `http_path` checks (was missing entirely)
- `ssrf-callback` scenario: added missing OAST domains (`oast.me`, `.oast.site`, `.oast.online`, `.oast.me`, `canarytokens.com`, `requestbin.net`, `webhook.site`) to `http_path` checks — these were previously only checked in `http_args`, leaving path-based SSRF probes undetected

## [0.6.1] - 2026-02-01

### Fixed
- Replaced invalid `RegexpMatch` with `matches` expr operator in scenario filters

## [0.6.0] - 2026-02-01

### Added
- `cache-buster-probe` scenario — detects bot networks using cache-busting query parameters to probe WordPress sites
- `open-redirect-probe` scenario — detects redirect parameter fuzzing with external URL targets
- `param-stuffing` scenario — detects requests with 20+ query parameters (parameter fuzzing indicator)

## [0.5.1] - 2026-01-29

### Added
- nftables CIDR enforcement via interval sets for `ip_blocklist` (works around CrowdSec firewall bouncer CIDR bug)

### Changed
- Renamed `blocked_ips` variable to `ip_blocklist` for consistency with `ip_whitelist`

### Fixed
- Fixed idempotent re-apply and overlapping CIDR handling in nftables blocklist

## [0.4.0] - 2026-01-29

### Added
- `encoded-attack-payload` scenario — detects double-encoded and HTML-entity-encoded attack payloads used to evade WAF/IDS
- `xss-extended` scenario — supplements Hub's XSS detection with event handler attributes and DOM property access patterns

## [0.3.0] - 2025-01-22

### Added
- Built-in attack detection scenarios (enabled by default):
  - `actuator-probe` - Spring Boot actuator endpoint probing
  - `debug-fuzzing` - Debug/error endpoint probing
  - `custom-bad-user-agent` - Immediate block for scanner user agents (supplements Hub)
  - `ssrf-callback` - SSRF attempts with callback domains (burpcollaborator, interact.sh, etc.)
- Configurable ban durations via custom `profiles.yaml`
- Per-scenario parameters (capacity, leakspeed, blackhole, ban duration)

### Changed
- Refactored scenario tasks to use loops (improved maintainability)
- Simplified configuration by removing redundant variables
- Use `ip_whitelist` and `ip_blocklist` directly (removed indirection)

### Removed
- `crowdsec_packages` variable (hardcoded)
- `crowdsec_service_enabled/state` variables (hardcoded)
- `crowdsec_firewall_bouncer_mode` variable (unused)
- `crowdsec_firewall_bouncer_package` variable (hardcoded)
- `crowdsec_firewall_bouncer_service_enabled/state` variables (hardcoded)
- `crowdsec_whitelists` variable (use `ip_whitelist` directly)
- `crowdsec_blocked_ips` variable (use `ip_blocklist` directly)
- `crowdsec_import_blocked_ips` variable (simplified)

## [0.2.0] - 2025-01-18

### Added
- `crowdsec_http_probing_exclude_404` option to exclude 404 responses from http-probing scenario (reduces false positives for REST APIs)
- `crowdsec_scenarios_remove` variable to remove unwanted scenarios installed by collections

## [0.1.1] - 2025-01-17

### Added
- Log acquisition for `/var/log/nginx/access.log` and `/var/log/nginx/error.log` (catches direct IP access and unknown hosts)

## [0.1.0] - 2025-01-17

### Added
- Initial release
- CrowdSec Security Engine installation
- nftables Firewall Bouncer support
- Trellis-aware log acquisition (`/srv/www/*/logs/*.log`)
- Hub collections for WordPress, nginx, SSH, and CVE protection
- IP whitelist integration (`ip_whitelist` variable)
- Blocked IPs import as CrowdSec decisions (`ip_blocklist` variable)
- CrowdSec Console enrollment support
- Custom scenario definitions
- Automatic fail2ban/ferm migration (disable legacy services)
- Legacy iptables cleanup option

[Unreleased]: https://github.com/AltanS/trellis-crowdsec/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.8.0...v0.9.0
[0.6.1]: https://github.com/AltanS/trellis-crowdsec/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/AltanS/trellis-crowdsec/compare/v0.4.0...v0.5.1
[0.4.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/AltanS/trellis-crowdsec/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AltanS/trellis-crowdsec/releases/tag/v0.1.0
