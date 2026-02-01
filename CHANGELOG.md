# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/AltanS/trellis-crowdsec/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/AltanS/trellis-crowdsec/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/AltanS/trellis-crowdsec/compare/v0.4.0...v0.5.1
[0.4.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/AltanS/trellis-crowdsec/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AltanS/trellis-crowdsec/releases/tag/v0.1.0
