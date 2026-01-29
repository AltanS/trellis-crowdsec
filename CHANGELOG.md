# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/AltanS/trellis-crowdsec/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/AltanS/trellis-crowdsec/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/AltanS/trellis-crowdsec/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AltanS/trellis-crowdsec/releases/tag/v0.1.0
