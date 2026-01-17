# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- Blocked IPs import as CrowdSec decisions (`blocked_ips` variable)
- CrowdSec Console enrollment support
- Custom scenario definitions
- Automatic fail2ban/ferm migration (disable legacy services)
- Legacy iptables cleanup option

[Unreleased]: https://github.com/AltanS/trellis-crowdsec/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/AltanS/trellis-crowdsec/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/AltanS/trellis-crowdsec/releases/tag/v0.1.0
