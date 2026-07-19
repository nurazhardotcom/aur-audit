# Changelog

All notable changes to **aur-audit** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-07-16

### Added
- `VERSION` file as single source of truth for semver
- `CHANGELOG.md` documenting release history for hiring managers and recruiters
- Production-release badge in `README.md` linking to GitLab Releases page
- Production-release stamp line crediting Nur Azhar

## [0.x] - 2025-11 (pre-tagged snapshot)

### Origin
- Initial Babashka static-analysis scanner for Arch User Repository PKGBUILD/.install scripts
- Detection rules: NET-01, OBF-01, EXEC-01, PERS-01, ENV-01, WRITE-01
- `aur-monitor.clj` RSS-feed threat scanner
- Arch Linux packaging via `PKGBUILD` + `.SRCINFO`
- GitLab CI self-audit
- `.pre-commit-config.yaml` with detect-secrets

[Unreleased]: https://gitlab.com/nurazhar/aur-audit/-/compare/v1.0.0...main
[1.0.0]: https://gitlab.com/nurazhar/aur-audit/-/releases/v1.0.0
[0.x]: https://gitlab.com/nurazhar/aur-audit/-/releases/permalink?inline=true
