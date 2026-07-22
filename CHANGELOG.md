# Changelog

All notable changes to **aur-audit** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-07-22

### Added
- **NPM-01** rule (`:critical`) — catches `npm|bun|yarn|pnpm install|add|i exec` of `atomic-lockfile`, `js-digest`, `lockfile-js` (the actual payload of the 2026-06-12 AUR incident).
- **OBF-02** rule (`:high`) — catches `curl|wget … | base64 -d? | sh|bash` piped shell execution.
- **SVC-01** rule (`:critical`) — catches systemd `ExecStart` pointing at `/tmp/` or `/dev/shm/` (rootkit launcher pattern).
- **`host-state-checks` vector** — runtime checks for filesystem/service state separate from source-text rules:
  - `HOST-BPF-01` (`/sys/fs/bpf/hidden_*` IOC for the eBPF rootkit component of the incident).
  - `HOST-SVC-01` (systemd ExecStart targeting ephemeral filesystems).
- **`--json` output flag** — single-line JSON for CI/pipeline ingestion (no external `clojure.data.json` dependency; inline serializer).
- **`--no-host` flag** — skip host-state checks (e.g. when audit-runner has no read perms on `/sys/fs/bpf`).
- **`--no-color` flag** — disable ANSI colour output (auto-disabled when stdout is not a TTY).
- **`.SRCINFO` scanning** in `audit-directory`.
- **`test/aur_audit_test.clj`** — unit tests covering all 9 rules + JSON serializer; wired via `bb test`.
- **`.gitlab-ci.yml` `test` stage** ahead of self-audit.
- **`aur-monitor.clj` blacklist pre-filter** — fetches `lenucksi/aur-malware-check` community blacklist and rejects matching packages before cloning.
- **`aur-monitor.clj` `--json` flag** — emits a structured result summary.
- **`aur-monitor.clj` load-file bug fix** — `(load-file "aur-audit.clj")` → `(load-file "aur_audit.clj")`.

### Changed
- `--no-color` automatically enabled when stdout is not a TTY.

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

[Unreleased]: https://gitlab.com/nurazhar/aur-audit/-/compare/v1.1.0...main
[1.1.0]: https://gitlab.com/nurazhar/aur-audit/-/compare/v1.0.0...v1.1.0
[1.0.0]: https://gitlab.com/nurazhar/aur-audit/-/releases/v1.0.0
[0.x]: https://gitlab.com/nurazhar/aur-audit/-/releases/permalink?inline=true
