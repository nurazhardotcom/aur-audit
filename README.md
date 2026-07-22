# aur-audit

[![Latest Release](https://gitlab.com/nurazhar/aur-audit/-/badges/release.svg)](https://gitlab.com/nurazhar/aur-audit/-/releases)
[![CI](https://gitlab.com/nurazhar/aur-audit/badges/main/pipeline.svg)](https://gitlab.com/nurazhar/aur-audit/-/pipelines)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)

`aur-audit v1.1.1` · Last verified 2026-07-22 · MIT ©2026 Nur Azhar

A lightweight Clojure (Babashka) static analysis tool to inspect Arch User Repository (AUR) `PKGBUILD` and `.install` scripts for potential indicators of compromise (IoC) and backdoors, plus targeted host-state checks for filesystem- and systemd-resident artefacts.

Developed in response to the active AUR malicious package incident (June 2026).

---

## Detection Capabilities

### Static (source-text) rules
- **Outbound Connections (NET-01)** · *critical*: `curl`, `wget`, `nc`, `socket`, `/dev/tcp`, `/dev/udp` in install hooks.
- **Obfuscation (OBF-01)** · *high*: `base64 -d`, `openssl enc`, `xxd -r`, `eval`.
- **Direct Piped Execution (EXEC-01)** · *high*: process substitution into a shell.
- **Service Persistence (PERS-01)** · *high*: `/etc/systemd`, `/etc/cron`, `systemctl enable|start`.
- **Environment Hijacking (ENV-01)** · *high*: `.bashrc`, `.zshrc`, `.profile`.
- **Arbitrary Host Modification (WRITE-01)** · *medium*: redirects into `/etc`, `/usr`, `/var`, `/boot`, `/home`, `/opt`.

### June 2026 incident-specific rules
- **NPM-01** · *critical*: `npm|bun|yarn|pnpm install|add|i|exec … atomic-lockfile|js-digest|lockfile-js` — the literal payload of the 2026-06-12 campaign.
- **OBF-02** · *high*: `curl|wget … | base64 -d? | sh|bash` — remote payload piped to a shell.
- **SVC-01** · *critical*: `ExecStart=/tmp/…` or `ExecStart=/dev/shm/…` — ephemeral-filesystem `ExecStart` (rootkit launcher).

### Host-state checks (runtime)
- **HOST-BPF-01** · *critical*: any pinned BPF map matching `hidden_*` under `/sys/fs/bpf/` (the eBPF-rootkit IOC of the incident).
- **HOST-SVC-01** · *high*: any live systemd unit with `ExecStart=/tmp/` or `ExecStart=/dev/shm/`.

---

## Installation & Requirements

Requires [Babashka](https://babashka.org/) (a native Clojure scripting engine).

### Installation via AUR:
```bash
paru -S babashka-bin
```

### Install the tool:
```bash
# Clone the repository
git clone https://gitlab.com/nurazhar/aur-audit.git
cd aur-audit
chmod +x aur-audit.clj
```

---

## Usage

### 1. Audit a Local Directory
Audit an AUR package directory (e.g. from your AUR helper cache):
```bash
./aur-audit.clj ~/.cache/paru/clone/google-chrome
```

Audit a single file:
```bash
./aur-audit.clj /path/to/PKGBUILD
```

### Flags
| Flag | Effect |
|---|---|
| `--json` | Single-line JSON output (no colour, machine-friendly) |
| `--no-host` | Skip the BPF/systemd host-state checks (e.g. in CI without `/sys/fs/bpf` perms) |
| `--no-color` | Force-disable colour (auto-disabled when not a TTY) |

### 2. Threat Feed Monitor
Audit the most recently updated packages from the official AUR RSS feed, with a community blacklist pre-filter:
```bash
./aur-monitor.clj
./aur-monitor.clj --json     # structured output for piping
```
The monitor clones recent packages into `/tmp/` directories, runs the auditor rules, reports findings, and cleans up the sandbox workspaces. Packages listed in the community black-list (`lenucksi/aur-malware-check/data/campaigns/aur-infected/packages.txt`) are filtered out *before* cloning.

### 3. Test Suite
Run the unit-test suite covering all 9 rules (17 tests / 42 assertions):
```bash
bb aur_audit_test.clj
```

> **Why no `bb tasks`?** The babashka 1.12 `:tasks` block in `bb.edn` was dropped after CI failures from SCI static-analysis quirks on `:requires` and `aur-audit-test/-main` qualifier resolution. Direct file invocation works on every babashka version and never collides with the built-in `:test` task that scans `test/`.

---

## Integrating with AUR Helpers (`paru`)

You can set up `paru` to easily pass packages through the auditor before executing builds. 

Add an alias to your shell configuration (`~/.zshrc` or `~/.bashrc`):
```bash
# Audit before paru installs
alias paru-audit='paru -G && for dir in ~/.cache/paru/clone/*/; do /path/to/aur-audit.clj "$dir" || break; done'
```

---

## System Integrations

### 1. pacman PreTransaction Hook

When the `aur-audit-git` package is installed, a pacman hook is dropped at `/etc/pacman.d/hooks/aur-scan.hook`. It runs before every `pacman -S` / `-U` transaction and scans the configured AUR cache directories with the v1.1+ rule set.

```bash
# Default scan target is ~/.cache/paru/clone/ (common paru cache).
# Adjust or add paths for your AUR helper (yay, aura, etc.).
# Edit env via /etc/environment or a drop-in file.
```

Set the environment variable before the hook runs:
```bash
# /etc/environment
AUR_AUDIT_DIRS="/home/youruser/.cache/paru/clone/ /var/cache/pacman/pkg/"
```

To skip the hook for a single transaction:
```bash
sudo pacman ... --ignore-hook aur-scan
```

### 2. systemd Daily Blacklist Scanner

User systemd units are installed to `/usr/lib/systemd/user/`.

```bash
# Enable the daily timer
systemctl --user enable aur-audit.timer
systemctl --user start aur-audit.timer
systemctl --user list-timers aur-audit.timer
```

The oneshot service runs:
```
cd ~/tools/aur-malware-check && python3 -m aur_check --refresh --full
```

Adjust `WorkingDirectory=` in `systemd/aur-audit.service` to match where you cloned `lenucksi/aur-malware-check`. Webhook notifications are tracked in `TODO.md`.

