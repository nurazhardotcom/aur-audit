# aur-audit

A lightweight Clojure (Babashka) static analysis tool to inspect Arch User Repository (AUR) `PKGBUILD` and `.install` scripts for potential indicators of compromise (IoC) and backdoors.

Developed in response to the active AUR malicious package incident (June 2026).

---

## Detection Capabilities

The auditor evaluates package installation and compilation files against rules targeting:
- **Outbound Connections (NET-01)**: Dynamic downloads (`curl`, `wget`, `fetch`) or socket creation within install hooks.
- **Obfuscation (OBF-01)**: Base64 decoding (`base64 -d`), encryption utilities, or dynamic script evaluation.
- **Direct Piped Execution (EXEC-01)**: Piping remote data directly to a shell interpreter (`sh <(curl ...)`).
- **Service Persistence (PERS-01)**: Creating systemd unit files or cron entries outside packaging configurations.
- **Environment Hijacking (ENV-01)**: Profiling or writing to shell profiles (`.bashrc`, `.zshrc`, `/etc/profile`).
- **Arbitrary Host Modification (WRITE-01)**: Appending or modifying critical system directories outside package build namespaces.

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
git clone https://github.com/nurazhardotcom/aur-audit.git
cd aur-audit
chmod +x aur-audit.clj
```

---

## Usage

Audit an AUR package directory (e.g. from your AUR helper cache):
```bash
./aur-audit.clj ~/.cache/paru/clone/google-chrome
```

Audit a single file:
```bash
./aur-audit.clj /path/to/PKGBUILD
```

---

## Integrating with AUR Helpers (`paru`)

You can set up `paru` to easily pass packages through the auditor before executing builds. 

Add an alias to your shell configuration (`~/.zshrc` or `~/.bashrc`):
```bash
# Audit before paru installs
alias paru-audit='paru -G && for dir in ~/.cache/paru/clone/*/; do /path/to/aur-audit.clj "$dir" || break; done'
```
