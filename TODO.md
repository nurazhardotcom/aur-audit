# aur-audit — follow-up work & roadmap

This file tracks follow-up ideas for the `aur-audit` project. Items that are small and safe are marked **Easy — ship now** and will be implemented as part of the current release cycle. Items marked **Medium** or **Hard** are kept as future work; feel free to open an issue or merge request if you want to pick one up.

## ✅ Easy — shipped in this release

- [x] **pacman PreTransaction hook template** — `hooks/aur-scan.hook` plus a small wrapper script so `pacman -U *.pkg.tar.zst` can route through `aur-audit` before install.
- [x] **systemd daily blacklist scanner** — `systemd/aur-audit.service` and `systemd/aur-audit.timer` to run the community blacklist refresh on a schedule and surface alerts.
- [x] **XML-based AUR RSS parsing** — replace the fragile regex `re-seq` parser in `aur-monitor.clj` with `clojure.data.xml` so malformed feeds don't silently break monitoring.

## 🔧 Medium — next release or good first issue

- [ ] **Replace the `paru-audit` shell alias with a real `paru` plugin** that hooks into `paru`'s pre-build phase (`paru -S --pre-build` or similar) instead of a `for` loop in shell rc. Requires understanding the exact `paru` plugin/extension point.
- [ ] **Pre-compile `aur-audit` with GraalVM `native-image`** so end users don't need to install Babashka. Needs a CI job that builds a JAR/uberjar and runs `native-image`, plus architecture matrix builds.

## 🏗️ Hard / needs design

- [ ] **Live `aur-audit.timer` webhook notifications** — extend the daily scanner to POST to Discord/Matrix/ntfy when a new campaign entry appears. Needs state-keeping (e.g. a small SQLite file or `~/.cache` timestamp) to avoid duplicate alerts and a config file for webhook URLs.

---

Last updated: 2026-07-22
