# Maintainer: Nur Azhar <96178154+nurazhar@gitlab.com>
pkgname=aur-audit-git
_pkgname=aur-audit
pkgver=1.1.1.r0.g0000000
pkgrel=1
pkgdesc="A static analysis security auditing tool designed to inspect AUR PKGBUILD and install scripts for indicators of compromise"
arch=('any')
url="https://gitlab.com/nurazhar/aur-audit"
license=('MIT')
depends=('babashka')
makedepends=('git')
provides=("${_pkgname}")
conflicts=("${_pkgname}")
source=("git+${url}.git")
sha256sums=('SKIP')

pkgver() {
  cd "${_pkgname}"
  git describe --long --tags --abbrev=7 | sed 's/\([^-]*-g\)/r\1/;s/-/./g'
}

package() {
  cd "${srcdir}/${_pkgname}"
  
  # Install executable scripts to /usr/bin/
  install -Dm755 aur-audit.clj "${pkgdir}/usr/bin/aur-audit"
  install -Dm755 aur-monitor.clj "${pkgdir}/usr/bin/aur-monitor"
  install -Dm755 bin/aur-audit-pacman-hook "${pkgdir}/usr/bin/aur-audit-pacman-hook"
  
  # Install pacman hook so every transaction routes through the auditor
  install -Dm644 hooks/aur-scan.hook "${pkgdir}/etc/pacman.d/hooks/aur-scan.hook"
  
  # Install systemd user units for the daily community blacklist scan
  install -Dm644 systemd/aur-audit.service "${pkgdir}/usr/lib/systemd/user/aur-audit.service"
  install -Dm644 systemd/aur-audit.timer "${pkgdir}/usr/lib/systemd/user/aur-audit.timer"
  
  # Install documentation
  install -Dm644 README.md "${pkgdir}/usr/share/doc/${_pkgname}/README.md"
  install -Dm644 TODO.md "${pkgdir}/usr/share/doc/${_pkgname}/TODO.md"
}
