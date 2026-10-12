#!/usr/bin/env bash
# hider — kurulum script'i
# Desteklenen: Debian/Kali/Ubuntu, Arch, Fedora, macOS
set -euo pipefail

# Renkler
KIRMIZI='\033[91m'; YESIL='\033[92m'; SARI='\033[93m'; CYAN='\033[96m'; BITIR='\033[0m'

log()  { echo -e "${CYAN}[*]${BITIR} $*"; }
ok()   { echo -e "${YESIL}[✓]${BITIR} $*"; }
warn() { echo -e "${SARI}[!]${BITIR} $*"; }
die()  { echo -e "${KIRMIZI}[✗]${BITIR} $*" >&2; exit 1; }

# Root kontrolü (Windows/macOS Homebrew için esnetildi)
if [[ "${OSTYPE:-}" == linux* ]]; then
  [[ $EUID -ne 0 ]] && die "Bu script root olarak çalıştırılmalı."
fi

# OS tespiti
OS_FAMILY="unknown"
if [[ -f /etc/os-release ]]; then
  . /etc/os-release
  case "${ID:-}${ID_LIKE:-}" in
    *debian*|*ubuntu*) OS_FAMILY="debian" ;;
    *arch*)            OS_FAMILY="arch" ;;
    *fedora*|*rhel*)   OS_FAMILY="fedora" ;;
    *)                 OS_FAMILY="linux-other" ;;
  esac
elif [[ "${OSTYPE:-}" == darwin* ]]; then
  OS_FAMILY="macos"
fi

log "Tespit edilen OS ailesi: $OS_FAMILY"

# Python3 kontrolü
command -v python3 >/dev/null || die "python3 yüklü değil."
ok "python3: $(python3 --version)"

# requests kontrolü / kurulumu
if ! python3 -c "import requests" 2>/dev/null; then
  log "python3-requests kuruluyor..."
  case "$OS_FAMILY" in
    debian)        apt-get update -qq && apt-get install -y python3-requests ;;
    arch)          pacman -S --noconfirm --needed python-requests ;;
    fedora)        dnf install -y python3-requests ;;
    macos)         python3 -m pip install --user requests ;;
    *)             python3 -m pip install --user requests ;;
  esac
fi
ok "python3-requests hazır."

# -----------------------------------------------
# BACKEND KURULUMLARI
# -----------------------------------------------

# 1) Debian/Kali → anonsurf
if [[ "$OS_FAMILY" == "debian" ]]; then
  if ! command -v anonsurf >/dev/null; then
    warn "anonsurf yok. 'kali-anonsurf-deb-src' klasörü varsa derlenecek."

    if [[ -d "kali-anonsurf-deb-src" ]]; then
      log "anonsurf bağımlılıkları kuruluyor..."
      apt-get install -y tor secure-delete i2p || warn "Bazı paketler kurulamadı."

      log "kali-anonsurf.deb derleniyor..."
      dpkg-deb -b kali-anonsurf-deb-src kali-anonsurf.deb
      if ! dpkg -i kali-anonsurf.deb 2>/dev/null; then
        warn "Bağımlılık sorunu, düzeltiliyor..."
        apt-get -f install -y
        dpkg -i kali-anonsurf.deb
      fi
      ok "anonsurf kuruldu."
    else
      warn "anonsurf zaten yok ve kaynak klasörü de yok, atlanıyor."
    fi
  else
    ok "anonsurf zaten kurulu."
  fi
fi

# 2) Tüm Linux dağıtımları → Tor
if [[ "$OS_FAMILY" == debian || "$OS_FAMILY" == arch || \
      "$OS_FAMILY" == fedora || "$OS_FAMILY" == linux-other ]]; then
  if ! command -v tor >/dev/null; then
    log "tor kuruluyor..."
    case "$OS_FAMILY" in
      debian)        apt-get install -y tor ;;
      arch)          pacman -S --noconfirm --needed tor ;;
      fedora)        dnf install -y tor ;;
      linux-other)   warn "Bilinmeyen dağıtım, tor'u manuel kurun." ;;
    esac
  fi
  command -v tor >/dev/null && ok "tor hazır." || warn "tor kurulamadı."
fi

# 3) macOS → Homebrew tor
if [[ "$OS_FAMILY" == "macos" ]]; then
  if command -v brew >/dev/null; then
    if ! command -v tor >/dev/null; then
      log "brew üzerinden tor kuruluyor..."
      brew install tor
    fi
    command -v tor >/dev/null && ok "tor hazır." || warn "tor kurulamadı."
  else
    warn "Homebrew yok. Tor kurulumu atlandı."
  fi
fi

# -----------------------------------------------
# KURULUM SONU
# -----------------------------------------------
ok "Kurulum tamamlandı."
echo
echo "Örnek kullanım:"
echo "  python3 hider.py -t 30"
echo "  python3 hider.py -r --min-wait 20 --max-wait 90"
echo "  python3 hider.py -p /yol/proxy.txt -t 45"
