#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# hider — Çok platformlu otomatik IP değiştirici.
# Backend'ler: anonsurf | tor | proxy
# Platformlar: Debian/Kali/Ubuntu, Arch/CachyOS/Manjaro, Fedora, openSUSE, macOS, Windows

AUTHOR = 'kaandgnsh'
GITHUB = 'https://github.com/kaandgnsh/hider'
INSTAGRAM = '@kaandgnsh'

import argparse
import hashlib
import hmac
import logging
import os
import platform
import random
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("[!] 'requests' yok: pip install requests")

try:
    import socks  # noqa
    _HAS_SOCKS = True
except ImportError:
    _HAS_SOCKS = False

C_GRI     = '\033[90m'
C_MOR     = '\033[95m'
C_CYAN    = '\033[96m'
C_YESIL   = '\033[92m'
C_SARI    = '\033[93m'
C_KIRMIZI = '\033[91m'
C_KALIN   = '\033[1m'
C_BITIR   = '\033[0m'

IP_API  = 'https://api.ipify.org/'
GEO_API = 'https://ipinfo.io/{ip}/json'
LOG_FILE = 'hider.log'
ALLOWED_MACS = []
MAX_RETRY = 5
TOR_CONTROL_PORT = 9051
TOR_SOCKS_PORT   = 9050

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger('hider')


def _read_osrelease():
    for path in ('/etc/os-release', '/usr/lib/os-release'):
        try:
            data = {}
            with open(path, encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or '=' not in line:
                        continue
                    k, v = line.split('=', 1)
                    data[k.strip()] = v.strip().strip('"\'')
            if data:
                return data
        except FileNotFoundError:
            continue
    return {}


def detect_os():
    system = platform.system().lower()
    info = {'system': system, 'family': 'unknown', 'distro': ''}

    if system == 'linux':
        osrel = _read_osrelease()
        distro = osrel.get('ID', '').lower()
        id_like = osrel.get('ID_LIKE', '').lower()
        name = osrel.get('NAME', '').lower()
        info['distro'] = distro or name or 'unknown'

        all_ids = {distro} | set(id_like.split()) | set(name.split())

        debian_ids = {
            'debian', 'ubuntu', 'kali', 'linuxmint', 'pop', 'raspbian',
            'parrot', 'devuan', 'zorin', 'elementary', 'mx', 'antix',
            'deepin', 'neon', 'trisquel', 'pureos',
        }
        arch_ids = {
            'arch', 'cachyos', 'manjaro', 'endeavouros', 'garuda', 'artix',
            'arco', 'archlabs', 'blackarch', 'archcraft', 'rebornos',
            'archman', 'anarchy', 'obscura', 'archbang', 'ctlos',
            'cachy', 'archlinux',
        }
        fedora_ids = {
            'fedora', 'rhel', 'centos', 'rocky', 'almalinux', 'ol',
            'nobara', 'bazzite', 'ultramarine', 'silverblue', 'kinoite',
        }
        suse_ids = {
            'opensuse', 'opensuse-leap', 'opensuse-tumbleweed', 'sles',
            'suse', 'opensuse-microos',
        }

        if all_ids & debian_ids:
            info['family'] = 'debian'
        elif all_ids & arch_ids:
            info['family'] = 'arch'
        elif all_ids & fedora_ids:
            info['family'] = 'fedora'
        elif all_ids & suse_ids:
            info['family'] = 'suse'
        else:
            info['family'] = 'linux-other'

    elif system == 'windows':
        info['family'] = 'windows'
        info['distro'] = 'windows-' + platform.release()

    elif system == 'darwin':
        info['family'] = 'macos'
        info['distro'] = 'macos-' + platform.mac_ver()[0]

    return info


def have(cmd):
    return shutil.which(cmd) is not None


def run(cmd, quiet=True, timeout=None):
    log.debug("Komut: %s", ' '.join(cmd))
    try:
        return subprocess.call(
            cmd,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
            timeout=timeout,
        )
    except FileNotFoundError:
        return 127
    except subprocess.TimeoutExpired:
        return 124


def get_ip(proxies=None, timeout=8.0):
    try:
        r = requests.get(IP_API, proxies=proxies, timeout=timeout)
        r.raise_for_status()
        return r.text.strip()
    except requests.RequestException as e:
        log.debug("IP alinamadi: %s", e)
        return None


def get_geo(ip, proxies=None):
    try:
        r = requests.get(GEO_API.format(ip=ip), proxies=proxies, timeout=6)
        r.raise_for_status()
        return r.json()
    except requests.RequestException:
        return {}


def fmt_geo(info):
    if not info:
        return '?'
    parts = [info.get('city'), info.get('country'), info.get('org')]
    return ', '.join(p for p in parts if p) or '?'


def _has_root_privileges():
    if os.name == 'nt':
        return True
    return hasattr(os, 'geteuid') and os.geteuid() == 0


def _privilege_label():
    if os.name == 'nt':
        return 'not applicable (Windows)'
    return 'root' if _has_root_privileges() else 'user'


def _re_exec_with_sudo():
    if _has_root_privileges():
        return
    if os.environ.get('HIDER_SUDO_REEXEC') == '1':
        print(C_KIRMIZI + "[!] Root yetkisi alinamadi." + C_BITIR)
        sys.exit(1)
    if not have('sudo'):
        print(C_KIRMIZI + "[!] Root yetkisi gerekiyor, 'sudo' da yok." + C_BITIR)
        print("    Ya root olarak calistir: sudo python3 hider.py ...")
        print("    Ya da --no-sudo ile calistir (sadece proxy backend calisir).")
        sys.exit(1)

    print(C_SARI + "[*] Root yetkisi gerekiyor, sudo ile yeniden baslatiliyor..." + C_BITIR)
    env = os.environ.copy()
    env['HIDER_SUDO_REEXEC'] = '1'
    try:
        os.execvpe('sudo', ['sudo', '-E', sys.executable] + sys.argv, env)
    except OSError as e:
        print(C_KIRMIZI + "[!] sudo baslatilamadi: " + str(e) + C_BITIR)
        sys.exit(1)


def _install_pysocks(osinfo):
    """Install PySocks only through the OS package manager; never bypass PEP 668."""
    global _HAS_SOCKS
    if _HAS_SOCKS:
        return True

    fam = osinfo['family']
    commands = {
        'debian': ['apt-get', 'install', '-y', 'python3-socks'],
        'arch': ['pacman', '-S', '--noconfirm', '--needed', 'python-pysocks'],
        'fedora': ['dnf', 'install', '-y', 'python3-pysocks'],
        'suse': ['zypper', '--non-interactive', 'install', 'python3-PySocks'],
    }
    command = commands.get(fam)
    if command is None:
        print(C_SARI + "[!] PySocks otomatik kurulumu bu sistemde desteklenmiyor." + C_BITIR)
        print("    Paket yoneticinizle veya izole bir sanal ortamda manuel kurun.")
        return False

    print(C_SARI + "[*] PySocks OS paket yoneticisiyle kuruluyor..." + C_BITIR)
    if run(command, quiet=False) != 0:
        print(C_KIRMIZI + "[!] PySocks kurulumu basarisiz." + C_BITIR)
        return False

    try:
        import socks  # noqa: F401
        _HAS_SOCKS = True
        print(C_YESIL + "[OK] PySocks kuruldu." + C_BITIR)
        return True
    except ImportError:
        print(C_KIRMIZI + "[!] PySocks kuruldu ancak bu Python ortamina yuklenemedi." + C_BITIR)
        print("    PySocks'i hider'i calistiran Python ortamina manuel kurun.")
        return False


class ProxyPool:
    def __init__(self, file_path):
        self.proxies = []
        self._load(file_path)
        if not self.proxies:
            raise ValueError("Proxy listesi bos veya gecersiz.")

    def _load(self, path):
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError("Proxy dosyasi yok: " + str(p))
        if not p.is_file():
            raise ValueError("Gecerli bir dosya degil: " + str(p))

        for line in p.read_text(encoding='utf-8', errors='ignore').splitlines():
            url = self._parse(line)
            if url:
                self.proxies.append(url)

        if not self.proxies:
            raise ValueError("Dosyada gecerli proxy yok: " + str(p))

        log.info("%d proxy yuklendi: %s", len(self.proxies), p)

    @staticmethod
    def _parse(line):
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        if '://' in line:
            return line
        parts = line.split(':')
        if len(parts) == 2:
            return 'http://' + parts[0] + ':' + parts[1]
        if len(parts) == 4:
            return 'http://' + parts[2] + ':' + parts[3] + '@' + parts[0] + ':' + parts[1]
        return None

    def random(self):
        return random.choice(self.proxies)

    def to_requests_dict(self, proxy_url):
        return {'http': proxy_url, 'https': proxy_url}

    def get_working(self, timeout=6.0, max_tries=12):
        tried = set()
        for _ in range(min(max_tries, len(self.proxies))):
            proxy = self.random()
            if proxy in tried:
                continue
            tried.add(proxy)
            ip = get_ip(self.to_requests_dict(proxy), timeout=timeout)
            if ip:
                return proxy, ip
        return None


class Backend:
    name = 'base'
    def available(self): return False
    def start(self): return False
    def rotate(self): return False
    def stop(self): pass
    def proxies(self): return None
    def describe(self): return self.name
    def last_ip(self): return None


class AnonsurfBackend(Backend):
    name = 'anonsurf'

    def available(self):
        return have('anonsurf')

    def start(self):
        return run(['anonsurf', 'start']) == 0

    def rotate(self):
        return run(['anonsurf', 'restart']) == 0

    def stop(self):
        run(['anonsurf', 'stop'])

    def describe(self):
        return 'anonsurf (Tor transparent proxy)'


class TorBackend(Backend):
    name = 'tor'
    CONTROL_HOST = '127.0.0.1'
    CONTROL_PORT = TOR_CONTROL_PORT
    SOCKS_PORT   = TOR_SOCKS_PORT

    def __init__(self, password=''):
        self.password = password

    def _socks_open(self):
        try:
            with socket.create_connection((self.CONTROL_HOST, self.SOCKS_PORT), timeout=2):
                return True
        except OSError:
            return False

    def _control_open(self):
        try:
            with socket.create_connection((self.CONTROL_HOST, self.CONTROL_PORT), timeout=2):
                return True
        except OSError:
            return False

    def available(self):
        return self._socks_open() and self._control_open()

    def start(self):
        return self.available()

    @staticmethod
    def _read_control_reply(sock, max_bytes=65536):
        """Read one complete Tor control-protocol reply."""
        buffer = bytearray()
        received = 0
        lines = []
        while received <= max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            received += len(chunk)
            buffer.extend(chunk)
            while True:
                boundary = buffer.find(b"\r\n")
                if boundary < 0:
                    break
                raw_line = bytes(buffer[:boundary])
                del buffer[:boundary + 2]
                lines.append(raw_line.decode("utf-8", errors="replace"))
                if (
                    len(raw_line) >= 4
                    and raw_line[:3].isdigit()
                    and raw_line[3:4] == b" "
                ):
                    return lines
        raise OSError("Incomplete or oversized Tor control-protocol reply.")

    def _auth(self, sock):
        """Authenticate with a configured password or Tor SAFECOOKIE."""
        try:
            sock.sendall(b"PROTOCOLINFO 1\r\n")
            protocol_lines = self._read_control_reply(sock)
            auth_line = next(
                (line for line in protocol_lines if "AUTH METHODS=" in line),
                "",
            )
            methods_match = re.search(r"METHODS=([A-Z,]+)", auth_line)
            if not methods_match:
                log.error("Tor did not advertise a supported authentication method.")
                return False

            methods = set(methods_match.group(1).split(","))

            if self.password and "HASHEDPASSWORD" in methods:
                if "\r" in self.password or "\n" in self.password:
                    log.error("Tor control password contains unsupported line breaks.")
                    return False
                escaped = self.password.replace("\\", "\\\\").replace('"', '\\"')
                sock.sendall(('AUTHENTICATE "' + escaped + '"\r\n').encode("utf-8"))
                return any(
                    line.startswith("250 OK")
                    for line in self._read_control_reply(sock)
                )

            cookie_match = re.search(r'COOKIEFILE="([^"]+)"', auth_line)
            if not cookie_match:
                log.error("Tor did not provide a cookie file for cookie authentication.")
                return False

            cookie = Path(cookie_match.group(1)).read_bytes()
            if len(cookie) != 32:
                log.error("Tor authentication cookie has an unexpected length.")
                return False

            if "SAFECOOKIE" in methods:
                client_nonce = secrets.token_bytes(32)
                sock.sendall(
                    b"AUTHCHALLENGE SAFECOOKIE "
                    + client_nonce.hex().encode("ascii")
                    + b"\r\n"
                )
                challenge_lines = self._read_control_reply(sock)
                challenge_line = next(
                    (line for line in challenge_lines if "AUTHCHALLENGE" in line),
                    "",
                )
                server_hash_match = re.search(
                    r"SERVERHASH=([0-9A-Fa-f]{64})", challenge_line
                )
                server_nonce_match = re.search(
                    r"SERVERNONCE=([0-9A-Fa-f]{64})", challenge_line
                )
                if not server_hash_match or not server_nonce_match:
                    log.error("Tor SAFECOOKIE challenge response was invalid.")
                    return False

                server_nonce = bytes.fromhex(server_nonce_match.group(1))
                server_key = b"Tor safe cookie authentication server-to-controller hash"
                client_key = b"Tor safe cookie authentication controller-to-server hash"
                message = cookie + client_nonce + server_nonce
                expected_server_hash = hmac.new(
                    server_key, message, hashlib.sha256
                ).digest()
                received_server_hash = bytes.fromhex(server_hash_match.group(1))
                if not hmac.compare_digest(expected_server_hash, received_server_hash):
                    log.error("Tor SAFECOOKIE server authentication failed.")
                    return False

                client_hash = hmac.new(
                    client_key, message, hashlib.sha256
                ).hexdigest()
                sock.sendall(
                    b"AUTHENTICATE "
                    + client_hash.encode("ascii")
                    + b"\r\n"
                )
                return any(
                    line.startswith("250 OK")
                    for line in self._read_control_reply(sock)
                )

            if "COOKIE" in methods:
                sock.sendall(
                    b"AUTHENTICATE "
                    + cookie.hex().encode("ascii")
                    + b"\r\n"
                )
                return any(
                    line.startswith("250 OK")
                    for line in self._read_control_reply(sock)
                )

            log.error("Tor advertises no supported safe authentication method.")
            return False
        except (OSError, ValueError) as e:
            log.error("Tor control authentication failed: %s", e)
            return False

    def _newnym(self):
        try:
            with socket.create_connection((self.CONTROL_HOST, self.CONTROL_PORT), timeout=5) as s:
                if not self._auth(s):
                    log.error("Tor kimlik dogrulama hatasi.")
                    return False
                s.sendall(b'SIGNAL NEWNYM\r\n')
                return s.recv(1024).startswith(b'250')
        except OSError as e:
            log.error("Tor kontrol portu hatasi: %s", e)
            return False

    def rotate(self):
        return self._newnym()

    def stop(self):
        # Tor may be shared with other applications; do not stop the system daemon.
        log.info("Leaving the Tor service running for other applications.")

    def proxies(self):
        return {
            'http':  'socks5h://' + self.CONTROL_HOST + ':' + str(self.SOCKS_PORT),
            'https': 'socks5h://' + self.CONTROL_HOST + ':' + str(self.SOCKS_PORT),
        }

    def describe(self):
        return 'Tor SOCKS5 (127.0.0.1:9050 -> ControlPort 9051)'

    def wait_bootstrap(self, max_seconds=60):
        if not _HAS_SOCKS:
            return False
        print(C_GRI + "[*] Tor devresi bekleniyor (max " + str(max_seconds) + "s)..." + C_BITIR)
        p = self.proxies()
        for i in range(max_seconds):
            ip = get_ip(p, timeout=5.0)
            if ip:
                print(C_YESIL + "[OK] Tor devresi kuruldu (IP: " + ip + ")" + C_BITIR)
                return True
            if i > 0 and i % 5 == 0:
                print(C_GRI + "    ..." + str(i) + "s (bootstrap devam ediyor)" + C_BITIR)
            time.sleep(1)
        return False


def safe_proxy_label(proxy_url):
    """Return a proxy endpoint without credentials or query parameters."""
    from urllib.parse import urlsplit

    candidate = proxy_url if '://' in proxy_url else 'http://' + proxy_url
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname or 'unknown'
        if ':' in host and not host.startswith('['):
            host = '[' + host + ']'
        port = ':' + str(parsed.port) if parsed.port is not None else ''
        return parsed.scheme + '://' + host + port
    except ValueError:
        return '[invalid proxy]'


class ProxyBackend(Backend):
    name = 'proxy'

    def __init__(self, pool):
        self.pool = pool
        self.current_proxy = None
        self._last_ip = None

    def available(self):
        return len(self.pool.proxies) > 0

    def start(self):
        result = self.pool.get_working()
        if not result:
            log.error("Hicbir proxy calismiyor.")
            return False
        self.current_proxy, self._last_ip = result
        log.info("Baslangic proxy: %s -> %s", safe_proxy_label(self.current_proxy), self._last_ip)
        return True

    def rotate(self):
        old = self.current_proxy
        for _ in range(15):
            result = self.pool.get_working()
            if result and result[0] != old:
                self.current_proxy, self._last_ip = result
                return True
        return False

    def stop(self):
        self.current_proxy = None

    def proxies(self):
        if not self.current_proxy:
            return None
        return self.pool.to_requests_dict(self.current_proxy)

    def last_ip(self):
        return self._last_ip

    def describe(self):
        return 'Proxy listesi (' + str(len(self.pool.proxies)) + ' adet)'


def _install_tor_pkg(osinfo):
    fam = osinfo['family']
    print(C_SARI + "[*] Tor paketi kuruluyor..." + C_BITIR)

    if fam == 'debian':
        run(['apt-get', 'update', '-qq'])
        rc = run(['apt-get', 'install', '-y', 'tor'], quiet=False)

    elif fam == 'arch':
        rc = run(['pacman', '-S', '--noconfirm', '--needed', 'tor'], quiet=False)
        if rc != 0 and not have('tor'):
            for helper in ('yay', 'paru'):
                if have(helper):
                    print(C_SARI + "[*] pacman basarisiz, " + helper + " ile deneniyor..." + C_BITIR)
                    rc = run([helper, '-S', '--noconfirm', '--needed', 'tor'], quiet=False)
                    if rc == 0:
                        break

    elif fam == 'fedora':
        rc = run(['dnf', 'install', '-y', 'tor'], quiet=False)

    elif fam == 'suse':
        rc = run(['zypper', '--non-interactive', 'install', 'tor'], quiet=False)

    elif fam == 'macos':
        if not have('brew'):
            print(C_KIRMIZI + "[!] Homebrew yok." + C_BITIR)
            return False
        rc = run(['brew', 'install', 'tor'], quiet=False)

    else:
        print(C_KIRMIZI + "[!] Bilinmeyen dagitim: " + fam + C_BITIR)
        return False

    return have('tor')


def _find_torrc():
    candidates = [
        '/etc/tor/torrc',
        '/usr/local/etc/tor/torrc',
        '/opt/homebrew/etc/tor/torrc',
        '/etc/torrc',
        '/usr/local/etc/torrc',
    ]
    for c in candidates:
        p = Path(c)
        if p.exists():
            return p
    return Path('/etc/tor/torrc')


def _configure_torrc():
    """Ensure local Tor ports use cookie authentication without weakening existing config."""
    torrc = _find_torrc()

    try:
        torrc.parent.mkdir(parents=True, exist_ok=True)
        if not torrc.exists():
            torrc.touch()
            print(C_SARI + "[*] torrc olusturuldu: " + str(torrc) + C_BITIR)
    except Exception as e:
        log.error("torrc olusturulamadi: %s", e)
        return False

    try:
        content = torrc.read_text(encoding='utf-8', errors='ignore')
    except Exception as e:
        log.error("torrc okunamadi: %s", e)
        return False

    active = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            active[parts[0].lower()] = parts[1].strip()
        elif parts:
            active[parts[0].lower()] = ""

    cookie_auth = active.get('cookieauthentication')
    cookie_values = cookie_auth.split() if cookie_auth is not None else []
    if cookie_auth is not None and (
        not cookie_values or cookie_values[0].strip('"').lower() not in {'1', 'true'}
    ):
        log.error(
            "CookieAuthentication is disabled in %s. Refusing to weaken Tor control-port security; "
            "set CookieAuthentication 1 manually and retry.",
            torrc,
        )
        return False

    expected_ports = {'socksport': '9050', 'controlport': '9051'}
    for directive, expected_port in expected_ports.items():
        configured = active.get(directive)
        if configured is None:
            continue
        if not re.search(r'(?:^|:)'+expected_port+r'(?:\s|$)', configured):
            log.error(
                "%s is already configured as %r in %s. Expected port %s; refusing to override it.",
                directive, configured, torrc, expected_port,
            )
            return False

    missing = []
    if 'socksport' not in active:
        missing.append('SocksPort ' + str(TOR_SOCKS_PORT))
    if 'controlport' not in active:
        missing.append('ControlPort ' + str(TOR_CONTROL_PORT))
    if cookie_auth is None:
        missing.append('CookieAuthentication 1')

    if not missing:
        log.info("Tor ports and cookie authentication are already configured.")
        return True

    if not os.access(str(torrc), os.W_OK):
        print(C_KIRMIZI + "[!] " + str(torrc) + " yazilamiyor (yetki gerekli)." + C_BITIR)
        return False

    try:
        with torrc.open('a', encoding='utf-8') as file:
            file.write('\n# --- hider local control settings ---\n')
            for directive in missing:
                file.write(directive + '\n')
        print(C_YESIL + "[OK] Tor local-port settings added with cookie authentication." + C_BITIR)
        return True
    except Exception as e:
        log.error("torrc yazilamadi: %s", e)
        return False


def _restart_tor():
    """Restart Tor to apply config without explicitly enabling a new boot-time service."""
    if have('systemctl'):
        rc = run(['systemctl', 'restart', 'tor'], quiet=False, timeout=45)
        if rc != 0:
            run(['systemctl', 'restart', 'tor@default'], quiet=False, timeout=45)
    elif have('rc-service'):
        run(['rc-service', 'tor', 'restart'], quiet=False, timeout=45)
    elif have('brew'):
        run(['brew', 'services', 'restart', 'tor'], quiet=False, timeout=45)
    elif have('service'):
        run(['service', 'tor', 'restart'], quiet=False, timeout=45)


def _wait_for_tor_ports(backend, max_seconds=40):
    print(C_GRI + "[*] Tor portlari bekleniyor (max " + str(max_seconds) + "s)..." + C_BITIR)
    for i in range(max_seconds):
        if backend.available():
            return True
        if i > 0 and i % 5 == 0:
            socks = backend._socks_open()
            ctrl = backend._control_open()
            print(C_GRI + "    ..." + str(i) + "s  SOCKS:" +
                  ('OK' if socks else 'X') + "  ControlPort:" +
                  ('OK' if ctrl else 'X') + C_BITIR)
        time.sleep(1)
    return False


def ensure_tor_ready(osinfo, allow_system_changes=False):
    backend = TorBackend()

    if not _HAS_SOCKS:
        if not allow_system_changes or not _install_pysocks(osinfo):
            return False

    if backend.available():
        return backend.wait_bootstrap(max_seconds=20)

    if not have('tor'):
        if not allow_system_changes:
            return False
        if not _install_tor_pkg(osinfo):
            print(C_KIRMIZI + "[!] Tor kurulamadi." + C_BITIR)
            return False
        print(C_YESIL + "[OK] Tor kuruldu." + C_BITIR)

    if not _configure_torrc():
        return False

    print(C_SARI + "[*] Tor servisi baslatiliyor..." + C_BITIR)
    _restart_tor()

    if not _wait_for_tor_ports(backend):
        print(C_KIRMIZI + "[!] Tor portlari acilmadi." + C_BITIR)
        print("    Kontrol: sudo systemctl status tor")
        print("    Log   : sudo journalctl -u tor -n 50")
        return False

    print(C_YESIL + "[OK] Tor portlari acik." + C_BITIR)

    if backend.wait_bootstrap(max_seconds=60):
        return True

    print(C_KIRMIZI + "[!] Tor devresi kurulamadi (bootstrap tamamlanmadi)." + C_BITIR)
    print("    Kontrol: sudo journalctl -u tor -n 30 | grep -i boot")
    return False


def get_mac():
    mac_int = uuid.getnode()
    mac = ':'.join('{:02x}'.format((mac_int >> ele) & 0xff)
                   for ele in range(0, 8 * 6, 8))
    if (mac_int >> 40) & 0x1:
        log.warning("MAC adresi rastgele uretilmis olabilir: %s", mac)
    return mac


def check_mac():
    mac = get_mac()
    if ALLOWED_MACS and mac not in ALLOWED_MACS:
        sys.exit(C_KIRMIZI + "[!] Yetkisiz MAC adresi: " + mac + C_BITIR)
    log.info("MAC adresi: %s", mac)
    return mac


_backend = None
_no_stop = False
_cleaned = False


def cleanup(*_):
    global _cleaned
    if _cleaned:
        return
    _cleaned = True
    print("\n" + C_SARI + "[*] hider kapatiliyor..." + C_BITIR)
    if _backend and not _no_stop:
        try:
            _backend.stop()
        except Exception as e:
            log.error("Temizlik hatasi: %s", e)
    sys.exit(0)


def parse_args():
    p = argparse.ArgumentParser(
        prog='hider',
        description='hider - Otomatik IP degistirici (anonsurf / tor / proxy)',
    )
    g = p.add_mutually_exclusive_group()
    g.add_argument('-t', '--time', type=int,
                   help='Sabit saniye araligi (orn: 30)')
    g.add_argument('-r', '--random', action='store_true',
                   help='Rastgele aralik (--min-wait / --max-wait)')
    p.add_argument('--min-wait', type=int, default=15,
                   help='Rastgele modda minimum saniye')
    p.add_argument('--max-wait', type=int, default=60,
                   help='Rastgele modda maksimum saniye')
    p.add_argument('-p', '--proxy-file', type=str,
                   help='Proxy listesi dosyasi')
    p.add_argument('-b', '--backend',
                   choices=['auto', 'anonsurf', 'tor', 'proxy'],
                   default='auto', help='Kullanilacak backend')
    p.add_argument('--tor-password', type=str, default='',
                   help='Tor kontrol portu sifresi')
    p.add_argument('--once', action='store_true',
                   help='Tek IP degisimi yap ve cik')
    p.add_argument('--no-stop', action='store_true',
                   help='Cikista backend durdurulmasin')
    p.add_argument('--no-install', action='store_true',
                   help='Backend yoksa otomatik kurma')
    p.add_argument('--no-sudo', action='store_true',
                   help='Root degilse sudo ile yeniden baslatma')
    p.add_argument('-v', '--verbose', action='store_true', help='Debug log')
    return p.parse_args()


def _print_manual_hint(osinfo):
    fam = osinfo['family']
    hint = {
        'debian': 'sudo apt install tor python3-socks',
        'arch':   'sudo pacman -S tor python-pysocks',
        'fedora': 'sudo dnf install tor python3-pysocks',
        'suse':   'sudo zypper install tor python3-PySocks',
        'macos':  'brew install tor && pip3 install PySocks',
        'windows': 'https://www.torproject.org/download/tor/',
    }.get(fam, 'Tor paketini manuel kurun.')
    print("    Manuel kur: " + hint)
    print("    Veya proxy listesi ver: python3 hider.py -p /yol/lista.txt")


def _confirm_system_changes(reason):
    print(C_SARI + "[!] System-level changes requested: " + reason + C_BITIR)
    try:
        answer = input("Proceed with these changes? [y/N] ")
    except EOFError:
        return False
    return answer.strip().lower() in {"y", "yes"}


def pick_backend(args, osinfo):
    if args.backend == 'proxy' or args.proxy_file:
        if not args.proxy_file:
            sys.exit(C_KIRMIZI + "[!] --proxy-file ile dosya yolu belirtin." + C_BITIR)
        try:
            return ProxyBackend(ProxyPool(args.proxy_file))
        except (FileNotFoundError, ValueError) as e:
            sys.exit(C_KIRMIZI + "[!] " + str(e) + C_BITIR)

    if args.backend == 'anonsurf':
        b = AnonsurfBackend()
        if not b.available():
            sys.exit(C_KIRMIZI + "[!] anonsurf bulunamadi." + C_BITIR)
        return b

    if args.backend == 'tor':
        b = TorBackend(password=args.tor_password)
        if b.available() and _HAS_SOCKS and b.wait_bootstrap(max_seconds=20):
            return b
        if args.no_install or not _confirm_system_changes(
            "Tor/PySocks may be installed, local torrc settings may be appended, and the Tor service may be restarted."
        ):
            _print_manual_hint(osinfo)
            sys.exit(1)
        if not ensure_tor_ready(osinfo, allow_system_changes=True):
            _print_manual_hint(osinfo)
            sys.exit(1)
        b = TorBackend(password=args.tor_password)
        if not b.available():
            print(C_KIRMIZI + "[!] Tor portlari hala kapali." + C_BITIR)
            _print_manual_hint(osinfo)
            sys.exit(1)
        return b

    if osinfo['family'] == 'debian':
        b = AnonsurfBackend()
        if b.available():
            log.info("anonsurf bulundu, onunla devam ediliyor.")
            return b

    b = TorBackend(password=args.tor_password)
    if b.available() and _HAS_SOCKS and b.wait_bootstrap(max_seconds=20):
        log.info("Tor hazir, onunla devam ediliyor.")
        return b

    if not args.no_install and _confirm_system_changes(
        "No ready backend was detected. Tor/PySocks may be installed, torrc may be changed, and Tor may be restarted."
    ):
        if ensure_tor_ready(osinfo, allow_system_changes=True):
            b = TorBackend(password=args.tor_password)
            if b.available():
                return b

    print(C_KIRMIZI + "[!] Uygun backend yok." + C_BITIR)
    print("    OS: " + osinfo['family'] + "/" + osinfo['distro'])
    _print_manual_hint(osinfo)
    sys.exit(1)


def banner(osinfo, backend):
    root_durum = _privilege_label()
    socks_durum = 'var' if _HAS_SOCKS else 'YOK'
    print(C_KALIN + C_CYAN + """
  _     _     _
 | |__ (_) __| | ___ _ __
 | '_ \\| |/ _` |/ _ \\ '__|
 | | | | | (_| |  __/ |
 |_| |_|_|\\__,_|\\___|_|
""" + C_BITIR + C_YESIL + """
Author:    """ + AUTHOR + """
GitHub:    """ + GITHUB + """
Instagram: """ + INSTAGRAM + """
""" + C_BITIR + C_GRI + """
OS      : """ + osinfo['family'] + " / " + (osinfo['distro'] or '?') + """
Backend : """ + backend.describe() + """
Yetki   : """ + root_durum + """
PySocks : """ + socks_durum + C_BITIR)


def clear_screen(osinfo):
    if osinfo['system'] == 'windows':
        os.system('cls')
    else:
        os.system('clear')


def main():
    global _backend, _no_stop

    args = parse_args()

    if not args.no_sudo and not _has_root_privileges():
        _re_exec_with_sudo()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    osinfo = detect_os()
    log.info("OS: %s / %s", osinfo['family'], osinfo['distro'])

    if args.random:
        if args.min_wait >= args.max_wait:
            sys.exit(C_KIRMIZI + "[!] --min-wait < --max-wait olmali." + C_BITIR)
        if args.max_wait > 3600:
            sys.exit(C_KIRMIZI + "[!] --max-wait <= 3600 olmali." + C_BITIR)
    else:
        if args.time is None:
            args.time = 30
        if args.time < 5:
            sys.exit(C_KIRMIZI + "[!] --time >= 5 saniye olmali." + C_BITIR)

    _backend = pick_backend(args, osinfo)
    _no_stop = args.no_stop

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    clear_screen(osinfo)
    banner(osinfo, _backend)

    print("\n" + C_KIRMIZI + "!! ONEMLI !!" + C_BITIR + " hider calisirken terminali kapatmayin.")
    if args.random:
        print(C_SARI + "Mod: Rastgele " + str(args.min_wait) + "-" + str(args.max_wait) + "s" + C_BITIR)
    else:
        print(C_SARI + "Mod: Sabit " + str(args.time) + "s" + C_BITIR)
    print()

    main_ip = get_ip()
    if not main_ip:
        sys.exit(C_KIRMIZI + "[!] Baslangic IP alinamadi." + C_BITIR)
    print(C_CYAN + "Mevcut IP:" + C_BITIR + " " + main_ip + "  (" + fmt_geo(get_geo(main_ip)) + ")")

    if not _backend.start():
        sys.exit(C_KIRMIZI + "[!] Backend baslatilamadi." + C_BITIR)

    time.sleep(3)
    cur_proxies = _backend.proxies()
    new_ip = get_ip(cur_proxies) or _backend.last_ip()
    if new_ip:
        print(C_YESIL + "Yeni IP  :" + C_BITIR + " " + new_ip + "  (" + fmt_geo(get_geo(new_ip, cur_proxies)) + ")")
    else:
        print(C_SARI + "[!] Yeni IP alinamadi, Tor devresi kuruluyor olabilir." + C_BITIR)

    if args.once:
        print(C_SARI + "[*] --once modu, cikiliyor." + C_BITIR)
        return 0

    print()
    while True:
        try:
            if args.random:
                wait = random.uniform(args.min_wait, args.max_wait)
            else:
                wait = args.time
            print(C_GRI + "[~] Sonraki degisim: " + ("%.1f" % wait) + "s sonra..." + C_BITIR)
            time.sleep(wait)

            clear_screen(osinfo)
            banner(osinfo, _backend)
            print()

            cur_proxies = _backend.proxies()
            old_ip = get_ip(cur_proxies)
            if old_ip:
                log.info("Eski IP: %s", old_ip)
            else:
                log.warning("Eski IP alinamadi, yine de rotate deneniyor.")

            success = False
            for attempt in range(1, MAX_RETRY + 1):
                if not _backend.rotate():
                    log.warning("Rotate basarisiz (%d/%d)", attempt, MAX_RETRY)
                    time.sleep(2)
                    continue
                time.sleep(3)
                cur_proxies = _backend.proxies()
                new_ip = get_ip(cur_proxies) or _backend.last_ip()
                if new_ip and new_ip != old_ip:
                    success = True
                    break
                log.warning("IP ayni (%s), tekrar deneniyor (%d/%d)...",
                            new_ip, attempt, MAX_RETRY)

            if success:
                print(C_YESIL + "[OK] IP degisti" + C_BITIR)
                print("  Eski: " + str(old_ip))
                print("  Yeni: " + C_YESIL + str(new_ip) + C_BITIR +
                      "  (" + fmt_geo(get_geo(new_ip, cur_proxies)) + ")")
                log.info("IP: %s -> %s", old_ip, new_ip)
            else:
                print(C_KIRMIZI + "[X] IP degistirilemedi (" + str(MAX_RETRY) + " deneme)" + C_BITIR)
                log.error("IP degismedi. Son IP: %s", old_ip)

        except KeyboardInterrupt:
            cleanup()
        except Exception as e:
            log.exception("Hata: %s", e)
            time.sleep(3)

    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        log.exception("Kritik hata: %s", e)
        sys.exit(1)
