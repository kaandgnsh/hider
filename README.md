# Hider

<p align="center">
  <strong>A multi-backend IP-routing and proxy rotation utility for controlled privacy labs.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-444444?style=for-the-badge" alt="Supported platforms">
  <img src="https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-315C45?style=for-the-badge" alt="MIT license">
  <a href="https://github.com/kaandgnsh/hider/actions/workflows/tests.yml">
    <img src="https://github.com/kaandgnsh/hider/actions/workflows/tests.yml/badge.svg?branch=main" alt="GitHub Actions">
  </a>
</p>

---

## Overview

**Hider** can rotate an application's HTTP egress through a user-supplied proxy list or use an existing Tor or anonsurf setup. Its capabilities depend on the selected backend and the operating system.

> **Privacy and safety:** An IP address change is not a guarantee of anonymity or complete traffic protection. The proxy backend routes only Hider's own HTTP requests; it does not change routing for every application on the device. The anonsurf backend can affect system-wide traffic. Use only devices and networks you control or are authorized to administer.

> **System changes:** When Tor setup is needed, Hider may install operating-system packages, append local Tor settings to `torrc`, and restart Tor after asking for confirmation. It will not disable cookie authentication, use pip's `--break-system-packages` option, or explicitly enable the Tor service at boot. Existing conflicting Tor settings are left untouched and cause setup to stop.

## Features

- Detects common Linux distributions, macOS, and Windows.
- Offers Tor, anonsurf, and user-provided proxy backends.
- Supports fixed or randomized rotation intervals and a one-shot mode.
- Uses Tor SAFECOOKIE authentication when supported by the local control port.
- Masks proxy credentials from the startup log.
- Uses bounded HTTP request timeouts and reports backend errors.
- Keeps a log for troubleshooting; review it before sharing because it may contain IP and network metadata.

## Requirements

- Python 3.8 or newer
- Python dependencies from `requirements.txt`
- A compatible Tor utility/service for the Tor backend, or an installed anonsurf backend, or a local proxy list
- Administrator privileges only for system-level setup or anonsurf operations

Install Python dependencies in an isolated environment where practical:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Arch-based systems, refresh the system package database with the normal full upgrade workflow before installing packages. Hider uses `pacman -S` rather than a partial `pacman -Sy` package transaction.

## Quick Start

Clone the repository:

```bash
git clone https://github.com/kaandgnsh/hider.git
cd hider
```

### Use a local proxy list

Each non-comment line should contain one proxy URL, for example:

```text
http://127.0.0.1:8080
socks5://127.0.0.1:9050
```

Run the proxy backend without automatic sudo escalation:

```bash
python3 hider.py --no-sudo --backend proxy --proxy-file ./proxies.txt --time 60
```

The list should contain trusted proxies. Credentials embedded in proxy URLs are not written to the startup log, but protect the proxy file itself and do not share it.

### Use an already configured Tor service

```bash
sudo python3 hider.py --backend tor --time 60 --no-install
```

If you omit `--no-install` and the Tor setup is missing, Hider asks before installing packages or changing Tor configuration.

### One-shot check

```bash
python3 hider.py --no-sudo --backend proxy --proxy-file ./proxies.txt --once
```

## CLI Reference

| Option | Description |
|:--|:--|
| `-t, --time SECONDS` | Fixed rotation interval; minimum 5 seconds. |
| `-r, --random` | Random interval mode. |
| `--min-wait SECONDS` | Lower bound for random mode. |
| `--max-wait SECONDS` | Upper bound for random mode; maximum 3,600 seconds. |
| `-p, --proxy-file PATH` | Path to a local proxy list. |
| `-b, --backend NAME` | `auto`, `anonsurf`, `tor`, or `proxy`. |
| `--tor-password PASSWORD` | Password for a Tor control port configured for hashed-password authentication. Prefer cookie authentication; command-line values may be visible to local process inspection. |
| `--once` | Perform one rotation and exit. |
| `--no-stop` | Do not run backend cleanup on exit. |
| `--no-install` | Do not automatically install packages or configure Tor. |
| `--no-sudo` | Do not re-exec through sudo. Use with a backend that does not require root. |
| `-v, --verbose` | Enable debug logging. |

## Tor Authentication and Configuration

Hider uses Tor's control protocol and prefers **SAFECOOKIE** authentication when available. It reads the cookie path reported by Tor's `PROTOCOLINFO` response and verifies the server response before sending the client authentication hash.

The script will append `SocksPort 9050`, `ControlPort 9051`, and `CookieAuthentication 1` only when those options are missing. If cookie authentication is explicitly disabled, or an existing port conflicts with Hider's expected local ports, automatic configuration stops rather than overriding the setting. Review any proposed changes before accepting them.

Hider does not explicitly enable Tor at boot and leaves the Tor daemon running when Hider exits because other applications may share the service.

## Network and Data Notes

- Hider requests the current egress IP from `api.ipify.org`.
- It requests approximate location and ISP information from `ipinfo.io` using the observed IP address.
- A configured proxy provider can observe traffic routed through its proxy.
- The local log may include network addresses and diagnostic metadata.
- Proxy-list credentials should be treated as secrets and stored with restrictive permissions.

Tor and proxies do not protect traffic from application-level leaks, account identifiers, browser fingerprinting, malware, or incorrectly configured applications. Do not rely on Hider as a system-wide anonymity or kill-switch solution.

## Troubleshooting

**Tor control authentication fails:** check that the running Tor service exposes the expected local ports and that the process running Hider can read the cookie file. Do not solve this by setting `CookieAuthentication 0`.

**Tor setup is declined or fails:** install and configure Tor manually using your operating system's official packages, then run with `--no-install`.

**Proxy list is rejected:** confirm the file path, one-proxy-per-line format, and that the listed endpoints are reachable and trusted.

## Tests

Run the unit tests:

```bash
python -m unittest discover -s tests -v
```

GitHub Actions tests selected Tor control-authentication and configuration behavior on Python 3.10, 3.11, and 3.12. The tests do not install packages, modify system configuration, or contact Tor services.

## Project Structure

```text
hider/
├── .github/
│   └── workflows/
│       └── tests.yml
├── tests/
│   └── test_hider.py
├── hider.py
├── installer.sh
├── hider.service
├── requirements.txt
└── README.md
```

## Responsible Use

Use Hider only for privacy research, authorized network testing, and systems you control. Follow applicable laws and provider terms.

## Author

**Kaan DOĞAN** · [GitHub](https://github.com/kaandgnsh) · [LinkedIn](https://www.linkedin.com/in/kaan-do%C4%9Fan-911663280/) · [Instagram](https://instagram.com/kaandgn.sh)

<p align="center">
  <sub>Privacy tooling should fail safely and explain its system changes.</sub>
</p>
