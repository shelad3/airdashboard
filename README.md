# AirDashboard

**Interactive cybersecurity audit TUI — 36 tools, zero terminal commands.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Textual](https://img.shields.io/badge/Textual-TUI-281F33?style=flat-square&logo=markdown&logoColor=white)](https://textual.textualize.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-black?style=flat-square&logo=linux&logoColor=white)]()
[![GitHub stars](https://img.shields.io/github/stars/shelad3/airdashboard?style=flat-square&logo=github)](https://github.com/shelad3/airdashboard/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/shelad3/airdashboard?style=flat-square&logo=github)](https://github.com/shelad3/airdashboard/network/members)
[![GitHub last commit](https://img.shields.io/github/last-commit/shelad3/airdashboard?style=flat-square&logo=github)](https://github.com/shelad3/airdashboard/commits)
[![GitHub issues](https://img.shields.io/github/issues/shelad3/airdashboard?style=flat-square&logo=github)](https://github.com/shelad3/airdashboard/issues)
[![GitHub pull requests](https://img.shields.io/github/issues-pr/shelad3/airdashboard?style=flat-square&logo=github)](https://github.com/shelad3/airdashboard/pulls)
[![Repo size](https://img.shields.io/github/repo-size/shelad3/airdashboard?style=flat-square&logo=github)](https://github.com/shelad3/airdashboard)
[![Code size](https://img.shields.io/github/languages/code-size/shelad3/airdashboard?style=flat-square&logo=github)](https://github.com/shelad3/airdashboard)
[![Tools](https://img.shields.io/badge/36-Tools-blueviolet?style=flat-square)](#integrated-tools-36)
[![Tabs](https://img.shields.io/badge/10-Tabs-22c55e?style=flat-square)](#tabs)
[![Categories](https://img.shields.io/badge/8-Categories-eab308?style=flat-square)](#integrated-tools-36)

A button-driven terminal dashboard that integrates **36 security tools** across **8 categories** into a unified interface. Every scan leads to the next action — no dead-ends, no manual commands.

![Dashboard](https://raw.githubusercontent.com/shelad3/airdashboard/master/docs/dashboard.png)

---

## Features

- **36 integrated tools** — nmap, masscan, aircrack-ng, nikto, sqlmap, hashcat, hydra, and more
- **10 interactive tabs** — each with a guided workflow
- **Zero terminal** — every action is button-driven with auto-filled fields
- **Scan diff** — compare scans, highlight new/gone hosts
- **Live signal sparkline** — real-time WiFi dBm trend
- **MAC vendor lookup** — 130+ OUI database entries
- **Recommendation engine** — auto-advises best tool for each task
- **Wordlist manager** — download rockyou, SecLists, generate with CeWL
- **SQLite history** — all scan results persisted and queryable
- **Root-aware** — warns when root is needed for monitor mode

---

## Quick Start

### Prerequisites

- Linux (tested on Ubuntu 24.04)
- Python 3.10+
- Root access (for WiFi/bluetooth features)

### Install

```bash
git clone https://github.com/shelad3/airdashboard.git
cd airdashboard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Install Security Tools

```bash
sudo bash tools/install_tools.sh
```

This installs nmap, aircrack-ng, nikto, hashcat, hydra, and 30+ other tools from apt, GitHub releases, and snap.

### Launch

```bash
sudo .venv/bin/python main.py
# or
sudo bash run.sh
```

---

## Tabs

| Tab | Purpose | Workflow |
|-----|---------|----------|
| **Dashboard** | System overview | Tool detection, recommendations, quick launch |
| **Scanner** | Network scanning | Ping sweep → select host → deep/vuln scan |
| **WiFi Audit** | Wireless attacks | Monitor → scan APs → capture handshake → crack |
| **Bluetooth** | BT enumeration | Scan → select → connect/enum |
| **Web Recon** | Web app testing | Nikto, Gobuster, WhatWeb, SQLMap, WPScan, FFUF |
| **Passwords** | Brute force & cracking | Hydra (online), John/Hashcat (offline), CeWL |
| **Wordlists** | Dictionary management | Download, browse, generate |
| **Benchmark** | Tool performance | Compare nmap vs masscan speed |
| **Live Log** | Real-time events | Scrolling scan output |
| **Docs** | Full documentation | In-app reference for everything |

---

## Integrated Tools (36)

<details>
<summary><b>Scanners (6)</b></summary>

| Tool | Description |
|------|-------------|
| nmap | Network discovery & security scanning |
| masscan | Blazing fast TCP port scanner (10M ports/sec) |
| rustscan | Fast port scanner written in Rust |
| netdiscover | ARP scanner for network discovery |
| arp-scan | ARP scan for local network enumeration |
| fping | Fast parallel ping scanner |

</details>

<details>
<summary><b>WiFi (7)</b></summary>

| Tool | Description |
|------|-------------|
| aircrack-ng | WEP/WPA key cracking suite |
| airodump-ng | WiFi packet capture & AP discovery |
| aireplay-ng | WiFi deauth/injection attacks |
| reaver | WPS PIN brute force attack tool |
| bully | WPS brute force (reaver alternative) |
| wifite | Automated WiFi attack tool |
| kismet | Wireless detector/sniffer/IDS |

</details>

<details>
<summary><b>Web (6)</b></summary>

| Tool | Description |
|------|-------------|
| nikto | Web server vulnerability scanner (6700+ tests) |
| gobuster | Directory/DNS/VHost brute force scanner |
| whatweb | Web technology fingerprinting |
| sqlmap | SQL injection detection & exploitation |
| wpscan | WordPress security scanner |
| ffuf | Fast web fuzzer for directory/parameter discovery |

</details>

<details>
<summary><b>Password Attacks (4)</b></summary>

| Tool | Description |
|------|-------------|
| hashcat | GPU-accelerated password cracking (300+ modes) |
| john | John the Ripper password cracker |
| hydra | Network login brute-forcer (SSH, FTP, HTTP...) |
| cewl | Custom wordlist generator from websites |

</details>

<details>
<summary><b>MITM / Network (4)</b></summary>

| Tool | Description |
|------|-------------|
| bettercap | MITM framework with WiFi/AP/ARP |
| responder | LLMNR/NBT-NS/MDNS poisoner |
| mitmproxy | Interactive HTTPS proxy |
| ettercap | ARP/DNS spoofing, MITM attacks |

</details>

<details>
<summary><b>Sniffing (3)</b></summary>

| Tool | Description |
|------|-------------|
| tshark | Wireshark CLI — packet capture & analysis |
| tcpdump | CLI packet capture tool |
| dsniff | Network auditing & password sniffing toolkit |

</details>

<details>
<summary><b>Enumeration (4)</b></summary>

| Tool | Description |
|------|-------------|
| enum4linux | Windows/Samba network enumeration |
| smbclient | SMB/CIFS client for listing/sharing files |
| dnsenum | DNS enumeration & subdomain brute force |
| theHarvester | Email, subdomain, IP, and URL harvester |

</details>

<details>
<summary><b>Post-Exploitation (2)</b></summary>

| Tool | Description |
|------|-------------|
| linpeas.sh | Linux Privilege Escalation Awesome Script |
| linuxprivchecker | Linux privilege escalation checker |

</details>

---

## Architecture

```
airdashboard/
├── main.py                  # App entry point (10 tabs, CSS, root check)
├── run.sh                   # Launch script
├── requirements.txt         # textual, requests
├── core/
│   ├── run.py               # Shared subprocess helpers
│   ├── scanner.py           # Network scanner, SQLite history, CSV parsing
│   ├── web.py               # Nikto, Gobuster, WhatWeb, SQLMap, WPScan, FFUF
│   ├── password.py          # Hydra, John, Hashcat, CeWL
│   ├── audit.py             # WiFi audit: monitor mode, capture, crack
│   ├── tools.py             # 36 tools, detection, benchmark, MAC lookup
│   └── wordlist.py          # Download manager, local wordlist browser
├── ui/
│   ├── __init__.py          # Exports all 10 tab widgets
│   ├── helpers.py           # WLAN detection, iwconfig, sysinfo, signals
│   ├── dashboard.py         # System info, tool detection, quick launch
│   ├── scanner.py           # Network scanner tab
│   ├── wifi.py              # WiFi audit tab
│   ├── bluetooth.py         # Bluetooth tab
│   ├── web_recon.py         # Web reconnaissance tab
│   ├── passwords.py         # Password attacks tab
│   ├── wordlist.py          # Wordlist download/manager tab
│   ├── benchmark.py         # Tool benchmarking tab
│   ├── live_log.py          # Real-time event log tab
│   └── docs.py              # In-app documentation
├── tools/
│   ├── install_tools.sh     # Full tool installer
│   └── tools.json           # Tool manifest with install commands
└── storage/
    ├── captures/            # WiFi handshake files
    ├── wordlists/           # Downloaded dictionaries
    └── reports/             # Audit reports
```

---

## Requirements

### Python Dependencies

```
textual>=0.40
requests>=2.28
```

### System Tools

The installer handles these automatically:

```bash
sudo bash tools/install_tools.sh
```

Or install manually: `nmap`, `aircrack-ng`, `nikto`, `hashcat`, `hydra`, `bettercap`, `wireshark`, `sqlmap`, and more.

---

## Usage Examples

### Network Scan

1. Open **Scanner** tab
2. Click **Ping Sweep** — discovers live hosts on your LAN
3. Click a host row — auto-fills the target field
4. Click **Deep Scan** — runs full port + service detection

### WiFi Audit

1. Open **WiFi Audit** tab
2. Click **Enable Monitor** — puts adapter in monitor mode
3. Click **Scan APs** — discovers nearby access points
4. Select an AP, enter channel, click **Capture Handshake**
5. Click **Analyze** — checks for captured handshakes
6. Click **Crack** — runs aircrack-ng against the handshake

### Web Recon

1. Open **Web Recon** tab
2. Enter target URL (e.g. `http://192.168.1.1`)
3. Click **Nikto** — scans for web vulnerabilities
4. Click **Gobuster** — brute-forces hidden directories
5. Click **WhatWeb** — identifies technologies/frameworks

### Password Attack

1. Open **Passwords** tab
2. Enter target IP, select service (SSH/FTP/HTTP)
3. Select a wordlist, click **Brute Force**
4. Results appear in the table with credentials

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Disclaimer

**This tool is for authorized security testing and educational purposes only.**

Unauthorized access to computer networks and systems is illegal. Always obtain explicit written permission before performing security testing on any system you do not own. The developers assume no liability for misuse of this software.
