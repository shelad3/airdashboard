"""Documentation tab — comprehensive reference for every tool, feature, and workflow."""

from textual.app import ComposeResult
from textual.containers import ScrollableContainer, Horizontal
from textual.widgets import Static, Button, Markdown


DOC_TEXT = """# AirDashboard — Complete Documentation

## Overview
AirDashboard is a **Textual-based TUI cybersecurity audit dashboard** that integrates
36 security tools across 8 categories into a unified, button-driven interface. Every
action leads to the next step — no dead-ends, no terminal commands required.

**Must run as root** for monitor mode, packet capture, and airodump operations.

---

## Getting Started

### Launch
```bash
cd ~/Documents/projects/python/airdashboard
sudo .venv/bin/python main.py
# or
sudo bash run.sh
```

### Install Missing Tools
```bash
sudo bash tools/install_tools.sh
```
This installs all security tools from apt, GitHub releases, and downloads wordlists.

### First-Time Setup
1. Open the **Dashboard** tab — check which tools are installed (green ✓) or missing (red ✗)
2. Note the **Quick Launch** buttons at the bottom of Dashboard
3. Your wireless interface is auto-detected via `iw dev` (falls back to `wlp2s0`)

---

## Tab Reference (10 Tabs)

### 1. Dashboard
- **System info**: kernel version, CPU load, memory usage, detected wireless interface
- **WiFi Status**: current SSID, signal strength (dBm + bar), link quality, BSSID
- **Tool Detection**: scans PATH for all 36 tools, shows version + availability
- **Recommendations**: auto-advises best tool for port scan, WiFi survey, password crack,
  web scan, online brute force — based on what's actually installed
- **Quick Launch**: one-click buttons to jump to Scanner, WiFi Audit, Web Recon,
  Password Attacks, or Bluetooth tabs

### 2. Scanner (Network Scanning)
**Workflow: Scan → Select Host → Deep Scan / Vuln Scan**

Scan types:
- **Ping Sweep** (`nmap -sn 192.168.1.0/24`) — discover live hosts
- **TCP Top Ports** (`nmap -T4 -F`) — fast scan common ports
- **Stealth Scan** (`nmap -sS -T4 -F`) — SYN stealth scan
- **Masscan** (`masscan 192.168.1.0/24 -p80,443,22... --rate=1000`) — blazing fast

After scan:
- Results appear in a table (Address, Hostname, Detail)
- Click any host row → auto-fills target input below
- **Deep Scan** (`nmap -sV -sC -T4 -p-`) — all 65535 ports + service/version detection
- **Vuln Scan** (`nmap --script vuln -T4`) — NSE vulnerability scripts
- **History**: shows last 20 scans from SQLite database
- **Scan diff**: compares with previous scan, highlights new/gone hosts (green+/red-)
- **Stop** button terminates running scan immediately

All scan results saved to `~/.airdashboard/history.db` (SQLite).

### 3. WiFi Audit
**Workflow: Monitor → Scan APs → Select Target → Capture → Analyze → Crack**

Step-by-step:
1. **Enable Monitor** — runs `sudo airmon-ng start <iface>` to put card in monitor mode
2. **Scan APs** — runs `airodump-ng` for 8 seconds, parses CSV for AP list
3. **Select AP** — click a row to auto-fill BSSID, channel, ESSID fields
4. **Capture Handshake** — airodump-ng targets specific AP, sends deauth packets via
   `aireplay-ng --deauth 5`, listens for WPA handshake
5. **Analyze** — uses `aircrack-ng -s` to check for handshakes, count packets/APs
6. **Crack** — runs `aircrack-ng -w <wordlist>` against captured handshake
7. **WPS Attack** — runs `reaver -i <mon_iface> -b <bssid> -vv` for WPS PIN brute force

- **Full Auto Audit**: nmap scan → airodump AP discovery → bettercap network probe
- **Signal sparkline**: live dBm trend with sparkline bar chart
- **Monitor status**: auto-refreshes every 3s, shows monitor interface name
- **Capture files**: lists all .cap/.pcap files with sizes, select for analyze/crack

Capture files stored in `storage/captures/`.

### 4. Bluetooth
**Workflow: Scan → Select Device → Connect / Enumerate / Attack**

- Powered by `bluetoothctl` from the BlueZ stack
- Device discovery, pairing, service enumeration
- Target input auto-fills from selected row
- Actions: connect, info, pair, enumerate services
- Requires Bluetooth adapter (USB dongle recommended)

### 5. Web Reconnaissance
**Workflow: Enter Target URL → Scan → Findings → Deep Scan**

Tools available:
- **Nikto** — web server vulnerability scanner (6700+ tests)
  Tests for: dangerous files, misconfigurations, outdated software,CGI issues
- **Gobuster Dir** — directory brute force (PHP, HTML, JS, TXT extensions)
  Default wordlist: `/usr/share/wordlists/dirb/common.txt`
- **Gobuster DNS** — subdomain brute force against domain
- **WhatWeb** — technology fingerprinting (CMS, frameworks, libraries, server)
  Parses JSON output to extract plugin names + versions
- **FFUF** — high-speed web fuzzer with custom wordlist/extension support
- **WPScan** — WordPress-specific: plugins, themes, users, CVEs
  Enumerates `ap,at,u` (all plugins, all themes, users)
- **SQLMap** — automatic SQL injection detection + exploitation
  Runs in batch mode, level 1 risk 1, outputs to `/tmp/sqlmap_out`

Select a finding → URL auto-fills → re-scan with deeper tools.

### 6. Password Attacks
**Workflow: Online Brute → Offline Crack → Wordlist Gen**

#### Hydra (Online Brute Force)
- 10 supported services: SSH, FTP, Telnet, HTTP Basic Auth, HTTP POST Form,
  MySQL, PostgreSQL, RDP, SMB, SNMP
- Enter target IP, select service, enter username or user list
- Select wordlist from local list or enter path
- Uses `-f` (stop on first found) and `-vV` (verbose)
- Parses output for `[port][service] host: login: password` pattern

#### John the Ripper (Offline CPU Cracking)
- Accepts hash file + optional wordlist
- Auto-detects hash format or select manually
- Also runs `john --show` to display previously cracked hashes

#### Hashcat (Offline GPU Cracking)
- 7 hash types: MD5 (0), NTLM (1000), SHA1 (100), SHA256 (1400),
  SHA512crypt (1800), bcrypt (3200), Kerberos 5 TGS (13100)
- Requires GPU — button shows disabled if not available
- Also runs `hashcat --show` for previously cracked results

#### CeWL (Wordlist Generation)
- Crawls a target URL (configurable depth + min word length)
- Generates custom wordlist at `/tmp/cewl_output_<url>.txt`
- Refreshes local wordlist browser after generation

### 7. Wordlists
- **Download**: rockyou (140 MB, 14M passwords), top 100K, SecLists web discovery
- **Local files**: lists all files in `storage/wordlists/` + system wordlists
- Shows file sizes, supports browsing selected wordlists
- Download progress bar via streaming HTTP
- Used by WiFi crack and password attack tabs

### 8. Benchmark
- **Localhost Scan**: `nmap -T4 -F 127.0.0.1`
- **Quick LAN Scan**: `nmap -T4 -F 192.168.1.0/24`
- **Masscan Speed Test**: `masscan 192.168.1.0/24 -p80,443,22 --rate=1000`
- Measures: wall-clock time, stdout/stderr size, return code
- Results appear in a table for comparison

### 9. Live Log
- Real-time system event log
- Displays scan output, tool messages, errors
- Filtered, highlighted, scrollable
- Max 500 lines displayed

---

## All 36 Integrated Tools

### Scanners (6)
| Tool | Category | Description | Best For |
|------|----------|-------------|----------|
| nmap | scanner | Network discovery & security scanning | Service/OS detection, scripts |
| masscan | scanner | Blazing fast TCP port scanner (10M/s) | Large-scale port scanning |
| rustscan | scanner | Fast port scanner written in Rust | Quick port discovery + nmap |
| netdiscover | scanner | ARP scanner for network discovery | LAN host discovery |
| arp-scan | scanner | ARP scan for local network | Ethernet segment detection |
| fping | scanner | Fast parallel ping scanner | Subnet alive detection |

### WiFi (7)
| Tool | Description | Best For |
|------|-------------|----------|
| aircrack-ng | WEP/WPA key cracking suite | Offline handshake cracking |
| airodump-ng | WiFi packet capture & AP discovery | Reconnaissance, handshake capture |
| aireplay-ng | WiFi deauth/injection attacks | Deauth, packet injection |
| reaver | WPS PIN brute force attack tool | WPS PIN recovery |
| bully | WPS brute force (reaver alternative) | Faster on some APs |
| wifite | Automated WiFi attack tool | Full WEP/WPA/WPS audit |
| kismet | Wireless detector/sniffer/IDS | Passive WiFi monitoring |

### Web (6)
| Tool | Description | Best For |
|------|-------------|----------|
| nikto | Web server vuln scanner (6700+ tests) | Misconfigs, dangerous files |
| gobuster | Directory/DNS/VHost brute force | Hidden dirs, subdomains |
| whatweb | Web technology fingerprinting | CMS, frameworks detection |
| sqlmap | SQL injection auto-detection + exploit | SQLi testing, DB enumeration |
| wpscan | WordPress security scanner | Plugin/theme/user vulns |
| ffuf | Fast web fuzzer | High-speed URL fuzzing |

### Password Attacks (4)
| Tool | Description | Best For |
|------|-------------|----------|
| hashcat | GPU-accelerated password cracking (300+ modes) | High-speed hash cracking |
| john | John the Ripper password cracker | Multi-format cracking |
| hydra | Network login brute-forcer | Online password brute force |
| cewl | Custom wordlist generator from websites | Target-specific wordlists |

### MITM / Network (4)
| Tool | Description | Best For |
|------|-------------|----------|
| bettercap | MITM framework with WiFi/AP/ARP | Active MITM, credential sniffing |
| responder | LLMNR/NBT-NS/MDNS poisoner | Windows credential capture |
| mitmproxy | Interactive HTTPS proxy | HTTP/HTTPS traffic inspection |
| ettercap | ARP/DNS spoofing, MITM attacks | LAN MITM, plugin system |

### Sniffing (3)
| Tool | Description | Best For |
|------|-------------|----------|
| tshark | Wireshark CLI — packet capture | Protocol analysis, filtering |
| tcpdump | CLI packet capture tool | Quick captures, debugging |
| dsniff | Network auditing toolkit | FTP/HTTP/IMAP/Telnet sniffing |

### Enumeration (4)
| Tool | Description | Best For |
|------|-------------|----------|
| enum4linux | Windows/Samba enumeration | SMB/NetBIOS user/share/policy |
| smbclient | SMB/CIFS client | Browse shares, list users |
| dnsenum | DNS enumeration tool | Zone transfer, subdomain brute |
| theHarvester | Email/subdomain/IP harvester | OSINT gathering |

### Post-Exploitation (2)
| Tool | Description | Best For |
|------|-------------|----------|
| linpeas.sh | Linux privesc awesome script | Automated privesc discovery |
| linuxprivchecker | Linux privesc checker | Kernel exploits, SUID, cron |

---

## Core Modules (Python API)

### `core/run.py` — Subprocess Helpers
```python
run(cmd: list[str], timeout: int = 30) -> str
  # Run command, return combined stdout+stderr

run_live(cmd: list[str], timeout: int = 60, line_callback=None) -> int
  # Stream output line-by-line, returns exit code
```

### `core/scanner.py` — Network Scanner
```python
ScanRunner(callback=None)
  .run(cmd, timeout)  — run command with live line streaming
  .stop()             — terminate running scan
  .running            — bool property

save_scan(scan_type, target, tool, cmd, hosts) -> scan_id
get_previous_scan(scan_type, target, tool) -> dict | None
diff_hosts(old_hosts, new_hosts) -> (added, removed)
parse_nmap_hosts(line) -> ("host"|"port", data)
parse_airodump_ap(line) -> dict | None
parse_airodump_csv(csv_path) -> list[dict]
```
All scan history stored in SQLite at `~/.airdashboard/history.db`.

### `core/web.py` — Web Recon Wrappers
```python
nikto_scan(target, port="80", callback) -> dict
gobuster_dir(target, wordlist, extensions, callback) -> dict
gobuster_dns(target, wordlist, callback) -> dict
whatweb_scan(target, callback) -> dict
sqlmap_scan(target_url, level=1, risk=1, callback) -> dict
wpscan_scan(target_url, enumerate="ap,at,u", callback) -> dict
ffuf_fuzz(target_url, wordlist, extensions, callback) -> dict
```
All return: `{"target": str, "results": [...], "total": int, "raw": list[str]}`

### `core/password.py` — Password Attack Wrappers
```python
hydra_brute(target, service, username, userlist, passlist, threads, callback) -> dict
john_crack(hashfile, wordlist, fmt, callback) -> dict
hashcat_crack(hashfile, hashtype, wordlist, rules, callback) -> dict
cewl_wordlist(url, depth, min_length, callback) -> dict
```
Hydra services: ssh, ftp, telnet, http-get, http-post-form, mysql, postgres, rdp, smb, snmp
Hashcat types: 0=MD5, 100=SHA1, 1000=NTLM, 1400=SHA256, 1800=sha512crypt, 3200=bcrypt, 13100=Kerberos

### `core/audit.py` — WiFi Audit Workflow
```python
monitor_start(iface) / monitor_stop(iface)
get_monitor_iface(base_iface) -> str
is_monitor_mode(iface) -> bool
get_capture_files() -> list[dict]
analyze_cap(cap_path) -> dict  # size, aps, handshakes, packets
capture_handshake(bssid, channel, essid, iface, timeout, callback) -> dict
crack_handshake(cap_path, wordlist_path, bssid, callback) -> dict
full_audit(iface, callback) -> dict
```

### `core/wordlist.py` — Wordlist Manager
```python
WORDLISTS = {"rockyou": ..., "rockyou_sample": ..., "seclists_discovery": ...}
get_local_wordlists() -> list[dict]
download_wordlist(name, progress_callback) -> bool
WORDLIST_DIR = "storage/wordlists/"
```

### `core/tools.py` — Tool Detection & Recommendations
```python
TOOLS = {  # 36 tools, 8 categories
  name: {"bin", "category", "description", "heavyness", "best_for"}
}
detect_tools() -> dict  # adds path, version, available to each
benchmark_tool(tool_bin, args, timeout) -> dict
advise_tool(task, available) -> dict  # recommends best tool for task
lookup_mac(mac) -> str  # OUI vendor database (130+ entries)
BENCHMARK_SCANS = {"scan_local", "quick_scan", "masscan_speed"}
```

Tasks: port_scan, fast_scan, wifi_survey, wps_attack, password_crack,
online_bruteforce, web_scan, dir_bruteforce, sqli_test, wordpress_scan,
tech_fingerprint, mitm, cred_harvest, packet_capture, smb_enum,
subdomain_enum, privesc

---

## File Structure
```
airdashboard/
├── main.py                  # App entry point (9 tabs, CSS, root check)
├── run.sh                   # Launch script (sudo .venv/bin/python main.py)
├── requirements.txt         # textual, requests
├── core/
│   ├── run.py               # Shared subprocess helpers
│   ├── scanner.py           # Network scanner, SQLite history, CSV parsing
│   ├── web.py               # Nikto, Gobuster, WhatWeb, SQLMap, WPScan, FFUF
│   ├── password.py          # Hydra, John, Hashcat, CeWL
│   ├── audit.py             # WiFi audit: monitor, capture, crack
│   ├── tools.py             # 36 tools, detect, benchmark, advise, MAC lookup
│   └── wordlist.py          # Download manager, local wordlist browser
├── ui/
│   ├── __init__.py          # Exports all 9 tab widgets
│   ├── helpers.py           # WLAN detection, iwconfig, sysinfo, signal display
│   ├── dashboard.py         # System info, tool detection, quick launch
│   ├── scanner.py           # Network scanner tab
│   ├── wifi.py              # WiFi audit tab
│   ├── bluetooth.py         # Bluetooth tab
│   ├── web_recon.py         # Web reconnaissance tab
│   ├── passwords.py         # Password attacks tab
│   ├── wordlist.py          # Wordlist download/manager tab
│   ├── benchmark.py         # Tool benchmarking tab
│   ├── live_log.py          # Real-time event log tab
│   └── docs.py              # This documentation tab
├── tools/
│   ├── install_tools.sh     # Full tool installer (apt + GitHub + snap)
│   └── tools.json           # Tool manifest with install commands
└── storage/
    ├── captures/            # WiFi handshake .cap/.pcap files
    ├── wordlists/           # Downloaded + system wordlists
    └── reports/             # Audit reports
```

---

## Recommendation Engine

`advise_tool(task, available)` recommends the best tool for a task:
- **port_scan**: nmap (primary) → masscan (alt)
- **fast_scan**: masscan (primary) → nmap (alt)
- **wifi_survey**: airodump-ng (primary) → wifite (alt)
- **wps_attack**: reaver (primary) → bully (alt)
- **password_crack**: hashcat (primary) → john (alt)
- **online_bruteforce**: hydra (only option)
- **web_scan**: nikto (primary) → gobuster (alt)
- **dir_bruteforce**: gobuster (primary) → ffuf (alt)
- **sqli_test**: sqlmap (only option)
- **wordpress_scan**: wpscan (only option)
- **tech_fingerprint**: whatweb (only option)
- **mitm**: bettercap (primary) → ettercap (alt)
- **cred_harvest**: responder (only option)
- **packet_capture**: tshark (primary) → tcpdump (alt)
- **smb_enum**: enum4linux (primary) → smbclient (alt)
- **subdomain_enum**: dnsenum (primary) → theHarvester (alt)
- **privesc**: linpeas (primary) → linuxprivchecker (alt)

---

## MAC Vendor Database

130+ OUI entries in `core/tools.py` for real-time vendor identification:
Intel, Apple, Dell, Cisco, Huawei, Samsung, Xiaomi, TP-Link, Raspberry Pi,
Ubiquiti, Google/Nest, Amazon, Netgear, Microsoft, Sony, Canon, Belkin, HTC,
OnePlus, Motorola, LG Electronics, Aruba, Roku, Nintendo, Sonos, D-Link, HP

---

## Storage & Data

| Path | Purpose |
|------|---------|
| `~/.airdashboard/history.db` | SQLite scan history (scans + hosts tables) |
| `~/.airdashboard/completions/` | Shell completions |
| `storage/captures/` | WiFi handshake .cap/.pcap files |
| `storage/wordlists/` | Downloaded wordlists + system symlinks |
| `storage/reports/` | Audit reports |
| `/tmp/adboard-01.csv` | Temporary airodump scan output |
| `/tmp/sqlmap_out/` | SQLMap output directory |
| `/tmp/cewl_output_*.txt` | CeWL generated wordlists |
| `/opt/Responder/` | Responder GitHub clone |

---

## Legal Disclaimer

**This tool is for authorized security testing and educational purposes only.**
Unauthorized access to computer networks and systems is illegal. Always obtain
explicit written permission before performing security testing on any system you
do not own. The developers assume no liability for misuse of this software.
"""

class DocsTab(ScrollableContainer):
    """Comprehensive documentation for every tool, module, and workflow."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]AirDashboard — Documentation[/]", classes="section-title")
        yield Static(
            "[dim]36 tools · 8 categories · 10 tabs · 170+ lines of docs[/]",
            id="docs-meta",
        )
        yield Markdown(DOC_TEXT, id="docs-content")
