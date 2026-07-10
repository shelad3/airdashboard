"""Tool detection, benchmarking, recommendation engine, and MAC vendor lookup."""

import shutil
import subprocess
import time
import json
import os
import re

from core.run import run as _run


TOOLS = {
    # Scanners
    "nmap": {
        "bin": "nmap", "category": "scanner",
        "description": "Network discovery & security scanning",
        "heavyness": "medium", "best_for": "Detailed service/OS detection, script scanning",
    },
    "masscan": {
        "bin": "masscan", "category": "scanner",
        "description": "Blazing fast TCP port scanner (10M ports/sec)",
        "heavyness": "light", "best_for": "Large-scale port scanning, full Internet scans",
    },
    "rustscan": {
        "bin": "rustscan", "category": "scanner",
        "description": "Fast port scanner written in Rust, feeds into nmap",
        "heavyness": "light", "best_for": "Quick port discovery + nmap integration",
    },
    "netdiscover": {
        "bin": "netdiscover", "category": "scanner",
        "description": "ARP scanner for network discovery",
        "heavyness": "light", "best_for": "Local network host discovery via ARP",
    },
    "arp-scan": {
        "bin": "arp-scan", "category": "scanner",
        "description": "ARP scan tool for local network enumeration",
        "heavyness": "light", "best_for": "Detect hosts on local Ethernet segment",
    },
    "fping": {
        "bin": "fping", "category": "scanner",
        "description": "Fast parallel ping scanner",
        "heavyness": "light", "best_for": "Fast host alive detection across subnets",
    },
    # WiFi
    "aircrack-ng": {
        "bin": "aircrack-ng", "category": "wifi",
        "description": "WEP/WPA key cracking suite",
        "heavyness": "medium", "best_for": "Offline handshake cracking",
    },
    "airodump-ng": {
        "bin": "airodump-ng", "category": "wifi",
        "description": "WiFi packet capture & AP discovery",
        "heavyness": "light", "best_for": "WiFi reconnaissance, handshake capture",
    },
    "aireplay-ng": {
        "bin": "aireplay-ng", "category": "wifi",
        "description": "WiFi deauth/injection attacks",
        "heavyness": "light", "best_for": "Deauth attacks, packet injection",
    },
    "reaver": {
        "bin": "reaver", "category": "wifi",
        "description": "WPS PIN brute force attack tool",
        "heavyness": "medium", "best_for": "WPS PIN recovery, brute force APs with WPS enabled",
    },
    "bully": {
        "bin": "bully", "category": "wifi",
        "description": "WPS brute force attack alternative to reaver",
        "heavyness": "medium", "best_for": "WPS PIN brute force, faster than reaver on some APs",
    },
    "wifite": {
        "bin": "wifite", "category": "wifi",
        "description": "Automated WiFi attack tool",
        "heavyness": "light", "best_for": "Automated WEP/WPA/WPS audit",
    },
    "kismet": {
        "bin": "kismet", "category": "wifi",
        "description": "Wireless network detector, sniffer, and IDS",
        "heavyness": "medium", "best_for": "Passive WiFi monitoring, packet capture",
    },
    # Web
    "nikto": {
        "bin": "nikto", "category": "web",
        "description": "Web server vulnerability scanner (6700+ tests)",
        "heavyness": "medium", "best_for": "Web server misconfigurations, dangerous files, outdated software",
    },
    "gobuster": {
        "bin": "gobuster", "category": "web",
        "description": "Directory/DNS/VHost brute force scanner",
        "heavyness": "medium", "best_for": "Hidden directory/file discovery, DNS subdomain brute force",
    },
    "whatweb": {
        "bin": "whatweb", "category": "web",
        "description": "Web technology fingerprinting",
        "heavyness": "light", "best_for": "Identify CMS, frameworks, libraries, web server",
    },
    "sqlmap": {
        "bin": "sqlmap", "category": "web",
        "description": "Automatic SQL injection detection & exploitation",
        "heavyness": "heavy", "best_for": "SQL injection testing, database enumeration",
    },
    "wpscan": {
        "bin": "wpscan", "category": "web",
        "description": "WordPress security scanner",
        "heavyness": "medium", "best_for": "WordPress plugin/theme vuln scanning, user enumeration",
    },
    "ffuf": {
        "bin": "ffuf", "category": "web",
        "description": "Fast web fuzzer for directory/parameter discovery",
        "heavyness": "light", "best_for": "High-speed URL/parameter fuzzing",
    },
    # Password attacks
    "hashcat": {
        "bin": "hashcat", "category": "cracker",
        "description": "GPU-accelerated password cracking (300+ modes)",
        "heavyness": "heavy", "best_for": "High-speed hash cracking with GPU",
    },
    "john": {
        "bin": "john", "category": "cracker",
        "description": "John the Ripper password cracker",
        "heavyness": "heavy", "best_for": "Multi-format password cracking, wordlist/rules",
    },
    "hydra": {
        "bin": "hydra", "category": "cracker",
        "description": "Network login brute-forcer (SSH, FTP, HTTP, etc.)",
        "heavyness": "medium", "best_for": "Online password brute force against network services",
    },
    "cewl": {
        "bin": "cewl", "category": "cracker",
        "description": "Custom wordlist generator from websites",
        "heavyness": "light", "best_for": "Generate target-specific password wordlists from web pages",
    },
    # Network / MITM
    "bettercap": {
        "bin": "bettercap", "category": "mitm",
        "description": "MITM framework with WiFi/AP/ARP capabilities",
        "heavyness": "heavy", "best_for": "Active MITM attacks, credential sniffing, ARP spoofing",
    },
    "responder": {
        "bin": "responder", "category": "mitm",
        "description": "LLMNR/NBT-NS/MDNS poisoner and credential harvester",
        "heavyness": "light", "best_for": "Windows network credential capture via name resolution poisoning",
    },
    "mitmproxy": {
        "bin": "mitmproxy", "category": "mitm",
        "description": "Interactive HTTPS proxy for traffic interception",
        "heavyness": "medium", "best_for": "HTTP/HTTPS traffic inspection, modification, replay",
    },
    "ettercap": {
        "bin": "ettercap", "category": "mitm",
        "description": "ARP spoofing, DNS spoofing, MITM attacks",
        "heavyness": "medium", "best_for": "LAN MITM attacks, credential sniffing, plugin system",
    },
    # Sniffing / Analysis
    "tshark": {
        "bin": "tshark", "category": "sniffer",
        "description": "Wireshark CLI — packet capture and analysis",
        "heavyness": "light", "best_for": "Packet capture, protocol analysis, traffic filtering",
    },
    "tcpdump": {
        "bin": "tcpdump", "category": "sniffer",
        "description": "CLI packet capture tool",
        "heavyness": "light", "best_for": "Quick packet captures, network debugging",
    },
    "dsniff": {
        "bin": "dsniff", "category": "sniffer",
        "description": "Network auditing and password sniffing toolkit",
        "heavyness": "light", "best_for": "Sniff FTP, HTTP, IMAP, Telnet, SNMP credentials",
    },
    # Enumeration
    "enum4linux": {
        "bin": "enum4linux", "category": "enum",
        "description": "Windows/Samba network enumeration tool",
        "heavyness": "light", "best_for": "SMB/NetBIOS user/share/policy enumeration",
    },
    "smbclient": {
        "bin": "smbclient", "category": "enum",
        "description": "SMB/CIFS client for listing/sharing files",
        "heavyness": "light", "best_for": "Browse SMB shares, list users, download files",
    },
    "dnsenum": {
        "bin": "dnsenum", "category": "enum",
        "description": "DNS enumeration tool for subdomain discovery",
        "heavyness": "light", "best_for": "DNS zone transfer, subdomain brute force",
    },
    "theharvester": {
        "bin": "theHarvester", "category": "enum",
        "description": "Email, subdomain, IP, and URL harvester",
        "heavyness": "light", "best_for": "OSINT: gather emails, subdomains, hosts from public sources",
    },
    # Post-exploitation
    "linpeas": {
        "bin": "linpeas.sh", "category": "postex",
        "description": "Linux Privilege Escalation Awesome Script",
        "heavyness": "light", "best_for": "Automated Linux privesc vector discovery",
    },
    "linuxprivchecker": {
        "bin": "linuxprivchecker.py", "category": "postex",
        "description": "Linux privilege escalation checker",
        "heavyness": "light", "best_for": "Check for kernel exploits, SUID, cron misconfigs",
    },
}

BENCHMARK_SCANS = {
    "scan_local": {
        "label": "Localhost Scan",
        "nmap": ["nmap", "-T4", "-F", "127.0.0.1"],
    },
    "quick_scan": {
        "label": "Quick LAN Scan (top ports)",
        "nmap": ["nmap", "-T4", "-F", "192.168.1.1/24"],
    },
    "masscan_speed": {
        "label": "Masscan Speed Test",
        "masscan": ["masscan", "192.168.1.0/24", "-p80,443,22", "--rate=1000"],
    },
}


_tool_cache = None
_tool_cache_time = 0


def detect_tools(force=False):
    """Detect installed tools. Caches results for 60 seconds."""
    global _tool_cache, _tool_cache_time
    import time as _time
    now = _time.time()
    if _tool_cache is not None and not force and (now - _tool_cache_time) < 60:
        return _tool_cache

    results = {}
    for name, info in TOOLS.items():
        path = shutil.which(info["bin"])
        if path:
            try:
                r = subprocess.run([info["bin"], "--version"],
                                   capture_output=True, text=True, timeout=3)
                ver = r.stdout.split("\n")[0][:60] if r.stdout else r.stderr.split("\n")[0][:60]
            except Exception:
                ver = "detected"
            results[name] = {**info, "path": path, "version": ver, "available": True}
        else:
            results[name] = {**info, "path": None, "version": None, "available": False}
    _tool_cache = results
    _tool_cache_time = now
    return results


def benchmark_tool(tool_bin: str, args: list[str], timeout=30) -> dict:
    start = time.time()
    try:
        proc = subprocess.Popen([tool_bin] + args,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return {"error": "timeout", "time": timeout}

        elapsed = time.time() - start
        return {
            "time": round(elapsed, 2),
            "stdout_len": len(stdout),
            "stderr_len": len(stderr),
            "returncode": proc.returncode,
            "error": None,
        }
    except FileNotFoundError:
        return {"error": "not_found", "time": 0}


def advise_tool(task: str, available: dict) -> dict:
    recommendations = {
        "port_scan": {
            "primary": "nmap",
            "reason": "Most feature-rich, scriptable, industry standard",
            "alt": "masscan",
        },
        "fast_scan": {
            "primary": "masscan",
            "reason": "Fastest port scanner, async architecture",
            "alt": "nmap",
        },
        "wifi_survey": {
            "primary": "airodump-ng",
            "reason": "Lightweight, shows APs/clients/signal in real-time",
            "alt": "wifite",
        },
        "wps_attack": {
            "primary": "reaver",
            "reason": "WPS PIN brute force, well-established",
            "alt": "bully",
        },
        "password_crack": {
            "primary": "hashcat",
            "reason": "GPU-accelerated, supports 300+ hash modes",
            "alt": "john",
        },
        "online_bruteforce": {
            "primary": "hydra",
            "reason": "Multi-protocol parallel login brute forcer",
            "alt": None,
        },
        "web_scan": {
            "primary": "nikto",
            "reason": "6700+ web vulnerability tests, industry standard",
            "alt": "gobuster",
        },
        "dir_bruteforce": {
            "primary": "gobuster",
            "reason": "Fast directory/DNS brute force, written in Go",
            "alt": "ffuf",
        },
        "sqli_test": {
            "primary": "sqlmap",
            "reason": "Automatic SQL injection detection and exploitation",
            "alt": None,
        },
        "wordpress_scan": {
            "primary": "wpscan",
            "reason": "WordPress-specific: plugins, themes, users, vulns",
            "alt": None,
        },
        "tech_fingerprint": {
            "primary": "whatweb",
            "reason": "Identifies CMS, frameworks, libraries, web server",
            "alt": None,
        },
        "mitm": {
            "primary": "bettercap",
            "reason": "Full MITM suite, HTTP/HTTPS/credential capture",
            "alt": "ettercap",
        },
        "cred_harvest": {
            "primary": "responder",
            "reason": "LLMNR/NBT-NS poisoning, captures NTLM hashes",
            "alt": None,
        },
        "packet_capture": {
            "primary": "tshark",
            "reason": "Full protocol analysis, Wireshark's power in CLI",
            "alt": "tcpdump",
        },
        "smb_enum": {
            "primary": "enum4linux",
            "reason": "Comprehensive SMB/NetBIOS enumeration",
            "alt": "smbclient",
        },
        "subdomain_enum": {
            "primary": "dnsenum",
            "reason": "DNS zone transfer + subdomain brute force",
            "alt": "theharvester",
        },
        "privesc": {
            "primary": "linpeas",
            "reason": "Comprehensive Linux privilege escalation checks",
            "alt": "linuxprivchecker",
        },
    }
    rec = recommendations.get(task, {})
    primary = rec.get("primary")
    if primary and available.get(primary, {}).get("available"):
        return {
            "tool": primary,
            "name": TOOLS[primary]["description"],
            "heavyness": TOOLS[primary]["heavyness"],
            "reason": rec["reason"],
        }
    alt = rec.get("alt")
    if alt and available.get(alt, {}).get("available"):
        return {
            "tool": alt,
            "name": TOOLS[alt]["description"],
            "heavyness": TOOLS[alt]["heavyness"],
            "reason": f"Primary unavailable, using {alt}",
        }
    return {"tool": None, "name": "No suitable tool found", "heavyness": "N/A", "reason": ""}


# ─── MAC Vendor Lookup (OUI Database) ────────────────────

OUI_DB = {
    "00037F": "Intel",
    "000C29": "VMware",
    "005056": "VMware",
    "000569": "Hewlett-Packard",
    "000C6E": "Atheros",
    "001111": "Apple",
    "00163E": "Apple",
    "001B63": "Apple",
    "0026B0": "Apple",
    "003065": "Apple",
    "005061": "Apple",
    "08EDB9": "Dell",
    "14FEB5": "Dell",
    "B8CA3A": "Dell",
    "F8BC12": "Dell",
    "3C5715": "Dell",
    "0021CC": "Dell",
    "0022EE": "D-Link",
    "1CB72C": "D-Link",
    "C03F0E": "D-Link",
    "001E52": "Cisco",
    "00226D": "Cisco",
    "A41437": "Cisco",
    "18A6F7": "Cisco",
    "6C9CED": "Cisco",
    "5C6B32": "Huawei",
    "38F554": "Huawei",
    "3C2C99": "Huawei",
    "0016CB": "Samsung",
    "0025E6": "Samsung",
    "342D0D": "Samsung",
    "8C7712": "Samsung",
    "A470D6": "Samsung",
    "D88D5C": "Samsung",
    "C04A00": "Xiaomi",
    "284FCE": "Xiaomi",
    "108F44": "Xiaomi",
    "48F317": "Xiaomi",
    "F03A55": "TP-Link",
    "14CF92": "TP-Link",
    "E41F8A": "TP-Link",
    "1C3E84": "TP-Link",
    "64D1A3": "TP-Link",
    "C025A5": "TP-Link",
    "FC75E6": "TP-Link",
    "A08996": "TP-Link",
    "0050F1": "Raspberry Pi",
    "D83ADD": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "28B2BD": "Raspberry Pi",
    "006083": "Raspberry Pi",
    "ACBC32": "Roku",
    "0017C8": "Nintendo",
    "005040": "Microsoft",
    "0C715D": "Netgear",
    "2C339B": "Netgear",
    "6C3B6B": "Netgear",
    "8C3BA7": "Netgear",
    "A0369F": "Netgear",
    "A8610A": "Netgear",
    "209BA5": "LG Electronics",
    "24DA11": "LG Electronics",
    "7CD844": "LG Electronics",
    "48A2B7": "Aruba",
    "60D9C7": "Aruba",
    "08D09F": "Ubiquiti",
    "24A43C": "Ubiquiti",
    "26A43C": "Ubiquiti",
    "2CA60D": "Ubiquiti",
    "60E327": "Ubiquiti",
    "74ACB9": "Ubiquiti",
    "7857BE": "Ubiquiti",
    "8886A0": "Ubiquiti",
    "D85D2B": "Ubiquiti",
    "A021B7": "Google/Nest",
    "18B430": "Google/Nest",
    "3C5A37": "Google/Nest",
    "BCF685": "Google/Nest",
    "C8D726": "Google/Nest",
    "E4FA1D": "Google/Nest",
    "0CB862": "Amazon",
    "3C6A2C": "Amazon",
    "68DDF4": "Amazon",
    "1C5A3B": "Amazon",
    "5CF938": "Amazon",
    "5E9381": "Amazon",
    "747DF4": "Amazon",
    "A026D9": "Amazon",
    "04F021": "Sonos",
    "2CBE08": "Sonos",
    "B89675": "Sonos",
    "001CC4": "HTC",
    "002618": "HTC",
    "F4F29A": "OnePlus",
    "A8BD1A": "OnePlus",
    "00A0C9": "Intel",
    "000F1F": "Intel",
    "00241D": "Intel",
    "0057B7": "Intel",
    "0C8C8D": "Intel",
    "100E2B": "Intel",
    "1CC1DE": "Intel",
    "288023": "Intel",
    "34E894": "Intel",
    "402CF4": "Intel",
    "448500": "Intel",
    "4C796F": "Intel",
    "54A205": "Intel",
    "6886A7": "Intel",
    "6CF37F": "Intel",
    "8065E9": "Intel",
    "98CA33": "Intel",
    "A088B4": "Intel",
    "A88F1A": "Intel",
    "ACE010": "Intel",
    "D023DB": "Intel",
    "DC3714": "Intel",
    "E0D55E": "Intel",
    "F4D9FB": "Intel",
    "FC2F40": "Intel",
    "BC991B": "Motorola",
    "0037B1": "Motorola",
    "001E4A": "Motorola",
    "107BEF": "Motorola",
    "C06F81": "Sony",
    "002640": "Sony",
    "005064": "Canon",
    "0040D6": "Huawei",
    "001432": "Belkin",
    "009E1E": "Belkin",
    "0CF5A4": "Belkin",
    "10BEF5": "Belkin",
    "60F81D": "Belkin",
    "AC84C6": "Belkin",
}


def lookup_mac(mac: str) -> str:
    prefix = mac.upper().replace(":", "")[:6]
    return OUI_DB.get(prefix, "Unknown")
