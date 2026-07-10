#!/bin/bash
# AirDashboard — Tool Installer
# Run with: sudo bash install_tools.sh
# Installs all missing security tools and downloads wordlists

set -e
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
TOOLS_JSON="$BASE_DIR/tools.json"

echo "╔══════════════════════════════════════════════════╗"
echo "║        AirDashboard — Tool Installer            ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[!] Please run with sudo: sudo bash install_tools.sh"
    exit 1
fi

echo "[*] Updating package lists..."
apt update -qq

echo ""
echo "[*] Installing core security tools..."
apt install -y \
    nmap masscan \
    aircrack-ng reaver bully \
    hashcat john hydra cewl \
    nikto sqlmap whatweb \
    bettercap wireshark tcpdump dsniff \
    smbclient dnsenum \
    netdiscover arp-scan fping \
    ettercap-text-only mitmproxy \
    bluez bluez-tools blueman \
    curl wget git || true

echo ""
echo "[*] Installing packages with special handling..."
# enum4linux — not in apt, use snap
if ! command -v enum4linux &>/dev/null && ! snap list enum4linux &>/dev/null; then
    echo "  Installing enum4linux via snap..."
    snap install enum4linux 2>/dev/null || echo "  [!] enum4linux snap install failed"
fi

# Responder — Python tool, install from GitHub
if ! command -v responder &>/dev/null; then
    echo "  Installing Responder..."
    if [ ! -d "/opt/Responder" ]; then
        git clone https://github.com/lgandx/Responder.git /opt/Responder 2>/dev/null || echo "  [!] Responder clone failed"
    fi
    # Create a wrapper symlink
    if [ -f "/opt/Responder/Responder.py" ]; then
        ln -sf /opt/Responder/Responder.py /usr/local/bin/responder 2>/dev/null
        chmod +x /opt/Responder/Responder.py 2>/dev/null
    fi
fi

echo ""
echo "[*] Installing optional tools (may take a while)..."
# gobuster, ffuf, rustscan — install from GitHub releases if available
if ! command -v gobuster &>/dev/null; then
    echo "  Installing gobuster..."
    GOBUSTER_URL="https://github.com/OJ/gobuster/releases/latest/download/gobuster_Linux_x86_64.tar.gz"
    curl -sL "$GOBUSTER_URL" | tar xz -C /usr/local/bin gobuster 2>/dev/null || \
        echo "  [!] gobuster install failed — install manually: https://github.com/OJ/gobuster"
fi

if ! command -v ffuf &>/dev/null; then
    echo "  Installing ffuf..."
    FFUF_URL="https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz"
    curl -sL "$FFUF_URL" | tar xz -C /usr/local/bin ffuf 2>/dev/null || \
        echo "  [!] ffuf install failed — install manually: https://github.com/ffuf/ffuf"
fi

# wpscan
if ! command -v wpscan &>/dev/null; then
    echo "  Installing wpscan..."
    gem install wpscan 2>/dev/null || \
    gem install --user-install wpscan 2>/dev/null || \
        echo "  [!] wpscan install failed — run: sudo gem install wpscan"
fi

# kismet
apt install -y kismet 2>/dev/null || echo "  [!] kismet not available in repos"

# theHarvester
if ! command -v theHarvester &>/dev/null; then
    echo "  Installing theHarvester..."
    pip3 install --break-system-packages theHarvester 2>/dev/null || true
fi

echo ""
echo "[*] Installing Python audit tools..."
pip3 install --break-system-packages scapy pycryptodome 2>/dev/null || true

echo ""
echo "[*] Downloading wordlists..."
WORDLIST_DIR="$BASE_DIR/../storage/wordlists"
mkdir -p "$WORDLIST_DIR"

# Top 100K passwords (small, fast download)
if [ ! -f "$WORDLIST_DIR/top100k.txt" ]; then
    echo "  Downloading top 100K passwords..."
    curl -sL -o "$WORDLIST_DIR/top100k.txt" \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt"
fi

# Common web content discovery
if [ ! -f "$WORDLIST_DIR/common-web.txt" ]; then
    echo "  Downloading common web paths..."
    curl -sL -o "$WORDLIST_DIR/common-web.txt" \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
fi

# DNS subdomain list
if [ ! -f "$WORDLIST_DIR/dns-subdomains.txt" ]; then
    echo "  Downloading DNS subdomain list..."
    curl -sL -o "$WORDLIST_DIR/dns-subdomains.txt" \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
fi

# System wordlists symlink
if [ ! -d "$WORDLIST_DIR/system" ] && [ -d "/usr/share/wordlists" ]; then
    ln -s /usr/share/wordlists "$WORDLIST_DIR/system" 2>/dev/null || true
fi

echo ""
echo "[*] Setting up project storage..."
chown -R $(logname):$(logname) "$BASE_DIR/../storage" 2>/dev/null || true

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Installation complete!                          ║"
echo "║  Launch dashboard: ./run.sh                      ║"
echo "╚══════════════════════════════════════════════════╝"
