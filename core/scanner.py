"""Network scanner wrappers with live output streaming, scan history, and diff."""

import os
import subprocess
import threading
import re
import json
import sqlite3
import time
from pathlib import Path


DB_PATH = Path.home() / ".airdashboard" / "history.db"


def detect_subnet() -> str:
    """Auto-detect the local subnet CIDR (e.g. '192.168.1.0/24')."""
    import socket
    import struct
    try:
        out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
        for line in out.split("\n"):
            # Lines like: "192.168.1.0/24 dev wlp2s0 proto kernel ..."
            if "/" in line and "dev" in line:
                cidr = line.split()[0]
                if "." in cidr and "/" in cidr:
                    return cidr
    except Exception:
        pass
    # Fallback: get local IP and guess /24
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ".".join(ip.split(".")[:3]) + ".0/24"
    except Exception:
        pass
    return "192.168.1.0/24"


def detect_local_ip() -> str:
    """Get the local IP address of this machine."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            scan_type TEXT,
            target TEXT,
            tool TEXT,
            cmd TEXT,
            results TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            scan_id INTEGER,
            address TEXT,
            hostname TEXT,
            ports TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)
    conn.commit()
    return conn


def save_scan(scan_type, target, tool, cmd, hosts):
    conn = get_db()
    ts = time.time()
    cur = conn.execute(
        "INSERT INTO scans (timestamp, scan_type, target, tool, cmd, results) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, scan_type, target, tool, " ".join(cmd), json.dumps(hosts)),
    )
    scan_id = cur.lastrowid
    for h in hosts:
        conn.execute(
            "INSERT INTO hosts (scan_id, address, hostname, ports) VALUES (?, ?, ?, ?)",
            (scan_id, h.get("address", ""), h.get("hostname", ""), h.get("ports", "")),
        )
    conn.commit()
    conn.close()
    return scan_id


def get_previous_scan(scan_type, target, tool):
    conn = get_db()
    cur = conn.execute(
        "SELECT id, timestamp, results FROM scans WHERE scan_type=? AND target=? AND tool=? ORDER BY timestamp DESC LIMIT 1 OFFSET 1",
        (scan_type, target, tool),
    )
    row = cur.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "timestamp": row[1], "hosts": json.loads(row[2])}
    return None


def diff_hosts(old_hosts, new_hosts):
    old_addrs = {h.get("address") for h in old_hosts}
    new_addrs = {h.get("address") for h in new_hosts}
    added = [h for h in new_hosts if h.get("address") not in old_addrs]
    removed = [h for h in old_hosts if h.get("address") not in new_addrs]
    return added, removed


class ScanRunner:
    def __init__(self, callback=None):
        self.process = None
        self.callback = callback
        self._stop = threading.Event()

    def run(self, cmd: list[str], timeout=60):
        self._stop.clear()
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            for line in iter(self.process.stdout.readline, ""):
                if self._stop.is_set():
                    self.process.terminate()
                    break
                if self.callback:
                    self.callback(line.rstrip())
            self.process.stdout.close()
            self.process.wait(timeout=timeout)
        except FileNotFoundError:
            if self.callback:
                self.callback(f"[red]Tool not found: {cmd[0]}[/]")
        except subprocess.TimeoutExpired:
            self.process.kill()
            if self.callback:
                self.callback("[red]Scan timed out[/]")

    def stop(self):
        self._stop.set()
        if self.process:
            self.process.terminate()

    @property
    def running(self):
        return self.process is not None and self.process.poll() is None


def parse_nmap_hosts(line: str):
    match = re.search(r"Nmap scan report for (.+)", line)
    if match:
        return ("host", match.group(1))
    match = re.search(r"(\d+/tcp)\s+open\s+(\S+)", line)
    if match:
        return ("port", f"{match.group(1)} {match.group(2)}")
    return None


def parse_airodump_ap(line: str):
    parts = line.split(",")
    if len(parts) > 13:
        bssid = parts[0].strip()
        ch = parts[3].strip()
        power = parts[8].strip()
        enc = (parts[5].strip() or parts[6].strip())[:8]
        essid = parts[13].strip().strip('"')
        if bssid and len(bssid) == 17:
            return {"bssid": bssid, "channel": ch, "signal": power, "enc": enc, "essid": essid}
    return None


def parse_airodump_csv(csv_path: str) -> list[dict]:
    """Parse an airodump CSV file and return a list of AP dicts."""
    aps = []
    if not os.path.exists(csv_path):
        return aps
    with open(csv_path) as f:
        for line in f:
            ap = parse_airodump_ap(line)
            if ap:
                aps.append(ap)
    return aps
