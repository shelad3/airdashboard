"""Bluetooth scanner, enumerator, and basic audit tools."""

import os
import re
import time
import subprocess
import shutil
from pathlib import Path

from core.run import run as _run
from core.tools import lookup_mac


BT_ADAPTER = "hci0"


def bt_status() -> dict:
    """Get Bluetooth adapter status."""
    info = {"available": False, "address": "", "state": "", "name": ""}
    out = _run(["hciconfig", BT_ADAPTER], timeout=5)
    m = re.search(r"BD Address:\s*([0-9A-F:]+)", out)
    if m:
        info["available"] = True
        info["address"] = m.group(1)
    if "UP" in out and "RUNNING" in out:
        info["state"] = "UP RUNNING"
    elif "UP" in out:
        info["state"] = "UP"
    else:
        info["state"] = "DOWN"
    m = re.search(r"Name:\s*'(.+)'", out)
    if m:
        info["name"] = m.group(1)
    return info


def hcitool_scan(timeout=10) -> list[dict]:
    """Scan for Bluetooth devices using hcitool."""
    devices = []
    out = _run(["hcitool", "scan", "--flush"], timeout=timeout + 5)
    for line in out.split("\n"):
        m = re.match(r"\s+([0-9A-F:]{17})\s+(.+)", line)
        if m:
            mac = m.group(1).strip()
            name = m.group(2).strip()
            vendor = lookup_mac(mac)
            devices.append({"mac": mac, "name": name, "vendor": vendor, "type": "BR/EDR"})
    return devices


def bluetoothctl_scan(timeout=12) -> list[dict]:
    """Scan for BT/BLE devices using bluetoothctl."""
    devices = []
    try:
        proc = subprocess.Popen(
            ["bluetoothctl"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        proc.stdin.write("scan on\n")
        proc.stdin.flush()
        time.sleep(timeout)
        proc.stdin.write("scan off\nquit\n")
        proc.stdin.flush()
        stdout, _ = proc.communicate(timeout=10)
    except Exception:
        return devices
    for line in stdout.split("\n"):
        m = re.search(r"Device\s+([0-9A-F:]{17})\s+(.+)", line)
        if m:
            mac = m.group(1).upper()
            name = m.group(2).strip()
            vendor = lookup_mac(mac)
            devices.append({"mac": mac, "name": name, "vendor": vendor, "type": "BLE"})
    return devices


def lescan(timeout=10) -> list[dict]:
    """Scan for BLE devices using hcitool lescan."""
    devices = []
    out = _run(["timeout", str(timeout), "hcitool", "lescan"], timeout=timeout + 5)
    for line in out.split("\n"):
        m = re.match(r"([0-9A-F:]{17})\s+(.+)", line)
        if m:
            mac = m.group(1).upper()
            name = m.group(2).strip()
            if name.lower() not in ("unknown", "n/a"):
                vendor = lookup_mac(mac)
                devices.append({"mac": mac, "name": name, "vendor": vendor, "type": "BLE"})
    return devices


def scan_all(timeout=12) -> list[dict]:
    """Run both hcitool and BLE scan, deduplicate."""
    seen = set()
    all_devices = []
    for dev in hcitool_scan(timeout):
        if dev["mac"] not in seen:
            seen.add(dev["mac"])
            all_devices.append(dev)
    for dev in lescan(timeout):
        if dev["mac"] not in seen:
            seen.add(dev["mac"])
            all_devices.append(dev)
    return all_devices


def device_info(mac: str) -> dict:
    """Get detailed info about a specific BT device."""
    info = {"mac": mac, "name": "", "vendor": lookup_mac(mac), "rssi": "", "services": []}
    out = _run(["hcitool", "name", mac], timeout=5)
    info["name"] = out.strip()
    out = _run(["hcitool", "rssi", mac], timeout=5)
    m = re.search(r"RSSI:\s*(-?\d+)", out)
    if m:
        info["rssi"] = m.group(1)
    out = _run(["sdptool", "browse", mac], timeout=15)
    for line in out.split("\n"):
        m = re.search(r"Service Name:\s*(.+)", line)
        if m:
            info["services"].append(m.group(1).strip())
        m = re.search(r"Service Description:\s*(.+)", line)
        if m:
            info["services"].append(m.group(1).strip())
    return info


def l2ping(mac: str, count: int = 3) -> str:
    """Ping a BT device to check reachability."""
    return _run(["l2ping", "-c", str(count), mac], timeout=15)


def device_rssi(mac: str) -> str:
    """Get RSSI of a connected/paired device."""
    out = _run(["hcitool", "rssi", mac], timeout=5)
    m = re.search(r"RSSI:\s*(-?\d+)", out)
    return m.group(1) if m else "N/A"


def bt_audit(mac: str, line_callback=None) -> dict:
    """Run a full BT audit against a target device."""
    report = {"mac": mac, "name": "", "vendor": "", "rssi": "", "services": [], "l2ping": "", "open_ports": []}

    def log(msg):
        if line_callback:
            line_callback(msg)

    log(f"[cyan]Auditing BT device: {mac}[/]")
    info = device_info(mac)
    report["name"] = info["name"]
    report["vendor"] = info["vendor"]
    report["rssi"] = info["rssi"]
    report["services"] = info["services"]
    log(f"  Name: {info['name']}")
    log(f"  Vendor: {info['vendor']}")
    log(f"  RSSI: {info.get('rssi', 'N/A')}")
    log(f"  Services ({len(info['services'])}): {', '.join(info['services'][:10])}")
    report["l2ping"] = l2ping(mac)
    log(f"  L2Ping: {'Reachable' if 'bytes' in report['l2ping'] else 'Unreachable'}")

    # RFCOMM port scan (common BT SP profiles)
    log("[cyan]  Scanning RFCOMM channels 1-15...[/]")
    for ch in range(1, 16):
        r = _run(["sdptool", "records", "--channel", str(ch), mac], timeout=3)
        if r.strip():
            report["open_ports"].append(ch)
            log(f"    Channel {ch}: data")
    log(f"  Found {len(report['open_ports'])} open RFCOMM channels")
    log("[green]BT audit complete[/]")
    return report
