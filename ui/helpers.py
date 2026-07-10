"""Shared helpers and configuration for all UI tabs."""

import os
import re
import shutil
import subprocess
import time as _time
from pathlib import Path

from core.run import run as run_cmd


RESULTS_DIR = Path.home() / ".airdashboard"
RESULTS_DIR.mkdir(exist_ok=True)


def detect_wlan_interface() -> str:
    """Auto-detect the first wireless interface, falling back to wlp2s0."""
    try:
        out = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5).stdout
        for line in out.split("\n"):
            line = line.strip()
            if line.startswith("Interface "):
                return line.split()[1]
    except Exception:
        pass
    return "wlp2s0"


WLAN = detect_wlan_interface()

_iwconfig_cache = {"data": None, "time": 0}
_sysinfo_cache = {"data": None, "time": 0}


def get_iwconfig():
    now = _time.time()
    if _iwconfig_cache["data"] is not None and (now - _iwconfig_cache["time"]) < 5:
        return _iwconfig_cache["data"]
    out = run_cmd(["iwconfig", WLAN])
    info = {"ssid": "", "signal": "", "freq": "", "ap": "", "quality": "", "channel": ""}
    m = re.search(r'ESSID:"([^"]*)"', out)
    if m: info["ssid"] = m.group(1)
    m = re.search(r"Frequency:([\d.]+ \w+)", out)
    if m: info["freq"] = m.group(1)
    m = re.search(r"Access Point: ([0-9a-fA-F:]+)", out)
    if m: info["ap"] = m.group(1)
    m = re.search(r"Signal level=(-?\d+)", out)
    if m: info["signal"] = m.group(1)
    m = re.search(r"Link Quality=(\d+/\d+)", out)
    if m: info["quality"] = m.group(1)
    _iwconfig_cache["data"] = info
    _iwconfig_cache["time"] = now
    return info


def get_sysinfo():
    now = _time.time()
    if _sysinfo_cache["data"] is not None and (now - _sysinfo_cache["time"]) < 10:
        return _sysinfo_cache["data"]
    out = run_cmd(["uname", "-a"])
    kernel = out.split()[2] if out else "?"
    load = run_cmd(["cat", "/proc/loadavg"]).split()[:3] if os.path.exists("/proc/loadavg") else "?"
    mem = run_cmd(["free", "-h"]).split("\n")[1].split() if shutil.which("free") else []
    mem_str = f"{mem[2]}/{mem[1]}" if len(mem) > 2 else "?"
    result = (kernel, " ".join(load), mem_str)
    _sysinfo_cache["data"] = result
    _sysinfo_cache["time"] = now
    return result


def signal_bar(sig_str, width=15):
    if not sig_str or sig_str == "?":
        return "?" * width
    sig = int(sig_str)
    filled = max(0, min(width, (sig + 100) // 7))
    return "█" * filled + "░" * (width - filled)


def signal_sparkline(values, width=16):
    if not values:
        return "░" * width
    mn, mx = min(values), max(values)
    rng = mx - mn if mx != mn else 1
    out = ""
    for v in values:
        idx = int((v - mn) / rng * 7)
        out += "▁▂▃▄▅▆▇█"[min(idx, 7)]
    return out.rjust(width)


def thread_write(widget, method_name, *args):
    """Call a widget method from a background thread safely."""
    widget.call_from_thread(getattr(widget, method_name), *args)
