"""Tool manager — reads tools.json manifest and checks install status."""

import json
import shutil
import subprocess
from pathlib import Path


TOOLS_JSON = Path(__file__).resolve().parent / "tools.json"


def load_manifest() -> dict:
    with open(TOOLS_JSON) as f:
        return json.load(f)


def check_tools() -> list[dict]:
    """Check each tool in the manifest against the system."""
    manifest = load_manifest()
    results = []
    for category, tools in manifest.items():
        for name, info in tools.items():
            bin_name = info.get("bin", "")
            if bin_name and shutil.which(bin_name):
                try:
                    r = subprocess.run([bin_name, "--version"],
                                       capture_output=True, text=True, timeout=5)
                    ver = r.stdout.split("\n")[0][:50] if r.stdout else r.stderr.split("\n")[0][:50]
                except Exception:
                    ver = "detected"
                status = "installed"
                version = ver
            else:
                status = "missing"
                version = ""
            results.append({
                "category": category,
                "name": name,
                "bin": bin_name,
                "description": info.get("description", ""),
                "status": status,
                "version": version,
                "install_cmd": info.get("install", ""),
            })
    return results


def get_missing_tools() -> list[dict]:
    return [t for t in check_tools() if t["status"] == "missing"]


def get_installed_tools() -> list[dict]:
    return [t for t in check_tools() if t["status"] == "installed"]
