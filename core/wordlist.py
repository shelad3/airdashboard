"""Wordlist downloader and manager."""

import os
from pathlib import Path

import requests
import threading


WORDLISTS = {
    "rockyou": {
        "url": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
        "size_mb": 140,
        "desc": "Most famous password wordlist (14M passwords)",
    },
    "rockyou_sample": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
        "size_mb": 1,
        "desc": "Top 100K passwords from rockyou",
    },
    "seclists_discovery": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
        "size_mb": 0.5,
        "desc": "Common web content discovery paths",
    },
}

WORDLIST_DIR = str(Path(__file__).resolve().parent.parent / "storage" / "wordlists")


def ensure_dir():
    os.makedirs(WORDLIST_DIR, exist_ok=True)


def get_local_wordlists():
    ensure_dir()
    results = []
    for name in os.listdir(WORDLIST_DIR):
        path = os.path.join(WORDLIST_DIR, name)
        if os.path.isfile(path):
            size = os.path.getsize(path)
            results.append({"name": name, "path": path, "size_mb": round(size / 1e6, 1)})
    return results


def download_wordlist(name: str, progress_callback=None):
    ensure_dir()
    if name not in WORDLISTS:
        return False
    info = WORDLISTS[name]
    dest = os.path.join(WORDLIST_DIR, f"{name}.txt")
    if os.path.exists(dest):
        return True
    try:
        r = requests.get(info["url"], stream=True, timeout=30)
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        downloaded = 0
        with open(dest, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                if progress_callback and total:
                    progress_callback(downloaded / total * 100)
        return True
    except Exception as e:
        return str(e)
