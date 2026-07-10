"""Shared subprocess helpers used across all core modules."""

import subprocess
from typing import Optional


def run(cmd: list[str], timeout: int = 30) -> str:
    """Run a command and return combined stdout+stderr."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except Exception as e:
        return f"Error: {e}"


def run_live(cmd: list[str], timeout: int = 60, line_callback=None) -> int:
    """Run a command streaming output line-by-line. Returns exit code."""
    proc = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        for line in iter(proc.stdout.readline, ""):
            if line_callback:
                line_callback(line.rstrip())
        proc.stdout.close()
        proc.wait(timeout=timeout)
        return proc.returncode
    except FileNotFoundError:
        return -1
    except subprocess.TimeoutExpired:
        if proc:
            proc.kill()
        return -2
