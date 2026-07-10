"""UI package — all TUI tab widgets."""

from ui.dashboard import DashboardTab
from ui.scanner import ScannerTab
from ui.wifi import WiFiAuditTab
from ui.bluetooth import BluetoothTab
from ui.web_recon import WebReconTab
from ui.passwords import PasswordAttacksTab
from ui.wordlist import WordlistTab
from ui.benchmark import BenchmarkTab
from ui.live_log import LiveLogTab
from ui.docs import DocsTab

__all__ = [
    "DashboardTab", "ScannerTab", "WiFiAuditTab", "BluetoothTab",
    "WebReconTab", "PasswordAttacksTab", "WordlistTab",
    "BenchmarkTab", "LiveLogTab", "DocsTab",
]
