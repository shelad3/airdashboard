#!/usr/bin/env python3
"""AirDashboard — Interactive cybersecurity audit TUI."""

import os
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, TabbedContent, TabPane

from ui import (
    DashboardTab, ScannerTab, WiFiAuditTab, BluetoothTab,
    WebReconTab, PasswordAttacksTab, WordlistTab,
    BenchmarkTab, LiveLogTab, DocsTab,
)


RESULTS_DIR = Path.home() / ".airdashboard"
RESULTS_DIR.mkdir(exist_ok=True)


class AirdashboardApp(App):
    TITLE = "AirDashboard"
    CSS = """
    Screen { background: $surface; }
    .section-title { text-style: bold; padding: 0 1; margin-bottom: 1; }
    .dash-card { border: solid $primary; margin: 0 0 1 0; padding: 1; height: auto; }
    #scan-buttons, #wifi-buttons, #bench-buttons, #wl-buttons, #log-buttons,
    #wifi-mon-row, #bt-buttons, #bt-action-row,
    #scan-action-row, #web-scan-buttons, #web-deep-buttons, #web-target-row,
    #pw-hydra-row, #pw-hydra-files, #pw-crack-row, #pw-crack-files, #pw-cewl-row,
    #web-action-row, #docs-buttons { height: 3; padding: 0 1; margin-bottom: 1; }
    #wifi-bssid, #wifi-channel, #wifi-essid,
    #bt-target, #scan-target-input, #web-target, #web-action-url,
    #pw-target, #pw-username, #pw-userlist, #pw-passlist,
    #pw-hashfile, #pw-crack-wordlist, #pw-cewl-url { width: 28; margin-right: 1; }
    #pw-service, #pw-hashtype { width: 22; margin-right: 1; }
    .label { padding: 0 0 0 1; color: $text-muted; }
    Button { margin-right: 1; }
    DataTable { height: 10; border: solid $secondary; margin-bottom: 1; }
    RichLog { border: solid $secondary; height: 1fr; }
    #scan-log, #wifi-log, #live-log, #bt-log, #web-log, #pw-log { height: 1fr; }
    #bench-log { height: 8; }
    #wifi-sparkline { margin: 0 1 1 1; padding: 1; border: solid $secondary; }
    ProgressBar { margin: 0 1; }
    TabbedContent { height: 1fr; }
    TabPane { padding: 1; }
    #wl-list, #wifi-capture-list, #pw-wordlist-list { height: 6; border: solid $secondary; margin-bottom: 1; }
    #wl-progress { margin-bottom: 1; }
    #scan-status, #wifi-status, #wifi-mon-status, #bt-status { margin: 0 1 1 1; }
    #bench-desc, #wl-desc { margin: 0 1 1 1; color: $text-muted; }
    #log-count { margin: 0 1; color: $text-muted; }
    #wifi-workflow, #bt-workflow, #scan-workflow, #web-workflow, #pw-workflow {
        margin: 0 1 1 1; padding: 1; border: solid $accent;
        background: $surface-darken-1; color: $text;
    }
    #wifi-select-hint, #bt-select-hint, #scan-select-hint, #web-select-hint {
        margin: 0 1; color: $text-muted; padding: 0 1;
    }
    #web-hint { margin: 0 1; color: $text-muted; padding: 0 1; }
    #docs-meta { margin: 0 1; color: $text-muted; padding: 0 1; }
    #docs-content { height: 1fr; }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Dashboard", id="dash"):
                yield DashboardTab()
            with TabPane("Scanner", id="scan"):
                yield ScannerTab()
            with TabPane("WiFi Audit", id="wifi"):
                yield WiFiAuditTab()
            with TabPane("Bluetooth", id="bt"):
                yield BluetoothTab()
            with TabPane("Web Recon", id="web"):
                yield WebReconTab()
            with TabPane("Passwords", id="pw"):
                yield PasswordAttacksTab()
            with TabPane("Wordlists", id="wordlists"):
                yield WordlistTab()
            with TabPane("Benchmark", id="bench"):
                yield BenchmarkTab()
            with TabPane("Live Log", id="log"):
                yield LiveLogTab()
            with TabPane("Docs", id="docs"):
                yield DocsTab()
        yield Footer()

    def on_mount(self):
        if os.geteuid() != 0:
            self.notify("Not running as root — monitor mode and airodump require sudo", timeout=8)
        self.notify("[bold green]Ready[/]", timeout=3)


if __name__ == "__main__":
    import sys
    try:
        app = AirdashboardApp()
        app.run()
    except Exception as e:
        print(f"\n[CRASH] {type(e).__name__}: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")
