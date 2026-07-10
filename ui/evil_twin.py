"""Evil Twin tab — fake WiFi AP with captive portal credential capture."""

import threading
from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, DataTable, RichLog, Input, Select, Checkbox

from ui.helpers import WLAN
from core.evil_twin import (
    scan_targets, start_evil_twin, stop_evil_twin,
    get_captured_credentials, CRED_LOG,
)


class EvilTwinTab(ScrollableContainer):
    """Evil Twin: scan targets → clone AP → capture credentials via captive portal."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Evil Twin — Fake AP / Credential Capture[/]", classes="section-title")
        yield Static(
            "[yellow]⚠ For authorized penetration testing only[/]",
            id="et-warning",
        )
        yield Static(
            "  [dim]Scan Targets[/] →  [dim]Select Clone[/] →  [dim]Start Evil Twin[/] →  [dim]Capture Credentials[/]",
            id="et-workflow",
        )

        # Step 1: Scan
        yield Horizontal(
            Button("Scan Nearby APs", id="et-scan", variant="primary"),
            Button("Stop Evil Twin", id="et-stop", variant="error"),
            id="et-buttons",
        )
        yield DataTable(id="et-scan-results")

        # Step 2: Configure
        yield Static("[bold]Configuration[/]", classes="section-title")
        yield Horizontal(
            Static("ESSID:", classes="label"),
            Input(id="et-essid", placeholder="target AP name (or custom)"),
            Static("Channel:", classes="label"),
            Input(id="et-channel", placeholder="6", value="6"),
            Static("Gateway:", classes="label"),
            Input(id="et-gateway", placeholder="10.0.0.1", value="10.0.0.1"),
            id="et-config-row",
        )
        yield Horizontal(
            Button("Start Evil Twin", id="et-start", variant="warning"),
            Static("", id="et-status"),
            id="et-action-row",
        )

        # Step 3: Captured credentials
        yield Static("[bold]Captured Credentials[/]", classes="section-title")
        yield Horizontal(
            Button("Refresh", id="et-refresh-creds", variant="default"),
            Button("Clear Log", id="et-clear-creds", variant="default"),
            id="et-cred-buttons",
        )
        yield DataTable(id="et-creds")
        yield RichLog(id="et-log", highlight=True, max_lines=300)

    def on_mount(self):
        self._processes = []
        table = self.query_one("#et-scan-results", DataTable)
        table.add_columns("#", "BSSID", "Signal", "Enc", "ESSID")
        table.cursor_type = "row"
        creds = self.query_one("#et-creds", DataTable)
        creds.add_columns("#", "Time", "Username", "Password")
        creds.cursor_type = "row"
        self._refresh_creds()

    def onDataTableRowSelected(self, event: DataTable.RowSelected):
        table = self.query_one("#et-scan-results", DataTable)
        try:
            row = table.get_row_at(event.cursor_row)
        except Exception:
            return
        if len(row) >= 5:
            essid = str(row[4]).strip()
            bssid = str(row[1]).strip()
            self.query_one("#et-essid", Input).value = essid
            log = self.query_one("#et-log", RichLog)
            log.write(f"[green]Selected:[/] {essid} ({bssid}) — edit ESSID if you want a custom name")

    def on_button_pressed(self, event: Button.Pressed):
        log = self.query_one("#et-log", RichLog)
        bid = event.button.id

        if bid == "et-scan":
            log.write(f"[cyan]Scanning nearby APs on {WLAN}...[/]")
            table = self.query_one("#et-scan-results", DataTable)
            table.clear()
            threading.Thread(target=self._run_scan, daemon=True).start()

        elif bid == "et-start":
            essid = self.query_one("#et-essid", Input).value.strip()
            channel = self.query_one("#et-channel", Input).value.strip() or "6"
            gateway = self.query_one("#et-gateway", Input).value.strip() or "10.0.0.1"
            if not essid:
                log.write("[red]Enter an ESSID to clone (or scan first)[/]")
                return
            log.write(f"[bold yellow]Starting Evil Twin: {essid}...[/]")
            self.query_one("#et-status", Static).update("[red]Active[/]")
            threading.Thread(
                target=self._start_twin, args=(WLAN, essid, channel, gateway),
                daemon=True,
            ).start()

        elif bid == "et-stop":
            log.write("[red]Stopping Evil Twin...[/]")
            stop_evil_twin(self._processes)
            self._processes = []
            self.query_one("#et-status", Static).update("[dim]Stopped[/]")
            log.write("[green]Evil Twin stopped[/]")

        elif bid == "et-refresh-creds":
            self._refresh_creds()

        elif bid == "et-clear-creds":
            if CRED_LOG.exists():
                CRED_LOG.unlink()
            self._refresh_creds()
            log.write("[dim]Credential log cleared[/]")

    def _run_scan(self):
        from core.tools import lookup_mac
        table = self.query_one("#et-scan-results", DataTable)
        targets = scan_targets(WLAN)
        for i, ap in enumerate(targets, 1):
            self.call_from_thread(
                table.add_row, str(i), ap["bssid"], ap["signal"], ap["enc"], ap["essid"],
            )
        self.call_from_thread(
            self.query_one("#et-log", RichLog).write,
            f"[green]{len(targets)} APs found.[/]  Select one to clone"
            if targets else "[yellow]No APs found[/]",
        )

    def _start_twin(self, iface, essid, channel, gateway):
        def cb(line):
            self.call_from_thread(self.query_one("#et-log", RichLog).write, line)
        result = start_evil_twin(iface, essid, channel, gateway, callback=cb)
        if result["success"]:
            self._processes = result.get("processes", [])
        else:
            self.call_from_thread(
                self.query_one("#et-status", Static).update, f"[red]{result.get('error', 'failed')}[/]",
            )

    def _refresh_creds(self):
        table = self.query_one("#et-creds", DataTable)
        table.clear()
        creds = get_captured_credentials()
        for i, c in enumerate(creds, 1):
            table.add_row(str(i), c["timestamp"], c["username"], c["password"])
        if creds:
            self.query_one("#et-log", RichLog).write(
                f"[green]{len(creds)} credentials captured[/]"
            )
