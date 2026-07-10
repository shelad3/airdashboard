"""Bluetooth tab — interactive workflow: scan → select device → info/ping/audit."""

import threading

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, Input, DataTable, RichLog

from core.bt import (
    bt_status, scan_all, lescan,
    device_info, l2ping, bt_audit,
)


class BluetoothTab(ScrollableContainer):
    """Interactive BT audit: scan → click device → auto-fill MAC → audit actions."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Bluetooth Scanner[/]", classes="section-title")
        yield Static(
            "  [dim]Step 1:[/] Scan Devices   →   "
            "[dim]Step 2:[/] Select Device   →   "
            "[dim]Step 3:[/] Info / Ping / Audit",
            id="bt-workflow",
        )
        yield Static("", id="bt-status")
        yield Horizontal(
            Button("1) Scan All Devices", id="bt-scan-all", variant="primary"),
            Button("1) BLE Scan Only", id="bt-lescan", variant="primary"),
            Button("Stop", id="bt-stop", variant="error"),
            id="bt-buttons",
        )
        yield DataTable(id="bt-results")
        yield Static(
            "[dim]↑↓ select a device row → auto-fills MAC below[/]",
            id="bt-select-hint",
        )
        yield Horizontal(
            Static("Target:", classes="label"),
            Input(id="bt-target", placeholder="select from table"),
            Button("2) Get Info", id="bt-info", variant="primary", disabled=True),
            Button("2) Ping", id="bt-ping", variant="primary", disabled=True),
            Button("2) Full Audit", id="bt-audit", variant="warning", disabled=True),
            id="bt-action-row",
        )
        yield RichLog(id="bt-log", highlight=True, max_lines=500)

    def on_mount(self):
        self.refresh_bt_status()
        self.set_interval(5, self.refresh_bt_status)
        table = self.query_one("#bt-results", DataTable)
        table.add_columns("#", "Vendor", "MAC", "Name", "Type")
        table.cursor_type = "row"

    def refresh_bt_status(self):
        s = bt_status()
        st = self.query_one("#bt-status", Static)
        if s["available"]:
            color = "green" if "RUNNING" in s["state"] else "yellow"
            st.update(
                f"[bold {color}]Adapter: {s['address']} ({s['state']})[/]"
                f"  |  {s['name']}"
            )
        else:
            st.update("[bold red]No Bluetooth adapter detected[/]")

    def onDataTableRowSelected(self, event: DataTable.RowSelected):
        """Auto-fill MAC when a device row is selected."""
        table = self.query_one("#bt-results", DataTable)
        try:
            row = table.get_row_at(event.cursor_row)
        except Exception:
            return
        if len(row) >= 4:
            mac = str(row[2]).strip()
            name = str(row[3]).strip()
            self.query_one("#bt-target", Input).value = mac
            self.query_one("#bt-info", Button).disabled = False
            self.query_one("#bt-ping", Button).disabled = False
            self.query_one("#bt-audit", Button).disabled = False
            log = self.query_one("#bt-log", RichLog)
            log.write(f"[green]Selected:[/] {name or 'Unknown'}  MAC: {mac}  → Click Info / Ping / Audit")

    def on_button_pressed(self, event: Button.Pressed):
        log = self.query_one("#bt-log", RichLog)
        table = self.query_one("#bt-results", DataTable)
        bid = event.button.id
        hint = self.query_one("#bt-select-hint", Static)

        if bid == "bt-stop":
            log.write("[red]Stopped[/]")
            return

        if bid == "bt-scan-all":
            log.write("[cyan]Scanning for all BT/BLE devices (12s)...[/]")
            table.clear()
            hint.update("[dim]Scanning...[/]")

            def do_scan():
                devices = scan_all(12)
                count = 0
                for i, d in enumerate(devices, 1):
                    count += 1
                    self.call_from_thread(
                        table.add_row, str(i), d["vendor"], d["mac"], d["name"], d["type"],
                    )
                self.call_from_thread(
                    hint.update,
                    f"[green]{count} devices found.[/]  [dim]↑↓ select a row → auto-fills MAC below[/]"
                    if count else "[yellow]No devices found. Ensure Bluetooth is on.[/]",
                )

            threading.Thread(target=do_scan, daemon=True).start()

        elif bid == "bt-lescan":
            log.write("[cyan]Scanning for BLE devices (10s)...[/]")
            table.clear()
            hint.update("[dim]Scanning BLE...[/]")

            def do_lescan():
                devices = lescan(10)
                count = 0
                for i, d in enumerate(devices, 1):
                    count += 1
                    self.call_from_thread(
                        table.add_row, str(i), d["vendor"], d["mac"], d["name"], d["type"],
                    )
                self.call_from_thread(
                    hint.update,
                    f"[green]{count} BLE devices found.[/]  [dim]↑↓ select a row[/]"
                    if count else "[yellow]No BLE devices found.[/]",
                )

            threading.Thread(target=do_lescan, daemon=True).start()

        elif bid == "bt-info":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            log.write(f"[cyan]Getting info for {mac}...[/]")

            def do_info():
                info = device_info(mac)
                self.call_from_thread(log.write, f"  Name: {info['name'] or 'Unknown'}")
                self.call_from_thread(log.write, f"  Vendor: {info['vendor']}")
                self.call_from_thread(log.write, f"  RSSI: {info.get('rssi', 'N/A')}")
                if info["services"]:
                    self.call_from_thread(log.write, f"  Services ({len(info['services'])}):")
                    for s in info["services"][:15]:
                        self.call_from_thread(log.write, f"    - {s}")
                else:
                    self.call_from_thread(log.write, "  [yellow]No services found[/]")

            threading.Thread(target=do_info, daemon=True).start()

        elif bid == "bt-ping":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            log.write(f"[cyan]Pinging {mac}...[/]")

            def do_ping():
                result = l2ping(mac)
                self.call_from_thread(log.write, result)

            threading.Thread(target=do_ping, daemon=True).start()

        elif bid == "bt-audit":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            log.write(f"[bold cyan]=== Full BT Audit: {mac} ===[/]")

            def cb(line):
                self.call_from_thread(log.write, line)

            threading.Thread(target=lambda: bt_audit(mac, cb), daemon=True).start()
