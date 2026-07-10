"""Bluetooth tab — scan → audit → encryption test → disconnect/block → flood."""

import threading

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, Input, DataTable, RichLog

from core.bt import (
    bt_status, scan_all, lescan, ensure_bt_up,
    device_info, l2ping, bt_audit,
    bt_encryption_test, bt_disconnect_target, bt_block_device, bt_unblock_device,
    bt_name_flood, bt_inquiry_flood, bt_l2cap_flood,
    bt_paired_devices, bt_connected_devices, bt_remove_device,
    btmon_monitor, hcidump_capture, bt_connection_flood, bt_spoof_pairing,
)


class BluetoothTab(ScrollableContainer):
    """Interactive BT audit: scan → select → info/ping/audit → encryption test → flood."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Bluetooth Security Audit[/]", classes="section-title")
        yield Static(
            "  [dim]Scan[/] →  [dim]Select Device[/] →  [dim]Info/Ping/Audit[/] →  "
            "[dim]Encryption Test[/] →  [dim]Disconnect/Block[/] →  [dim]Flood[/]",
            id="bt-workflow",
        )
        yield Static("", id="bt-status")

        # Paired / Connected devices
        yield Static("[bold]Paired & Connected Devices[/]", classes="section-title")
        yield Horizontal(
            Button("Show Paired Devices", id="bt-show-paired", variant="primary"),
            Button("Show Connected Only", id="bt-show-connected", variant="success"),
            Button("Remove (Unpair) Selected", id="bt-remove", variant="error", disabled=True),
            id="bt-paired-row",
        )
        yield DataTable(id="bt-paired-results")

        # Step 1: Scan
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

        # Step 2: Action buttons
        yield Horizontal(
            Static("Target:", classes="label"),
            Input(id="bt-target", placeholder="select from table"),
            Button("2) Get Info", id="bt-info", variant="primary", disabled=True),
            Button("2) Ping", id="bt-ping", variant="primary", disabled=True),
            Button("2) Full Audit", id="bt-audit", variant="warning", disabled=True),
            id="bt-action-row",
        )

        # Step 3: Encryption test + disconnect/block
        yield Horizontal(
            Button("3) Encryption Test", id="bt-encrypt", variant="warning", disabled=True),
            Button("4) Disconnect", id="bt-disconnect", variant="warning", disabled=True),
            Button("4) Block Device", id="bt-block", variant="error", disabled=True),
            Button("4) Unblock", id="bt-unblock", variant="default", disabled=True),
            id="bt-sec-row",
        )

        # Step 4: Flooding
        yield Static("[bold]Flooding / Disruption[/]", classes="section-title")
        yield Horizontal(
            Input(id="bt-flood-count", placeholder="count (50)", value="50"),
            Button("5) Name Flood", id="bt-flood-name", variant="error", disabled=True),
            Button("5) L2CAP Flood", id="bt-flood-l2cap", variant="error", disabled=True),
            Button("5) Inquiry Flood", id="bt-flood-inquiry", variant="error"),
            id="bt-flood-row",
        )

        yield RichLog(id="bt-log", highlight=True, max_lines=500)

        # ─── Connection Monitor ─────────────────────────
        yield Static("[bold]Connection Monitor[/]", classes="section-title")
        yield Static(
            "[dim]See devices connecting to other phones/speakers in real-time via btmon/hcidump[/]",
            id="bt-monitor-hint",
        )
        yield Horizontal(
            Button("Start Monitor (15s)", id="bt-monitor", variant="warning"),
            Button("Capture Packets (10s)", id="bt-hcidump", variant="warning"),
            Input(id="bt-monitor-duration", placeholder="seconds", value="15"),
            id="bt-monitor-row",
        )

        # ─── Disruption ─────────────────────────────────
        yield Static("[bold]Connection Disruption[/]", classes="section-title")
        yield Static(
            "[yellow]⚠ Flooding a target can disrupt its active connection to another device[/]",
            id="bt-disrupt-hint",
        )
        yield Horizontal(
            Button("Connection Flood", id="bt-conn-flood", variant="error", disabled=True),
            Button("Spoof Pairing", id="bt-spoof", variant="error", disabled=True),
            Input(id="bt-disrupt-count", placeholder="rounds (20)", value="20"),
            id="bt-disrupt-row",
        )

    def on_mount(self):
        self.refresh_bt_status()
        self.set_interval(15, self.refresh_bt_status)
        table = self.query_one("#bt-results", DataTable)
        table.add_columns("#", "Vendor", "MAC", "Name", "Type")
        table.cursor_type = "row"
        paired_table = self.query_one("#bt-paired-results", DataTable)
        paired_table.add_columns("#", "Status", "MAC", "Name", "Vendor", "RSSI")
        paired_table.cursor_type = "row"

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

    def _enable_action_buttons(self):
        for btn_id in ("bt-info", "bt-ping", "bt-audit", "bt-encrypt",
                       "bt-disconnect", "bt-block", "bt-unblock",
                       "bt-flood-name", "bt-flood-l2cap",
                       "bt-conn-flood", "bt-spoof"):
            try:
                self.query_one(f"#{btn_id}", Button).disabled = False
            except Exception:
                pass

    def onDataTableRowSelected(self, event: DataTable.RowSelected):
        table = event.control
        try:
            row = table.get_row_at(event.cursor_row)
        except Exception:
            return
        if table.id == "bt-paired-results" and len(row) >= 4:
            mac = str(row[2]).strip()
            name = str(row[3]).strip()
            self.query_one("#bt-target", Input).value = mac
            self._enable_action_buttons()
            self.query_one("#bt-remove", Button).disabled = False
            log = self.query_one("#bt-log", RichLog)
            log.write(f"[green]Selected:[/] {name or 'Unknown'}  MAC: {mac}  → All actions enabled")
        elif table.id == "bt-results" and len(row) >= 4:
            mac = str(row[2]).strip()
            name = str(row[3]).strip()
            self.query_one("#bt-target", Input).value = mac
            self._enable_action_buttons()
            log = self.query_one("#bt-log", RichLog)
            log.write(f"[green]Selected:[/] {name or 'Unknown'}  MAC: {mac}  → All actions enabled")

    def on_button_pressed(self, event: Button.Pressed):
        log = self.query_one("#bt-log", RichLog)
        table = self.query_one("#bt-results", DataTable)
        bid = event.button.id

        if bid == "bt-stop":
            log.write("[red]Stopped[/]")
            return

        if bid == "bt-show-paired":
            log.write("[cyan]Loading paired devices...[/]")
            paired_table = self.query_one("#bt-paired-results", DataTable)
            paired_table.clear()

            def do_paired():
                devices = bt_paired_devices()
                for i, d in enumerate(devices, 1):
                    self.call_from_thread(
                        paired_table.add_row, str(i), d["status"],
                        d["mac"], d["name"], d["vendor"], "",
                    )
                self.call_from_thread(
                    log.write,
                    f"[green]{len(devices)} paired devices found.[/]" if devices
                    else "[yellow]No paired devices.[/]"
                )
            threading.Thread(target=do_paired, daemon=True).start()

        elif bid == "bt-show-connected":
            log.write("[cyan]Checking connected devices...[/]")
            paired_table = self.query_one("#bt-paired-results", DataTable)
            paired_table.clear()

            def do_connected():
                devices = bt_connected_devices()
                connected = [d for d in devices if d.get("status") == "connected"]
                for i, d in enumerate(devices, 1):
                    status_color = "green" if d.get("status") == "connected" else "dim"
                    self.call_from_thread(
                        paired_table.add_row, str(i),
                        f"[{status_color}]{d['status']}[/{status_color}]",
                        d["mac"], d["name"], d["vendor"],
                        d.get("rssi", ""),
                    )
                self.call_from_thread(
                    log.write,
                    f"[green]{len(connected)} connected, {len(devices)} total paired.[/]" if devices
                    else "[yellow]No paired devices.[/]"
                )
            threading.Thread(target=do_connected, daemon=True).start()

        elif bid == "bt-remove":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            log.write(f"[red]Removing (unpairing) {mac}...[/]")
            threading.Thread(
                target=lambda: (
                    bt_remove_device(mac),
                    self.call_from_thread(log.write, f"[green]Device {mac} removed[/]"),
                    self.call_from_thread(self._refresh_paired),
                ),
                daemon=True,
            ).start()

        if bid == "bt-scan-all":
            log.write("[cyan]Powering on adapter + scanning for all BT/BLE devices (12s)...[/]")
            table.clear()
            self.query_one("#bt-select-hint", Static).update("[dim]Scanning...[/]")

            def do_scan():
                devices, status = scan_all(12)
                self.call_from_thread(log.write, f"[dim]{status}[/]")
                for i, d in enumerate(devices, 1):
                    self.call_from_thread(
                        table.add_row, str(i), d["vendor"], d["mac"], d["name"], d["type"],
                    )
                self.call_from_thread(
                    self.query_one("#bt-select-hint", Static).update,
                    f"[green]{len(devices)} devices found.[/]  [dim]↑↓ select a row → auto-fills MAC below[/]"
                    if devices else "[yellow]No devices found — adapter may be busy or no devices in range.[/]",
                )
            threading.Thread(target=do_scan, daemon=True).start()

        elif bid == "bt-lescan":
            log.write("[cyan]Powering on adapter + scanning for BLE devices (10s)...[/]")
            table.clear()
            self.query_one("#bt-select-hint", Static).update("[dim]Scanning BLE...[/]")

            def do_lescan():
                ensure_bt_up()
                devices = lescan(10)
                for i, d in enumerate(devices, 1):
                    self.call_from_thread(
                        table.add_row, str(i), d["vendor"], d["mac"], d["name"], d["type"],
                    )
                self.call_from_thread(
                    self.query_one("#bt-select-hint", Static).update,
                    f"[green]{len(devices)} BLE devices found.[/]  [dim]↑↓ select a row[/]"
                    if devices else "[yellow]No BLE devices found.[/]",
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
            threading.Thread(target=lambda: log.write(l2ping(mac)), daemon=True).start()

        elif bid == "bt-audit":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            log.write(f"[bold cyan]=== Full BT Audit: {mac} ===[/]")
            threading.Thread(
                target=lambda: bt_audit(mac, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-encrypt":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            log.write(f"[bold yellow]=== Encryption Test: {mac} ===[/]")
            threading.Thread(
                target=lambda: bt_encryption_test(mac, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-disconnect":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            threading.Thread(
                target=lambda: bt_disconnect_target(mac, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-block":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            threading.Thread(
                target=lambda: bt_block_device(mac, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-unblock":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            log.write(f"[cyan]Unblocking {mac}...[/]")
            threading.Thread(
                target=lambda: (bt_unblock_device(mac), log.write(f"[green]Unblocked {mac}[/]")),
                daemon=True,
            ).start()

        elif bid == "bt-flood-name":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            count = int(self.query_one("#bt-flood-count", Input).value.strip() or "50")
            threading.Thread(
                target=lambda: bt_name_flood(mac, count, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-flood-l2cap":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a device from the table first[/]")
                return
            count = int(self.query_one("#bt-flood-count", Input).value.strip() or "50")
            threading.Thread(
                target=lambda: bt_l2cap_flood(mac, count, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-flood-inquiry":
            duration = int(self.query_one("#bt-flood-count", Input).value.strip() or "15")
            threading.Thread(
                target=lambda: bt_inquiry_flood(duration, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-monitor":
            duration = int(self.query_one("#bt-monitor-duration", Input).value.strip() or "15")
            log.write(f"[bold cyan]Starting BT monitor for {duration}s — watch for connections...[/]")
            log.write("[dim]This sees: devices pairing, connecting, disconnecting in your area[/]")
            threading.Thread(
                target=lambda: btmon_monitor(duration, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-hcidump":
            duration = int(self.query_one("#bt-monitor-duration", Input).value.strip() or "10")
            log.write(f"[bold cyan]Capturing BT packets for {duration}s...[/]")
            threading.Thread(
                target=lambda: hcidump_capture(duration, callback=lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-conn-flood":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a target device first[/]")
                return
            count = int(self.query_one("#bt-disrupt-count", Input).value.strip() or "20")
            log.write(f"[bold red]Connection disruption on {mac} ({count} rounds)...[/]")
            log.write("[dim]This will flood the target with connection requests[/]")
            threading.Thread(
                target=lambda: bt_connection_flood(mac, count, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

        elif bid == "bt-spoof":
            mac = self.query_one("#bt-target", Input).value.strip()
            if not mac:
                log.write("[red]Select a target device first[/]")
                return
            log.write(f"[bold red]Sending spoofed pairing to {mac}...[/]")
            threading.Thread(
                target=lambda: bt_spoof_pairing(mac, lambda line: self.call_from_thread(log.write, line)),
                daemon=True,
            ).start()

    def _refresh_paired(self):
        """Refresh the paired devices table."""
        paired_table = self.query_one("#bt-paired-results", DataTable)
        paired_table.clear()
        devices = bt_paired_devices()
        for i, d in enumerate(devices, 1):
            paired_table.add_row(str(i), d["status"], d["mac"], d["name"], d["vendor"], "")
