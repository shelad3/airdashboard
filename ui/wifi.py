"""WiFi Audit tab — unified workflow: monitor → scan → select → capture → crack."""

import os
import threading
from collections import deque

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, DataTable, RichLog, Input, SelectionList

from ui.helpers import WLAN, get_iwconfig, signal_bar, signal_sparkline, run_cmd
from core.tools import lookup_mac
from core.scanner import parse_airodump_csv
from core.audit import (
    monitor_start, monitor_stop, get_monitor_iface, is_monitor_mode,
    get_capture_files, analyze_cap, capture_handshake, crack_handshake,
    full_audit, CAPTURES_DIR, WORDLISTS_DIR,
)
from core.run import run as _run_cmd


class WiFiAuditTab(ScrollableContainer):
    """Unified WiFi audit: monitor mode → scan APs → select → capture → analyze → crack."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]WiFi Audit[/]", classes="section-title")
        yield Static(
            "  [dim]Monitor[/] →  [dim]Scan APs[/] →  [dim]Select Target[/] →  "
            "[dim]Capture Handshake[/] →  [dim]Analyze[/] →  [dim]Crack[/]",
            id="wifi-workflow",
        )

        # Live signal info
        yield Static("", id="wifi-status")
        yield Static("", id="wifi-sparkline")

        # Monitor mode
        yield Horizontal(
            Button("Enable Monitor", id="wifi-mon-on", variant="success"),
            Button("Disable Monitor", id="wifi-mon-off", variant="error"),
            Static("", id="wifi-mon-status"),
            id="wifi-mon-row",
        )

        # Scan
        yield Horizontal(
            Button("1) Scan APs", id="wifi-scan", variant="primary"),
            Button("Full Auto Audit", id="wifi-full", variant="default"),
            Button("Show Interface", id="wifi-info", variant="default"),
            id="wifi-buttons",
        )
        yield DataTable(id="wifi-results")
        yield Static(
            "[dim]↑↓ select an AP row → auto-fills capture fields below[/]",
            id="wifi-select-hint",
        )

        # Capture fields + actions
        yield Horizontal(
            Static("BSSID:", classes="label"), Input(id="wifi-bssid", placeholder="from table"),
            Static("CH:", classes="label"), Input(id="wifi-channel", placeholder="from table"),
            Static("ESSID:", classes="label"), Input(id="wifi-essid", placeholder="from table"),
        )
        yield Horizontal(
            Button("2) Capture Handshake", id="wifi-capture", variant="success", disabled=True),
            Button("3) Analyze", id="wifi-analyze", variant="primary", disabled=True),
            Button("4) Crack", id="wifi-crack", variant="warning", disabled=True),
            Button("WPS Attack", id="wifi-wps", variant="error", disabled=True),
            id="wifi-action-buttons",
        )

        # Captures list
        yield SelectionList[str](id="wifi-capture-list")

        # Log
        yield RichLog(id="wifi-log", highlight=True, max_lines=500)

    def on_mount(self):
        self.signal_history = deque(maxlen=30)
        self.selected_ap = None
        self.mon_iface = ""
        table = self.query_one("#wifi-results", DataTable)
        table.add_columns("#", "Vendor", "BSSID", "Signal", "Enc", "ESSID")
        table.cursor_type = "row"
        self.set_interval(2, self.refresh_wifi_info)
        self.set_interval(3, self.refresh_monitor_status)
        self.refresh_monitor_status()
        self._refresh_captures()

    def refresh_wifi_info(self):
        info = get_iwconfig()
        sig_str = info.get("signal", "?")
        self.query_one("#wifi-status", Static).update(
            f"[bold]Connected:[/] {info['ssid'] or '—'}  "
            f"Signal: {sig_str} dBm  "
            f"BSSID: {info['ap']}"
        )
        if sig_str and sig_str != "?":
            self.signal_history.append(int(sig_str))
        spark = signal_sparkline(list(self.signal_history))
        bar = signal_bar(sig_str) if sig_str and sig_str != "?" else "?" * 15
        self.query_one("#wifi-sparkline", Static).update(
            f"[bold]Signal Trend:[/] {spark}  [bold]{sig_str} dBm[/]  {bar}"
        )

    def refresh_monitor_status(self):
        mon = get_monitor_iface()
        self.mon_iface = mon
        active = is_monitor_mode(mon)
        st = self.query_one("#wifi-mon-status", Static)
        if active:
            st.update(f"[bold green]Monitor: {mon} (active)[/]")
        else:
            st.update("[dim]Monitor: inactive[/]")

    def onDataTableRowSelected(self, event: DataTable.RowSelected):
        table = self.query_one("#wifi-results", DataTable)
        try:
            row = table.get_row_at(event.cursor_row)
        except Exception:
            return
        if len(row) >= 6:
            bssid = str(row[2]).strip()
            essid = str(row[5]).strip()
            self.query_one("#wifi-bssid", Input).value = bssid
            self.query_one("#wifi-essid", Input).value = essid
            self.query_one("#wifi-channel", Input).value = ""
            self.query_one("#wifi-capture", Button).disabled = False
            self.query_one("#wifi-wps", Button).disabled = False
            self.selected_ap = {"bssid": bssid, "essid": essid}
            log = self.query_one("#wifi-log", RichLog)
            log.write(f"[green]Selected:[/] {essid or bssid}  → enter channel, then Capture")

    def on_button_pressed(self, event: Button.Pressed):
        log = self.query_one("#wifi-log", RichLog)
        table = self.query_one("#wifi-results", DataTable)
        bid = event.button.id

        if bid == "wifi-mon-on":
            log.write("[cyan]Enabling monitor mode...[/]")
            log.write(monitor_start(WLAN))
            self.refresh_monitor_status()

        elif bid == "wifi-mon-off":
            log.write("[cyan]Disabling monitor mode...[/]")
            log.write(monitor_stop(WLAN))
            self.refresh_monitor_status()

        elif bid == "wifi-info":
            log.write(run_cmd(["iwconfig", WLAN]))

        elif bid == "wifi-scan":
            log.write("[cyan]Scanning for APs (8s)...[/]")
            table.clear()
            self.query_one("#wifi-select-hint", Static).update("[dim]Scanning...[/]")
            threading.Thread(target=self._run_scan, daemon=True).start()

        elif bid == "wifi-full":
            log.write("[bold cyan]Full Auto Audit: nmap → airodump → bettercap...[/]")
            def cb(line):
                self.call_from_thread(log.write, line)
            threading.Thread(target=lambda: full_audit(WLAN, cb), daemon=True).start()

        elif bid == "wifi-capture":
            bssid = self.query_one("#wifi-bssid", Input).value.strip()
            channel = self.query_one("#wifi-channel", Input).value.strip()
            essid = self.query_one("#wifi-essid", Input).value.strip()
            if not bssid:
                log.write("[red]Select an AP from the table first[/]")
                return
            if not channel:
                log.write("[red]Enter the channel number[/]")
                return
            mon = self.mon_iface or WLAN
            log.write(f"[bold cyan]Capturing handshake from {essid or bssid} (ch {channel})...[/]")
            self.query_one("#wifi-capture", Button).disabled = True

            def cb(line):
                self.call_from_thread(log.write, line)
            def on_done(result):
                self.call_from_thread(self._on_capture_done, result)

            threading.Thread(
                target=lambda: on_done(capture_handshake(bssid, channel, essid, mon, 30, cb)),
                daemon=True,
            ).start()

        elif bid == "wifi-analyze":
            sel = self.query_one("#wifi-capture-list", SelectionList)
            selected = sel.selected
            if not selected:
                log.write("[red]Select a capture file below[/]")
                return
            fpath = str(CAPTURES_DIR / selected[0])
            log.write(f"[cyan]Analyzing: {selected[0]}[/]")
            analysis = analyze_cap(fpath)
            log.write(
                f"  Size: {analysis['size_kb']} KB  |  "
                f"APs: {analysis['aps']}  |  "
                f"Handshakes: {analysis['handshakes']}  |  "
                f"Packets: {analysis['packets']}"
            )
            if analysis["handshakes"] > 0:
                log.write("[green]Handshake found! → Click 'Crack'[/]")
                self.query_one("#wifi-crack", Button).disabled = False
            else:
                log.write("[yellow]No handshake. Try capturing again.[/]")

        elif bid == "wifi-crack":
            sel = self.query_one("#wifi-capture-list", SelectionList)
            selected = sel.selected
            if not selected:
                log.write("[red]Select a capture file below[/]")
                return
            wordlists = list(WORDLISTS_DIR.glob("*.txt")) + list(WORDLISTS_DIR.glob("*.lst"))
            if not wordlists:
                log.write("[yellow]No wordlists. Download one from Wordlists tab.[/]")
                return
            wl = str(wordlists[0])
            fpath = str(CAPTURES_DIR / selected[0])
            log.write(f"[bold cyan]Cracking: {selected[0]} with {os.path.basename(wl)}[/]")
            self.query_one("#wifi-crack", Button).disabled = True

            def cb(line):
                self.call_from_thread(log.write, line)
            def on_done(result):
                self.call_from_thread(self._on_crack_done, result)

            threading.Thread(
                target=lambda: on_done(crack_handshake(fpath, wl, line_callback=cb)),
                daemon=True,
            ).start()

        elif bid == "wifi-wps":
            bssid = self.query_one("#wifi-bssid", Input).value.strip()
            if not bssid:
                log.write("[red]Select an AP from the table first[/]")
                return
            essid = self.query_one("#wifi-essid", Input).value.strip()
            log.write(f"[bold cyan]WPS attack on {essid or bssid} via reaver...[/]")
            self.query_one("#wifi-wps", Button).disabled = True

            def cb(line):
                self.call_from_thread(log.write, line)

            def do_reaver():
                from core.run import run as _r
                _r(["reaver", "-i", self.mon_iface or WLAN, "-b", bssid, "-vv"], timeout=300)
                self.call_from_thread(log.write, "[dim]Reaver attack finished[/]")
                self.call_from_thread(self._enable_wps_button)

            threading.Thread(target=do_reaver, daemon=True).start()

    def _run_scan(self):
        log = self.query_one("#wifi-log", RichLog)
        table = self.query_one("#wifi-results", DataTable)
        hint = self.query_one("#wifi-select-hint", Static)
        run_cmd(["timeout", "8", "airodump-ng", WLAN, "--band", "bg",
                 "--write", "/tmp/adboard", "--output-format", "csv",
                 "--background", "1"])
        aps = parse_airodump_csv("/tmp/adboard-01.csv")
        for i, ap in enumerate(aps, 1):
            vendor = lookup_mac(ap["bssid"])
            self.call_from_thread(
                table.add_row, str(i), vendor, ap["bssid"], ap["signal"], ap["enc"], ap["essid"],
            )
        self.call_from_thread(
            hint.update,
            f"[green]{len(aps)} APs found.[/]  [dim]↑↓ select a row → auto-fills below[/]"
            if aps else "[yellow]No APs found. Try running as root.[/]",
        )

    def _on_capture_done(self, result):
        log = self.query_one("#wifi-log", RichLog)
        self.query_one("#wifi-capture", Button).disabled = False
        if result.get("success"):
            log.write("[green]Handshake captured![/] → Analyze and crack below")
            self.query_one("#wifi-analyze", Button).disabled = False
        else:
            log.write(f"[yellow]Capture: {result.get('error', 'no handshake')}[/]")
        self._refresh_captures()

    def _on_crack_done(self, result):
        log = self.query_one("#wifi-log", RichLog)
        self.query_one("#wifi-crack", Button).disabled = False
        if result.get("key"):
            log.write(f"[bold green]KEY FOUND: {result['key']}[/]")
        else:
            log.write("[yellow]Key not found. Try a different wordlist.[/]")

    def _enable_wps_button(self):
        self.query_one("#wifi-wps", Button).disabled = False

    def _refresh_captures(self):
        sel = self.query_one("#wifi-capture-list", SelectionList)
        sel.clear_options()
        if not CAPTURES_DIR.exists():
            return
        for f in sorted(CAPTURES_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
            if f.suffix in (".cap", ".pcap", ".pcapng"):
                size_kb = round(f.stat().st_size / 1024, 1)
                sel.add_option((f"{f.name} ({size_kb} KB)", f.name, False))
