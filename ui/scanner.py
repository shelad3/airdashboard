"""Scanner tab — network scanning with selectable results and deep scan."""

import re
import time
import threading

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, DataTable, RichLog, Input

from core.scanner import ScanRunner, save_scan, get_previous_scan, diff_hosts, get_db
from core.run import run as _run
from core.tools import lookup_mac


class ScannerTab(ScrollableContainer):
    """Interactive scanner: scan → select host → deep scan → ports/services."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Network Scanner[/]", classes="section-title")
        yield Static(
            "  [dim]Step 1:[/] Discover Hosts   →   "
            "[dim]Step 2:[/] Select Host   →   "
            "[dim]Step 3:[/] Deep Scan",
            id="scan-workflow",
        )
        yield Horizontal(
            Button("1) Ping Sweep (nmap -sn)", id="scan-nmap-ping", variant="primary"),
            Button("1) TCP Top Ports", id="scan-nmap-tcp", variant="primary"),
            Button("1) Stealth Scan", id="scan-nmap-stealth", variant="primary"),
            Button("1) Masscan (fast)", id="scan-masscan", variant="primary"),
            Button("History", id="scan-history", variant="default"),
            Button("Stop", id="scan-stop", variant="error"),
            id="scan-buttons",
        )
        yield Static("", id="scan-status")
        yield DataTable(id="scan-results")
        yield Static(
            "[dim]↑↓ select a host → deep scan it[/]",
            id="scan-select-hint",
        )
        yield Horizontal(
            Static("Target:", classes="label"),
            Input(id="scan-target-input", placeholder="auto-filled from table"),
            Button("2) Deep Scan (ports+services)", id="scan-deep", variant="success", disabled=True),
            Button("2) Vuln Scan (nmap scripts)", id="scan-vuln", variant="warning", disabled=True),
            id="scan-action-row",
        )
        yield RichLog(id="scan-log", highlight=True, max_lines=500)

    def on_mount(self):
        self.runner = None
        self.scan_hosts = []
        self.scan_tool = ""
        self.scan_target = ""
        table = self.query_one("#scan-results", DataTable)
        table.add_columns("#", "Address", "Hostname", "Detail")
        table.cursor_type = "row"

    def onDataTableRowSelected(self, event: DataTable.RowSelected):
        """Auto-fill target when a host row is selected."""
        table = self.query_one("#scan-results", DataTable)
        try:
            row = table.get_row_at(event.cursor_row)
        except Exception:
            return
        if len(row) >= 3:
            addr = str(row[1]).strip()
            hostname = str(row[2]).strip()
            self.query_one("#scan-target-input", Input).value = addr
            self.query_one("#scan-deep", Button).disabled = False
            self.query_one("#scan-vuln", Button).disabled = False
            log = self.query_one("#scan-log", RichLog)
            log.write(f"[green]Selected:[/] {hostname or addr}  → Click Deep Scan or Vuln Scan")

    def on_button_pressed(self, event: Button.Pressed):
        log = self.query_one("#scan-log", RichLog)
        table = self.query_one("#scan-results", DataTable)
        status = self.query_one("#scan-status")
        hint = self.query_one("#scan-select-hint", Static)
        bid = event.button.id

        if bid == "scan-stop":
            if self.runner:
                self.runner.stop()
                log.write("[red]Scan stopped[/]")
            return

        if bid == "scan-history":
            self.show_history()
            return

        if bid == "scan-deep":
            target = self.query_one("#scan-target-input", Input).value.strip()
            if not target:
                log.write("[red]Select a host from the table first[/]")
                return
            log.write(f"[cyan]Deep scanning {target} (ports + services)...[/]")
            self._run_deep_scan(target, [
                "nmap", "-sV", "-sC", "-T4", "-p-", target,
            ], "Deep Scan")
            return

        if bid == "scan-vuln":
            target = self.query_one("#scan-target-input", Input).value.strip()
            if not target:
                log.write("[red]Select a host from the table first[/]")
                return
            log.write(f"[cyan]Vulnerability scanning {target} (nmap scripts)...[/]")
            self._run_deep_scan(target, [
                "nmap", "--script", "vuln", "-T4", target,
            ], "Vuln Scan")
            return

        scans = {
            "scan-nmap-ping": ("ping-sweep", "192.168.1.0/24", ["nmap", "-sn", "192.168.1.0/24"]),
            "scan-nmap-tcp": ("tcp-top", "192.168.1.0/24", ["nmap", "-T4", "-F", "192.168.1.0/24"]),
            "scan-nmap-stealth": ("stealth", "192.168.1.0/24", ["nmap", "-sS", "-T4", "-F", "192.168.1.0/24"]),
            "scan-masscan": ("masscan", "192.168.1.0/24", ["masscan", "192.168.1.0/24", "-p80,443,22,21,25,8080,8443", "--rate=1000"]),
        }
        scan_info = scans.get(bid)
        if not scan_info:
            return

        scan_type, target, cmd = scan_info
        self.scan_tool = cmd[0]
        self.scan_target = target
        self.scan_type = scan_type
        self.scan_hosts = []

        status.update(f"[bold cyan]Running: {' '.join(cmd)}[/]")
        hint.update("[dim]Scanning...[/]")
        log.clear()
        table.clear()

        def on_line(line):
            self.call_from_thread(log.write, line)
            parsed = re.search(r"Nmap scan report for (.+)", line)
            if parsed:
                addr = parsed.group(1).strip("()")
                self.scan_hosts.append({"address": addr, "hostname": addr, "ports": ""})
            # masscan: Discovered open port 80/tcp on 192.168.1.1
            masscan_match = re.search(r"Discovered open port (\d+/tcp) on (\S+)", line)
            if masscan_match:
                port = masscan_match.group(1)
                addr = masscan_match.group(2)
                # Dedupe
                existing = [h for h in self.scan_hosts if h["address"] == addr]
                if existing:
                    if existing[0]["ports"]:
                        existing[0]["ports"] += f", {port}"
                    else:
                        existing[0]["ports"] = port
                else:
                    self.scan_hosts.append({"address": addr, "hostname": addr, "ports": port})

        self.runner = ScanRunner(callback=on_line)
        t = threading.Thread(target=self.finish_scan, args=(cmd, scan_type, target), daemon=True)
        t.start()

    def _run_deep_scan(self, target, cmd, label):
        log = self.query_one("#scan-log", RichLog)
        status = self.query_one("#scan-status")
        hint = self.query_one("#scan-select-hint", Static)
        table = self.query_one("#scan-results", DataTable)

        status.update(f"[bold cyan]{label}: {' '.join(cmd)}[/]")
        hint.update(f"[dim]{label} running on {target}...[/]")

        def on_line(line):
            self.call_from_thread(log.write, line)

        def do_scan():
            runner = ScanRunner(callback=on_line)
            runner.run(cmd, 180)
            self.call_from_thread(status.update, f"[green]{label} complete on {target}[/]")
            self.call_from_thread(hint.update, f"[green]{label} done.[/]  [dim]select another host or scan type[/]")

        threading.Thread(target=do_scan, daemon=True).start()

    def finish_scan(self, cmd, scan_type, target):
        self.runner.run(cmd, 120)
        time.sleep(0.3)
        self.call_from_thread(self._save_and_diff)

    def _save_and_diff(self):
        log = self.query_one("#scan-log", RichLog)
        status = self.query_one("#scan-status")
        table = self.query_one("#scan-results", DataTable)
        hint = self.query_one("#scan-select-hint", Static)

        if not self.scan_hosts:
            status.update("[yellow]No hosts found[/]")
            hint.update("[yellow]No hosts. Try a different scan or subnet.[/]")
            return

        save_scan(self.scan_type, self.scan_target, self.scan_tool, ["nmap"], self.scan_hosts)
        prev = get_previous_scan(self.scan_type, self.scan_target, self.scan_tool)

        for i, h in enumerate(self.scan_hosts, 1):
            table.add_row(str(i), h["address"], h.get("hostname", ""), "")

        if prev:
            added, removed = diff_hosts(prev["hosts"], self.scan_hosts)
            diff_text = ""
            if added:
                diff_text += f"\n[green]+ {len(added)} new:[/] " + ", ".join(h["address"] for h in added[:5])
                for h in added:
                    table.add_row("[green]+[/]", h["address"], h.get("hostname", ""), "[green]NEW[/]")
            if removed:
                diff_text += f"\n[red]- {len(removed)} gone:[/] " + ", ".join(h["address"] for h in removed[:5])
            if not added and not removed:
                diff_text = "\n[blue]No changes[/]"
            log.write(f"[bold cyan]Diff:[/]{diff_text}")
            status.update(f"[green]{len(self.scan_hosts)} hosts ({len(added)} new, {len(removed)} gone)[/]")
        else:
            status.update(f"[green]{len(self.scan_hosts)} hosts (first scan)[/]")

        hint.update(
            f"[green]{len(self.scan_hosts)} hosts found.[/]  "
            f"[dim]↑↓ select a host → deep scan / vuln scan below[/]"
        )

    def show_history(self):
        log = self.query_one("#scan-log", RichLog)
        conn = get_db()
        cur = conn.execute("SELECT id, timestamp, scan_type, target, tool FROM scans ORDER BY timestamp DESC LIMIT 20")
        rows = cur.fetchall()
        conn.close()
        log.write("[bold cyan]--- Scan History (last 20) ---[/]")
        for row in rows:
            ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(row[1]))
            log.write(f"  #{row[0]} {ts} | {row[2]} | {row[3]} | {row[4]}")
        if not rows:
            log.write("  [yellow]No scans recorded yet[/]")
