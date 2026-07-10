"""Web Recon tab — nikto, gobuster, whatweb, sqlmap, wpscan, ffuf with interactive workflow."""

import threading
from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, DataTable, RichLog, Input, Select

from core.web import (
    nikto_scan, gobuster_dir, gobuster_dns, whatweb_scan,
    sqlmap_scan, wpscan_scan, ffuf_fuzz,
)
from core.tools import lookup_mac


class WebReconTab(ScrollableContainer):
    """Interactive web reconnaissance: target → scan → findings → deeper scan."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Web Reconnaissance[/]", classes="section-title")
        yield Static(
            "  [dim]Target[/] →  [dim]Scan[/] →  [dim]Findings[/] →  [dim]Deep Scan[/]",
            id="web-workflow",
        )

        # Target input
        yield Horizontal(
            Static("Target URL:", classes="label"),
            Input(id="web-target", placeholder="http://192.168.1.1 or https://example.com"),
            Button("Scan", id="web-go", variant="primary"),
            id="web-target-row",
        )

        # Scan type buttons
        yield Horizontal(
            Button("Nikto (vulns)", id="web-nikto", variant="primary"),
            Button("Gobuster (dirs)", id="web-gobuster", variant="primary"),
            Button("Gobuster (DNS)", id="web-gobuster-dns", variant="primary"),
            Button("WhatWeb (tech)", id="web-whatweb", variant="primary"),
            Button("FFUF (fuzz)", id="web-ffuf", variant="primary"),
            id="web-scan-buttons",
        )

        yield Static("[dim]WordPress? Use WPScan ↓   SQLi? Use sqlmap ↓[/]", id="web-hint")

        yield Horizontal(
            Button("WPScan", id="web-wpscan", variant="warning", disabled=True),
            Button("SQLMap (select URL)", id="web-sqlmap", variant="warning", disabled=True),
            id="web-deep-buttons",
        )

        # Results
        yield DataTable(id="web-results")
        yield Static("[dim]↑↓ select a finding → deeper scan below[/]", id="web-select-hint")

        # Action row
        yield Horizontal(
            Static("URL:", classes="label"),
            Input(id="web-action-url", placeholder="auto-filled from selection"),
            Button("Re-scan finding", id="web-rescan", variant="success", disabled=True),
            id="web-action-row",
        )

        yield RichLog(id="web-log", highlight=True, max_lines=500)

    def on_mount(self):
        self.last_results = []
        self.current_tool = ""
        table = self.query_one("#web-results", DataTable)
        table.add_columns("#", "Finding", "Details")
        table.cursor_type = "row"

    def onDataTableRowSelected(self, event: DataTable.RowSelected):
        table = self.query_one("#web-results", DataTable)
        try:
            row = table.get_row_at(event.cursor_row)
        except Exception:
            return
        if len(row) >= 2:
            finding = str(row[1]).strip()
            detail = str(row[2]).strip() if len(row) > 2 else ""
            # Auto-fill URL field for deep scan
            target = self.query_one("#web-target", Input).value.strip()
            if finding.startswith("/"):
                url = target.rstrip("/") + finding
            elif finding.startswith("http"):
                url = finding
            else:
                url = target
            self.query_one("#web-action-url", Input).value = url
            self.query_one("#web-sqlmap", Button).disabled = False
            self.query_one("#web-rescan", Button).disabled = False
            log = self.query_one("#web-log", RichLog)
            log.write(f"[green]Selected:[/] {finding}  → WPScan / SQLMap / Re-scan")

    def on_button_pressed(self, event: Button.Pressed):
        log = self.query_one("#web-log", RichLog)
        table = self.query_one("#web-results", DataTable)
        bid = event.button.id

        if bid in ("web-go", "web-nikto", "web-gobuster", "web-gobuster-dns",
                   "web-whatweb", "web-ffuf", "web-wpscan", "web-sqlmap", "web-rescan"):
            target = self.query_one("#web-target", Input).value.strip()
            if not target:
                log.write("[red]Enter a target URL first[/]")
                return
            if not target.startswith("http"):
                target = "http://" + target
                self.query_one("#web-target", Input).value = target

        if bid == "web-nikto":
            log.write(f"[bold cyan]Running nikto on {target}...[/]")
            table.clear()
            self.last_results = []
            self.current_tool = "nikto"
            self.query_one("#web-hint", Static).update("[dim]Nikto scanning...[/]")
            threading.Thread(target=self._run_nikto, args=(target,), daemon=True).start()

        elif bid == "web-gobuster":
            log.write(f"[bold cyan]Running gobuster dir on {target}...[/]")
            table.clear()
            self.last_results = []
            self.current_tool = "gobuster"
            self.query_one("#web-hint", Static).update("[dim]Gobuster scanning...[/]")
            threading.Thread(target=self._run_gobuster_dir, args=(target,), daemon=True).start()

        elif bid == "web-gobuster-dns":
            log.write(f"[bold cyan]Running gobuster DNS on {target}...[/]")
            table.clear()
            self.last_results = []
            self.current_tool = "gobuster-dns"
            self.query_one("#web-hint", Static).update("[dim]Gobuster DNS scanning...[/]")
            threading.Thread(target=self._run_gobuster_dns, args=(target,), daemon=True).start()

        elif bid == "web-whatweb":
            log.write(f"[bold cyan]Running whatweb on {target}...[/]")
            table.clear()
            self.last_results = []
            self.current_tool = "whatweb"
            self.query_one("#web-hint", Static).update("[dim]WhatWeb scanning...[/]")
            threading.Thread(target=self._run_whatweb, args=(target,), daemon=True).start()

        elif bid == "web-ffuf":
            log.write(f"[bold cyan]Running ffuf on {target}...[/]")
            table.clear()
            self.last_results = []
            self.current_tool = "ffuf"
            self.query_one("#web-hint", Static).update("[dim]FFUF fuzzing...[/]")
            threading.Thread(target=self._run_ffuf, args=(target,), daemon=True).start()

        elif bid == "web-wpscan":
            log.write(f"[bold cyan]Running wpscan on {target}...[/]")
            table.clear()
            self.last_results = []
            self.current_tool = "wpscan"
            self.query_one("#web-hint", Static).update("[dim]WPScan scanning...[/]")
            threading.Thread(target=self._run_wpscan, args=(target,), daemon=True).start()

        elif bid == "web-sqlmap":
            action_url = self.query_one("#web-action-url", Input).value.strip()
            url = action_url or target
            log.write(f"[bold cyan]Running sqlmap on {url}...[/]")
            table.clear()
            self.last_results = []
            self.current_tool = "sqlmap"
            self.query_one("#web-hint", Static).update("[dim]SQLMap scanning... (this may take a while)[/]")
            threading.Thread(target=self._run_sqlmap, args=(url,), daemon=True).start()

        elif bid == "web-rescan":
            action_url = self.query_one("#web-action-url", Input).value.strip()
            if not action_url:
                log.write("[red]No URL selected[/]")
                return
            log.write(f"[cyan]Re-scanning: {action_url}[/]")
            threading.Thread(target=self._run_nikto, args=(action_url,), daemon=True).start()

    def _run_nikto(self, target):
        def cb(line):
            self.call_from_thread(self.query_one("#web-log", RichLog).write, line)
        result = nikto_scan(target, callback=cb)
        self.call_from_thread(self._show_nikto_results, result)

    def _show_nikto_results(self, result):
        table = self.query_one("#web-results", DataTable)
        table.clear()
        self.last_results = result["vulns"]
        for i, v in enumerate(result["vulns"], 1):
            table.add_row(str(i), v["id"], v["description"])
        self.query_one("#web-hint", Static).update(
            f"[green]{result['total']} vulnerabilities found.[/]" if result["total"]
            else "[yellow]No vulnerabilities found.[/]"
        )
        self.query_one("#web-log", RichLog).write(
            f"[bold green]Nikto: {result['total']} findings[/]" if result["total"]
            else "[yellow]Nikto: no findings[/]"
        )

    def _run_gobuster_dir(self, target):
        def cb(line):
            self.call_from_thread(self.query_one("#web-log", RichLog).write, line)
        result = gobuster_dir(target, callback=cb)
        self.call_from_thread(self._show_gobuster_results, result)

    def _run_gobuster_dns(self, target):
        def cb(line):
            self.call_from_thread(self.query_one("#web-log", RichLog).write, line)
        result = gobuster_dns(target, callback=cb)
        table = self.query_one("#web-results", DataTable)
        self.call_from_thread(table.clear)
        self.last_results = []
        for i, sub in enumerate(result["subdomains"], 1):
            self.call_from_thread(table.add_row, str(i), sub, "")
        self.call_from_thread(
            self.query_one("#web-hint", Static).update,
            f"[green]{result['total']} subdomains found.[/]" if result["total"]
            else "[yellow]No subdomains found.[/]"
        )
        self.call_from_thread(
            self.query_one("#web-log", RichLog).write,
            f"[bold green]Gobuster DNS: {result['total']} subdomains[/]" if result["total"]
            else "[yellow]Gobuster DNS: no results[/]"
        )

    def _show_gobuster_results(self, result):
        table = self.query_one("#web-results", DataTable)
        table.clear()
        self.last_results = result["dirs"]
        for i, d in enumerate(result["dirs"], 1):
            table.add_row(str(i), d["path"], f"Status {d['status']}  Size {d['size']}")
        self.query_one("#web-hint", Static).update(
            f"[green]{result['total']} directories found.[/]" if result["total"]
            else "[yellow]No directories found.[/]"
        )
        self.query_one("#web-log", RichLog).write(
            f"[bold green]Gobuster: {result['total']} directories[/]" if result["total"]
            else "[yellow]Gobuster: no results[/]"
        )

    def _run_whatweb(self, target):
        def cb(line):
            self.call_from_thread(self.query_one("#web-log", RichLog).write, line)
        result = whatweb_scan(target, callback=cb)
        table = self.query_one("#web-results", DataTable)
        self.call_from_thread(table.clear)
        self.last_results = result["technologies"]
        for i, t in enumerate(result["technologies"], 1):
            ver = f" v{t['version']}" if t.get("version") else ""
            self.call_from_thread(table.add_row, str(i), t["name"], ver)
        self.call_from_thread(
            self.query_one("#web-hint", Static).update,
            f"[green]{result['total']} technologies detected.[/]" if result["total"]
            else "[yellow]No technologies detected.[/]"
        )
        self.call_from_thread(
            self.query_one("#web-log", RichLog).write,
            f"[bold green]WhatWeb: {result['total']} technologies[/]" if result["total"]
            else "[yellow]WhatWeb: no results[/]"
        )

    def _run_ffuf(self, target):
        def cb(line):
            self.call_from_thread(self.query_one("#web-log", RichLog).write, line)
        result = ffuf_fuzz(target, callback=cb)
        table = self.query_one("#web-results", DataTable)
        self.call_from_thread(table.clear)
        self.last_results = result["results"]
        for i, r in enumerate(result["results"], 1):
            self.call_from_thread(table.add_row, str(i), r["path"], f"Status {r['status']}  Size {r['size']}")
        self.call_from_thread(
            self.query_one("#web-hint", Static).update,
            f"[green]{result['total']} fuzz results.[/]" if result["total"]
            else "[yellow]No fuzz results.[/]"
        )
        self.call_from_thread(
            self.query_one("#web-log", RichLog).write,
            f"[bold green]FFUF: {result['total']} results[/]" if result["total"]
            else "[yellow]FFUF: no results[/]"
        )

    def _run_wpscan(self, target):
        def cb(line):
            self.call_from_thread(self.query_one("#web-log", RichLog).write, line)
        result = wpscan_scan(target, callback=cb)
        table = self.query_one("#web-results", DataTable)
        self.call_from_thread(table.clear)
        self.last_results = result["findings"]
        for i, f in enumerate(result["findings"], 1):
            self.call_from_thread(table.add_row, str(i), f[:80], f[80:] if len(f) > 80 else "")
        self.call_from_thread(
            self.query_one("#web-hint", Static).update,
            f"[green]{result['total']} WPScan findings.[/]" if result["total"]
            else "[yellow]No WPScan findings.[/]"
        )
        self.call_from_thread(
            self.query_one("#web-log", RichLog).write,
            f"[bold green]WPScan: {result['total']} findings[/]" if result["total"]
            else "[yellow]WPScan: no findings[/]"
        )

    def _run_sqlmap(self, url):
        def cb(line):
            self.call_from_thread(self.query_one("#web-log", RichLog).write, line)
        result = sqlmap_scan(url, callback=cb)
        table = self.query_one("#web-results", DataTable)
        self.call_from_thread(table.clear)
        self.last_results = result["injections"]
        for i, inj in enumerate(result["injections"], 1):
            self.call_from_thread(table.add_row, str(i), inj[:80], inj[80:] if len(inj) > 80 else "")
        self.call_from_thread(
            self.query_one("#web-hint", Static).update,
            f"[green]{result['total']} SQL injection findings.[/]" if result["total"]
            else "[yellow]No SQL injection found.[/]"
        )
        self.call_from_thread(
            self.query_one("#web-log", RichLog).write,
            f"[bold green]SQLMap: {result['total']} findings[/]" if result["total"]
            else "[yellow]SQLMap: no findings[/]"
        )
