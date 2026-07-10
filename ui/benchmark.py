"""Benchmark tab — compare tools side-by-side."""

import shutil

from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, DataTable, RichLog

from core.tools import detect_tools, benchmark_tool, BENCHMARK_SCANS


class BenchmarkTab(ScrollableContainer):
    def compose(self):
        yield Static("[bold]Tool Benchmarking[/]", classes="section-title")
        yield Static(
            "Compare tools side-by-side: execution time and output size.\n"
            "The dashboard will recommend the best tool based on performance.",
            id="bench-desc",
        )
        yield Horizontal(
            Button("Benchmark All Scanners", id="bench-all", variant="primary"),
            Button("Compare nmap vs ping", id="bench-compare", variant="primary"),
            Button("Clear Results", id="bench-clear", variant="default"),
            id="bench-buttons",
        )
        yield DataTable(id="bench-table")
        yield RichLog(id="bench-log", highlight=True)

    def on_mount(self):
        table = self.query_one("#bench-table", DataTable)
        table.add_columns("Test", "Tool", "Time (s)", "Output (KB)", "Result")

    def on_button_pressed(self, event: Button.Pressed):
        log = self.query_one("#bench-log", RichLog)
        table = self.query_one("#bench-table", DataTable)

        if event.button.id == "bench-clear":
            table.clear()
            log.clear()
            return

        if event.button.id == "bench-all":
            log.write("[cyan]Benchmarking all available tools...[/]")
            tools = detect_tools()
            for name, info in tools.items():
                if not info["available"] or info["category"] not in ("scanner", "wifi", "cracker"):
                    continue
                log.write(f"  Testing {name}...")
                bm = benchmark_tool(info["bin"], ["--version"])
                table.add_row(
                    "Version check", name,
                    str(bm.get("time", "?")),
                    f"{bm.get('stdout_len', 0) / 1024:.1f}",
                    "OK" if not bm.get("error") else bm["error"],
                )
            log.write("[green]Benchmark complete[/]")

        if event.button.id == "bench-compare":
            log.write("[cyan]Comparing scan methods...[/]")
            table.clear()
            for scan_name, scan_info in BENCHMARK_SCANS.items():
                label = scan_info.get("label", scan_name)
                for tool_name, cmd in scan_info.items():
                    if tool_name == "label":
                        continue
                    if not shutil.which(cmd[0]):
                        log.write(f"  [yellow]{cmd[0]} not installed, skipping[/]")
                        continue
                    log.write(f"  Running {cmd[0]}...")
                    bm = benchmark_tool(cmd[0], cmd[1:], timeout=30)
                    table.add_row(
                        label, cmd[0],
                        str(bm.get("time", "?")),
                        f"{(bm.get('stdout_len', 0) + bm.get('stderr_len', 0)) / 1024:.1f}",
                        f"exit {bm.get('returncode', '?')}" if not bm.get("error") else bm["error"],
                    )
            log.write("[green]Comparison complete. Faster = better for quick scans.[/]")
