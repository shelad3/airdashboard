"""Live Log tab — centralized timestamped log console."""

from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, RichLog

import datetime


class LiveLogTab(ScrollableContainer):
    def compose(self):
        yield Static("[bold]Live Log Console[/]", classes="section-title")
        yield Horizontal(
            Button("Clear", id="log-clear", variant="default"),
            Button("Pause / Resume", id="log-pause", variant="default"),
            id="log-buttons",
        )
        yield Static("", id="log-count")
        yield RichLog(id="live-log", highlight=True, max_lines=2000)

    def on_mount(self):
        self.paused = False
        self.line_count = 0
        self.buffer = []
        self.add_log("[green]Log console started[/]", "system")

    def add_log(self, text, category="info"):
        if self.paused:
            self.buffer.append((text, category))
            return
        self.line_count += 1
        log = self.query_one("#live-log", RichLog)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        labels = {"info": "", "scan": "[cyan]", "wifi": "[yellow]", "crack": "[red]", "system": "[green]"}
        prefix = labels.get(category, "")
        log.write(f"{prefix}[{ts}] {text}[/]")
        self.query_one("#log-count", Static).update(f"Lines: {self.line_count}")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "log-clear":
            self.query_one("#live-log", RichLog).clear()
            self.line_count = 0
            self.query_one("#log-count", Static).update("Lines: 0")
        elif event.button.id == "log-pause":
            self.paused = not self.paused
            event.button.label = "Resume" if self.paused else "Pause"
            if not self.paused and self.buffer:
                for text, cat in self.buffer:
                    self.add_log(text, cat)
                self.buffer.clear()
