"""Wordlist tab — download and manage password wordlists."""

from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, DataTable, SelectionList, ProgressBar

from core.wordlist import WORDLISTS, download_wordlist, get_local_wordlists


class WordlistTab(ScrollableContainer):
    def compose(self):
        yield Static("[bold]Wordlist Manager[/]", classes="section-title")
        yield Static("Download and manage password wordlists for cracking.", id="wl-desc")
        yield SelectionList[str](id="wl-list")
        yield Horizontal(
            Button("Download Selected", id="wl-download", variant="primary"),
            Button("Show Local", id="wl-local", variant="default"),
            id="wl-buttons",
        )
        yield ProgressBar(id="wl-progress")
        yield DataTable(id="wl-results")

    def on_mount(self):
        sel = self.query_one("#wl-list", SelectionList)
        for name, info in WORDLISTS.items():
            sel.add_option((f"{name} ({info['size_mb']}MB) - {info['desc']}", name, False))
        table = self.query_one("#wl-results", DataTable)
        table.add_columns("Name", "Size", "Type")
        self.query_one("#wl-progress", ProgressBar).display = False

    def on_button_pressed(self, event: Button.Pressed):
        log = self.query_one("#wl-results", DataTable)
        progress = self.query_one("#wl-progress", ProgressBar)

        if event.button.id == "wl-local":
            log.clear()
            for wl in get_local_wordlists():
                log.add_row(wl["name"], f"{wl['size_mb']} MB", "local")
            return

        if event.button.id == "wl-download":
            sel = self.query_one("#wl-list", SelectionList)
            selected = sel.selected
            if not selected:
                self.notify("Select at least one wordlist")
                return
            for name in selected:
                progress.display = True
                progress.update(total=100, progress=0)

                def cb(pct):
                    self.call_from_thread(progress.update, progress=pct)

                result = download_wordlist(name, cb)
                if result is True:
                    log.add_row(name, f"{WORDLISTS[name]['size_mb']} MB", "downloaded")
                else:
                    log.add_row(name, "error", str(result))
            progress.display = False
