"""Password Attacks tab — hydra, john, hashcat, cewl with interactive workflow."""

import os
import threading
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, ScrollableContainer
from textual.widgets import Static, Button, DataTable, RichLog, Input, Select, SelectionList

from core.password import hydra_brute, john_crack, hashcat_crack, cewl_wordlist
from core.wordlist import get_local_wordlists, WORDLIST_DIR

HASH_TYPES = [
    ("MD5 (0)", 0),
    ("NTLM (1000)", 1000),
    ("SHA1 (100)", 100),
    ("SHA256 (1400)", 1400),
    ("SHA512crypt (1800)", 1800),
    ("bcrypt (3200)", 3200),
    ("Kerberos 5 TGS (13100)", 13100),
]

HYDRA_SERVICES = [
    ("SSH", "ssh"),
    ("FTP", "ftp"),
    ("Telnet", "telnet"),
    ("HTTP Basic Auth", "http-get"),
    ("HTTP POST Form", "http-post-form"),
    ("MySQL", "mysql"),
    ("PostgreSQL", "postgres"),
    ("RDP", "rdp"),
    ("SMB", "smb"),
    ("SNMP", "snmp"),
]


class PasswordAttacksTab(ScrollableContainer):
    """Password attack workflows: online brute (hydra), offline crack (john/hashcat), wordlist gen (cewl)."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Password Attacks[/]", classes="section-title")
        yield Static(
            "  [dim]Online:[/] Hydra brute force  →  "
            "[dim]Offline:[/] John / Hashcat  →  "
            "[dim]Wordlist Gen:[/] CeWL",
            id="pw-workflow",
        )

        # Hydra section
        yield Static("[bold]Online Brute Force (Hydra)[/]", classes="section-title")
        yield Horizontal(
            Static("Target IP:", classes="label"),
            Input(id="pw-target", placeholder="192.168.1.1"),
            Static("Service:", classes="label"),
            Select(
                options=[(label, val) for label, val in HYDRA_SERVICES],
                value="ssh",
                id="pw-service",
                allow_blank=False,
            ),
            Static("User:", classes="label"),
            Input(id="pw-username", placeholder="root"),
            Button("Brute Force", id="pw-hydra", variant="warning"),
            id="pw-hydra-row",
        )
        yield Horizontal(
            Static("User List:", classes="label"),
            Input(id="pw-userlist", placeholder="path to user list (optional)"),
            Static("Pass List:", classes="label"),
            Input(id="pw-passlist", placeholder="path to wordlist"),
            Button("Browse Wordlists", id="pw-browse", variant="default"),
            id="pw-hydra-files",
        )

        # John / Hashcat section
        yield Static("[bold]Offline Hash Cracking[/]", classes="section-title")
        yield Horizontal(
            Static("Hash File:", classes="label"),
            Input(id="pw-hashfile", placeholder="/path/to/hashes.txt"),
            Static("Hash Type:", classes="label"),
            Select(
                options=HASH_TYPES,
                value=0,
                id="pw-hashtype",
                allow_blank=False,
            ),
            Button("John (CPU)", id="pw-john", variant="success"),
            Button("Hashcat (GPU)", id="pw-hashcat", variant="success", disabled=True),
            id="pw-crack-row",
        )
        yield Horizontal(
            Static("Wordlist:", classes="label"),
            Input(id="pw-crack-wordlist", placeholder="path to wordlist for cracking"),
            id="pw-crack-files",
        )

        # Wordlist generation
        yield Static("[bold]Wordlist Generation (CeWL)[/]", classes="section-title")
        yield Horizontal(
            Static("URL:", classes="label"),
            Input(id="pw-cewl-url", placeholder="https://example.com"),
            Static("Depth:", classes="label"),
            Input(id="pw-cewl-depth", placeholder="2"),
            Button("Generate Wordlist", id="pw-cewl", variant="primary"),
            id="pw-cewl-row",
        )

        # Local wordlists
        yield SelectionList[str](id="pw-wordlist-list")

        # Results
        yield DataTable(id="pw-results")
        yield RichLog(id="pw-log", highlight=True, max_lines=500)

    def on_mount(self):
        table = self.query_one("#pw-results", DataTable)
        table.add_columns("#", "Username", "Password", "Host/Service")
        table.cursor_type = "row"
        self._refresh_wordlists()

    def _refresh_wordlists(self):
        sel = self.query_one("#pw-wordlist-list", SelectionList)
        sel.clear_options()
        wordlists = get_local_wordlists()
        for wl in wordlists:
            sel.add_option((f"{wl['name']} ({wl['size_mb']} MB)", wl['path'], False))
        # Also check system wordlists
        for p in [Path("/usr/share/wordlists/rockyou.txt"),
                  Path("/usr/share/wordlists/dirb/common.txt"),
                  Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")]:
            if p.exists():
                size_mb = round(p.stat().st_size / 1e6, 1)
                sel.add_option((f"{p.name} (system, {size_mb} MB)", str(p), False))

    def on_button_pressed(self, event: Button.Pressed):
        log = self.query_one("#pw-log", RichLog)
        table = self.query_one("#pw-results", DataTable)
        bid = event.button.id

        if bid == "pw-hydra":
            target = self.query_one("#pw-target", Input).value.strip()
            service = self.query_one("#pw-service").value
            username = self.query_one("#pw-username", Input).value.strip()
            userlist = self.query_one("#pw-userlist", Input).value.strip()
            passlist = self.query_one("#pw-passlist", Input).value.strip()

            if not target:
                log.write("[red]Enter a target IP[/]")
                return
            if not passlist:
                # Check wordlist selection
                sel = self.query_one("#pw-wordlist-list", SelectionList)
                selected = sel.selected
                if selected:
                    passlist = str(selected[0])
                else:
                    log.write("[red]Select or enter a wordlist[/]")
                    return

            log.write(f"[bold cyan]Hydra: {service}://{target} user={username or userlist}[/]")
            table.clear()

            def cb(line):
                self.call_from_thread(log.write, line)

            def on_done(result):
                self.call_from_thread(self._on_hydra_done, result)

            threading.Thread(
                target=lambda: on_done(hydra_brute(
                    target, service, username=username, userlist=userlist,
                    passlist=passlist, callback=cb,
                )),
                daemon=True,
            ).start()

        elif bid == "pw-john":
            hashfile = self.query_one("#pw-hashfile", Input).value.strip()
            if not hashfile:
                log.write("[red]Enter a hash file path[/]")
                return
            wordlist = self.query_one("#pw-crack-wordlist", Input).value.strip()
            hashtype = self.query_one("#pw-hashtype").value
            log.write(f"[bold cyan]John: cracking {hashfile} (type {hashtype})[/]")
            table.clear()

            def cb(line):
                self.call_from_thread(log.write, line)

            def on_done(result):
                self.call_from_thread(self._on_john_done, result)

            threading.Thread(
                target=lambda: on_done(john_crack(hashfile, wordlist=wordlist, callback=cb)),
                daemon=True,
            ).start()

        elif bid == "pw-hashcat":
            hashfile = self.query_one("#pw-hashfile", Input).value.strip()
            if not hashfile:
                log.write("[red]Enter a hash file path[/]")
                return
            wordlist = self.query_one("#pw-crack-wordlist", Input).value.strip()
            hashtype = self.query_one("#pw-hashtype").value
            log.write(f"[bold cyan]Hashcat: cracking {hashfile} (type {hashtype})[/]")
            table.clear()

            def cb(line):
                self.call_from_thread(log.write, line)

            def on_done(result):
                self.call_from_thread(self._on_hashcat_done, result)

            threading.Thread(
                target=lambda: on_done(hashcat_crack(hashfile, hashtype=hashtype, wordlist=wordlist, callback=cb)),
                daemon=True,
            ).start()

        elif bid == "pw-cewl":
            url = self.query_one("#pw-cewl-url", Input).value.strip()
            depth = self.query_one("#pw-cewl-depth", Input).value.strip() or "2"
            if not url:
                log.write("[red]Enter a URL for CeWL[/]")
                return
            log.write(f"[bold cyan]CeWL: generating wordlist from {url} (depth={depth})...[/]")

            def cb(line):
                self.call_from_thread(log.write, line)

            def on_done(result):
                self.call_from_thread(self._on_cewl_done, result)

            threading.Thread(
                target=lambda: on_done(cewl_wordlist(url, depth=int(depth), callback=cb)),
                daemon=True,
            ).start()

        elif bid == "pw-browse":
            self._refresh_wordlists()
            log.write("[cyan]Wordlist list refreshed[/]")

    def _on_hydra_done(self, result):
        table = self.query_one("#pw-results", DataTable)
        log = self.query_one("#pw-log", RichLog)
        for i, c in enumerate(result["creds"], 1):
            table.add_row(str(i), c["username"], c["password"], f"{c['host']}:{c['port']}/{c['service']}")
        if result["creds"]:
            log.write(f"[bold green]Hydra: {result['total']} credentials found![/]")
        else:
            log.write(f"[yellow]Hydra: {result['status']}[/]")

    def _on_john_done(self, result):
        table = self.query_one("#pw-results", DataTable)
        log = self.query_one("#pw-log", RichLog)
        for i, c in enumerate(result["cracks"], 1):
            table.add_row(str(i), c["password"], c["hash"][:32], "john")
        if result["cracks"]:
            log.write(f"[bold green]John: {result['total']} hashes cracked![/]")
        else:
            log.write("[yellow]John: no hashes cracked[/]")

    def _on_hashcat_done(self, result):
        table = self.query_one("#pw-results", DataTable)
        log = self.query_one("#pw-log", RichLog)
        for i, c in enumerate(result["cracks"], 1):
            table.add_row(str(i), c["password"], c["hash"][:32], "hashcat")
        if result["cracks"]:
            log.write(f"[bold green]Hashcat: {result['total']} hashes cracked![/]")
        else:
            log.write("[yellow]Hashcat: no hashes cracked[/]")

    def _on_cewl_done(self, result):
        log = self.query_one("#pw-log", RichLog)
        if result["word_count"] > 0:
            log.write(f"[bold green]CeWL: {result['word_count']} words → {result['output_file']}[/]")
        else:
            log.write("[yellow]CeWL: no words generated[/]")
        self._refresh_wordlists()
