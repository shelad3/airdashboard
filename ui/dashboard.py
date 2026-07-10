"""Dashboard tab — system info, WiFi status, tool detection, recommendations, quick-launch."""

from textual.containers import ScrollableContainer, Horizontal
from textual.widgets import Static, Button

from ui.helpers import WLAN, get_sysinfo, get_iwconfig, signal_bar
from core.tools import detect_tools, advise_tool
from tools.manager import check_tools


class DashboardTab(ScrollableContainer):
    def compose(self):
        yield Static(id="dash-sysinfo", classes="dash-card")
        yield Static(id="dash-wifi", classes="dash-card")
        yield Static(id="dash-tools", classes="dash-card")
        yield Static(id="dash-advice", classes="dash-card")
        yield Static("[bold]Quick Launch[/]", classes="section-title")
        yield Horizontal(
            Button("Network Scan", id="ql-scanner", variant="primary"),
            Button("WiFi Audit", id="ql-wifi", variant="primary"),
            Button("Web Recon", id="ql-web", variant="primary"),
            Button("Password Attack", id="ql-pw", variant="warning"),
            Button("Bluetooth", id="ql-bt", variant="default"),
        )

    def on_mount(self):
        self.refresh_all()
        self.set_interval(3, self.refresh_all)

    def on_button_pressed(self, event: Button.Pressed):
        tab_map = {
            "ql-scanner": "scan",
            "ql-wifi": "wifi",
            "ql-web": "web",
            "ql-pw": "pw",
            "ql-bt": "bt",
        }
        tab_id = tab_map.get(event.button.id)
        if tab_id:
            self.app.query_one("TabbedContent").active = tab_id

    def refresh_all(self):
        kernel, load, mem = get_sysinfo()
        wifi = get_iwconfig()
        tools = detect_tools()

        self.query_one("#dash-sysinfo").update(
            f"[bold white]System[/]\n"
            f"  Kernel: {kernel}\n"
            f"  Load: {load}\n"
            f"  Memory: {mem}\n"
            f"  Interface: {WLAN}"
        )

        sig = wifi.get("signal", "?")
        qual = wifi.get("quality", "?")
        bar = signal_bar(sig) if sig and sig != "?" else "?" * 15
        self.query_one("#dash-wifi").update(
            f"[bold white]WiFi Status[/]\n"
            f"  SSID: [green]{wifi['ssid'] or '—'}[/]\n"
            f"  Signal: {sig} dBm  {bar}\n"
            f"  Link: {qual}  |  BSSID: {wifi['ap']}"
        )

        tool_lines = []
        for name, t in sorted(tools.items()):
            icon = "[green]✓[/]" if t["available"] else "[red]✗[/]"
            tool_lines.append(f"  {icon} [bold]{name}[/] — {t['description']}")
        manifest_tools = check_tools()
        installed = sum(1 for t in manifest_tools if t["status"] == "installed")
        missing = sum(1 for t in manifest_tools if t["status"] == "missing")
        missing_names = ", ".join(t["name"] for t in manifest_tools if t["status"] == "missing") or "none"
        self.query_one("#dash-tools").update(
            f"[bold white]System Tools ({installed} installed, {missing} missing)[/]\n"
            + "\n".join(tool_lines)
            + f"\n\n[bold yellow]Missing:[/] {missing_names}\n"
            + "[dim]Run: sudo bash tools/install_tools.sh to install[/]"
        )

        adv = advise_tool("port_scan", tools)
        adv2 = advise_tool("wifi_survey", tools)
        adv3 = advise_tool("password_crack", tools)
        adv4 = advise_tool("web_scan", tools)
        adv5 = advise_tool("online_bruteforce", tools)
        self.query_one("#dash-advice").update(
            f"[bold white]Recommendations[/]\n"
            f"  [bold]Port Scan:[/] {adv['name']} ({adv['heavyness']}) — {adv['reason']}\n"
            f"  [bold]WiFi Survey:[/] {adv2['name']} ({adv2['heavyness']})\n"
            f"  [bold]Password Crack:[/] {adv3['name']} ({adv3['heavyness']})\n"
            f"  [bold]Web Scan:[/] {adv4['name']} ({adv4['heavyness']}) — {adv4['reason']}\n"
            f"  [bold]Online Brute:[/] {adv5['name']} ({adv5['heavyness']}) — {adv5['reason']}"
        )
