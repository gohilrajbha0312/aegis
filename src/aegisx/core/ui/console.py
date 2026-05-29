from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.theme import Theme
from rich import box
import re

custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "danger": "bold red",
    "success": "bold green",
    "primary": "cyan",
    "highlight": "yellow"
})

console = Console(theme=custom_theme, style="on black")

# ─────────────────────────────────────────────────────────
# Noise patterns that should NEVER be printed to the terminal
# ─────────────────────────────────────────────────────────
_NOISE_PATTERNS = [
    r"^\s*$",                           # blank lines
    r"fe80::",                          # IPv6 link-local
    r"ff02::",                          # IPv6 multicast
    r"mac: [0-9a-f:]{17}",             # raw MAC addresses in verbose output
    r"multicast_ips:",
    r"broadcast-listener",
    r"broadcast-dhcp",
    r"broadcast-eigrp",
    r"broadcast-igmp",
    r"broadcast-ospf",
    r"broadcast-pim",
    r"targets-ipv6",
    r"targets-sniffer",
    r"targets-asn",
    r"ipv6-multicast",
    r"knx-gateway",
    r"mrinfo",
    r"\|_",                            # nmap script pipe lines
    r"^\|   ",                         # nmap table indented lines
    r"^\|$",
    r"Use --script-args=newtargets",
    r"hostmap-robtex",
    r"http-robtex",
    r"TEMPORARILY DISABLED",
    r"targets-asn\.asn is a mandatory",
    r"Starting Nmap",
    r"Nmap done:",
    r"Post-scan script results:",
    r"Pre-scan script results:",
    r"Stats: 0:00",
    r"NSE Timing:",
    r"No profinet",
    r"OS and Service detection performed",
    r"Too many fingerprints",
    r"Network Distance",
    r"eap-info",
    r"EAP-TTLS|EAP-TLS|EAP-MSCHAP|PEAP",
    r"dns-brute: Can't guess",
]

_VULN_KEYWORDS = [
    "filtered", "open", "WARN", "CVE-", "VULNERABLE",
    "WARNING", "unusual-port", "dns-blacklist", "SPAM",
    "port-states", "fcrdns", "STATE", "SERVICE", "VERSION",
    "PORT", "Host is up", "Host script results",
]

_compiled_noise = [re.compile(p, re.IGNORECASE) for p in _NOISE_PATTERNS]
_compiled_vuln  = [re.compile(p) for p in _VULN_KEYWORDS]

def _is_noise(line: str) -> bool:
    for pat in _compiled_noise:
        if pat.search(line):
            return True
    return False

def _is_finding(line: str) -> bool:
    for pat in _compiled_vuln:
        if pat.search(line):
            return True
    return False


class ConsoleUI:
    """
    Centralized console engine — hacker aesthetic via `rich`.
    Streams tool output filtered to security-relevant lines only.
    """

    @classmethod
    def header(cls, text: str):
        panel = Panel(
            Text(text, style="bold cyan", justify="center"),
            border_style="cyan",
            padding=(0, 2),
            box=box.DOUBLE_EDGE
        )
        console.print(panel)

    @classmethod
    def approval_gateway(cls, description: str, cmd_str: str) -> str:
        panel = Panel(
            f"[white]{description}[/white]\n"
            f"[bold magenta]$ {cmd_str}[/bold magenta]",
            title="[bold red]ACTION REQUIRED[/bold red]",
            border_style="red",
            box=box.HEAVY,
            style="on grey11"
        )
        console.print(panel)
        console.print("[info]Please authorize execution:[/info]")
        console.print("  [1] Allow once")
        console.print("  [2] Allow for this session")
        console.print("  [3] Deny this action")
        console.print("  [4] Deny for this session")
        return cls.prompt("Selection (1/2/3/4): ").strip()

    @classmethod
    def info(cls, text: str):
        console.print(f"[bold cyan]\\[*][/bold cyan] {text}")

    @classmethod
    def success(cls, text: str):
        console.print(f"[bold green]\\[+][/bold green] {text}")

    @classmethod
    def warning(cls, text: str):
        console.print(f"[bold yellow]\\[!][/bold yellow] {text}")

    @classmethod
    def error(cls, text: str):
        console.print(f"[bold red]\\[-][/bold red] {text}")

    @classmethod
    def prompt(cls, text: str) -> str:
        console.print(f"[bold cyan]\\[?][/bold cyan] {text}", end="")
        return input(" ")

    @classmethod
    def command(cls, text: str):
        console.print(f"[bold magenta]$ {text}[/bold magenta]")

    @classmethod
    def stream_line(cls, line: str):
        """
        Streams a single line of tool output.
        Suppresses noise; highlights security-relevant findings.
        """
        if not line.strip():
            return
        if _is_noise(line):
            return
        if _is_finding(line):
            console.print(f"[bold yellow]  {line}[/bold yellow]")
        else:
            console.print(f"[dim]  {line}[/dim]")

    @classmethod
    def finding_table(cls, findings: list):
        """Renders a rich findings summary table."""
        if not findings:
            return
        table = Table(
            title="[bold red]AEGIS-X — Vulnerability Findings[/bold red]",
            box=box.DOUBLE_EDGE,
            border_style="red",
            show_lines=True
        )
        table.add_column("Risk", style="bold red", width=8)
        table.add_column("Finding", style="bold white", width=40)
        table.add_column("Confidence", style="cyan", width=10)
        table.add_column("Evidence", style="dim", width=50)

        for f in findings:
            risk = f.get("risk_level", "LOW")
            color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(risk, "white")
            table.add_row(
                f"[{color}]{risk}[/{color}]",
                f.get("finding_type", "Unknown"),
                f"{f.get('consensus_score', f.get('base_confidence', 0.0)):.2f}",
                str(f.get("recommended_validation", []))[:80]
            )
        console.print(table)
