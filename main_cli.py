#!/usr/bin/env python3
"""Rich-powered WPA auditing workflow CLI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from airodump_clients import AirodumpError, get_connected_clients
from handshake_cracking import (
    HandshakeError,
    capture_handshake,
    crack_wpa_password,
    deauth_clients,
    verify_handshake,
)
from sniff_beacons import AccessPoint, discover_access_points


console = Console()


@dataclass
class Target:
    bssid: str
    channel: str
    ssid: str = "<unknown>"


def _menu() -> str:
    table = Table(title="BreakPoint Dashboard")
    table.add_column("Option", style="cyan", width=4)
    table.add_column("Action", style="green")
    table.add_row("1", "Scan")
    table.add_row("2", "Select Target")
    table.add_row("3", "Capture Handshake")
    table.add_row("4", "Kick All Users")
    table.add_row("5", "Audit Password")
    table.add_row("q", "Quit")
    console.print(table)
    return Prompt.ask("Choose an option", default="q")


def _show_scan_results(results: list[AccessPoint]) -> None:
    table = Table(title="Discovered Access Points")
    table.add_column("#", style="cyan", width=4)
    table.add_column("SSID", style="green")
    table.add_column("BSSID", style="magenta")
    table.add_column("Channel", style="yellow")
    table.add_column("Signal", style="white")

    for idx, ap in enumerate(results, start=1):
        table.add_row(str(idx), ap.ssid, ap.bssid, ap.channel, ap.rssi)

    console.print(table)


def run_cli() -> int:
    interface = Prompt.ask("Monitor interface", default="wlan0mon")
    target: Optional[Target] = None
    last_cap: Optional[Path] = None
    scan_results: list[AccessPoint] = []

    while True:
        choice = _menu().strip().lower()

        if choice == "q":
            console.print("[bold blue]Bye.[/bold blue]")
            return 0

        if choice == "1":
            timeout = int(Prompt.ask("Scan timeout (seconds)", default="10"))
            try:
                scan_results = discover_access_points(interface=interface, timeout=timeout)
            except (PermissionError, OSError) as exc:
                console.print(f"[red]Scan failed:[/red] {exc}")
                continue
            if not scan_results:
                console.print("[yellow]No access points discovered.[/yellow]")
            else:
                _show_scan_results(scan_results)
            continue

        if choice == "2":
            if scan_results:
                selected = Prompt.ask("Select target by # (or press enter to manual)", default="")
                if selected.isdigit():
                    idx = int(selected)
                    if 1 <= idx <= len(scan_results):
                        ap = scan_results[idx - 1]
                        target = Target(bssid=ap.bssid.upper(), channel=ap.channel, ssid=ap.ssid)
                        console.print(Panel.fit(f"Selected: {target.ssid} ({target.bssid}) ch {target.channel}"))
                        continue

            bssid = Prompt.ask("Target BSSID").upper()
            channel = Prompt.ask("Target channel")
            ssid = Prompt.ask("SSID", default="<unknown>")
            target = Target(bssid=bssid, channel=channel, ssid=ssid)
            console.print(Panel.fit(f"Selected: {target.ssid} ({target.bssid}) ch {target.channel}"))
            continue

        if choice == "3":
            if not target:
                console.print("[red]Select a target first (option 2).[/red]")
                continue

            out_prefix = Prompt.ask("Output prefix", default="captures/handshake")
            duration = int(Prompt.ask("Capture duration (seconds)", default="25"))
            try:
                cap_path = capture_handshake(
                    interface=interface,
                    bssid=target.bssid,
                    channel=target.channel,
                    output_prefix=out_prefix,
                    capture_seconds=duration,
                )
                last_cap = cap_path
                ok = verify_handshake(str(cap_path), bssid=target.bssid)
            except (HandshakeError, ValueError) as exc:
                console.print(f"[red]Capture failed:[/red] {exc}")
                continue

            if ok:
                console.print(f"[green]Handshake captured:[/green] {cap_path}")
            else:
                console.print(f"[yellow]Capture complete, but no valid handshake detected:[/yellow] {cap_path}")
            continue

        if choice == "4":
            if not target:
                console.print("[red]Select a target first (option 2).[/red]")
                continue
            count = int(Prompt.ask("Deauth frame count", default="16"))
            try:
                deauth_clients(interface=interface, bssid=target.bssid, channel=target.channel, count=count)
            except HandshakeError as exc:
                console.print(f"[red]Deauth failed:[/red] {exc}")
                continue
            console.print("[green]Deauth frames sent.[/green]")
            continue

        if choice == "5":
            cap_input = Prompt.ask("Capture file", default=str(last_cap) if last_cap else "")
            wordlist = Prompt.ask("Wordlist path", default="/usr/share/wordlists/rockyou.txt")
            bssid = target.bssid if target else None
            try:
                password = crack_wpa_password(cap_input, wordlist, bssid=bssid)
            except HandshakeError as exc:
                console.print(f"[red]Audit failed:[/red] {exc}")
                continue

            if password:
                console.print(f"[bold green]Password found:[/bold green] {password}")
            else:
                console.print("[yellow]Password not found in provided wordlist.[/yellow]")
            continue

        if choice == "clients":
            if not target:
                console.print("[red]Select a target first (option 2).[/red]")
                continue
            try:
                clients = get_connected_clients(interface, target.bssid, duration_seconds=10, channel=target.channel)
            except (AirodumpError, ValueError) as exc:
                console.print(f"[red]Client scan failed:[/red] {exc}")
                continue
            console.print(Panel.fit("\n".join(clients) if clients else "No clients detected."))
            continue

        console.print("[red]Unknown option. Choose 1-5 or q.[/red]")


if __name__ == "__main__":
    raise SystemExit(run_cli())
