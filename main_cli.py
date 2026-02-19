#!/usr/bin/env python3
"""Rich-powered WPA auditing workflow CLI."""

from __future__ import annotations

import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from airodump_clients import AirodumpError, get_connected_clients
from config import Config
from database import CapturedHandshake, ScanResult, make_session_factory
from handshake_cracking import HandshakeError, capture_handshake, crack_wpa_password, deauth_clients, verify_handshake
from logging_setup import setup_logging
from session_restore import SessionState, load_session, save_session
from analysis import diff_scans, export_cracked_csv, export_json, handshake_quality_from_eapol_count, password_entropy
from reporting import build_topology_edges, render_html_report, timeline_events
from visualization import signal_heatmap, topology_graph
from capability_checks import clean_handshake_cap, interface_supports_injection
from sniff_beacons import AccessPoint, discover_access_points, discover_probed_networks
from remaining_features import online_cracking_submit, telegram_notify, vendor_vulnerability_lookup
from toggle_interface_mode import AirmonError, set_interface_mode

console = Console()
logger = setup_logging()
_shutdown_requested = False


@dataclass
class Target:
    bssid: str
    channel: str
    ssid: str = "<unknown>"


class InterfaceModeManager:
    def __init__(self, interface: str):
        self.interface = interface

    def __enter__(self) -> "InterfaceModeManager":
        logger.debug("Setting %s to monitor mode", self.interface)
        try:
            set_interface_mode(self.interface, "monitor")
        except AirmonError as exc:
            logger.warning("Could not set monitor mode for %s: %s", self.interface, exc)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        logger.debug("Restoring %s to managed mode", self.interface)
        try:
            set_interface_mode(self.interface, "managed")
        except AirmonError as restore_exc:
            logger.warning("Could not restore managed mode: %s", restore_exc)
        return False


def _on_sigint(_signum, _frame) -> None:
    global _shutdown_requested
    _shutdown_requested = True
    console.print("\n[yellow]Graceful shutdown requested...[/yellow]")


def _menu() -> str:
    table = Table(title="BreakPoint Dashboard")
    table.add_column("Option", style="cyan", width=4)
    table.add_column("Action", style="green")
    for key, action in [
        ("1", "Scan"),
        ("2", "Select Target"),
        ("3", "Capture Handshake"),
        ("4", "Kick All Users"),
        ("5", "Audit Password"),
        ("6", "Show Connected Clients"),
        ("7", "Target Profile"),
        ("8", "Generate Report + Exports"),
        ("9", "Probed Networks"),
        ("0", "Feature Stub Status"),
        ("q", "Quit"),
    ]:
        table.add_row(key, action)
    console.print(table)
    return Prompt.ask("Choose an option", default="q")


def _show_scan_results(results: list[AccessPoint], encryption_filter: str | None = None) -> list[AccessPoint]:
    filtered = results
    if encryption_filter:
        needle = encryption_filter.lower()
        filtered = [ap for ap in results if needle in ap.encryption.lower()]

    table = Table(title="Discovered Access Points")
    for col, style in [
        ("#", "cyan"), ("SSID", "green"), ("BSSID", "magenta"), ("Channel", "yellow"),
        ("Band", "white"), ("Signal", "white"), ("Encryption", "blue"), ("Vendor", "white"),
    ]:
        table.add_column(col, style=style)

    for idx, ap in enumerate(filtered, start=1):
        table.add_row(str(idx), ap.ssid, ap.bssid, ap.channel, ap.band, ap.rssi, ap.encryption, ap.manufacturer)

    console.print(table)
    return filtered


def run_cli() -> int:
    cfg = Config.load()
    session = load_session(cfg.paths.session_file)
    db_factory = make_session_factory(f"sqlite:///{cfg.paths.db_file}")

    interface = Prompt.ask("Monitor interface", default=cfg.interface)
    signal.signal(signal.SIGINT, _on_sigint)
    if not interface_supports_injection(interface):
        console.print("[yellow]Warning:[/yellow] Packet injection support check did not pass.")

    target: Optional[Target] = None
    if session.bssid and session.channel:
        target = Target(bssid=session.bssid, channel=session.channel, ssid=session.ssid or "<unknown>")
        console.print(Panel.fit(f"Restored session target: {target.ssid} ({target.bssid}) ch {target.channel}"))

    last_cap: Optional[Path] = Path(session.last_cap) if session.last_cap else None
    if last_cap and last_cap.exists():
        console.print(f"[cyan]Recovered pending capture:[/cyan] {last_cap}")

    scan_results: list[AccessPoint] = []

    with db_factory() as db:
        pending = [h for h in db.query(CapturedHandshake).all() if h.status in {"captured", "partial"}]
    if pending:
        console.print(f"[yellow]Session restore:[/yellow] {len(pending)} pending handshakes found.")

    with InterfaceModeManager(interface):
        while not _shutdown_requested:
            choice = _menu().strip().lower()
            if choice == "q":
                break

            if choice == "1":
                timeout = int(Prompt.ask("Scan timeout (seconds)", default=str(cfg.defaults.scan_timeout)))
                encryption_filter = Prompt.ask("Encryption filter (optional)", default="").strip() or None
                try:
                    scan_results = discover_access_points(interface=interface, timeout=timeout)
                except (PermissionError, OSError) as exc:
                    console.print(f"[red]Scan failed:[/red] {exc}")
                    logger.exception("scan failed")
                    continue
                filtered = _show_scan_results(scan_results, encryption_filter=encryption_filter)
                if any(ap.wpa3_sae for ap in filtered):
                    console.print("[yellow]Notice:[/yellow] WPA3-SAE networks detected; dictionary attacks are not straightforward.")
                with db_factory() as db:
                    for ap in filtered:
                        db.add(ScanResult(
                            bssid=ap.bssid, ssid=ap.ssid, channel=ap.channel, rssi=ap.rssi,
                            encryption=ap.encryption, manufacturer=ap.manufacturer,
                        ))
                    db.commit()
                continue

            if choice == "2":
                if scan_results:
                    selected = Prompt.ask("Select target by # (or enter to manual)", default="")
                    if selected.isdigit() and 1 <= int(selected) <= len(scan_results):
                        ap = scan_results[int(selected) - 1]
                        target = Target(bssid=ap.bssid.upper(), channel=ap.channel, ssid=ap.ssid)
                        console.print(Panel.fit(f"Selected: {target.ssid} ({target.bssid}) ch {target.channel}"))
                        continue
                target = Target(
                    bssid=Prompt.ask("Target BSSID").upper(),
                    channel=Prompt.ask("Target channel"),
                    ssid=Prompt.ask("SSID", default="<unknown>"),
                )
                console.print(Panel.fit(f"Selected: {target.ssid} ({target.bssid}) ch {target.channel}"))
                continue

            if choice == "3":
                if not target:
                    console.print("[red]Select a target first.[/red]")
                    continue
                out_prefix = Prompt.ask("Output prefix", default=str(cfg.paths.captures_dir / "handshake"))
                duration = int(Prompt.ask("Capture duration (seconds)", default=str(cfg.defaults.capture_seconds)))
                try:
                    cap_path = capture_handshake(interface, target.bssid, target.channel, out_prefix, capture_seconds=duration)
                    last_cap = cap_path
                    ok = verify_handshake(str(cap_path), bssid=target.bssid)
                except (HandshakeError, ValueError) as exc:
                    console.print(f"[red]Capture failed:[/red] {exc}")
                    logger.exception("capture failed")
                    continue

                with db_factory() as db:
                    db.add(CapturedHandshake(bssid=target.bssid, cap_path=str(cap_path), status="verified" if ok else "partial"))
                    db.commit()
                console.print(f"[green]Capture complete:[/green] {cap_path}")
                continue

            if choice == "4":
                if not target:
                    console.print("[red]Select a target first.[/red]")
                    continue
                count = int(Prompt.ask("Deauth frame count", default=str(cfg.defaults.deauth_count)))
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
                try:
                    password = crack_wpa_password(cap_input, wordlist, bssid=target.bssid if target else None)
                except HandshakeError as exc:
                    console.print(f"[red]Audit failed:[/red] {exc}")
                    continue

                if password:
                    console.print(f"[bold green]Password found:[/bold green] {password}")
                else:
                    console.print("[yellow]Password not found.[/yellow]")
                continue

            if choice == "6":
                if not target:
                    console.print("[red]Select a target first.[/red]")
                    continue
                try:
                    clients = get_connected_clients(interface=interface, target_bssid=target.bssid, channel=target.channel)
                except AirodumpError as exc:
                    console.print(f"[red]Client scan failed:[/red] {exc}")
                    continue
                console.print(Panel("\n".join(clients) if clients else "No clients currently observed.", title="Connected Clients"))
                continue


            if choice == "7":
                if not target:
                    console.print("[red]Select a target first.[/red]")
                    continue
                selected_ap = next((ap for ap in scan_results if ap.bssid.upper() == target.bssid.upper()), None)
                if not selected_ap:
                    console.print("[yellow]Target details unavailable (scan first).[/yellow]")
                    continue
                panel = Panel.fit(
                    f"SSID: {selected_ap.ssid}\nBSSID: {selected_ap.bssid}\nChannel: {selected_ap.channel} ({selected_ap.band})\nEncryption: {selected_ap.encryption}\nVendor: {selected_ap.manufacturer}\nBeacon interval: {selected_ap.beacon_interval_ms}ms\nEstimated uptime: {selected_ap.uptime_seconds}s",
                    title="Target Profile",
                )
                console.print(panel)
                continue

            if choice == "8":
                reports_dir = cfg.paths.reports_dir
                reports_dir.mkdir(parents=True, exist_ok=True)
                scan_dicts = [ap.__dict__ for ap in scan_results]
                json_path = export_json(reports_dir / "scan_export.json", {"aps": scan_dicts})
                html_path = render_html_report(reports_dir / "audit_report.html", "BreakPoint Audit Report", {"ap_count": len(scan_dicts)})
                topo_edges = build_topology_edges(scan_dicts, [{"bssid": target.bssid, "client_mac": "FF:FF:FF:FF:FF:FF"}] if target else [])
                with db_factory() as db:
                    hs_rows = db.query(CapturedHandshake).all()
                cracked_rows = []
                for row in hs_rows:
                    if row.cracked_password:
                        cracked_rows.append({
                            "bssid": row.bssid,
                            "ssid": target.ssid if target else "<unknown>",
                            "password": row.cracked_password,
                            "entropy": round(password_entropy(row.cracked_password), 2),
                        })
                csv_path = export_cracked_csv(reports_dir / "cracked.csv", cracked_rows)
                quality = handshake_quality_from_eapol_count(4 if hs_rows else 0)
                diff = diff_scans([], scan_dicts)
                _ = timeline_events([{"timestamp": "2026-01-01T00:00:00Z", "event": "scan"}])
                heatmap_path = signal_heatmap(reports_dir / "signal_heatmap.png", [(i, 0, int(ap.rssi.split()[0])) for i, ap in enumerate(scan_results) if ap.rssi.endswith("dBm")])
                topo_img = topology_graph(reports_dir / "topology.png", topo_edges)
                if last_cap and Path(last_cap).exists():
                    try:
                        cleaned = clean_handshake_cap(last_cap, reports_dir / "handshake_clean.cap")
                        logger.info("Cleaned handshake written: %s", cleaned)
                    except Exception as exc:
                        logger.warning("Handshake clean skipped: %s", exc)
                logger.info("Report generated. Handshake quality=%s, topology_edges=%d", quality, len(topo_edges))
                console.print(f"[green]Exports:[/green] {json_path}, {html_path}, {csv_path}, {heatmap_path}, {topo_img} | new APs: {len(diff['new'])}")
                continue

            if choice == "9":
                timeout = int(Prompt.ask("Probe sniff timeout", default="8"))
                probes = discover_probed_networks(interface=interface, timeout=timeout)
                if not probes:
                    console.print("[yellow]No probe requests observed.[/yellow]")
                    continue
                table = Table(title="Probed Networks")
                table.add_column("Client")
                table.add_column("Probed SSID")
                for pr in probes:
                    table.add_row(pr.client_mac, pr.probed_ssid)
                console.print(table)
                continue

            if choice == "0":
                vendor = target.ssid if target else "Unknown"
                vulns = vendor_vulnerability_lookup("TestVendor")
                online = online_cracking_submit()
                tg = telegram_notify("token", "chat", "BreakPoint status update")
                console.print(Panel.fit(f"Online crack: {online}\nTelegram: {tg}\nVendor vulns: {vulns}", title="Stub Features"))
                continue

            console.print("[red]Unknown option.[/red]")

    save_session(cfg.paths.session_file, SessionState(
        bssid=target.bssid if target else None,
        channel=target.channel if target else None,
        ssid=target.ssid if target else None,
        last_cap=str(last_cap) if last_cap else None,
    ))
    console.print("[bold blue]Bye.[/bold blue]")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
