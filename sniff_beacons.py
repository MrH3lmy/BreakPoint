#!/usr/bin/env python3
"""Sniff nearby 802.11 beacon frames and print discovered access points."""

from __future__ import annotations

import argparse
import importlib
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    rssi: str
    channel: str


def _load_scapy_symbols() -> tuple[object, object, object, object, object]:
    scapy_all = importlib.import_module("scapy.all")
    return (
        getattr(scapy_all, "Dot11"),
        getattr(scapy_all, "Dot11Beacon"),
        getattr(scapy_all, "Dot11Elt"),
        getattr(scapy_all, "RadioTap"),
        getattr(scapy_all, "sniff"),
    )


def _parse_channel(packet: object, dot11_elt: object) -> str:
    """Extract channel from Dot11Elt tags when present."""
    elt = packet.getlayer(dot11_elt)
    while elt is not None:
        if elt.ID == 3 and isinstance(elt.info, bytes) and elt.info:
            return str(elt.info[0])
        elt = elt.payload.getlayer(dot11_elt)
    return "N/A"


def _parse_ssid(packet: object, dot11_elt: object) -> str:
    """Extract SSID from beacon frame and normalize hidden SSIDs."""
    try:
        ssid = packet[dot11_elt].info.decode("utf-8", errors="replace")
    except Exception:
        return "<unknown>"

    return ssid if ssid else "<hidden>"


def _parse_rssi(packet: object) -> str:
    """Read RSSI from RadioTap header if present."""
    signal = getattr(packet, "dBm_AntSignal", None)
    return f"{signal} dBm" if signal is not None else "N/A"


def _signal_value(ap: AccessPoint) -> int:
    if ap.rssi.endswith(" dBm"):
        try:
            return int(ap.rssi.split()[0])
        except ValueError:
            pass
    return -999


def discover_access_points(interface: str, timeout: int | None = 10) -> List[AccessPoint]:
    """Discover access points from beacon frames on the given monitor interface."""
    dot11, dot11_beacon, dot11_elt, _radiotap, sniff = _load_scapy_symbols()
    access_points: Dict[str, AccessPoint] = {}

    def _handle_packet(packet: object) -> None:
        if not packet.haslayer(dot11_beacon) or not packet.haslayer(dot11):
            return

        bssid: Optional[str] = packet[dot11].addr2
        if not bssid:
            return

        access_points[bssid] = AccessPoint(
            bssid=bssid,
            ssid=_parse_ssid(packet, dot11_elt),
            rssi=_parse_rssi(packet),
            channel=_parse_channel(packet, dot11_elt),
        )

    sniff(iface=interface, prn=_handle_packet, store=False, timeout=timeout)
    return sorted(access_points.values(), key=lambda ap: (_signal_value(ap), ap.bssid), reverse=True)


def _print_table(access_points: List[AccessPoint]) -> None:
    """Print an AP table sorted by strongest signal then BSSID."""
    header = ("BSSID", "SSID", "Signal Strength", "Channel")
    widths = [len(col) for col in header]
    for ap in access_points:
        widths[0] = max(widths[0], len(ap.bssid))
        widths[1] = max(widths[1], len(ap.ssid))
        widths[2] = max(widths[2], len(ap.rssi))
        widths[3] = max(widths[3], len(ap.channel))

    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(line)
    print("| " + " | ".join(col.ljust(widths[i]) for i, col in enumerate(header)) + " |")
    print(line)

    for ap in access_points:
        values = (ap.bssid, ap.ssid, ap.rssi, ap.channel)
        print("| " + " | ".join(values[i].ljust(widths[i]) for i in range(4)) + " |")
    print(line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Sniff 802.11 Beacon frames and list nearby access points."
    )
    parser.add_argument("interface", help="Wireless interface in monitor mode (e.g., wlan0mon)")
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Sniff timeout in seconds. Omit to run until Ctrl+C.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        access_points = discover_access_points(args.interface, timeout=args.timeout)
    except PermissionError:
        print("Error: insufficient privileges. Run as root (or with sudo).")
        return 1
    except OSError as exc:
        print(f"Error: sniffing failed on interface '{args.interface}': {exc}")
        return 1
    except KeyboardInterrupt:
        access_points = []

    if access_points:
        _print_table(access_points)
    else:
        print("No 802.11 beacon frames captured.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
