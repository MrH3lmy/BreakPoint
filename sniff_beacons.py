#!/usr/bin/env python3
"""Sniff nearby 802.11 management frames and print discovered access points."""

from __future__ import annotations

import argparse
import asyncio
import importlib
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class AccessPoint:
    bssid: str
    ssid: str
    rssi: str
    channel: str
    band: str = "unknown"
    encryption: str = "unknown"
    manufacturer: str = "Unknown"
    beacon_interval_ms: int = 0
    uptime_seconds: int = 0
    wpa3_sae: bool = False


@dataclass
class ProbeObservation:
    client_mac: str
    probed_ssid: str
    bssid: str = ""


def _load_scapy_symbols() -> tuple[object, object, object, object, object, object]:
    scapy_all = importlib.import_module("scapy.all")
    return (
        getattr(scapy_all, "Dot11"),
        getattr(scapy_all, "Dot11Beacon"),
        getattr(scapy_all, "Dot11Elt"),
        getattr(scapy_all, "Dot11ProbeReq"),
        getattr(scapy_all, "RadioTap"),
        getattr(scapy_all, "AsyncSniffer"),
    )


def _parse_channel(packet: object, dot11_elt: object) -> str:
    elt = packet.getlayer(dot11_elt)
    while elt is not None:
        if elt.ID == 3 and isinstance(elt.info, bytes) and elt.info:
            return str(elt.info[0])
        # HE operation extension tags may contain alt channel hints (best effort)
        if elt.ID in {192, 255} and isinstance(elt.info, bytes) and elt.info:
            maybe = elt.info[0]
            if maybe:
                return str(maybe)
        elt = elt.payload.getlayer(dot11_elt)
    return "N/A"


def _infer_band(channel: str) -> str:
    try:
        value = int(channel)
    except ValueError:
        return "unknown"
    if 1 <= value <= 14:
        return "2.4 GHz"
    if 32 <= value <= 177:
        return "5 GHz"
    if value >= 1 and str(channel).startswith("6"):
        return "6 GHz"
    return "unknown"


def _parse_ssid(packet: object, dot11_elt: object) -> str:
    try:
        ssid = packet[dot11_elt].info.decode("utf-8", errors="replace")
    except Exception:
        return "<unknown>"
    return ssid if ssid else "<hidden>"


def _parse_encryption(packet: object) -> str:
    try:
        capability = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").lower()
    except Exception:
        return "unknown"
    if "privacy" not in capability:
        return "Open"
    rsn = getattr(packet, "network_stats", lambda: {})().get("crypto", set())
    if rsn:
        return "/".join(sorted(rsn))
    return "WEP/WPA"


def _is_wpa3_sae(encryption: str) -> bool:
    return "sae" in encryption.lower() or "wpa3" in encryption.lower()


def _parse_beacon_interval(packet: object) -> int:
    return int(getattr(packet, "beacon_interval", 0) or 0)


def _parse_uptime_seconds(packet: object) -> int:
    tsft = getattr(packet, "timestamp", 0)
    try:
        return int(tsft / 1_000_000)
    except Exception:
        return 0


def _parse_rssi(packet: object) -> str:
    signal = getattr(packet, "dBm_AntSignal", None)
    return f"{signal} dBm" if signal is not None else "N/A"


def _signal_value(ap: AccessPoint) -> int:
    if ap.rssi.endswith(" dBm"):
        try:
            return int(ap.rssi.split()[0])
        except ValueError:
            pass
    return -999


def _lookup_manufacturer(mac: str) -> str:
    try:
        manuf = importlib.import_module("manuf")
        parser = manuf.MacParser()
        return parser.get_manuf(mac) or "Unknown"
    except Exception:
        return "Unknown"


async def discover_access_points_async(interface: str, timeout: int | None = 10) -> List[AccessPoint]:
    dot11, dot11_beacon, dot11_elt, _dot11_probe_req, _radiotap, async_sniffer = _load_scapy_symbols()
    access_points: Dict[str, AccessPoint] = {}

    def _handle_packet(packet: object) -> None:
        if not packet.haslayer(dot11_beacon) or not packet.haslayer(dot11):
            return
        bssid: Optional[str] = packet[dot11].addr2
        if not bssid:
            return

        channel = _parse_channel(packet, dot11_elt)
        encryption = _parse_encryption(packet)
        access_points[bssid] = AccessPoint(
            bssid=bssid,
            ssid=_parse_ssid(packet, dot11_elt),
            rssi=_parse_rssi(packet),
            channel=channel,
            band=_infer_band(channel),
            encryption=encryption,
            manufacturer=_lookup_manufacturer(bssid),
            beacon_interval_ms=_parse_beacon_interval(packet),
            uptime_seconds=_parse_uptime_seconds(packet),
            wpa3_sae=_is_wpa3_sae(encryption),
        )

    sniffer = async_sniffer(iface=interface, prn=_handle_packet, store=False)
    sniffer.start()
    await asyncio.sleep(timeout if timeout is not None else 10)
    sniffer.stop()
    return sorted(access_points.values(), key=lambda ap: (_signal_value(ap), ap.bssid), reverse=True)


async def discover_probed_networks_async(interface: str, timeout: int | None = 10) -> list[ProbeObservation]:
    dot11, _dot11_beacon, dot11_elt, dot11_probe_req, _radiotap, async_sniffer = _load_scapy_symbols()
    probes: list[ProbeObservation] = []

    def _handle(packet: object) -> None:
        if not packet.haslayer(dot11_probe_req) or not packet.haslayer(dot11):
            return
        try:
            ssid = packet[dot11_elt].info.decode("utf-8", errors="ignore")
        except Exception:
            ssid = ""
        if ssid:
            probes.append(
                ProbeObservation(
                    client_mac=packet[dot11].addr2 or "",
                    probed_ssid=ssid,
                    bssid=packet[dot11].addr1 or "",
                )
            )

    sniffer = async_sniffer(iface=interface, prn=_handle, store=False)
    sniffer.start()
    await asyncio.sleep(timeout if timeout is not None else 10)
    sniffer.stop()
    return probes


def discover_access_points(interface: str, timeout: int | None = 10) -> List[AccessPoint]:
    return asyncio.run(discover_access_points_async(interface=interface, timeout=timeout))


def discover_probed_networks(interface: str, timeout: int | None = 10) -> list[ProbeObservation]:
    return asyncio.run(discover_probed_networks_async(interface=interface, timeout=timeout))


def _print_table(access_points: List[AccessPoint]) -> None:
    header = ("BSSID", "SSID", "Signal", "Channel", "Band", "Enc", "Vendor")
    widths = [len(col) for col in header]
    for ap in access_points:
        values = (ap.bssid, ap.ssid, ap.rssi, ap.channel, ap.band, ap.encryption, ap.manufacturer)
        for i, val in enumerate(values):
            widths[i] = max(widths[i], len(val))

    line = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    print(line)
    print("| " + " | ".join(col.ljust(widths[i]) for i, col in enumerate(header)) + " |")
    print(line)
    for ap in access_points:
        values = (ap.bssid, ap.ssid, ap.rssi, ap.channel, ap.band, ap.encryption, ap.manufacturer)
        print("| " + " | ".join(values[i].ljust(widths[i]) for i in range(len(values))) + " |")
    print(line)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sniff 802.11 management frames and list nearby APs.")
    parser.add_argument("interface", help="Wireless interface in monitor mode (e.g., wlan0mon)")
    parser.add_argument("--timeout", type=int, default=None, help="Sniff timeout in seconds.")
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
