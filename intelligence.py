"""Recon and defensive intelligence helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class HiddenSSIDFinding:
    bssid: str
    inferred_ssid: str
    client_mac: str


def correlate_hidden_ssids(ap_rows: list[dict], probe_rows: list[dict]) -> list[HiddenSSIDFinding]:
    """Correlate hidden APs with probe requests to infer likely SSIDs.

    This is heuristic-only and does not transmit traffic.
    """
    hidden_bssids = {ap["bssid"] for ap in ap_rows if ap.get("ssid") in {"<hidden>", ""}}
    findings: list[HiddenSSIDFinding] = []
    for probe in probe_rows:
        bssid = probe.get("bssid")
        ssid = probe.get("probed_ssid")
        client = probe.get("client_mac", "")
        if bssid in hidden_bssids and ssid:
            findings.append(HiddenSSIDFinding(bssid=bssid, inferred_ssid=ssid, client_mac=client))
    return findings


def resolve_geo(ip_lookup: callable | None = None) -> tuple[float | None, float | None, str]:
    """Return approximate coordinates via IP-geolocation callback if available."""
    if not ip_lookup:
        return None, None, "GPS unavailable"
    try:
        data = ip_lookup() or {}
        return data.get("lat"), data.get("lon"), data.get("source", "ip-geolocation")
    except Exception:
        return None, None, "GPS lookup failed"
