"""Reporting and visualization helpers."""

from __future__ import annotations

from pathlib import Path


def render_html_report(path: str | Path, title: str, findings: dict) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    rows = "".join(f"<li><b>{k}</b>: {v}</li>" for k, v in findings.items())
    p.write_text(
        f"""<!doctype html><html><head><meta charset='utf-8'><title>{title}</title></head>
<body><h1>{title}</h1><ul>{rows}</ul></body></html>""",
        encoding="utf-8",
    )
    return p


def build_topology_edges(aps: list[dict], clients: list[dict]) -> list[tuple[str, str]]:
    known_aps = {ap["bssid"] for ap in aps}
    edges = []
    for client in clients:
        bssid = client.get("bssid")
        mac = client.get("client_mac")
        if bssid in known_aps and mac:
            edges.append((bssid, mac))
    return edges


def timeline_events(events: list[dict]) -> list[dict]:
    return sorted(events, key=lambda e: e.get("timestamp", ""))
