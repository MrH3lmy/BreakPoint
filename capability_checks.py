"""Defensive capability checks and capture cleanup."""

from __future__ import annotations

import importlib
import subprocess
from pathlib import Path


def interface_supports_injection(interface: str) -> bool:
    """Best-effort injection support check via aireplay-ng --test."""
    try:
        result = subprocess.run(
            ["aireplay-ng", "--test", interface],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception:
        return False
    out = f"{result.stdout}\n{result.stderr}".lower()
    return "injection is working" in out or "test failed" not in out


def clean_handshake_cap(input_cap: str | Path, output_cap: str | Path) -> Path:
    """Keep only EAPOL and beacon frames to reduce capture noise."""
    in_path = Path(input_cap)
    out_path = Path(output_cap)
    if not in_path.exists():
        raise FileNotFoundError(str(in_path))

    scapy = importlib.import_module("scapy.all")
    packets = scapy.rdpcap(str(in_path))
    filtered = [p for p in packets if p.haslayer("EAPOL") or p.haslayer("Dot11Beacon")]
    scapy.wrpcap(str(out_path), filtered)
    return out_path
