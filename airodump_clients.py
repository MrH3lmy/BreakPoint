#!/usr/bin/env python3
"""Capture connected wireless clients for a target BSSID using airodump-ng."""

from __future__ import annotations

import csv
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import List


class AirodumpError(RuntimeError):
    """Raised when airodump-ng capture or parsing fails."""


def _normalize_mac(value: str) -> str:
    return value.strip().upper()


def _parse_airodump_csv(csv_path: Path, target_bssid: str) -> List[str]:
    """Parse airodump-ng CSV and return station MACs connected to target BSSID."""
    stations: List[str] = []
    in_station_section = False
    normalized_target = _normalize_mac(target_bssid)

    with csv_path.open("r", newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row or not any(cell.strip() for cell in row):
                continue

            first_col = row[0].strip()
            if first_col == "Station MAC":
                in_station_section = True
                continue

            if not in_station_section:
                continue

            if len(row) < 6:
                continue

            station_mac = _normalize_mac(row[0])
            station_bssid = _normalize_mac(row[5])

            if station_bssid == normalized_target and station_mac:
                stations.append(station_mac)

    return sorted(set(stations))


def get_connected_clients(
    interface: str,
    target_bssid: str,
    duration_seconds: int = 10,
    channel: str | None = None,
) -> List[str]:
    """Run airodump-ng in the background for a short capture and return station MACs.

    Args:
        interface: Monitor-mode interface (for example, ``wlan0mon``).
        target_bssid: AP BSSID to filter client associations for.
        duration_seconds: Capture duration in seconds.
        channel: Optional channel value to speed up lock-on.
    """
    if duration_seconds <= 0:
        raise ValueError("duration_seconds must be > 0")

    if not shutil.which("airodump-ng"):
        raise AirodumpError("airodump-ng not found in PATH. Install aircrack-ng first.")

    with tempfile.TemporaryDirectory(prefix="airodump_capture_") as tmp_dir:
        output_prefix = Path(tmp_dir) / "capture"
        command = [
            "airodump-ng",
            "--write",
            str(output_prefix),
            "--output-format",
            "csv",
            interface,
            "--bssid",
            target_bssid,
        ]

        if channel:
            command.extend(["--channel", channel])

        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            time.sleep(duration_seconds)
        finally:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

        csv_path = Path(f"{output_prefix}-01.csv")
        if not csv_path.exists():
            raise AirodumpError("airodump-ng did not produce a CSV output file.")

        return _parse_airodump_csv(csv_path, target_bssid)
