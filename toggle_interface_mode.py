#!/usr/bin/env python3
"""Toggle wireless interface mode between managed and monitor using airmon-ng."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from typing import List


class AirmonError(RuntimeError):
    """Raised for airmon-ng related failures."""


def _run_command(command: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _require_airmon() -> None:
    if not shutil.which("airmon-ng"):
        raise AirmonError("airmon-ng not found in PATH. Install aircrack-ng first.")


def _kill_interfering_processes() -> None:
    check = _run_command(["airmon-ng", "check"])
    if check.returncode != 0:
        raise AirmonError(f"Failed to inspect interfering processes:\n{check.stderr or check.stdout}")

    # Best practice before changing mode.
    kill = _run_command(["airmon-ng", "check", "kill"])
    if kill.returncode != 0:
        raise AirmonError(f"Failed to kill interfering processes:\n{kill.stderr or kill.stdout}")


def set_interface_mode(interface: str, mode: str) -> None:
    """Set interface mode using airmon-ng.

    Args:
        interface: interface name (example: wlan0).
        mode: either "monitor" or "managed".
    """
    if mode not in {"monitor", "managed"}:
        raise ValueError("mode must be 'monitor' or 'managed'")

    _require_airmon()
    _kill_interfering_processes()

    if mode == "monitor":
        cmd = ["airmon-ng", "start", interface]
    else:
        cmd = ["airmon-ng", "stop", interface]

    result = _run_command(cmd)
    if result.returncode != 0:
        raise AirmonError(f"Failed to set {interface} to {mode}:\n{result.stderr or result.stdout}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Toggle interface between Managed and Monitor modes via airmon-ng."
    )
    parser.add_argument("interface", help="Wireless interface name (e.g., wlan0)")
    parser.add_argument(
        "mode",
        choices=["monitor", "managed"],
        help="Target mode to set",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        set_interface_mode(args.interface, args.mode)
    except (AirmonError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Successfully set {args.interface} to {args.mode} mode.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
