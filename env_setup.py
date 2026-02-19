#!/usr/bin/env python3
"""Module 1 helpers: privilege detection and wireless interface discovery."""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Dict, List


def _run_command(command: List[str]) -> subprocess.CompletedProcess:
    """Run a command and return the completed process."""
    return subprocess.run(command, capture_output=True, text=True, check=False)


def check_root_and_wireless_interfaces() -> Dict[str, object]:
    """Check root/sudo privileges and list wireless interfaces.

    Returns:
        Dictionary with:
            - is_root: bool
            - has_passwordless_sudo: bool
            - wireless_interfaces: list[str]
    """
    is_root = os.geteuid() == 0

    has_passwordless_sudo = False
    if not is_root and shutil.which("sudo"):
        sudo_check = _run_command(["sudo", "-n", "true"])
        has_passwordless_sudo = sudo_check.returncode == 0

    interfaces: List[str] = []

    if shutil.which("iw"):
        iw_result = _run_command(["iw", "dev"])
        if iw_result.returncode == 0:
            for line in iw_result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("Interface "):
                    interfaces.append(stripped.split()[1])

    if not interfaces and shutil.which("iwconfig"):
        iwconfig_result = _run_command(["iwconfig"])
        if iwconfig_result.returncode == 0:
            for line in iwconfig_result.stdout.splitlines():
                if not line.strip():
                    continue
                if line[0].isspace():
                    continue
                name = line.split()[0]
                if "no wireless extensions" not in line:
                    interfaces.append(name)

    unique_interfaces = sorted(set(interfaces))

    return {
        "is_root": is_root,
        "has_passwordless_sudo": has_passwordless_sudo,
        "wireless_interfaces": unique_interfaces,
    }


if __name__ == "__main__":
    info = check_root_and_wireless_interfaces()

    print(f"Running as root: {info['is_root']}")
    print(f"Has passwordless sudo: {info['has_passwordless_sudo']}")

    interfaces = info["wireless_interfaces"]
    if interfaces:
        print("Wireless interfaces found:")
        for iface in interfaces:
            print(f" - {iface}")
    else:
        print("No wireless interfaces found.")
