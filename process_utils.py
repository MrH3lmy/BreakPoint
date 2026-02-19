"""Safe subprocess wrapper utilities."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence


class CommandExecutionError(RuntimeError):
    """Raised when command execution fails before producing a result."""


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


def run_command(cmd: Sequence[str], timeout: int | None = None) -> CommandResult:
    try:
        result = subprocess.run(
            list(cmd),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandExecutionError(f"Command timed out: {' '.join(cmd)}") from exc
    except PermissionError as exc:
        raise CommandExecutionError(f"Permission denied running command: {' '.join(cmd)}") from exc

    return CommandResult(result.returncode, result.stdout, result.stderr)
