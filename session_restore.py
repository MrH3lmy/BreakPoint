"""Session state persistence and restore helpers."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class SessionState:
    bssid: str | None = None
    channel: str | None = None
    ssid: str | None = None
    last_cap: str | None = None


def load_session(path: str | Path) -> SessionState:
    p = Path(path)
    if not p.exists():
        return SessionState()
    return SessionState(**json.loads(p.read_text(encoding="utf-8")))


def save_session(path: str | Path, state: SessionState) -> None:
    Path(path).write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")
