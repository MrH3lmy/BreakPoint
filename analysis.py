"""Analysis helpers for quality, entropy, and historical comparisons."""

from __future__ import annotations

import csv
import json
import math
from collections import Counter
from pathlib import Path


def password_entropy(password: str) -> float:
    if not password:
        return 0.0
    counts = Counter(password)
    length = len(password)
    return -sum((c / length) * math.log2(c / length) for c in counts.values()) * length


def handshake_quality_from_eapol_count(eapol_frames: int) -> str:
    if eapol_frames >= 4:
        return "complete"
    if eapol_frames > 0:
        return "partial"
    return "none"


def export_json(path: str | Path, payload: dict) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p


def export_cracked_csv(path: str | Path, rows: list[dict]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["bssid", "ssid", "password", "entropy"])
        writer.writeheader()
        writer.writerows(rows)
    return p


def diff_scans(previous: list[dict], current: list[dict]) -> dict[str, list[dict]]:
    prev = {row["bssid"]: row for row in previous}
    cur = {row["bssid"]: row for row in current}
    new = [cur[b] for b in sorted(set(cur) - set(prev))]
    gone = [prev[b] for b in sorted(set(prev) - set(cur))]
    changed = [cur[b] for b in sorted(set(cur) & set(prev)) if cur[b].get("ssid") != prev[b].get("ssid")]
    return {"new": new, "gone": gone, "changed": changed}
