"""Non-operational scaffolding for remaining requested features.

These helpers provide safe/dummy interfaces for planning, reporting, and integration testing.
They intentionally do not execute high-impact offensive actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import csv
import json


@dataclass
class FeatureResult:
    name: str
    implemented: bool
    mode: str
    details: str


def pmkid_attack(*_args, **_kwargs) -> FeatureResult:
    return FeatureResult("pmkid_attack", False, "disabled", "High-impact attack flow intentionally disabled.")


def evil_twin_setup(*_args, **_kwargs) -> FeatureResult:
    return FeatureResult("evil_twin_setup", False, "disabled", "Template-only; no AP cloning performed.")


def beacon_flood(*_args, **_kwargs) -> FeatureResult:
    return FeatureResult("beacon_flood", False, "disabled", "Disabled by safety policy.")


def jamming(*_args, **_kwargs) -> FeatureResult:
    return FeatureResult("jamming", False, "disabled", "Disabled by safety policy.")


def mdk4_wrapper(*_args, **_kwargs) -> FeatureResult:
    return FeatureResult("mdk4_wrapper", False, "disabled", "Command wrapper intentionally unavailable.")


def karma_simulation(*_args, **_kwargs) -> FeatureResult:
    return FeatureResult("karma_simulation", False, "disabled", "Simulation disabled.")


def authentication_dos(*_args, **_kwargs) -> FeatureResult:
    return FeatureResult("authentication_dos", False, "disabled", "Disabled by safety policy.")


def convert_cap_to_hc22000(cap_path: str | Path, output_path: str | Path) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(f"dummy conversion from {cap_path}\n", encoding="utf-8")
    return out


def crunch_wordlist(pattern: str, output_path: str | Path, limit: int = 32) -> Path:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = [pattern.replace("?", str(i)) for i in range(limit)]
    out.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return out


def online_cracking_submit(*_args, **_kwargs) -> dict:
    return {"status": "queued", "provider": "dummy", "ticket": "LOCAL-DEMO"}


def rainbow_lookup(*_args, **_kwargs) -> str | None:
    return None


def cpu_fallback_cracker(candidates: list[str], expected: str | None = None) -> str | None:
    if expected and expected in candidates:
        return expected
    return candidates[0] if candidates else None


def notify_event(message: str) -> dict:
    return {"notified": True, "channel": "stdout", "message": message}


def ensure_wordlist(path: str | Path) -> Path:
    p = Path(path)
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("password\nadmin123\nqwerty\n", encoding="utf-8")
    return p


def generate_rule_candidates(base_words: list[str]) -> list[str]:
    suffixes = ["2024", "2025", "!", "@123"]
    out = []
    for word in base_words:
        out.extend([word] + [f"{word}{s}" for s in suffixes])
    return out


def export_cracked_credentials(path: str | Path, rows: list[dict]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["bssid", "ssid", "password"])
        w.writeheader()
        w.writerows(rows)
    return p


def vendor_vulnerability_lookup(vendor: str) -> list[dict]:
    # Dummy local CVE mapping placeholder
    db = {
        "Unknown": [],
        "TestVendor": [{"cve": "CVE-0000-0000", "note": "default credentials advisory (demo)"}],
    }
    return db.get(vendor, [])


def telegram_notify(token: str, chat_id: str, message: str) -> dict:
    return {"sent": False, "reason": "dummy/no-network", "chat_id": chat_id, "preview": message[:80]}


def save_history(path: str | Path, payload: dict) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return p
