"""Configuration management for BreakPoint."""

from __future__ import annotations

import importlib
from pathlib import Path
from threading import Lock
from typing import Any, ClassVar

try:
    from pydantic import BaseModel, Field
except Exception:  # pragma: no cover
    class BaseModel:  # lightweight fallback
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        @classmethod
        def model_validate(cls, data: dict[str, Any]):
            return cls(**data)

    def Field(default_factory=None):
        return default_factory() if default_factory else None


class PathsConfig(BaseModel):
    captures_dir: Path = Path("captures")
    logs_file: Path = Path("breakpoint.log")
    db_file: Path = Path("breakpoint.db")
    session_file: Path = Path(".breakpoint_session.json")
    reports_dir: Path = Path("reports")


class DefaultsConfig(BaseModel):
    scan_timeout: int = 10
    capture_seconds: int = 25
    deauth_count: int = 16


class Config(BaseModel):
    interface: str = "wlan0mon"
    paths: PathsConfig = Field(default_factory=PathsConfig)
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)

    _instance: ClassVar["Config | None"] = None
    _lock: ClassVar[Lock] = Lock()


    def __init__(self, **data):
        super().__init__(**data)
        if isinstance(getattr(self, "paths", None), dict):
            self.paths = PathsConfig(**self.paths)
        if isinstance(getattr(self, "defaults", None), dict):
            self.defaults = DefaultsConfig(**self.defaults)

    @classmethod
    def load(cls, path: str | Path = "config.yaml") -> "Config":
        if cls._instance is not None:
            return cls._instance
        with cls._lock:
            if cls._instance is not None:
                return cls._instance

            payload: dict[str, Any] = {}
            cfg_path = Path(path)
            if cfg_path.exists():
                yaml_spec = importlib.util.find_spec("yaml")
                if yaml_spec:
                    yaml = importlib.import_module("yaml")
                    payload = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
                else:
                    payload = _naive_yaml_parse(cfg_path.read_text(encoding="utf-8"))

            cls._instance = cls.model_validate(payload)
            return cls._instance


def _naive_yaml_parse(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not raw.startswith(" ") and ":" in line:
            key, value = line.split(":", 1)
            if not value.strip():
                out[key.strip()] = {}
                current = out[key.strip()]
            else:
                out[key.strip()] = _coerce(value.strip())
        elif current is not None and ":" in line:
            key, value = line.split(":", 1)
            current[key.strip()] = _coerce(value.strip())
    return out


def _coerce(value: str) -> Any:
    if value.isdigit():
        return int(value)
    return value
