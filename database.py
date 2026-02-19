"""Persistence layer using SQLAlchemy when available, sqlite fallback otherwise."""

from __future__ import annotations

import importlib
import sqlite3
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ScanResult:
    bssid: str
    ssid: str
    channel: str
    rssi: str
    encryption: str = "unknown"
    manufacturer: str = "Unknown"


@dataclass
class CapturedHandshake:
    bssid: str
    cap_path: str
    cracked_password: str | None = None
    status: str = "captured"


class _SimpleSession:
    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bssid TEXT, ssid TEXT, channel TEXT, rssi TEXT, encryption TEXT, manufacturer TEXT,
            created_at TEXT)"""
        )
        self.conn.execute(
            """CREATE TABLE IF NOT EXISTS captured_handshakes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bssid TEXT, cap_path TEXT, cracked_password TEXT, status TEXT, created_at TEXT)"""
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.conn.close()

    def add(self, obj):
        now = datetime.utcnow().isoformat()
        if isinstance(obj, ScanResult):
            self.conn.execute(
                "INSERT INTO scan_results (bssid,ssid,channel,rssi,encryption,manufacturer,created_at) VALUES (?,?,?,?,?,?,?)",
                (obj.bssid, obj.ssid, obj.channel, obj.rssi, obj.encryption, obj.manufacturer, now),
            )
        elif isinstance(obj, CapturedHandshake):
            self.conn.execute(
                "INSERT INTO captured_handshakes (bssid,cap_path,cracked_password,status,created_at) VALUES (?,?,?,?,?)",
                (obj.bssid, obj.cap_path, obj.cracked_password, obj.status, now),
            )

    def commit(self):
        self.conn.commit()

    def query(self, model):
        table = "scan_results" if model is ScanResult else "captured_handshakes"
        rows = self.conn.execute(f"SELECT * FROM {table}").fetchall()
        if model is ScanResult:
            return type("Q", (), {"all": lambda _s: [ScanResult(bssid=r[1], ssid=r[2], channel=r[3], rssi=r[4], encryption=r[5], manufacturer=r[6]) for r in rows]})()
        return type("Q", (), {"all": lambda _s: [CapturedHandshake(bssid=r[1], cap_path=r[2], cracked_password=r[3], status=r[4]) for r in rows]})()


def make_session_factory(db_url: str):
    sqlalchemy_spec = importlib.util.find_spec("sqlalchemy")
    if sqlalchemy_spec:
        from sqlalchemy import DateTime, Integer, String, create_engine
        from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

        class Base(DeclarativeBase):
            pass

        class SA_ScanResult(Base):
            __tablename__ = "scan_results"
            id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
            bssid: Mapped[str] = mapped_column(String(32), index=True)
            ssid: Mapped[str] = mapped_column(String(128))
            channel: Mapped[str] = mapped_column(String(16))
            rssi: Mapped[str] = mapped_column(String(16))
            encryption: Mapped[str] = mapped_column(String(32), default="unknown")
            manufacturer: Mapped[str] = mapped_column(String(128), default="Unknown")
            created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

        class SA_CapturedHandshake(Base):
            __tablename__ = "captured_handshakes"
            id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
            bssid: Mapped[str] = mapped_column(String(32), index=True)
            cap_path: Mapped[str] = mapped_column(String(512))
            cracked_password: Mapped[str | None] = mapped_column(String(255), nullable=True)
            status: Mapped[str] = mapped_column(String(32), default="captured")
            created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

        db_file = db_url.replace("sqlite:///", "")
        engine = create_engine(f"sqlite:///{db_file}", future=True)
        Base.metadata.create_all(engine)
        return sessionmaker(engine, expire_on_commit=False)

    db_path = db_url.replace("sqlite:///", "")
    return lambda: _SimpleSession(db_path)
