from pathlib import Path

from config import Config
from database import ScanResult, make_session_factory


def test_config_loads_yaml(tmp_path: Path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text("interface: wlan9mon\ndefaults:\n  scan_timeout: 22\n")
    Config._instance = None
    cfg = Config.load(cfg_file)
    assert cfg.interface == "wlan9mon"
    assert cfg.defaults.scan_timeout == 22


def test_sqlite_persists_scan(tmp_path: Path):
    session_factory = make_session_factory(f"sqlite:///{tmp_path / 'bp.db'}")
    with session_factory() as db:
        db.add(ScanResult(bssid="AA", ssid="X", channel="6", rssi="-40 dBm"))
        db.commit()

    with session_factory() as db:
        rows = db.query(ScanResult).all()
        assert len(rows) == 1
        assert rows[0].ssid == "X"
