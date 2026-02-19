from pathlib import Path

import handshake_cracking as hc
import process_utils as pu


class DummyPopen:
    def __init__(self, *_args, **_kwargs):
        self.terminated = False

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.terminated = True


def test_verify_handshake_with_aircrack(monkeypatch: object, tmp_path: Path) -> None:
    cap = tmp_path / "test.cap"
    cap.write_text("x")

    monkeypatch.setattr(hc.shutil, "which", lambda tool: "/usr/bin/aircrack-ng" if tool == "aircrack-ng" else None)

    class Result:
        returncode = 0
        stdout = "[00:00:12] 1 handshake"
        stderr = ""

    monkeypatch.setattr(pu.subprocess, "run", lambda *args, **kwargs: Result())

    assert hc.verify_handshake(str(cap), bssid="AA:BB:CC:DD:EE:FF") is True


def test_crack_wpa_password_reads_output_file(monkeypatch: object, tmp_path: Path) -> None:
    cap = tmp_path / "test.cap"
    cap.write_text("cap")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("password")

    monkeypatch.setattr(hc.shutil, "which", lambda _tool: "/usr/bin/aircrack-ng")

    def fake_run(cmd, check, capture_output, text, timeout=None):
        out_index = cmd.index("-l") + 1
        Path(cmd[out_index]).write_text("supersecret\n")

        class Result:
            returncode = 0
            stdout = ""
            stderr = ""

        return Result()

    monkeypatch.setattr(pu.subprocess, "run", fake_run)

    assert hc.crack_wpa_password(str(cap), str(wordlist)) == "supersecret"


def test_capture_handshake_returns_cap(monkeypatch: object, tmp_path: Path) -> None:
    out_prefix = tmp_path / "capture"

    monkeypatch.setattr(hc.shutil, "which", lambda tool: "/usr/bin/ok" if tool in {"airodump-ng", "aireplay-ng"} else None)
    monkeypatch.setattr(hc.subprocess, "Popen", lambda *args, **kwargs: DummyPopen())
    monkeypatch.setattr(hc.time, "sleep", lambda _s: None)

    class Result:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(pu.subprocess, "run", lambda *args, **kwargs: Result())

    expected_cap = tmp_path / "capture-01.cap"

    original_exists = Path.exists

    def fake_exists(self):
        if self == expected_cap:
            return True
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    cap = hc.capture_handshake("wlan0mon", "AA:BB:CC:DD:EE:FF", "6", str(out_prefix), capture_seconds=5)

    assert cap == expected_cap
