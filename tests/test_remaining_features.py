from remaining_features import (
    authentication_dos,
    beacon_flood,
    convert_cap_to_hc22000,
    cpu_fallback_cracker,
    crunch_wordlist,
    ensure_wordlist,
    export_cracked_credentials,
    generate_rule_candidates,
    jamming,
    online_cracking_submit,
    pmkid_attack,
    rainbow_lookup,
    telegram_notify,
    vendor_vulnerability_lookup,
)


def test_disabled_attack_stubs():
    assert pmkid_attack().mode == "disabled"
    assert beacon_flood().mode == "disabled"
    assert jamming().mode == "disabled"
    assert authentication_dos().mode == "disabled"


def test_cracking_and_export_helpers(tmp_path):
    hc = convert_cap_to_hc22000("a.cap", tmp_path / "a.hc22000")
    wl = crunch_wordlist("pass?", tmp_path / "wl.txt", limit=3)
    local = ensure_wordlist(tmp_path / "rockyou.txt")
    csv_path = export_cracked_credentials(tmp_path / "cracked.csv", [{"bssid": "AA", "ssid": "X", "password": "secret"}])
    assert hc.exists() and wl.exists() and local.exists() and csv_path.exists()
    assert cpu_fallback_cracker(["a", "b"], expected="b") == "b"
    assert rainbow_lookup("x") is None
    assert online_cracking_submit()["status"] == "queued"


def test_misc_helpers():
    rules = generate_rule_candidates(["admin"])
    assert "admin2025" in rules
    assert isinstance(vendor_vulnerability_lookup("TestVendor"), list)
    assert telegram_notify("t", "c", "hello")["sent"] is False
