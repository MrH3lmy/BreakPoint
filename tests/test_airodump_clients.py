from pathlib import Path

from airodump_clients import _parse_airodump_csv


def test_parse_airodump_csv_filters_stations_by_bssid(tmp_path: Path) -> None:
    csv_file = tmp_path / "capture-01.csv"
    csv_file.write_text(
        "BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n"
        "AA:BB:CC:DD:EE:FF, 2024-01-01 00:00:00, 2024-01-01 00:00:03, 6, 54, WPA2, CCMP, PSK, -40, 12, 0, 0. 0. 0. 0, 6, MyWiFi,\n"
        "\n"
        "Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\n"
        "11:22:33:44:55:66, 2024-01-01 00:00:01, 2024-01-01 00:00:02, -55, 4, aa:bb:cc:dd:ee:ff,\n"
        "22:33:44:55:66:77, 2024-01-01 00:00:01, 2024-01-01 00:00:02, -61, 2, FF:EE:DD:CC:BB:AA,\n"
        "11:22:33:44:55:66, 2024-01-01 00:00:01, 2024-01-01 00:00:02, -55, 4, AA:BB:CC:DD:EE:FF,\n"
    )

    clients = _parse_airodump_csv(csv_file, "AA:BB:CC:DD:EE:FF")

    assert clients == ["11:22:33:44:55:66"]
