from sniff_beacons import AccessPoint, discover_access_points


class FakeDot11:
    pass


class FakeDot11Beacon:
    pass


class FakeDot11Elt:
    pass


class FakePacket:
    def __init__(self, bssid: str):
        self._bssid = bssid

    def haslayer(self, layer):
        return layer in {FakeDot11, FakeDot11Beacon}

    def __getitem__(self, layer):
        if layer is FakeDot11:
            class Layer:
                addr2 = self._bssid

            return Layer()
        raise KeyError


def test_discover_access_points_sorts_and_dedupes(monkeypatch):
    import sniff_beacons as sb

    packets = [
        FakePacket("AA:AA:AA:AA:AA:AA"),
        FakePacket("BB:BB:BB:BB:BB:BB"),
        FakePacket("AA:AA:AA:AA:AA:AA"),
    ]

    def fake_ssid(packet, dot11_elt):
        return "AP-" + packet._bssid[:2]

    def fake_channel(packet, dot11_elt):
        return "6" if packet._bssid.startswith("AA") else "1"

    def fake_rssi(packet):
        return "-30 dBm" if packet._bssid.startswith("AA") else "-70 dBm"

    def fake_sniff(iface, prn, store, timeout):
        for pkt in packets:
            prn(pkt)

    monkeypatch.setattr(sb, "_parse_ssid", fake_ssid)
    monkeypatch.setattr(sb, "_parse_channel", fake_channel)
    monkeypatch.setattr(sb, "_parse_rssi", fake_rssi)
    monkeypatch.setattr(
        sb,
        "_load_scapy_symbols",
        lambda: (FakeDot11, FakeDot11Beacon, FakeDot11Elt, object(), fake_sniff),
    )

    result = discover_access_points("wlan0mon", timeout=5)

    assert [ap.bssid for ap in result] == ["AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"]
    assert isinstance(result[0], AccessPoint)
