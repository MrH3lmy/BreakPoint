import asyncio

from sniff_beacons import AccessPoint, discover_access_points, discover_probed_networks


class FakeDot11:
    pass


class FakeDot11Beacon:
    pass


class FakeDot11Elt:
    pass


class FakeDot11ProbeReq:
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


class FakeAsyncSniffer:
    def __init__(self, iface, prn, store):
        self.prn = prn
        self.packets = [
            FakePacket("AA:AA:AA:AA:AA:AA"),
            FakePacket("BB:BB:BB:BB:BB:BB"),
            FakePacket("AA:AA:AA:AA:AA:AA"),
        ]

    def start(self):
        for pkt in self.packets:
            self.prn(pkt)

    def stop(self):
        return None


def test_discover_access_points_sorts_and_dedupes(monkeypatch):
    import sniff_beacons as sb

    def fake_ssid(packet, dot11_elt):
        return "AP-" + packet._bssid[:2]

    def fake_channel(packet, dot11_elt):
        return "6" if packet._bssid.startswith("AA") else "36"

    def fake_rssi(packet):
        return "-30 dBm" if packet._bssid.startswith("AA") else "-70 dBm"

    monkeypatch.setattr(sb, "_parse_ssid", fake_ssid)
    monkeypatch.setattr(sb, "_parse_channel", fake_channel)
    monkeypatch.setattr(sb, "_parse_rssi", fake_rssi)
    monkeypatch.setattr(sb, "_parse_encryption", lambda _pkt: "WPA2")
    monkeypatch.setattr(sb, "_lookup_manufacturer", lambda _mac: "TestVendor")
    original_sleep = asyncio.sleep
    monkeypatch.setattr(sb.asyncio, "sleep", lambda _seconds: original_sleep(0))
    monkeypatch.setattr(
        sb,
        "_load_scapy_symbols",
        lambda: (FakeDot11, FakeDot11Beacon, FakeDot11Elt, FakeDot11ProbeReq, object(), FakeAsyncSniffer),
    )

    result = discover_access_points("wlan0mon", timeout=1)

    assert [ap.bssid for ap in result] == ["AA:AA:AA:AA:AA:AA", "BB:BB:BB:BB:BB:BB"]
    assert isinstance(result[0], AccessPoint)
    assert result[0].manufacturer == "TestVendor"


def test_discover_probed_networks(monkeypatch):
    import sniff_beacons as sb

    class ProbePkt(FakePacket):
        def haslayer(self, layer):
            return layer in {FakeDot11, FakeDot11ProbeReq}

        def __getitem__(self, layer):
            if layer is FakeDot11:
                class Layer:
                    addr2 = "11:22:33:44:55:66"
                    addr1 = "AA:AA:AA:AA:AA:AA"
                return Layer()
            if layer is FakeDot11Elt:
                class Layer:
                    info = b"CorpWiFi"
                return Layer()
            raise KeyError

    class ProbeSniffer(FakeAsyncSniffer):
        def __init__(self, iface, prn, store):
            self.prn = prn
            self.packets = [ProbePkt("AA:AA:AA:AA:AA:AA")]

    original_sleep = asyncio.sleep
    monkeypatch.setattr(sb.asyncio, "sleep", lambda _seconds: original_sleep(0))
    monkeypatch.setattr(sb, "_load_scapy_symbols", lambda: (FakeDot11, FakeDot11Beacon, FakeDot11Elt, FakeDot11ProbeReq, object(), ProbeSniffer))

    probes = discover_probed_networks("wlan0mon", timeout=1)
    assert probes and probes[0].probed_ssid == "CorpWiFi"
