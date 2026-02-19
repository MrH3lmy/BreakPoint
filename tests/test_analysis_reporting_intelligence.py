from analysis import diff_scans, export_cracked_csv, export_json, handshake_quality_from_eapol_count, password_entropy
from intelligence import correlate_hidden_ssids, resolve_geo
from reporting import build_topology_edges, render_html_report, timeline_events


def test_entropy_and_quality():
    assert password_entropy("aaaa") == 0.0
    assert password_entropy("abc123") > 0
    assert handshake_quality_from_eapol_count(4) == "complete"
    assert handshake_quality_from_eapol_count(2) == "partial"


def test_exports_and_diff(tmp_path):
    j = export_json(tmp_path / "x.json", {"ok": True})
    c = export_cracked_csv(tmp_path / "c.csv", [{"bssid": "AA", "ssid": "x", "password": "p", "entropy": 1.0}])
    assert j.exists() and c.exists()
    d = diff_scans([{"bssid": "A", "ssid": "one"}], [{"bssid": "A", "ssid": "two"}, {"bssid": "B", "ssid": "new"}])
    assert len(d["new"]) == 1 and len(d["changed"]) == 1


def test_intel_and_reporting(tmp_path):
    findings = correlate_hidden_ssids(
        [{"bssid": "AA", "ssid": "<hidden>"}],
        [{"bssid": "AA", "probed_ssid": "CorpWiFi", "client_mac": "11"}],
    )
    assert findings and findings[0].inferred_ssid == "CorpWiFi"
    lat, lon, src = resolve_geo(lambda: {"lat": 1.0, "lon": 2.0, "source": "ip"})
    assert (lat, lon, src) == (1.0, 2.0, "ip")

    h = render_html_report(tmp_path / "r.html", "Report", {"a": 1})
    assert h.exists()
    edges = build_topology_edges([{"bssid": "AA"}], [{"bssid": "AA", "client_mac": "11"}])
    assert edges == [("AA", "11")]
    tl = timeline_events([{"timestamp": "2"}, {"timestamp": "1"}])
    assert tl[0]["timestamp"] == "1"
