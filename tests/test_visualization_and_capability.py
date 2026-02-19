from pathlib import Path

from capability_checks import interface_supports_injection
from visualization import signal_heatmap, topology_graph


def test_visualization_outputs(tmp_path: Path):
    heat = signal_heatmap(tmp_path / "h.png", [(0, 0, -30), (1, 0, -70)])
    topo = topology_graph(tmp_path / "t.png", [("AP1", "C1")])
    assert heat.exists()
    assert topo.exists()


def test_interface_check_graceful():
    assert isinstance(interface_supports_injection("wlan0mon"), bool)
