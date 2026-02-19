"""Visualization helpers for defensive reporting."""

from __future__ import annotations

from pathlib import Path


def signal_heatmap(path: str | Path, points: list[tuple[int, int, int]]) -> Path:
    """Render RSSI heatmap image from (x, y, rssi) tuples."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        import matplotlib.pyplot as plt
        import numpy as np
    except Exception:
        p.write_text("matplotlib unavailable", encoding="utf-8")
        return p

    if not points:
        p.write_text("no points", encoding="utf-8")
        return p

    max_x = max(x for x, _, _ in points) + 1
    max_y = max(y for _, y, _ in points) + 1
    grid = np.full((max_y, max_x), -100)
    for x, y, rssi in points:
        grid[y, x] = rssi

    plt.figure(figsize=(5, 4))
    plt.imshow(grid, cmap="viridis", interpolation="nearest")
    plt.colorbar(label="RSSI (dBm)")
    plt.title("Signal Heatmap")
    plt.tight_layout()
    plt.savefig(p)
    plt.close()
    return p


def topology_graph(path: str | Path, edges: list[tuple[str, str]]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        import matplotlib.pyplot as plt
        import networkx as nx
    except Exception:
        p.write_text("networkx/matplotlib unavailable", encoding="utf-8")
        return p

    graph = nx.Graph()
    graph.add_edges_from(edges)
    plt.figure(figsize=(6, 4))
    nx.draw_networkx(graph, with_labels=True, node_size=500, font_size=7)
    plt.tight_layout()
    plt.savefig(p)
    plt.close()
    return p
