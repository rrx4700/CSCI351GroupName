"""Smoke tests for graph_ui (skipped when matplotlib is not installed)."""

import tempfile
import unittest
from pathlib import Path

try:
    import matplotlib
    matplotlib.use("Agg")
except ImportError:  # pragma: no cover
    matplotlib = None

from packet_stats import PacketStatistics


def sample_stats() -> PacketStatistics:
    return PacketStatistics(
        total_packets=5,
        protocol_counts={
            "L2": {"Ethernet II": 4, "IEEE 802.3": 1},
            "L3": {"IPv4": 3, "ARP": 1, "Not identified": 1},
            "L4": {"TCP": 2, "UDP": 1, "Not identified": 2},
        },
        packet_size_bins={"0-249": 3, "250-499": 0, "500-749": 1},
        missing_l3_sizes=1,
        seconds=list(range(10)),
        packets_per_second=[2, 1, 0, 0, 1, 0, 0, 0, 0, 1],
        timing_origin="12:00:00,000,000",
        invalid_timestamps=0,
        packets_outside_window=0,
    )


@unittest.skipIf(matplotlib is None, "matplotlib is not installed")
class GraphUITests(unittest.TestCase):
    def test_saves_every_graph(self):
        import graph_ui
        with tempfile.TemporaryDirectory() as folder:
            written = graph_ui.display_dashboard(
                sample_stats(), Path(folder), show=False)
            names = sorted(path.name for path in written)
            self.assertEqual(names, [
                "dashboard.png", "packet_sizes.png", "packets_per_second.png",
                "protocols_l2.png", "protocols_l3.png", "protocols_l4.png"])
            for path in written:
                self.assertGreater(path.stat().st_size, 0)

    def test_dashboard_has_five_panels(self):
        import graph_ui
        import matplotlib.pyplot as plt
        fig = graph_ui.build_dashboard(sample_stats())
        self.assertEqual(len(fig.axes), 5)
        plt.close(fig)

    def test_handles_empty_capture(self):
        import graph_ui
        import matplotlib.pyplot as plt
        empty = PacketStatistics(0, {"L2": {}, "L3": {}, "L4": {}}, {}, 0,
                                 list(range(10)), [0] * 10, None, 0, 0)
        plt.close(graph_ui.build_dashboard(empty))


if __name__ == "__main__":
    unittest.main()
