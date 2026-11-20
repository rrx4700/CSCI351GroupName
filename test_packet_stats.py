"""Tests for phase 2 protocol, size, and time statistics."""

from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from Main import PacketRecord, process_packet, read_frames
from packet_stats import calculate_statistics, timestamp_microseconds


ROOT = Path(__file__).resolve().parent


def packet(timestamp="12:00:00,000,000", size=40, l2="Ethernet II",
           l3="IPv4", l4="TCP"):
    """Build parser metadata without depending on a constructed wire packet."""
    return PacketRecord(timestamp, l2, l3, l4, size)


class StatisticsTests(unittest.TestCase):
    """Check aggregation boundaries and integration with the current parser."""

    def test_protocol_counts_and_unidentified(self):
        """Count every input once per layer, including unsupported protocols."""
        records = [packet(), packet(l4="UDP"),
                   packet(l3="IPv6", l4="ICMPv6"),
                   packet(size=None, l3="ARP", l4=None),
                   packet(size=None, l2="IEEE 802.3", l3=None, l4=None),
                   packet(size=None, l3="EtherType 0x88b5", l4=None)]
        stats = calculate_statistics(iter(records))
        self.assertEqual(stats.total_packets, 6)
        self.assertEqual(stats.protocol_counts["L2"],
                         {"Ethernet II": 5, "IEEE 802.3": 1})
        self.assertEqual(stats.protocol_counts["L3"], {
            "IPv4": 2, "IPv6": 1, "ARP": 1, "Not identified": 1,
            "EtherType 0x88b5": 1})
        self.assertEqual(stats.protocol_counts["L4"], {
            "TCP": 1, "UDP": 1, "ICMPv6": 1, "Not identified": 3})
        for counts in stats.protocol_counts.values():
            self.assertEqual(sum(counts.values()), stats.total_packets)
        self.assertEqual(stats.missing_l3_sizes, 3)

    def test_size_boundaries_and_empty_bins(self):
        """Use L3 sizes with exact 250-byte boundaries and no frame padding."""
        stats = calculate_statistics(packet(size=size) for size in (
            0, 249, 250, 499, 500, 1499, 1500, 1501, None))
        self.assertEqual(stats.packet_size_bins, {
            "0-249": 2, "250-499": 2, "500-749": 1, "750-999": 0,
            "1000-1249": 0, "1250-1499": 1, "1500-1749": 2})
        self.assertEqual(stats.missing_l3_sizes, 1)
        self.assertEqual(sum(stats.packet_size_bins.values())
                         + stats.missing_l3_sizes, stats.total_packets)
        for invalid in (-1, 1.5, True):
            with self.subTest(size=invalid), self.assertRaises(ValueError):
                calculate_statistics([packet(size=invalid)])

    def test_first_ten_seconds(self):
        """Align to the first packet, include t=9.999999, exclude t=10."""
        times = ["12:00:00,500,000", "12:00:01,499,999",
                 "12:00:01,500,000", "12:00:03,500,000",
                 "12:00:10,499,999", "12:00:10,500,000"]
        stats = calculate_statistics(packet(timestamp=t) for t in times)
        self.assertEqual(stats.seconds, list(range(10)))
        self.assertEqual(stats.packets_per_second,
                         [2, 1, 0, 1, 0, 0, 0, 0, 0, 1])
        self.assertEqual(stats.timing_origin, times[0])
        self.assertEqual(stats.packets_outside_window, 1)

    def test_midnight_rollover(self):
        """Continue the ten-second window when the clock crosses midnight."""
        times = ["23:59:59,750,000", "00:00:00,250,000",
                 "00:00:00,750,000", "00:00:09,750,000"]
        stats = calculate_statistics(packet(timestamp=t) for t in times)
        self.assertEqual(stats.packets_per_second, [2, 1] + [0] * 8)
        self.assertEqual(stats.packets_outside_window, 1)

    def test_out_of_order_times(self):
        """Small backwards steps neither reset the origin nor add a day."""
        times = ["12:00:02", "12:00:04", "12:00:03", "12:00:01"]
        stats = calculate_statistics(packet(timestamp=t) for t in times)
        self.assertEqual(stats.packets_per_second, [1, 1, 1] + [0] * 7)
        self.assertEqual(stats.packets_outside_window, 1)

    def test_timestamp_formats_and_missing_times(self):
        """Missing/invalid times affect timing only; valid times use integers."""
        self.assertEqual(timestamp_microseconds("00:00:00,123,456"), 123456)
        self.assertEqual(timestamp_microseconds("00:00:00.123456"), 123456)
        self.assertEqual(timestamp_microseconds("00:00:00.1"), 100000)
        self.assertEqual(timestamp_microseconds("01:00:00"), 3600000000)
        invalid = ["unknown", "24:00:00", "12:60:00", "12:00:60",
                   "12:00:00,1,2", "12:00:00.1234567"]
        for timestamp in invalid:
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                timestamp_microseconds(timestamp)
        stats = calculate_statistics(packet(timestamp=t)
                                     for t in invalid + ["12:00:01"])
        self.assertEqual(stats.invalid_timestamps, len(invalid))
        self.assertEqual(stats.total_packets, len(invalid) + 1)
        self.assertEqual(stats.timing_origin, "12:00:01")
        self.assertEqual(stats.packets_per_second, [1] + [0] * 9)

    def test_empty_and_untimed_capture(self):
        """Return ten zero time bins and no invented origin for no data."""
        empty = calculate_statistics([])
        self.assertEqual(empty.total_packets, 0)
        self.assertEqual(empty.protocol_counts, {"L2": {}, "L3": {}, "L4": {}})
        self.assertEqual(empty.packet_size_bins, {"0-249": 0})
        self.assertEqual(empty.packets_per_second, [0] * 10)
        self.assertIsNone(empty.timing_origin)
        untimed = calculate_statistics([packet(timestamp="unknown")])
        self.assertIsNone(untimed.timing_origin)
        self.assertEqual(untimed.invalid_timestamps, 1)
        self.assertEqual(untimed.packet_size_bins, {"0-249": 1})

    def test_assignment_capture(self):
        """Consume real PacketRecords produced by the teammate's parser."""
        records = [process_packet(i, timestamp, frame)[0]
                   for i, (timestamp, frame)
                   in enumerate(read_frames(ROOT / "input.txt"), 1)]
        stats = calculate_statistics(records)
        self.assertEqual(stats.total_packets, 18)
        self.assertEqual(stats.protocol_counts, {
            "L2": {"Ethernet II": 14, "IEEE 802.3": 4},
            "L3": {"IPv4": 9, "IPv6": 2, "ARP": 3, "Not identified": 4},
            "L4": {"TCP": 6, "ICMP": 2, "IGMP": 1, "Not identified": 9}})
        self.assertEqual(stats.packet_size_bins, {
            "0-249": 9, "250-499": 0, "500-749": 0, "750-999": 1,
            "1000-1249": 0, "1250-1499": 0, "1500-1749": 1})
        self.assertEqual(stats.missing_l3_sizes, 7)
        self.assertEqual(stats.packets_per_second,
                         [1, 0, 0, 0, 1, 0, 1, 0, 0, 0])
        self.assertEqual(stats.invalid_timestamps, 0)
        self.assertEqual(stats.packets_outside_window, 15)
        # Result can be exported for graphs without custom JSON encoders.
        self.assertEqual(json.loads(json.dumps(asdict(stats))), asdict(stats))

    def test_cli(self):
        """Expose reusable JSON and useful errors without changing Main.py."""
        def run(*args):
            return subprocess.run(
                [sys.executable, "-B", str(ROOT / "packet_stats.py"), *args],
                cwd=ROOT, text=True, capture_output=True, check=False)

        result = run(str(ROOT / "input.txt"), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["total_packets"], 18)
        self.assertEqual(result.stderr, "")
        readable = run(str(ROOT / "input.txt"))
        self.assertEqual(readable.returncode, 0)
        self.assertIn("Packets/second (first 10 seconds)", readable.stdout)
        self.assertEqual(run("--help").returncode, 0)
        self.assertEqual(run().returncode, 2)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.txt"
            self.assertEqual(run(str(path)).returncode, 2)
            path.write_text("", encoding="utf-8")
            empty = run(str(path), "--json")
            self.assertEqual(empty.returncode, 1)
            self.assertEqual(json.loads(empty.stdout)["total_packets"], 0)
            path.write_text("ETHER\n|0   |00|\n", encoding="utf-8")
            bad = run(str(path), "--json")
            self.assertEqual(bad.returncode, 1)
            self.assertEqual(json.loads(bad.stdout)["total_packets"], 0)
            self.assertIn("Excluded 1 malformed packet", bad.stderr)


if __name__ == "__main__":
    unittest.main()
