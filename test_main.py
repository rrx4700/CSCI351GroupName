"""Standard-library tests; use installed TShark for independent checks."""

import csv
import io
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

import Main


ROOT = Path(__file__).resolve().parent
TSHARK = shutil.which("tshark")
if not TSHARK:
    installed = Path(r"C:\Program Files\Wireshark\tshark.exe")
    if installed.is_file():
        TSHARK = str(installed)


class PacketTests(unittest.TestCase):
    """Exercise Ethernet dispatch, malformed frames, and CLI messages."""

    @classmethod
    def setUpClass(cls):
        """Load the assignment capture and a known valid TCP packet."""
        cls.frames = Main.read_frames(ROOT / "input.txt")
        cls.tcp = cls.frames[6][1]

    def test_sample(self):
        """All sample packets produce Ethernet fields without errors."""
        self.assertEqual(len(self.frames), 18)
        reports = ["\n".join(Main.process_frame(i, stamp, frame))
                   for i, (stamp, frame) in enumerate(self.frames, 1)]
        for report in reports:
            self.assertIn("Destination MAC:", report)
            self.assertIn("Source MAC:", report)
            self.assertNotIn("INVALID", report)
        self.assertEqual(sum("IPv4 header:" in r for r in reports), 9)
        self.assertEqual(sum("TCP header:" in r for r in reports), 6)
        self.assertIn("ARP", reports[1])
        self.assertIn("broadcast", reports[1])
        self.assertIn("Length: 38", reports[12])
        self.assertIn("SNAP OUI: 00:00:0c", reports[14])
        self.assertIn("IPv6", reports[16])
        self.assertIn("multicast", reports[16])

    def encapsulations(self):
        """Wrap an unchanged IP/TCP packet in different Ethernet headers."""
        macs, ip = self.tcp[:12], self.tcp[14:]
        snap = bytes.fromhex("aaaa030000000800") + ip
        return [
            self.tcp,
            macs + bytes.fromhex("8100b0250800") + ip,
            macs + bytes.fromhex("88a800078100b0250800") + ip,
            macs + len(snap).to_bytes(2, "big") + snap,
            macs + bytes.fromhex("8100b025")
            + len(snap).to_bytes(2, "big") + snap,
        ]

    def test_encapsulations(self):
        """VLAN and SNAP offsets preserve valid IPv4/TCP checksums."""
        for frame, offset in zip(self.encapsulations(), [14, 18, 22, 22, 26]):
            with self.subTest(offset=offset, header=frame[:26].hex()):
                protocol, actual_offset, _, _ = Main.process_ethernet(frame)
                self.assertEqual((protocol, actual_offset), (0x0800, offset))
                report = "\n".join(Main.process_frame(1, "test", frame))
                self.assertEqual(report.count(": valid)"), 2)
        report = "\n".join(Main.process_frame(
            1, "test", self.encapsulations()[1]))
        self.assertIn("PCP: 5; DEI: 1; VLAN ID: 37", report)

    def test_non_ipv4(self):
        """Unknown EtherTypes and vendor SNAP IDs never enter IPv4."""
        for kind in (0x0806, 0x86DD, 0x88B5):
            frame = self.tcp[:12] + kind.to_bytes(2, "big") + self.tcp[14:]
            report = "\n".join(Main.process_frame(1, "test", frame))
            self.assertIn("skipped", report)
            self.assertNotIn("IPv4 header:", report)
        payload = bytes.fromhex("aaaa0300000c0800") + self.tcp[14:]
        frame = self.tcp[:12] + len(payload).to_bytes(2, "big") + payload
        self.assertIsNone(Main.process_ethernet(frame)[0])

    def test_malformed_headers(self):
        """Reject truncation and reserved type/length values."""
        macs = self.tcp[:12]
        bad_frames = [b"", self.tcp[:13],
                      macs + bytes.fromhex("81000001"),
                      macs + bytes.fromhex("05dd"),
                      macs + bytes.fromhex("05ff"),
                      macs + bytes.fromhex("0020aaaa03"),
                      macs + bytes.fromhex("0001aa"),
                      macs + bytes.fromhex("0003aaaa03"),
                      macs + bytes.fromhex("0003424200")]
        for frame in bad_frames:
            with self.subTest(frame=frame.hex()):
                with self.assertRaises(ValueError):
                    Main.process_ethernet(frame)

    def test_snap_padding_is_not_ip_payload(self):
        """Padding cannot make an IP packet exceed its 802.3 length."""
        frame = (self.tcp[:12] + (28).to_bytes(2, "big")
                 + bytes.fromhex("aaaa030000000800") + self.tcp[14:])
        with self.assertRaisesRegex(ValueError, "IPv4 total length"):
            Main.process_frame(1, "test", frame)

    def test_cli(self):
        """Help, file errors, empty input, and bad frames have useful status."""
        def run(*args):
            return subprocess.run(
                [sys.executable, str(ROOT / "Main.py"), *args],
                capture_output=True, text=True, cwd=ROOT, check=False)

        help_result = run("--help")
        self.assertEqual(help_result.returncode, 0)
        self.assertIn("Ethernet", help_result.stdout)
        self.assertIn("Exit codes:", help_result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.txt"
            self.assertEqual(run(str(path)).returncode, 2)
            path.write_text("", encoding="utf-8")
            self.assertEqual(run(str(path)).returncode, 1)
            path.write_text("ETHER\n|0   |00|\n", encoding="utf-8")
            result = run(str(path))
            self.assertEqual(result.returncode, 1)
            self.assertIn("shorter than the Ethernet header", result.stdout)
            self.assertIn("1 processing error(s)", result.stdout)

    @unittest.skipUnless(TSHARK, "Wireshark/TShark is not installed")
    def test_wireshark(self):
        """Compare MACs, framing, and checksums against Wireshark."""
        fields = ["eth.dst", "eth.src", "eth.type", "eth.len",
                  "ip.checksum", "ip.checksum.status",
                  "tcp.checksum", "tcp.checksum.status"]

        def dissect(path):
            command = [TSHARK, "-n", "-r", str(path),
                       "-o", "ip.check_checksum:TRUE",
                       "-o", "tcp.check_checksum:TRUE", "-T", "fields"]
            for field in fields:
                command.extend(["-e", field])
            result = subprocess.run(command, capture_output=True,
                                    text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            return list(csv.reader(io.StringIO(result.stdout), delimiter="\t"))

        rows = dissect(ROOT / "input.txt")
        self.assertEqual(len(rows), len(self.frames))
        for (_, frame), row in zip(self.frames, rows):
            report = "\n".join(Main.process_frame(1, "test", frame))
            self.assertIn(f"Destination MAC: {row[0]}", report)
            self.assertIn(f"Source MAC: {row[1]}", report)
            if row[2]:
                self.assertIn(f"EtherType: {row[2]}", report)
            else:
                self.assertIn(f"Length: {row[3]} bytes", report)
            for checksum, status in ((row[4], row[5]), (row[6], row[7])):
                if checksum:
                    self.assertEqual(status, "1")  # Wireshark: Good
                    self.assertIn(
                        f"{checksum} (calculated {checksum}: valid)", report)

        variants = self.encapsulations()
        bad_ip = bytearray(self.tcp)
        bad_ip[22] ^= 1  # TTL changes the IPv4 header checksum only.
        bad_tcp = bytearray(self.tcp)
        bad_tcp[-1] ^= 1  # Payload changes the TCP checksum only.
        variants.extend([bytes(bad_ip), bytes(bad_tcp)])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "variants.pcap"
            with path.open("wb") as capture:
                # Standard pcap, Ethernet link type; no packet libraries.
                capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4,
                                          2, 4, 0, 0, 65535, 1))
                for i, frame in enumerate(variants):
                    capture.write(struct.pack("<IIII", i, 0,
                                              len(frame), len(frame)))
                    capture.write(frame)
            rows = dissect(path)
        self.assertEqual(len(rows), len(variants))
        for i, (frame, row) in enumerate(zip(variants, rows)):
            expected = ("0", "1") if i == 5 else (
                ("1", "0") if i == 6 else ("1", "1"))
            self.assertEqual((row[5], row[7]), expected)
            report = "\n".join(Main.process_frame(1, "test", frame))
            self.assertEqual(report.count("INVALID"), int(i >= 5))


if __name__ == "__main__":
    unittest.main()
