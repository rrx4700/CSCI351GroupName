"""Phase 2 statistics calculated from person 1's PacketRecord metadata.

Name: Richard Xu
Contact: rrx4700@rit.edu

Requirements: Program-parse-and-checksums-part2-2261.docx (course handout).
Uses only Python's standard library and the project's packet parser.
"""

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import sys
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    from Main import PacketRecord


SIZE_BIN_WIDTH = 250
WINDOW_SECONDS = 10
MICROSECONDS_PER_SECOND = 1_000_000
DAY_MICROSECONDS = 86_400 * MICROSECONDS_PER_SECOND
UNIDENTIFIED = "Not identified"
TIMESTAMP_PATTERN = re.compile(
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:(?:,(?P<millis>\d{3}),(?P<micros>\d{3}))"
    r"|(?:\.(?P<fraction>\d{1,6})))?"
)


@dataclass
class PacketStatistics:
    """Ordered counts ready for plotting or JSON export.

    Size-bin endpoints are inclusive; time bins are [n, n + 1) seconds
    relative to the first valid timestamp in input order. Missing protocol
    metadata gets its own category so every layer totals total_packets.
    """

    total_packets: int
    protocol_counts: dict[str, dict[str, int]]
    packet_size_bins: dict[str, int]
    missing_l3_sizes: int
    seconds: list[int]
    packets_per_second: list[int]
    timing_origin: str | None
    invalid_timestamps: int
    packets_outside_window: int


def timestamp_microseconds(timestamp: str) -> int:
    """Parse capture time-of-day without floating-point rounding errors."""
    match = TIMESTAMP_PATTERN.fullmatch(timestamp.strip())
    if match is None:
        raise ValueError(f"unsupported packet timestamp: {timestamp!r}")
    hour, minute, second = (int(match[name])
                            for name in ("hour", "minute", "second"))
    if hour >= 24 or minute >= 60 or second >= 60:
        raise ValueError(f"invalid packet timestamp: {timestamp!r}")
    fraction = (match["fraction"] or
                (match["millis"] or "") + (match["micros"] or ""))
    micros = int(fraction.ljust(6, "0"))
    return ((hour * 60 + minute) * 60 + second) * 1_000_000 + micros


def calculate_statistics(records: Iterable["PacketRecord"]) -> PacketStatistics:
    """Aggregate packet metadata once, preserving capture order for time.

    A backwards clock jump exceeding 12 hours is treated as midnight.
    Smaller backwards jumps retain their timestamps (no sorting/clamping).
    Time-only captures cannot distinguish all multi-day or reordered cases.
    Missing sizes/timestamps are excluded only from the affected statistic.
    """
    protocols = {layer: Counter() for layer in ("L2", "L3", "L4")}
    sizes = Counter()
    rates = [0] * WINDOW_SECONDS
    total = missing_sizes = invalid_times = outside_window = 0
    origin = previous_time = None
    origin_text = None
    day_offset = 0

    for record in records:
        total += 1
        for layer, protocol in zip(protocols, (
                record.l2_protocol, record.l3_protocol, record.l4_protocol)):
            protocols[layer][protocol or UNIDENTIFIED] += 1

        if record.l3_size is None:
            missing_sizes += 1
        elif type(record.l3_size) is not int or record.l3_size < 0:
            raise ValueError("L3 packet size must be a nonnegative integer")
        else:
            sizes[record.l3_size // SIZE_BIN_WIDTH] += 1

        try:
            time_of_day = timestamp_microseconds(record.timestamp)
        except ValueError:
            invalid_times += 1
            continue
        if (previous_time is not None
                and previous_time - time_of_day > DAY_MICROSECONDS // 2):
            day_offset += DAY_MICROSECONDS
        previous_time = time_of_day
        absolute_time = day_offset + time_of_day
        if origin is None:
            origin = absolute_time
            origin_text = record.timestamp
        elapsed = absolute_time - origin
        if 0 <= elapsed < WINDOW_SECONDS * MICROSECONDS_PER_SECOND:
            rates[elapsed // MICROSECONDS_PER_SECOND] += 1
        else:
            outside_window += 1

    # Keep empty intermediate bins for a continuous, correctly spaced graph.
    size_bins = {
        f"{i * SIZE_BIN_WIDTH}-{(i + 1) * SIZE_BIN_WIDTH - 1}": sizes[i]
        for i in range(max(sizes, default=0) + 1)
    }
    return PacketStatistics(
        total_packets=total,
        protocol_counts={layer: dict(sorted(counts.items()))
                         for layer, counts in protocols.items()},
        packet_size_bins=size_bins,
        missing_l3_sizes=missing_sizes,
        seconds=list(range(WINDOW_SECONDS)),
        packets_per_second=rates,
        timing_origin=origin_text,
        invalid_timestamps=invalid_times,
        packets_outside_window=outside_window,
    )


def format_statistics(stats: PacketStatistics) -> str:
    """Create a readable summary without requiring a plotting library."""
    lines = [f"Packet statistics: {stats.total_packets} parsed packet(s)"]
    for layer, counts in stats.protocol_counts.items():
        lines.append(f"  {layer} protocol counts:")
        lines.extend(f"    {name}: {count}" for name, count in counts.items())
        if not counts:
            lines.append("    No packets")
    lines.append("  L3 packet sizes (bytes, inclusive ranges):")
    lines.extend(f"    {label}: {count}"
                 for label, count in stats.packet_size_bins.items())
    lines.append(f"    Size unavailable: {stats.missing_l3_sizes}")
    lines.append("  Packets/second (first 10 seconds):")
    lines.append(f"    Start timestamp: {stats.timing_origin or 'unavailable'}")
    lines.extend(f"    [{second}, {second + 1}) s: {count}"
                 for second, count in zip(stats.seconds,
                                          stats.packets_per_second))
    lines.append(f"    Invalid/missing timestamps: {stats.invalid_timestamps}")
    lines.append(f"    Outside time window: {stats.packets_outside_window}")
    return "\n".join(lines)


def main() -> int:
    """Run statistics independently while the team's graph UI is developed."""
    # Import at runtime to avoid coupling the aggregation API to the CLI.
    from Main import process_packet, read_frames

    parser = argparse.ArgumentParser(
        description="Count L2/L3/L4 protocols, L3 sizes, and packets/second.")
    parser.add_argument("file", type=Path, help="packet text capture")
    parser.add_argument("--json", action="store_true",
                        help="output statistics as JSON for graphing")
    args = parser.parse_args()
    try:
        frames = read_frames(args.file)
    except (OSError, UnicodeError) as error:
        parser.error(f"could not read {args.file}: {error}")

    records = []
    failed = 0
    for index, (timestamp, frame) in enumerate(frames, 1):
        try:
            record, _ = process_packet(index, timestamp, frame)
        except ValueError as error:
            failed += 1
            print(f"Packet {index}: excluded from statistics: {error}",
                  file=sys.stderr)
        else:
            records.append(record)

    stats = calculate_statistics(records)
    print(json.dumps(asdict(stats), indent=2) if args.json
          else format_statistics(stats))
    if not frames:
        print("No packet byte rows found in capture.", file=sys.stderr)
    if failed:
        print(f"Excluded {failed} malformed packet(s).", file=sys.stderr)
    return 1 if failed or not frames else 0


if __name__ == "__main__":
    raise SystemExit(main())
