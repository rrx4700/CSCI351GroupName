"""Phase 2 graphs for the packet statistics (matplotlib).

Draws the three graphs the statistics module prepares data for:
  1. Bar charts of protocol counts at L2, L3 and L4
  2. A histogram of L3 packet sizes (250-byte bins)
  3. A line graph of packets per second over the first 10 seconds

It only reads a packet_stats.PacketStatistics object, so it works the same
whether it is called from main2.py or run on its own:

    python graph_ui.py input.txt                 # open the dashboard window
    python graph_ui.py input.txt --save graphs   # also write PNGs to ./graphs
    python graph_ui.py input.txt --save graphs --no-show

Requires matplotlib (pip install matplotlib). The parser and statistics
modules still use only the standard library.

Name: Emile Racquet er8033
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from matplotlib.axes import Axes
    from matplotlib.figure import Figure
    from packet_stats import PacketStatistics


ACCENT = "#2a78d6"
UNKNOWN = "#b5b3ad"
TEXT = "#0b0b0b"
TEXT_MUTED = "#52514e"
GRID = "#e4e2dd"
SURFACE = "#fcfcfb"

UNIDENTIFIED = "Not identified"
LAYER_TITLES = {
    "L2": "Layer 2 (data link)",
    "L3": "Layer 3 (network)",
    "L4": "Layer 4 (transport)",
}


def _style_axes(ax: "Axes", value_axis: str = "y") -> None:
    """Recessive axes: light grid on the value axis only, no box."""
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=TEXT_MUTED, labelsize=9, length=0)
    ax.grid(axis=value_axis, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _integer_ticks(axis) -> None:
    from matplotlib.ticker import MaxNLocator
    axis.set_major_locator(MaxNLocator(integer=True))


def _title(ax: "Axes", title: str, subtitle: str | None = None) -> None:
    ax.set_title(title, loc="left", fontsize=11, fontweight="bold",
                 color=TEXT, pad=18 if subtitle else 8)
    if subtitle:
        ax.text(0, 1.02, subtitle, transform=ax.transAxes, fontsize=8.5,
                color=TEXT_MUTED, va="bottom")


def plot_protocol_counts(ax: "Axes", layer: str, counts: dict[str, int],
                         min_rows: int = 4) -> None:
    """Horizontal bars, largest first; 'Not identified' gray and last.

    min_rows reserves empty rows so bar thickness matches across the
    dashboard's three layer panels.
    """
    known = sorted(((n, c) for n, c in counts.items() if n != UNIDENTIFIED),
                   key=lambda item: (-item[1], item[0]))
    if UNIDENTIFIED in counts:
        known.append((UNIDENTIFIED, counts[UNIDENTIFIED]))
    names = [name for name, _ in known]
    values = [count for _, count in known]
    colors = [UNKNOWN if name == UNIDENTIFIED else ACCENT for name in names]

    _style_axes(ax, value_axis="x")
    positions = range(len(names))
    ax.barh(positions, values, color=colors, height=0.6)
    ax.set_yticks(list(positions), names, color=TEXT)
    # Reversed limits put the largest bar on top.
    ax.set_ylim(max(len(names), min_rows, 1) - 0.5, -0.5)
    _integer_ticks(ax.xaxis)
    ax.set_xlabel("Packets", color=TEXT_MUTED, fontsize=9)
    top = max(values, default=0)
    ax.set_xlim(0, top * 1.15 + 0.5)
    for y, value in zip(positions, values):
        ax.text(value + top * 0.02 + 0.05, y, str(value), va="center",
                fontsize=9, color=TEXT)
    _title(ax, LAYER_TITLES.get(layer, layer),
           f"{sum(values)} packets by {layer} protocol")
    if not names:
        ax.text(0.5, 0.5, "No packets", transform=ax.transAxes,
                ha="center", color=TEXT_MUTED)


def _bin_bounds(label: str) -> tuple[int, int]:
    low, high = label.split("-")
    return int(low), int(high)


def plot_packet_sizes(ax: "Axes", stats: "PacketStatistics") -> None:
    """Histogram of L3 sizes from the precomputed inclusive bins."""
    _style_axes(ax)
    bins = [(*_bin_bounds(label), count)
            for label, count in stats.packet_size_bins.items()]
    if bins:
        starts = [low for low, _, _ in bins]
        widths = [high - low + 1 for low, high, _ in bins]
        counts = [count for _, _, count in bins]
        ax.bar(starts, counts, width=widths, align="edge", color=ACCENT,
               edgecolor=SURFACE, linewidth=1.5)
        for start, width, count in zip(starts, widths, counts):
            if count:
                ax.text(start + width / 2, count, str(count), ha="center",
                        va="bottom", fontsize=9, color=TEXT)
        edges = starts + [starts[-1] + widths[-1]]
        ax.set_xticks(edges)
        ax.set_xlim(edges[0], edges[-1])
        ax.set_ylim(0, max(counts) * 1.15 + 0.5)
    _integer_ticks(ax.yaxis)
    ax.set_xlabel("L3 packet size (bytes)", color=TEXT_MUTED, fontsize=9)
    ax.set_ylabel("Packets", color=TEXT_MUTED, fontsize=9)
    sized = sum(stats.packet_size_bins.values())
    note = f"{sized} packets with a known L3 size"
    if stats.missing_l3_sizes:
        note += f"; {stats.missing_l3_sizes} without one are not shown"
    _title(ax, "L3 packet sizes", note)


def plot_packets_per_second(ax: "Axes", stats: "PacketStatistics") -> None:
    """Line graph of packets in each one-second window."""
    _style_axes(ax)
    ax.plot(stats.seconds, stats.packets_per_second, color=ACCENT,
            linewidth=2, marker="o", markersize=6,
            markeredgecolor=SURFACE, markeredgewidth=1.5)
    if stats.seconds:
        ax.set_xticks(stats.seconds)
        ax.set_xlim(stats.seconds[0] - 0.3, stats.seconds[-1] + 0.3)
    ax.set_ylim(0, max(stats.packets_per_second, default=0) + 1)
    _integer_ticks(ax.yaxis)
    ax.set_xlabel("Seconds since first packet", color=TEXT_MUTED, fontsize=9)
    ax.set_ylabel("Packets", color=TEXT_MUTED, fontsize=9)
    note = f"Starting at {stats.timing_origin or 'unknown time'}"
    if stats.packets_outside_window:
        note += (f"; {stats.packets_outside_window} later packets fall "
                 f"outside the {len(stats.seconds)}-second window")
    _title(ax, "Packets per second", note)


def build_dashboard(stats: "PacketStatistics") -> "Figure":
    """One figure: protocol bars on top, sizes and rate underneath."""
    import matplotlib.pyplot as plt

    fig = plt.figure(figsize=(15, 9), facecolor=SURFACE,
                     layout="constrained")
    grid = fig.add_gridspec(2, 6)
    for column, layer in enumerate(("L2", "L3", "L4")):
        ax = fig.add_subplot(grid[0, column * 2:column * 2 + 2])
        plot_protocol_counts(ax, layer, stats.protocol_counts.get(layer, {}))
    plot_packet_sizes(fig.add_subplot(grid[1, 0:3]), stats)
    plot_packets_per_second(fig.add_subplot(grid[1, 3:6]), stats)
    fig.suptitle(f"Packet capture statistics ({stats.total_packets} packets)",
                 x=0.01, ha="left", fontsize=14, fontweight="bold", color=TEXT)
    return fig


def save_graphs(stats: "PacketStatistics", out_dir: Path) -> list[Path]:
    """Write the dashboard plus each graph as its own PNG (for the report)."""
    import matplotlib.pyplot as plt

    out_dir.mkdir(parents=True, exist_ok=True)
    written = []

    def single(name: str, draw, size=(7, 4.5)) -> None:
        fig, ax = plt.subplots(figsize=size, facecolor=SURFACE,
                               layout="constrained")
        draw(ax)
        path = out_dir / name
        fig.savefig(path, dpi=150, facecolor=SURFACE)
        plt.close(fig)
        written.append(path)

    for layer in ("L2", "L3", "L4"):
        counts = stats.protocol_counts.get(layer, {})
        single(f"protocols_{layer.lower()}.png",
               lambda ax, l=layer, c=counts: plot_protocol_counts(
                   ax, l, c, min_rows=0),
               size=(6, 1.4 + 0.55 * max(len(counts), 1)))
    single("packet_sizes.png", lambda ax: plot_packet_sizes(ax, stats))
    single("packets_per_second.png",
           lambda ax: plot_packets_per_second(ax, stats))

    fig = build_dashboard(stats)
    path = out_dir / "dashboard.png"
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)
    written.append(path)
    return written


def display_dashboard(stats: "PacketStatistics", save_dir: Path | None = None,
                      show: bool = True) -> list[Path]:
    """Entry point used by main2.py: optionally save PNGs, then show window."""
    if not show:
        import matplotlib
        matplotlib.use("Agg")           # no window needed
    written = save_graphs(stats, save_dir) if save_dir else []
    for path in written:
        print(f"[+] Saved graph: {path}")
    if show:
        import matplotlib.pyplot as plt
        build_dashboard(stats)
        plt.show()
    return written


def main() -> int:
    from Main import process_packet, read_frames
    from packet_stats import calculate_statistics

    parser = argparse.ArgumentParser(
        description="Graph protocol counts, L3 sizes, and packets/second.")
    parser.add_argument("file", type=Path, help="packet text capture")
    parser.add_argument("--save", type=Path, metavar="DIR",
                        help="write PNG files of each graph to DIR")
    parser.add_argument("--no-show", action="store_true",
                        help="do not open the graph window")
    args = parser.parse_args()
    try:
        frames = read_frames(args.file)
    except (OSError, UnicodeError) as error:
        parser.error(f"could not read {args.file}: {error}")
    if not frames:
        print("No packet byte rows found in capture.", file=sys.stderr)
        return 1

    records = []
    failed = 0
    for index, (timestamp, frame) in enumerate(frames, 1):
        try:
            record, _ = process_packet(index, timestamp, frame)
        except ValueError as error:
            failed += 1
            print(f"Packet {index}: excluded from graphs: {error}",
                  file=sys.stderr)
        else:
            records.append(record)

    display_dashboard(calculate_statistics(records), args.save,
                      show=not args.no_show)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
