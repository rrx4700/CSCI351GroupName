"""Master GUY  Converter and Integration Pipeline

This script ties together the packet parser (Main.py), the checksum 
validator (checksum.py), and the statistics aggregator (packet_stats.py).
It converts the raw text dump into processed records, generates terminal 
reports, and prepares the structured data for the upcoming Graph UI.

Name: [Ekam Ghai]
"""

import argparse
import json
import sys
from pathlib import Path

# Import the existing team modules
import Main
import packet_stats

# graph_ui (matplotlib) is imported only when graphs are requested, so the
# rest of the pipeline still runs with just the standard library.


def export_to_json(stats, output_path: Path):
    """Convert the statistics object into a JSON file for external graphing tools."""
    from dataclasses import asdict
    
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(asdict(stats), f, indent=4)
    print(f"\n[+] Successfully exported statistics to {output_path}")


def launch_graph_ui(stats, save_dir=None, show=True):
    """Draw the Phase 2 graphs: protocol bar charts, L3 size histogram,
    and packets-per-second line graph (see graph_ui.py)."""
    try:
        import matplotlib  # noqa: F401  (graph_ui loads it lazily)
        import graph_ui
    except ImportError as error:
        print(f"\n[-] Graphs need matplotlib ({error}). "
              "Install it with: pip install matplotlib", file=sys.stderr)
        return
    print("\n[*] Drawing graphs...")
    graph_ui.display_dashboard(stats, save_dir=save_dir, show=show)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Integrated Packet Converter, Validator, and Statistics Engine."
    )
    parser.add_argument("file", type=Path, help="Path to the packet text dump file")
    parser.add_argument("--export-json", type=Path, metavar="FILE", 
                        help="Export the converted statistics to a JSON file")
    parser.add_argument("--ui", action="store_true",
                        help="Open the graph window (requires matplotlib)")
    parser.add_argument("--save-graphs", type=Path, metavar="DIR",
                        help="Save each graph as a PNG in DIR")
    
    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File '{args.file}' does not exist.", file=sys.stderr)
        return 1

    # 1. READ & PARSE FRAMES
    print(f"[*] Reading packet capture from: {args.file}")
    try:
        frames = Main.read_frames(args.file)
    except (OSError, UnicodeError) as error:
        print(f"Error reading file: {error}", file=sys.stderr)
        return 1

    if not frames:
        print("[-] No packet byte rows found in capture.")
        return 1

    records = []
    failed = 0

    # 2. PROCESS PACKETS & CALCULATE CHECKSUMS
    print("\n[*] Processing Packets & Validating Checksums...")
    print("-" * 60)
    for index, (timestamp, frame) in enumerate(frames, start=1):
        try:
            # Main.process_packet handles the L2/L3/L4 parsing and Checksum validation
            record, report_lines = Main.process_packet(index, timestamp, frame)
            records.append(record)
            print("\n".join(report_lines))
            print()
        except ValueError as error:
            failed += 1
            print(f"Packet {index} ({timestamp})\n  Could not process packet: {error}\n")

    print("-" * 60)
    print(f"[*] Finished processing: {len(frames)} total packets, {failed} errors.")

    # 3. GENERATE STATISTICS
    print("\n[*] Calculating Phase 2 Statistics...")
    print("-" * 60)
    stats = packet_stats.calculate_statistics(records)
    print(packet_stats.format_statistics(stats))

    # 4. EXPORT / CONVERT DATA (If requested)
    if args.export_json:
        export_to_json(stats, args.export_json)

    # 5. GRAPHS
    if args.ui or args.save_graphs:
        launch_graph_ui(stats, save_dir=args.save_graphs, show=args.ui)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())