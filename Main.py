"""Read packet text dumps and report IPv4/TCP headers and checksums.

Name: Boya Li, 
Contact: bl7968@rit.edu, 

Sources:
- IPv4: https://www.rfc-editor.org/rfc/rfc791
- TCP: https://www.rfc-editor.org/rfc/rfc9293
- Ethernet II and IEEE 802.3 framing: IEEE 802.3
"""

import argparse
import ipaddress
import re
from pathlib import Path


BYTE_PATTERN = re.compile(r"\|([0-9a-fA-F]{2})(?=\|)")
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}


def read_frames(filename: Path) -> list[tuple[str, bytes]]:
	"""Read byte rows from the text capture, retaining each frame timestamp."""
	frames = []
	timestamp = "unknown"

	with filename.open("r", encoding="utf-8") as capture_file:
		for line in capture_file:
			if "ETHER" in line:
				timestamp = line.split("ETHER", maxsplit=1)[0].strip()
				continue

			byte_values = BYTE_PATTERN.findall(line)
			if byte_values:
				frames.append((timestamp, bytes(int(value, 16) for value in byte_values)))

	return frames


def locate_network_payload(frame: bytes) -> tuple[int | None, int, str]:
	"""Return encapsulated protocol, payload offset, and Ethernet framing details."""
	if len(frame) < 14:
		raise ValueError("frame is shorter than the Ethernet header")

	type_or_length = int.from_bytes(frame[12:14], "big")
	payload_offset = 14

	if type_or_length <= 1500:
		payload_end = min(payload_offset + type_or_length, len(frame))
		payload = frame[payload_offset:payload_end]
		framing = f"IEEE 802.3 length: {type_or_length} bytes"
		if len(payload) >= 8 and payload[:3] == b"\xaa\xaa\x03":
			oui = payload[3:6]
			protocol = int.from_bytes(payload[6:8], "big")
			if oui == b"\x00\x00\x00":
				return protocol, payload_offset + 8, f"{framing}; SNAP EtherType 0x{protocol:04x}"
			return None, payload_offset + 8, (
				f"{framing}; SNAP OUI {oui.hex(':')}, protocol ID 0x{protocol:04x}"
			)
		return None, payload_offset, framing + "; LLC (no SNAP EtherType)"

	if type_or_length < 1536:
		return None, payload_offset, f"reserved type/length value 0x{type_or_length:04x}"

	protocol = type_or_length
	while protocol in VLAN_TYPES:
		if len(frame) < payload_offset + 4:
			raise ValueError("truncated VLAN tag")
		protocol = int.from_bytes(frame[payload_offset + 2:payload_offset + 4], "big")
		payload_offset += 4

	return protocol, payload_offset, f"EtherType: 0x{type_or_length:04x}"


def internet_checksum(data: bytes) -> int:
	"""Calculate the 16-bit one's-complement Internet checksum."""
	if len(data) % 2:
		data += b"\x00"

	total = sum(int.from_bytes(data[index:index + 2], "big")
				for index in range(0, len(data), 2))
	while total >> 16:
		total = (total & 0xffff) + (total >> 16)
	return (~total) & 0xffff


def checksum_result(actual: int, calculated: int) -> str:
	"""Format a checksum comparison for display."""
	result = "valid" if actual == calculated else "INVALID"
	return f"0x{actual:04x} (calculated 0x{calculated:04x}: {result})"


def process_ipv4(frame: bytes, ip_offset: int) -> list[str]:
	"""Decode IPv4 fields, validate its header checksum, and decode TCP if present."""
	if len(frame) < ip_offset + 20:
		raise ValueError("truncated IPv4 header")

	first_byte = frame[ip_offset]
	version = first_byte >> 4
	header_length = (first_byte & 0x0f) * 4
	if version != 4:
		raise ValueError(f"expected IPv4, found IP version {version}")
	if header_length < 20 or len(frame) < ip_offset + header_length:
		raise ValueError("invalid or truncated IPv4 header length")

	total_length = int.from_bytes(frame[ip_offset + 2:ip_offset + 4], "big")
	if total_length < header_length:
		raise ValueError("IPv4 total length is smaller than its header")
	ip_end = ip_offset + total_length
	if len(frame) < ip_end:
		raise ValueError("captured frame is shorter than the IPv4 total length")

	ip_header = frame[ip_offset:ip_offset + header_length]
	actual_ip_checksum = int.from_bytes(ip_header[10:12], "big")
	calculated_ip_checksum = internet_checksum(ip_header[:10] + b"\x00\x00" + ip_header[12:])

	flags_and_offset = int.from_bytes(frame[ip_offset + 6:ip_offset + 8], "big")
	fragment_offset = flags_and_offset & 0x1fff
	more_fragments = bool(flags_and_offset & 0x2000)
	protocol = frame[ip_offset + 9]
	source_ip = str(ipaddress.IPv4Address(frame[ip_offset + 12:ip_offset + 16]))
	destination_ip = str(ipaddress.IPv4Address(frame[ip_offset + 16:ip_offset + 20]))

	lines = [
		"  IPv4 header:",
		f"    Version: {version}",
		f"    Header length: {header_length} bytes",
		f"    DSCP/ECN: 0x{frame[ip_offset + 1]:02x}",
		f"    Total length: {total_length} bytes",
		f"    Identification: 0x{int.from_bytes(frame[ip_offset + 4:ip_offset + 6], 'big'):04x}",
		f"    Flags: 0x{flags_and_offset >> 13:01x}; fragment offset: {fragment_offset}",
		f"    TTL: {frame[ip_offset + 8]}",
		f"    Protocol: {protocol} ({'TCP' if protocol == 6 else 'not TCP'})",
		f"    Header checksum: {checksum_result(actual_ip_checksum, calculated_ip_checksum)}",
		f"    Source: {source_ip}",
		f"    Destination: {destination_ip}",
	]

	if protocol == 6:
		tcp_offset = ip_offset + header_length
		tcp_length = total_length - header_length
		lines.extend(process_tcp(frame, tcp_offset, tcp_length, source_ip,
								 destination_ip, fragment_offset, more_fragments))

	return lines


def process_tcp(frame: bytes, tcp_offset: int, tcp_length: int,
				source_ip: str, destination_ip: str,
				fragment_offset: int, more_fragments: bool) -> list[str]:
	"""Decode TCP fields and validate its pseudoheader-based checksum when possible."""
	if fragment_offset:
		return ["  TCP header: not present in this non-initial IPv4 fragment"]
	if tcp_length < 20 or len(frame) < tcp_offset + 20:
		raise ValueError("truncated TCP header")

	tcp_header_length = (frame[tcp_offset + 12] >> 4) * 4
	if tcp_header_length < 20 or tcp_header_length > tcp_length:
		raise ValueError("invalid TCP data offset")

	source_port = int.from_bytes(frame[tcp_offset:tcp_offset + 2], "big")
	destination_port = int.from_bytes(frame[tcp_offset + 2:tcp_offset + 4], "big")
	actual_checksum = int.from_bytes(frame[tcp_offset + 16:tcp_offset + 18], "big")
	segment = frame[tcp_offset:tcp_offset + tcp_length]

	lines = [
		"  TCP header:",
		f"    Source port: {source_port}",
		f"    Destination port: {destination_port}",
		f"    Sequence number: {int.from_bytes(frame[tcp_offset + 4:tcp_offset + 8], 'big')}",
		f"    Acknowledgment number: {int.from_bytes(frame[tcp_offset + 8:tcp_offset + 12], 'big')}",
		f"    Header length: {tcp_header_length} bytes",
		f"    Flags: 0x{frame[tcp_offset + 13]:02x}",
		f"    Window: {int.from_bytes(frame[tcp_offset + 14:tcp_offset + 16], 'big')}",
		f"    Checksum: 0x{actual_checksum:04x}",
		f"    Urgent pointer: {int.from_bytes(frame[tcp_offset + 18:tcp_offset + 20], 'big')}",
	]

	if more_fragments:
		lines.append("    Checksum validation: unavailable (IPv4 datagram is fragmented)")
	else:
		pseudo_header = (
			ipaddress.IPv4Address(source_ip).packed
			+ ipaddress.IPv4Address(destination_ip).packed
			+ b"\x00\x06"
			+ tcp_length.to_bytes(2, "big")
		)
		segment_for_checksum = segment[:16] + b"\x00\x00" + segment[18:]
		calculated_checksum = internet_checksum(pseudo_header + segment_for_checksum)
		lines.append(f"    Checksum validation: {checksum_result(actual_checksum, calculated_checksum)}")

	return lines


def process_frame(index: int, timestamp: str, frame: bytes) -> list[str]:
	"""Process one Ethernet frame and return its report lines."""
	protocol, payload_offset, framing = locate_network_payload(frame)
	header = [f"Packet {index} ({timestamp})", f"  Ethernet framing: {framing}"]

	if protocol != 0x0800:
		header.append("  IPv4/TCP processing: skipped (payload is not IPv4)")
		return header

	return header + process_ipv4(frame, payload_offset)


def main() -> int:
	"""Parse command-line options, process the capture, and report file errors."""
	parser = argparse.ArgumentParser(
		description="Display IPv4 and TCP header fields and validate their checksums."
	)
	parser.add_argument("file", nargs="?", type=Path, default=Path("input.txt"),
						help="packet text dump (default: input.txt)")
	arguments = parser.parse_args()

	try:
		frames = read_frames(arguments.file)
	except (OSError, UnicodeError) as error:
		parser.error(f"could not read {arguments.file}: {error}")

	if not frames:
		print(f"No packet byte rows found in {arguments.file}.")
		return 1

	print(f"Processing {len(frames)} packet(s) from {arguments.file}...\n")
	for index, (timestamp, frame) in enumerate(frames, start=1):
		try:
			report = process_frame(index, timestamp, frame)
		except (ValueError, ipaddress.AddressValueError) as error:
			report = [f"Packet {index} ({timestamp})", f"  Could not process packet: {error}"]
		print("\n".join(report))
		print()

	return 0


if __name__ == "__main__":
	raise SystemExit(main())
