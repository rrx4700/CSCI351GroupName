"""Read packet text dumps and report Ethernet/IPv4/TCP headers and checksums.

Name: Boya Li, Richard Xu, Emile Racquet, Ekam Ghai
Contact: bl7968@rit.edu, rrx4700@rit.edu, er8033@rit.edu, esg8275@rit.edu

Sources:
- IPv4: https://www.rfc-editor.org/rfc/rfc791
- TCP: https://www.rfc-editor.org/rfc/rfc9293
- Ethernet II and IEEE 802.3 framing: IEEE 802.3
- Ethernet fields: https://wiki.wireshark.org/Ethernet
- EtherTypes: https://www.iana.org/assignments/ieee-802-numbers/
- LLC/SNAP: https://www.rfc-editor.org/rfc/rfc1042
- VLAN fields: https://www.wireshark.org/docs/dfref/v/vlan.html
- Checksum sources (RFC 1071, RFC 791, RFC 9293, and others) are listed
  in checksum.py, which performs the IPv4 and TCP checksum calculations.
"""

import argparse
import ipaddress
import re
from pathlib import Path

import checksum


BYTE_PATTERN = re.compile(r"\|([0-9a-fA-F]{2})(?=\|)")
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
ETHER_TYPES = {
	0x0800: "IPv4",
	0x0806: "ARP",
	0x86DD: "IPv6",
	0x8100: "802.1Q VLAN",
	0x88A8: "802.1ad provider VLAN",
	0x9100: "legacy VLAN",
	0x88CC: "LLDP",
}


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


def describe_ethertype(protocol: int) -> str:
	"""Display a protocol number even when its name is unknown."""
	return f"0x{protocol:04x} ({ETHER_TYPES.get(protocol, 'unknown')})"


def process_ethernet(frame: bytes) -> tuple[int | None, int, int, list[str]]:
	"""Return protocol, payload bounds, and decoded Ethernet header fields."""
	if len(frame) < 14:
		raise ValueError("frame is shorter than the Ethernet header")

	destination = frame[:6]
	if destination == b"\xff" * 6:
		delivery = "broadcast"
	elif destination[0] & 1:
		delivery = "multicast"
	else:
		delivery = "unicast"
	lines = [
		"  Ethernet header:",
		f"    Destination MAC: {destination.hex(':')} ({delivery})",
		f"    Source MAC: {frame[6:12].hex(':')}",
	]
	type_or_length = int.from_bytes(frame[12:14], "big")
	payload_offset = 14
	payload_end = len(frame)

	# Each VLAN tag adds its control field and another type/length field.
	tag_number = 0
	while type_or_length in VLAN_TYPES:
		if len(frame) < payload_offset + 4:
			raise ValueError("truncated VLAN tag")
		tag_number += 1
		tci = int.from_bytes(frame[payload_offset:payload_offset + 2], "big")
		lines.extend([
			f"    VLAN tag {tag_number}: {describe_ethertype(type_or_length)}",
			f"      TCI: 0x{tci:04x}; PCP: {tci >> 13}; "
			f"DEI: {(tci >> 12) & 1}; VLAN ID: {tci & 0x0fff}",
		])
		type_or_length = int.from_bytes(
			frame[payload_offset + 2:payload_offset + 4], "big"
		)
		payload_offset += 4

	if type_or_length <= 1500:
		payload_end = payload_offset + type_or_length
		if payload_end > len(frame):
			raise ValueError("captured frame is shorter than the IEEE 802.3 length")
		lines.extend([
			"    Framing: IEEE 802.3",
			f"    Length: {type_or_length} bytes (excludes padding)",
		])
		payload = frame[payload_offset:payload_end]
		# Raw Novell IPX uses a length field but has no LLC header.
		if payload[:2] == b"\xff\xff":
			lines.append("    Encapsulation: raw IEEE 802.3 IPX (no LLC)")
			return None, payload_offset, payload_end, lines
		if len(payload) < 3:
			raise ValueError("truncated IEEE 802.2 LLC header")
		control_length = 1 if payload[2] & 3 == 3 else 2
		llc_length = 2 + control_length
		if len(payload) < llc_length:
			raise ValueError("truncated IEEE 802.2 LLC control field")
		lines.append(
			f"    LLC: DSAP 0x{payload[0]:02x}; SSAP 0x{payload[1]:02x}; "
			f"control 0x{payload[2:llc_length].hex()}"
		)
		if payload[:3] == b"\xaa\xaa\x03":
			if len(payload) < 8:
				raise ValueError("truncated SNAP header")
			oui = payload[3:6]
			protocol = int.from_bytes(payload[6:8], "big")
			lines.append(f"    SNAP OUI: {oui.hex(':')}")
			if oui == b"\x00\x00\x00":
				lines.append(f"    SNAP EtherType: {describe_ethertype(protocol)}")
				return protocol, payload_offset + 8, payload_end, lines
			lines.append(f"    SNAP vendor protocol ID: 0x{protocol:04x}")
			return None, payload_offset + 8, payload_end, lines
		return None, payload_offset + llc_length, payload_end, lines

	if type_or_length < 1536:
		raise ValueError(f"reserved Ethernet type/length value {type_or_length}")

	lines.extend([
		"    Framing: Ethernet II",
		f"    EtherType: {describe_ethertype(type_or_length)}",
	])
	return type_or_length, payload_offset, payload_end, lines


def locate_network_payload(frame: bytes) -> tuple[int | None, int, str]:
	"""Keep the original payload-locator interface for existing callers."""
	protocol, offset, _, lines = process_ethernet(frame)
	return protocol, offset, "; ".join(line.strip() for line in lines[3:])


def process_ipv4(frame: bytes, ip_offset: int) -> tuple[list[str], list[str]]:
	"""Decode IPv4 (and TCP) fields; return them and the checksum report."""
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

	# The IPv4 checksum covers the full header, including any options.
	ip_header = frame[ip_offset:ip_offset + header_length]
	ip_check = checksum.check_ipv4_header(ip_header)
	checks = ip_check.report_lines()

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
		f"    Header checksum: 0x{ip_check.actual:04x}",
		f"    Source: {source_ip}",
		f"    Destination: {destination_ip}",
	]

	if protocol == 6:
		tcp_offset = ip_offset + header_length
		tcp_length = total_length - header_length
		tcp_lines, tcp_checks = process_tcp(
			frame, tcp_offset, tcp_length, ip_header[12:16], ip_header[16:20],
			fragment_offset, more_fragments)
		lines.extend(tcp_lines)
		checks.extend(tcp_checks)

	return lines, checks


def process_tcp(frame: bytes, tcp_offset: int, tcp_length: int,
				source_ip: bytes, destination_ip: bytes,
				fragment_offset: int,
				more_fragments: bool) -> tuple[list[str], list[str]]:
	"""Decode TCP fields; return them and the TCP checksum report."""
	if fragment_offset:
		return (["  TCP header: not present in this non-initial IPv4 fragment"],
				[])
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

	# The TCP checksum needs the whole segment, which a fragment lacks.
	if more_fragments:
		checks = ["    TCP checksum (RFC 9293):",
				  f"      {'Result:':<24}not calculated "
				  "(IPv4 datagram is fragmented)"]
	else:
		checks = checksum.check_tcp_segment(
			source_ip, destination_ip, segment).report_lines()

	return lines, checks


def process_frame(index: int, timestamp: str, frame: bytes) -> list[str]:
	"""Process one Ethernet frame and return its report lines."""
	protocol, payload_offset, payload_end, ethernet = process_ethernet(frame)
	header = [f"Packet {index} ({timestamp})"] + ethernet

	if protocol != 0x0800:
		reason = (describe_ethertype(protocol) if protocol is not None
				  else "no supported IPv4 EtherType in this encapsulation")
		header.append(f"  IPv4/TCP processing: skipped ({reason})")
		return header

	# Keep Ethernet padding outside an IEEE 802.3 network payload.
	ip_lines, checks = process_ipv4(frame[:payload_end], payload_offset)
	# Header fields first, followed by the checksum calculations.
	return header + ip_lines + ["  Checksum calculations:"] + checks


def main() -> int:
	"""Parse command-line options, process the capture, and report file errors."""
	parser = argparse.ArgumentParser(
		description=("Display Ethernet, IPv4, and TCP header fields and "
					 "validate IPv4/TCP checksums."),
		epilog=("Example: python Main.py input.txt\n"
				"Input: packet text dump with ETHER timestamps and "
				"pipe-separated hexadecimal bytes.\n"
				"Non-IPv4 payloads are identified and skipped. "
				"TCP is decoded only within IPv4.\n"
				"Exit codes: 0 = processed; 1 = empty capture or packet "
				"errors; 2 = command-line or file error."),
		formatter_class=argparse.RawDescriptionHelpFormatter,
	)
	parser.add_argument("file", nargs="?", type=Path,
						help="packet text dump")
	arguments = parser.parse_args()
	# if no files passed in
	if arguments.file is None:
		parser.error("Please Pass in Argument For What Input File to Parse")
	try:
		frames = read_frames(arguments.file)
	except (OSError, UnicodeError) as error:
		parser.error(f"could not read {arguments.file}: {error}")

	if not frames:
		print(f"No packet byte rows found in {arguments.file}.")
		return 1

	print(f"Processing {len(frames)} packet(s) from {arguments.file}...\n")
	failed = 0
	for index, (timestamp, frame) in enumerate(frames, start=1):
		try:
			report = process_frame(index, timestamp, frame)
		except (ValueError, ipaddress.AddressValueError) as error:
			failed += 1
			report = [f"Packet {index} ({timestamp})", f"  Could not process packet: {error}"]
		print("\n".join(report))
		print()

	print(f"Finished: {len(frames)} packet(s), {failed} processing error(s).")
	return 1 if failed else 0


if __name__ == "__main__":
	raise SystemExit(main())
