"""
calculate IPv4 and TCP checksums and compare them to the header fields


Name: Emile Racquet
Contact: er8033@rir.edu

Sources:
    - RFC 1071, Computing the Internet Checksum:
      https://www.rfc-editor.org/rfc/rfc1071
    - RFC 791, Internet Protocol (IPv4 header checksum, section 3.1):
      https://www.rfc-editor.org/rfc/rfc791
    - RFC 9293, Transmission Control Protocol (TCP checksum and
      pseudo-header, section 3.1): https://www.rfc-editor.org/rfc/rfc9293
    - Checksum video from the assignment:
      https://www.youtube.com/watch?v=7LniwyiH0SM
    - IANA protocol numbers (TCP = 6):
      https://www.iana.org/assignments/protocol-numbers/
    - Python documentation for int.from_bytes and int.to_bytes:
      https://docs.python.org/3/library/stdtypes.html#int.from_bytes

"""

# byte positions of the checksum field inside each header
IPV4_CHECKSUM_OFFSET = 10
TCP_CHECKSUM_OFFSET = 16
TCP_PROTOCOL_NUMBER = 6


def ones_complement_sum(data: bytes) -> int:
    """
    return the 16 bit ones complement sum of data (RFC 1071)
    odd length data is padded with one zero byte, as RFC 1071 requires
    """
    if len(data) % 2:
        data = data + b"\x00"

    total = 0
    for index in range(0, len(data), 2):
        # combine two bytes into one big-endian 16 bit word
        word = (data[index] << 8) | data[index + 1]
        total += word
        # end around carry: fold anything above 16 bits back in
        total = (total & 0xFFFF) + (total >> 16)
    return total


def internet_checksum(data: bytes) -> int:
    # return the internet checksum: the complement of the sum
    return ~ones_complement_sum(data) & 0xFFFF


def zero_field(data: bytes, offset: int) -> bytes:
    # return a copy of data with the 2 byte field at offset set to zero
    return data[:offset] + b"\x00\x00" + data[offset + 2:]


def ipv4_header_checksum(ip_header: bytes) -> int:
    """
    calculate the checksum an IPv4 header should carry

    ip_header must be the complete header (IHL * 4 bytes, options
    included). The existing checksum field is treated as zero
    """
    if len(ip_header) < 20:
        raise ValueError("IPv4 header must be at least 20 bytes")
    return internet_checksum(zero_field(ip_header, IPV4_CHECKSUM_OFFSET))


def tcp_pseudo_header(source_ip: bytes, destination_ip: bytes,
                      tcp_length: int) -> bytes:
    # build the 12 byte IPv4 pseudo header used by the TCP checksum
    if len(source_ip) != 4 or len(destination_ip) != 4:
        raise ValueError("IPv4 addresses must be 4 bytes each")
    if not 0 <= tcp_length <= 0xFFFF:
        raise ValueError("TCP length must fit in 16 bits")
    return (source_ip + destination_ip
            + bytes([0, TCP_PROTOCOL_NUMBER])
            + tcp_length.to_bytes(2, "big"))


def tcp_checksum(source_ip: bytes, destination_ip: bytes,
                 segment: bytes) -> int:
    """
    calculate the checksum a TCP segment should carry 
    segment is the whole TCP segment: header, options, and data, with no
    ethernet padding. the existing checksum field is treated as zero
    """
    if len(segment) < 20:
        raise ValueError("TCP segment must be at least 20 bytes")
    pseudo_header = tcp_pseudo_header(source_ip, destination_ip,
                                      len(segment))
    return internet_checksum(
        pseudo_header + zero_field(segment, TCP_CHECKSUM_OFFSET))


class ChecksumCheck:
    # hold one checksum comparison and format it for the report

    def __init__(self, name: str, actual: int, calculated: int):
        # store the header field value and the calculated value
        self.name = name
        self.actual = actual
        self.calculated = calculated

    @property
    def valid(self) -> bool:
        # return True when the header field matches the calculation
        return self.actual == self.calculated

    def report_lines(self, indent: str = "    ") -> list[str]:
        #return labelled aligned report lines for this comparison
        if self.valid:
            result = "valid (field matches calculated value)"
        else:
            result = "INVALID (field does not match calculated value)"
        inner = indent + "  "
        return [
            f"{indent}{self.name}:",
            f"{inner}{'Value in header field:':<24}0x{self.actual:04x}",
            f"{inner}{'Calculated value:':<24}0x{self.calculated:04x}",
            f"{inner}{'Result:':<24}{result}",
        ]


def check_ipv4_header(ip_header: bytes) -> ChecksumCheck:
    # compare an IPv4 header checksum field to the calculated value
    actual = int.from_bytes(
        ip_header[IPV4_CHECKSUM_OFFSET:IPV4_CHECKSUM_OFFSET + 2], "big")
    return ChecksumCheck("IPv4 header checksum (RFC 791)", actual,
                         ipv4_header_checksum(ip_header))


def check_tcp_segment(source_ip: bytes, destination_ip: bytes,
                      segment: bytes) -> ChecksumCheck:
    # compare a TCP segment checksum field to the calculated value
    actual = int.from_bytes(
        segment[TCP_CHECKSUM_OFFSET:TCP_CHECKSUM_OFFSET + 2], "big")
    return ChecksumCheck("TCP checksum (RFC 9293)", actual,
                         tcp_checksum(source_ip, destination_ip, segment))
