# CSCI351GroupName

Run the packet parser with Python 3.10 or later (the existing type annotations
use Python 3.10 syntax). It uses only the Python standard library:

```text
python Main.py input.txt
python Main.py --help
```

Without a filename, it reads `input.txt` in the current directory. Paths with
spaces should be quoted. Input is the supplied text capture format: `ETHER`
timestamp lines and one pipe-separated hexadecimal byte row per packet.

The Ethernet report displays destination/source MAC addresses, destination
delivery type, and EtherType or IEEE 802.3 length. It also decodes VLAN tags
(including stacked tags) and LLC/SNAP fields. IPv4 payloads are passed to the
existing IPv4/TCP parser; ARP, IPv6, unknown EtherTypes, and unsupported LLC/SNAP
protocols are identified and skipped. IEEE 802.3 padding is excluded from IP
processing. Short headers and inconsistent lengths are reported as errors.

The program prints a packet count at startup and an error count at completion.
Exit status is 0 after processing, 1 for an empty capture or malformed packet,
and 2 for command-line/file errors. An `INVALID` checksum is a reported finding
and does not by itself change the exit status. Ethernet FCS is not validated;
the checksum calculations are for IPv4 and TCP.

Run the tests:

```text
python -B -m unittest -v test_main
```

Seven tests passed, including comparison against Wireshark's TShark with IP
and TCP checksum verification enabled. All 18 sample packets' MAC addresses
and type/length fields matched; all 9 IPv4 and 6 TCP checksums were valid in
both programs. Tests also cover VLAN/stacked VLAN and SNAP encapsulation,
non-IPv4 dispatch, malformed headers, padding boundaries, help/file errors,
and deliberately corrupted IPv4/TCP checksums. The Wireshark comparison is
skipped when TShark is not installed; the parser itself never requires it.

To repeat the sample comparison in PowerShell with Wireshark installed:

```powershell
& 'C:\Program Files\Wireshark\tshark.exe' -r input.txt -o ip.check_checksum:TRUE -o tcp.check_checksum:TRUE -T fields -e frame.number -e eth.dst -e eth.src -e eth.type -e eth.len -e ip.checksum -e ip.checksum.status -e tcp.checksum -e tcp.checksum.status
```

Checksum status `1` means good and `0` means bad. In the Wireshark GUI, open
`input.txt`, enable checksum validation in the IPv4 and TCP protocol
preferences, and expand the Ethernet, IPv4, and TCP trees to inspect fields.

Sources used for Ethernet parsing:

- [Wireshark Ethernet field descriptions](https://wiki.wireshark.org/Ethernet)
- [IANA EtherType registry](https://www.iana.org/assignments/ieee-802-numbers/)
- [RFC 1042: LLC/SNAP encapsulation](https://www.rfc-editor.org/rfc/rfc1042)
- [Wireshark VLAN fields](https://www.wireshark.org/docs/dfref/v/vlan.html)
- [TShark command reference](https://www.wireshark.org/docs/man-pages/tshark.html)

The IPv4/TCP sources are retained in the `Main.py` module docstring.
