#!/usr/bin/env python3
"""
Network Packet Analyzer
=======================

Captures packets travelling over a network interface, dissects each one, and
prints the important fields (source/destination IP, protocol, ports, payload)
in a clean, organised table.

Two capture backends are supported:

  1. Scapy  (preferred) -- rich dissection of many protocols. Requires the
     `scapy` package and, on Windows, the Npcap driver.
  2. Raw sockets (fallback) -- pure standard-library. Works without any third
     party package but decodes fewer protocols and, on Windows, needs the
     script to be run from an *Administrator* prompt.

Usage examples
--------------
    # Capture 50 packets on the default interface using scapy
    python packet_analyzer.py --count 50

    # Capture only TCP traffic for 30 seconds on a specific interface
    python packet_analyzer.py --filter tcp --timeout 30 --iface "Wi-Fi"

    # Force the raw-socket backend and save a log
    python packet_analyzer.py --backend socket --save capture.log

Run with  --list-ifaces  to see the interfaces scapy can use.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import socket
import struct
import sys
import textwrap

# --------------------------------------------------------------------------- #
#  Optional scapy import -- we degrade gracefully when it is missing.
# --------------------------------------------------------------------------- #
try:
    from scapy.all import (  # type: ignore
        sniff,
        get_working_ifaces,
        Ether,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
        DNS,
        Raw,
    )

    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - depends on host environment
    SCAPY_AVAILABLE = False


# --------------------------------------------------------------------------- #
#  Small helpers
# --------------------------------------------------------------------------- #
# Map of common IP protocol numbers -> human readable names.
IP_PROTO_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# Well known ports -> service name, used to make the output friendlier.
WELL_KNOWN_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    161: "snmp",
    443: "https",
    465: "smtps",
    587: "smtp",
    993: "imaps",
    995: "pop3s",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


def _now() -> str:
    """Return a high-resolution timestamp string for the current moment."""
    return _dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def _service(port: int) -> str:
    """Return 'port (service)' when the port is well known, else just the port."""
    name = WELL_KNOWN_PORTS.get(port)
    return f"{port} ({name})" if name else str(port)


def _hexdump(data: bytes, length: int = 16, max_bytes: int = 64) -> str:
    """Return a classic offset / hex / ASCII hexdump of ``data``.

    Only the first ``max_bytes`` bytes are shown so the console stays readable.
    """
    if not data:
        return "        <no payload>"

    shown = data[:max_bytes]
    lines = []
    for offset in range(0, len(shown), length):
        chunk = shown[offset : offset + length]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = f"{hex_part:<{length * 3 - 1}}"
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"        {offset:04x}  {hex_part}  {ascii_part}")

    if len(data) > max_bytes:
        lines.append(f"        ... {len(data) - max_bytes} more byte(s) not shown")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  A protocol-agnostic description object
# --------------------------------------------------------------------------- #
class PacketInfo:
    """Normalised view of a captured packet, whatever the backend."""

    def __init__(self) -> None:
        self.time: str = _now()
        self.src: str = "?"
        self.dst: str = "?"
        self.protocol: str = "?"
        self.length: int = 0
        self.src_port: int | None = None
        self.dst_port: int | None = None
        self.info: str = ""
        self.payload: bytes = b""

    # -- formatting ------------------------------------------------------- #
    def summary_row(self) -> str:
        """One-line summary suitable for a table."""
        src = self.src if self.src_port is None else f"{self.src}:{self.src_port}"
        dst = self.dst if self.dst_port is None else f"{self.dst}:{self.dst_port}"
        return (
            f"{self.time:<12} {self.protocol:<7} "
            f"{src:<24} {dst:<24} {self.length:>5}  {self.info}"
        )

    def detailed(self) -> str:
        """Multi-line detailed view including a payload hexdump."""
        lines = [
            "-" * 78,
            f"  Time        : {self.time}",
            f"  Protocol    : {self.protocol}",
            f"  Source      : {self.src}"
            + (f"  port {_service(self.src_port)}" if self.src_port is not None else ""),
            f"  Destination : {self.dst}"
            + (f"  port {_service(self.dst_port)}" if self.dst_port is not None else ""),
            f"  Length      : {self.length} bytes",
        ]
        if self.info:
            lines.append(f"  Info        : {self.info}")
        lines.append(f"  Payload     : {len(self.payload)} byte(s)")
        lines.append(_hexdump(self.payload))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Scapy backend
# --------------------------------------------------------------------------- #
def _describe_scapy(pkt) -> PacketInfo:
    """Convert a scapy packet into a :class:`PacketInfo`."""
    info = PacketInfo()
    info.length = len(pkt)

    # Layer 3 -----------------------------------------------------------
    if IP in pkt:
        info.src = pkt[IP].src
        info.dst = pkt[IP].dst
        info.protocol = IP_PROTO_NAMES.get(pkt[IP].proto, f"IP/{pkt[IP].proto}")
    elif IPv6 in pkt:
        info.src = pkt[IPv6].src
        info.dst = pkt[IPv6].dst
        info.protocol = IP_PROTO_NAMES.get(pkt[IPv6].nh, f"IPv6/{pkt[IPv6].nh}")
    elif ARP in pkt:
        arp = pkt[ARP]
        info.protocol = "ARP"
        info.src = arp.psrc
        info.dst = arp.pdst
        op = {1: "who-has", 2: "is-at"}.get(arp.op, str(arp.op))
        info.info = f"{op}  {arp.hwsrc} -> {arp.hwdst}"
    elif Ether in pkt:
        info.protocol = "Ethernet"
        info.src = pkt[Ether].src
        info.dst = pkt[Ether].dst

    # Layer 4 -----------------------------------------------------------
    if TCP in pkt:
        tcp = pkt[TCP]
        info.protocol = "TCP"
        info.src_port = tcp.sport
        info.dst_port = tcp.dport
        flags = tcp.sprintf("%TCP.flags%")
        info.info = f"[{flags}] seq={tcp.seq} ack={tcp.ack} win={tcp.window}"
    elif UDP in pkt:
        udp = pkt[UDP]
        info.protocol = "UDP"
        info.src_port = udp.sport
        info.dst_port = udp.dport
        if DNS in pkt:
            info.protocol = "DNS"
            dns = pkt[DNS]
            role = "response" if dns.qr else "query"
            qname = ""
            if dns.qd is not None:
                try:
                    qname = dns.qd.qname.decode(errors="replace")
                except Exception:
                    qname = str(dns.qd.qname)
            info.info = f"{role} {qname}".strip()
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        info.protocol = "ICMP"
        info.info = icmp.sprintf("type=%ICMP.type% code=%ICMP.code%")

    # Payload -----------------------------------------------------------
    if Raw in pkt:
        info.payload = bytes(pkt[Raw].load)

    return info


def capture_scapy(args) -> list[PacketInfo]:
    """Capture packets with scapy and return their descriptions."""
    collected: list[PacketInfo] = []
    printer = _make_printer(args, collected)

    def _handle(pkt) -> None:
        printer(_describe_scapy(pkt))

    print(_banner("scapy", args))
    sniff(
        iface=args.iface,
        filter=args.filter,
        prn=_handle,
        count=args.count,
        timeout=args.timeout,
        store=False,
    )
    return collected


# --------------------------------------------------------------------------- #
#  Raw-socket backend (standard library only)
# --------------------------------------------------------------------------- #
def _describe_raw_ipv4(packet: bytes) -> PacketInfo | None:
    """Decode an IPv4 packet captured from a raw socket."""
    info = PacketInfo()
    info.length = len(packet)

    if len(packet) < 20:
        return None

    version_ihl = packet[0]
    ihl = (version_ihl & 0x0F) * 4
    proto = packet[9]
    src = socket.inet_ntoa(packet[12:16])
    dst = socket.inet_ntoa(packet[16:20])

    info.src = src
    info.dst = dst
    info.protocol = IP_PROTO_NAMES.get(proto, f"IP/{proto}")

    rest = packet[ihl:]

    if proto == 6 and len(rest) >= 20:  # TCP
        sport, dport, seq, ack, offset_reserved = struct.unpack("!HHLLB", rest[:13])
        data_offset = (offset_reserved >> 4) * 4
        flags = rest[13]
        info.protocol = "TCP"
        info.src_port = sport
        info.dst_port = dport
        flag_names = _tcp_flag_names(flags)
        info.info = f"[{flag_names}] seq={seq} ack={ack}"
        info.payload = rest[data_offset:]
    elif proto == 17 and len(rest) >= 8:  # UDP
        sport, dport, length, _chk = struct.unpack("!HHHH", rest[:8])
        info.protocol = "UDP"
        info.src_port = sport
        info.dst_port = dport
        info.payload = rest[8:]
        if sport == 53 or dport == 53:
            info.protocol = "DNS"
    elif proto == 1 and len(rest) >= 4:  # ICMP
        icmp_type, code = rest[0], rest[1]
        info.protocol = "ICMP"
        info.info = f"type={icmp_type} code={code}"
        info.payload = rest[4:]
    else:
        info.payload = rest

    return info


def _tcp_flag_names(flags: int) -> str:
    names = []
    for bit, name in (
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ):
        if flags & bit:
            names.append(name)
    return ",".join(names) if names else "-"


def capture_socket(args) -> list[PacketInfo]:
    """Capture IPv4 packets using a raw socket (no third-party deps)."""
    collected: list[PacketInfo] = []
    printer = _make_printer(args, collected)

    print(_banner("raw socket", args))

    if sys.platform.startswith("win"):
        # On Windows raw sockets need to be bound to an interface IP and put
        # into promiscuous mode via SIO_RCVALL.
        host = socket.gethostbyname(socket.gethostname())
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except AttributeError:
            pass
    else:
        # On Linux we can grab full Ethernet frames.
        sniffer = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)
        )

    if args.timeout:
        sniffer.settimeout(args.timeout)

    seen = 0
    start = _dt.datetime.now()
    try:
        while True:
            if args.count and seen >= args.count:
                break
            if args.timeout and (_dt.datetime.now() - start).total_seconds() > args.timeout:
                break
            try:
                raw, _addr = sniffer.recvfrom(65535)
            except socket.timeout:
                break

            if sys.platform.startswith("win"):
                info = _describe_raw_ipv4(raw)
            else:
                # Strip the 14-byte Ethernet header, decode the IPv4 body.
                eth_proto = struct.unpack("!H", raw[12:14])[0]
                if eth_proto != 0x0800:  # only IPv4 for simplicity
                    continue
                info = _describe_raw_ipv4(raw[14:])

            if info is None:
                continue
            if not _passes_socket_filter(info, args.filter):
                continue

            printer(info)
            seen += 1
    finally:
        if sys.platform.startswith("win"):
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except AttributeError:
                pass
        sniffer.close()

    return collected


def _passes_socket_filter(info: PacketInfo, flt: str | None) -> bool:
    """Very small BPF-like filter for the raw-socket backend.

    Only single protocol keywords (tcp/udp/icmp/dns) are supported here; the
    scapy backend understands the full BPF syntax.
    """
    if not flt:
        return True
    return flt.strip().lower() in info.protocol.lower()


# --------------------------------------------------------------------------- #
#  Shared output plumbing
# --------------------------------------------------------------------------- #
def _make_printer(args, collected: list[PacketInfo]):
    """Return a callback that prints and records each packet."""
    header_printed = {"done": False}

    def _print(info: PacketInfo) -> None:
        collected.append(info)
        if args.detailed:
            line = info.detailed()
        else:
            if not header_printed["done"]:
                print(_table_header())
                header_printed["done"] = True
            line = info.summary_row()

        print(line)
        if args.save:
            with open(args.save, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    return _print


def _table_header() -> str:
    head = (
        f"{'Time':<12} {'Proto':<7} {'Source':<24} "
        f"{'Destination':<24} {'Len':>5}  Info"
    )
    return head + "\n" + "-" * len(head)


def _banner(backend: str, args) -> str:
    parts = [
        "",
        "=" * 78,
        "  Network Packet Analyzer",
        f"  backend : {backend}",
        f"  iface   : {args.iface or 'default'}",
        f"  filter  : {args.filter or 'none'}",
        f"  limit   : "
        + (f"{args.count} packets" if args.count else "unlimited")
        + (f", {args.timeout}s timeout" if args.timeout else ""),
        "=" * 78,
    ]
    return "\n".join(parts)


def _print_stats(collected: list[PacketInfo]) -> None:
    """Print a protocol breakdown after the capture finishes."""
    if not collected:
        print("\nNo packets were captured.")
        return

    counts: dict[str, int] = {}
    total_bytes = 0
    for info in collected:
        counts[info.protocol] = counts.get(info.protocol, 0) + 1
        total_bytes += info.length

    print("\n" + "=" * 40)
    print(f"  Capture summary - {len(collected)} packet(s), {total_bytes} bytes")
    print("=" * 40)
    for proto, n in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
        pct = n / len(collected) * 100
        bar = "#" * int(pct / 5)
        print(f"  {proto:<10} {n:>5}  {pct:5.1f}%  {bar}")
    print("=" * 40)


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def _list_ifaces() -> None:
    if not SCAPY_AVAILABLE:
        print("scapy is not installed, cannot list interfaces.")
        print("Install it with:  pip install scapy")
        return
    print("Available interfaces:")
    for iface in get_working_ifaces():
        print(f"  - {iface.name}   ({iface.description})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="packet_analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """\
            Capture and analyse network packets.

            The tool needs elevated privileges to place the interface into
            promiscuous mode: run it from an Administrator prompt on Windows or
            with sudo on Linux/macOS.
            """
        ),
    )
    parser.add_argument(
        "-i", "--iface", default=None,
        help="network interface to capture on (default: auto)",
    )
    parser.add_argument(
        "-c", "--count", type=int, default=0,
        help="number of packets to capture (0 = unlimited, Ctrl-C to stop)",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=0,
        help="stop capturing after this many seconds (0 = no timeout)",
    )
    parser.add_argument(
        "-f", "--filter", default=None,
        help="BPF filter for scapy (e.g. 'tcp port 80'); "
             "single keyword for the socket backend",
    )
    parser.add_argument(
        "-b", "--backend", choices=("auto", "scapy", "socket"), default="auto",
        help="capture backend to use (default: auto)",
    )
    parser.add_argument(
        "-d", "--detailed", action="store_true",
        help="show a detailed multi-line view with payload hexdump",
    )
    parser.add_argument(
        "-s", "--save", metavar="FILE", default=None,
        help="append the printed output to FILE as well",
    )
    parser.add_argument(
        "--list-ifaces", action="store_true",
        help="list the interfaces scapy can use and exit",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_ifaces:
        _list_ifaces()
        return 0

    # Decide which backend to use.
    backend = args.backend
    if backend == "auto":
        backend = "scapy" if SCAPY_AVAILABLE else "socket"
    if backend == "scapy" and not SCAPY_AVAILABLE:
        print("scapy requested but not installed - falling back to raw socket.")
        print("Install scapy for richer output:  pip install scapy\n")
        backend = "socket"

    try:
        if backend == "scapy":
            collected = capture_scapy(args)
        else:
            collected = capture_socket(args)
    except PermissionError:
        print(
            "\nPermission denied. Raw packet capture needs elevated privileges.\n"
            "  - Windows : run this from an Administrator PowerShell/CMD.\n"
            "  - Linux   : run with sudo, or grant CAP_NET_RAW.\n"
        )
        return 1
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        collected = []
    except OSError as exc:
        print(f"\nCapture failed: {exc}")
        return 1

    _print_stats(collected)
    return 0


if __name__ == "__main__":
    sys.exit(main())
