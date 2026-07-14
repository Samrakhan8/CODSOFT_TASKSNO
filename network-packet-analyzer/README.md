# Network Packet Analyzer

A Python tool that captures packets travelling over a network interface,
dissects each one, and presents the important details — **source IP,
destination IP, protocol type, ports, and packet payload** — in a clean,
organised format.

It ships with **two capture backends**:

| Backend | Requires | Decodes |
|---------|----------|---------|
| **Scapy** (preferred) | `pip install scapy` + [Npcap](https://npcap.com) on Windows | Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS, raw payload |
| **Raw socket** (fallback) | Nothing (standard library only) | IPv4, TCP, UDP, ICMP, raw payload |

The tool automatically uses Scapy when it is installed and silently falls back
to raw sockets otherwise.

---

## Requirements

- **Python 3.8+**
- **Administrator / root privileges** — putting a network card into
  promiscuous mode is a privileged operation.
  - Windows: run from an **Administrator** PowerShell or Command Prompt.
  - Linux/macOS: run with `sudo`.
- *(Optional but recommended)* Scapy + Npcap for richer output.

## Install

```bash
# from the project folder
pip install -r requirements.txt      # optional – enables the scapy backend
```

On Windows, also install the **Npcap** driver (tick *"Install Npcap in
WinPcap API-compatible Mode"*) from https://npcap.com/#download so Scapy can
access the network card.

## Usage

```bash
# Capture 50 packets on the default interface
python packet_analyzer.py --count 50

# Capture only TCP traffic to/from port 80 for 30 seconds
python packet_analyzer.py --filter "tcp port 80" --timeout 30

# Detailed view with a payload hexdump, on a named interface
python packet_analyzer.py --iface "Wi-Fi" --detailed --count 10

# Force the standard-library raw-socket backend and save a log
python packet_analyzer.py --backend socket --save capture.log

# List the interfaces scapy can see
python packet_analyzer.py --list-ifaces
```

### Options

| Flag | Meaning |
|------|---------|
| `-i, --iface`   | Interface to capture on (default: auto) |
| `-c, --count`   | Number of packets to capture (`0` = unlimited, Ctrl-C to stop) |
| `-t, --timeout` | Stop after N seconds (`0` = no timeout) |
| `-f, --filter`  | BPF filter for scapy (e.g. `tcp port 80`); single keyword (`tcp`/`udp`/`icmp`/`dns`) for the socket backend |
| `-b, --backend` | `auto` (default), `scapy`, or `socket` |
| `-d, --detailed`| Multi-line view with a payload hexdump |
| `-s, --save`    | Also append printed output to a file |
| `--list-ifaces` | List interfaces scapy can use and exit |

## Sample output

```
Time         Proto   Source                   Destination                Len  Info
-------------------------------------------------------------------------------------
14:03:21.512 TCP     192.168.1.20:52344       142.250.180.14:443          66  [SYN] seq=... ack=0 win=64240
14:03:21.540 TCP     142.250.180.14:443       192.168.1.20:52344          66  [SYN,ACK] seq=... ack=...
14:03:21.998 DNS     192.168.1.20:5353        192.168.1.1:53              78  query example.com.

========================================
  Capture summary — 3 packet(s), 210 bytes
========================================
  TCP          2   66.7%  #############
  DNS          1   33.3%  ######
========================================
```

## How it works

1. **Capture** — Scapy's `sniff()` or a raw `AF_PACKET` / `SOCK_RAW` socket
   pulls frames straight off the wire.
2. **Inspect** — each packet is walked layer by layer (Ethernet → IP → TCP/UDP
   → application) to understand the protocol behaviour.
3. **Extract** — source/destination IP, protocol, ports and payload are pulled
   into a normalised `PacketInfo` object.
4. **Present** — packets are printed as a live table (or a detailed hexdump),
   followed by a protocol-breakdown summary.

## Legal / ethical note

Only capture traffic on networks you own or are explicitly authorised to
monitor. Packet capture can expose sensitive data; use it responsibly.
