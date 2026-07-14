"""
generate_pcap.py - craft a synthetic pcap containing a mix of attack traffic
and benign traffic, so the NIDS can be demonstrated and tested fully offline
(no live capture, no Npcap required).

    python tools/generate_pcap.py            # writes pcaps/attacks.pcap

Each attack below is designed to trigger a specific rule in rules/local.rules;
the benign packets should trigger nothing.
"""

import os
import sys

from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw
from scapy.utils import wrpcap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "pcaps", "attacks.pcap")

HOME = "192.168.1.10"
ATTACKER = "203.0.113.5"     # port-scanner
BRUTE = "203.0.113.9"        # ssh brute-forcer
WEB = "198.51.100.7"         # web attacker
BENIGN = "198.51.100.20"     # legitimate client

pkts = []
_t = [1_700_000_000.0]       # base epoch time; bumped per packet


def add(pkt, dt=0.01):
    # Wrap in Ethernet so the pcap uses the standard EN10MB link type, which
    # scapy decodes without a libpcap backend (raw-IP link types do not).
    frame = Ether() / pkt
    frame.time = _t[0]
    _t[0] += dt
    pkts.append(frame)


def http(src, dst, dport, payload, sport=44000):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA") \
        / Raw(load=payload.encode())


# 1. ICMP ping sweep (sid 1000001)
add(IP(src=ATTACKER, dst=HOME) / ICMP(type=8) / Raw(load=b"abcdefgh"))

# 2. TCP SYN port scan: 20 SYNs to 20 ports in ~1s (sid 1000002, thresh 15/5s)
for i, port in enumerate(range(30, 50)):
    add(IP(src=ATTACKER, dst=HOME) / TCP(sport=40000 + i, dport=port, flags="S"),
        dt=0.05)

# 3. TCP NULL scan: no flags set (sid 1000003)
add(IP(src=ATTACKER, dst=HOME) / TCP(sport=40100, dport=80, flags=0))

# 4. SSH brute force: 6 SYNs to port 22 from one host (sid 1000004, thresh 5/30s)
for i in range(6):
    add(IP(src=BRUTE, dst=HOME) / TCP(sport=45000 + i, dport=22, flags="S"),
        dt=0.5)

# 5. Cleartext Telnet outbound (sid 1000005)
add(IP(src=HOME, dst=WEB) / TCP(sport=52000, dport=23, flags="S"))

# 6. SQL injection - UNION SELECT (sid 1000010)
add(http(WEB, HOME, 80,
         "GET /product?id=1 UNION SELECT username,password FROM users HTTP/1.1\r\n"
         "Host: shop.local\r\n\r\n"))

# 7. SQL injection - OR 1=1 (sid 1000011)
add(http(WEB, HOME, 80,
         "GET /login?user=admin' OR 1=1-- HTTP/1.1\r\nHost: shop.local\r\n\r\n"))

# 8. Directory traversal (sid 1000012)
add(http(WEB, HOME, 80,
         "GET /download?file=../../../../etc/passwd HTTP/1.1\r\n"
         "Host: shop.local\r\n\r\n"))

# 9. Cross-site scripting (sid 1000013)
add(http(WEB, HOME, 80,
         "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\n"
         "Host: shop.local\r\n\r\n"))

# 10. Scanner user-agent (sid 1000014)
add(http(WEB, HOME, 80,
         "GET / HTTP/1.1\r\nHost: shop.local\r\n"
         "User-Agent: sqlmap/1.7.2#stable (http://sqlmap.org)\r\n\r\n"))

# 11. Web shell command execution -> DROP + response (sid 1000020)
add(http(WEB, HOME, 80,
         "GET /uploads/shell.php?cmd=/bin/sh HTTP/1.1\r\n"
         "Host: shop.local\r\n\r\n"))

# 12. Cleartext credentials leaving the network (sid 1000021)
add(http(HOME, WEB, 80,
         "POST /login HTTP/1.1\r\nHost: extranet.example\r\n\r\n"
         "username=jdoe&password=Sup3rSecret", sport=53000))

# 13. Large ICMP payload - possible tunnel (sid 1000022)
add(IP(src=HOME, dst=WEB) / ICMP(type=8) / Raw(load=b"A" * 900))

# 14. EICAR test-string transfer (sid 1000023)
add(IP(src=WEB, dst=HOME) / TCP(sport=44100, dport=80, flags="PA")
    / Raw(load=b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"))

# --- Benign traffic (should NOT alert) -----------------------------------
add(http(BENIGN, HOME, 80,
         "GET /index.html HTTP/1.1\r\nHost: shop.local\r\n"
         "User-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n\r\n"))
add(IP(src=HOME, dst=BENIGN) / TCP(sport=80, dport=44000, flags="PA")
    / Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Hi</h1>"))
add(IP(src=HOME, dst=BENIGN) / TCP(sport=44000, dport=80, flags="A"))  # bare ACK
add(IP(src=BENIGN, dst="8.8.8.8") / UDP(sport=51000, dport=53)
    / Raw(load=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x03www\x07example\x03com\x00\x00\x01\x00\x01"))


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    wrpcap(OUT, pkts)
    print("Wrote %d packets to %s" % (len(pkts), os.path.relpath(OUT, ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
