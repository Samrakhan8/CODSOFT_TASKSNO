"""
engine.py - the NIDS core: read packets (from a pcap or a live interface),
match each against the loaded ruleset, and drive the alert + response sinks.

Usage:
    python -m nids.engine --pcap pcaps/attacks.pcap
    python -m nids.engine --iface "Ethernet"          # live (needs Npcap)
    python -m nids.engine --pcap pcaps/attacks.pcap --active-response

Run  python -m nids.engine --help  for all options.
"""

import argparse
import json
import os
import sys
import time

# Allow "python nids/engine.py" as well as "python -m nids.engine".
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nids.alert import AlertManager
from nids.response import Responder
from nids import rules as R

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


class Packet:
    """Normalised view of a packet, independent of scapy internals."""
    __slots__ = ("ts", "proto", "src_ip", "dst_ip", "src_port", "dst_port",
                 "tcp_flags", "icmp_type", "payload", "dsize", "length")

    def __init__(self):
        self.ts = 0.0
        self.proto = "ip"
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
        self.tcp_flags = set()
        self.icmp_type = None
        self.payload = b""
        self.dsize = 0
        self.length = 0


_FLAG_MAP = [("F", 0x01), ("S", 0x02), ("R", 0x04), ("P", 0x08),
             ("A", 0x10), ("U", 0x20), ("E", 0x40), ("C", 0x80)]


def from_scapy(sp):
    from scapy.all import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6

    pkt = Packet()
    pkt.ts = float(getattr(sp, "time", time.time()))
    pkt.length = len(sp)

    ip = None
    if IP in sp:
        ip = sp[IP]
    elif IPv6 in sp:
        ip = sp[IPv6]
    if ip is not None:
        pkt.src_ip = ip.src
        pkt.dst_ip = ip.dst

    if TCP in sp:
        pkt.proto = "tcp"
        t = sp[TCP]
        pkt.src_port = int(t.sport)
        pkt.dst_port = int(t.dport)
        flagval = int(t.flags)
        pkt.tcp_flags = {name for name, bit in _FLAG_MAP if flagval & bit}
    elif UDP in sp:
        pkt.proto = "udp"
        u = sp[UDP]
        pkt.src_port = int(u.sport)
        pkt.dst_port = int(u.dport)
    elif ICMP in sp:
        pkt.proto = "icmp"
        pkt.icmp_type = int(sp[ICMP].type)

    payload = bytes(sp.lastlayer().payload) if sp.lastlayer().payload else b""
    if not payload and hasattr(sp.lastlayer(), "load"):
        payload = bytes(sp.lastlayer().load)
    # Prefer the transport payload when present.
    for layer in (TCP, UDP):
        if layer in sp and hasattr(sp[layer], "payload") and sp[layer].payload:
            payload = bytes(sp[layer].payload)
            break
    pkt.payload = payload
    pkt.dsize = len(payload)
    return pkt


# --- Matching ------------------------------------------------------------
def _flags_match(spec, flags):
    if spec == "0":  # NULL scan: no TCP flag bits set at all
        return len(flags) == 0
    plus = spec.endswith("+")
    required = set(spec.rstrip("+*!"))
    if not required.issubset(flags):
        return False
    if plus:
        return True
    # exact-ish: no other primary flags beyond those required
    others = {"F", "S", "R", "P", "A", "U"} - required
    return not (others & flags)


def _dsize_match(spec, dsize):
    spec = spec.strip()
    for op in (">=", "<=", ">", "<", "="):
        if spec.startswith(op):
            n = int(spec[len(op):])
            return {
                ">=": dsize >= n, "<=": dsize <= n, ">": dsize > n,
                "<": dsize < n, "=": dsize == n,
            }[op]
    if "<>" in spec:  # range lo<>hi
        lo, hi = spec.split("<>")
        return int(lo) <= dsize <= int(hi)
    return dsize == int(spec)


def rule_matches_static(rule, pkt, variables):
    """All non-stateful conditions (everything except thresholds)."""
    if rule.proto != "ip" and rule.proto != pkt.proto:
        return False

    # direction: '->' means header src->dst; '<>' means either way.
    def side_ok(sip, sport, dip, dport):
        return (R.ip_matches(sip, pkt.src_ip, variables)
                and R.port_matches(sport, pkt.src_port)
                and R.ip_matches(dip, pkt.dst_ip, variables)
                and R.port_matches(dport, pkt.dst_port))

    forward = side_ok(rule.src_ip, rule.src_port, rule.dst_ip, rule.dst_port)
    if rule.direction == "<>":
        backward = side_ok(rule.dst_ip, rule.dst_port, rule.src_ip, rule.src_port)
        if not (forward or backward):
            return False
    elif not forward:
        return False

    if rule.flags is not None and pkt.proto == "tcp":
        if not _flags_match(rule.flags, pkt.tcp_flags):
            return False
    elif rule.flags is not None:
        return False

    if rule.itype is not None:
        if pkt.icmp_type is None or int(rule.itype) != pkt.icmp_type:
            return False

    if rule.dsize is not None and not _dsize_match(rule.dsize, pkt.dsize):
        return False

    for pattern, nocase in rule.contents:
        hay = pkt.payload.lower() if nocase else pkt.payload
        needle = pattern.lower() if nocase else pattern
        if needle not in hay:
            return False

    if rule.pcre is not None and not rule.pcre.search(pkt.payload):
        return False

    return True


class ThresholdState:
    """Sliding-window counters for threshold / detection_filter rules."""
    def __init__(self):
        self._hits = {}  # (sid, key) -> [timestamps]

    def passes(self, rule, pkt):
        th = rule.threshold
        if not th:
            return True
        key = pkt.src_ip if th["track"] == "by_src" else pkt.dst_ip
        bucket = self._hits.setdefault((rule.sid, key), [])
        now = pkt.ts
        cutoff = now - th["seconds"]
        bucket[:] = [t for t in bucket if t >= cutoff]
        bucket.append(now)
        # detection_filter/threshold: alert only once the count is reached.
        return len(bucket) >= th["count"]


class Engine:
    def __init__(self, ruleset, variables, alerts, responder=None,
                 active_response=False):
        self.rules = ruleset
        self.variables = variables
        self.alerts = alerts
        self.responder = responder
        self.active_response = active_response
        self.thresholds = ThresholdState()
        self.packets = 0

    def process(self, pkt):
        self.packets += 1
        for rule in self.rules:
            if not rule_matches_static(rule, pkt, self.variables):
                continue
            if not self.thresholds.passes(rule, pkt):
                continue
            self.alerts.alert(rule, pkt)
            if self.responder and (rule.action in ("drop", "reject")
                                   or self.active_response):
                self.responder.respond(rule, pkt)

    def run_pcap(self, path):
        from scapy.all import rdpcap
        for sp in rdpcap(path):
            self.process(from_scapy(sp))

    def run_live(self, iface, count=0):
        from scapy.all import sniff
        print("[*] Live capture on %s (Ctrl-C to stop)..." % iface)
        sniff(iface=iface, count=count, store=False,
              prn=lambda sp: self.process(from_scapy(sp)))


# --- Config / CLI --------------------------------------------------------
def load_config(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="nids", description="A Snort/Suricata-style network intrusion "
        "detection engine.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="read packets from a pcap file")
    src.add_argument("--iface", "-i", help="capture live from an interface "
                     "(requires Npcap on Windows)")
    ap.add_argument("--rules", "-r", default=os.path.join(ROOT, "rules", "local.rules"))
    ap.add_argument("--config", "-c", default=os.path.join(ROOT, "config", "nids.json"))
    ap.add_argument("--count", "-n", type=int, default=0,
                    help="live: stop after N packets (0 = unlimited)")
    ap.add_argument("--active-response", action="store_true",
                    help="run the responder on every alert, not just drop/reject")
    ap.add_argument("--enforce", action="store_true",
                    help="actually execute firewall block commands (needs admin)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--quiet", "-q", action="store_true",
                    help="suppress per-alert console output")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    variables = cfg.get("vars", {})
    logs = cfg.get("logs", {})
    eve = os.path.join(ROOT, logs.get("eve", "logs/eve.json"))
    fast = os.path.join(ROOT, logs.get("fast", "logs/fast.log"))
    blocklist = os.path.join(ROOT, logs.get("blocklist", "logs/blocked_ips.txt"))
    actions = os.path.join(ROOT, logs.get("actions", "logs/response_actions.log"))

    ruleset, errors = R.load_rules(args.rules)
    if errors:
        print("[!] %d rule parse error(s):" % len(errors), file=sys.stderr)
        for n, line, msg in errors:
            print("    line %d: %s (%s)" % (n, line[:60], msg), file=sys.stderr)
    print("[*] Loaded %d rules from %s" % (len(ruleset), os.path.basename(args.rules)))

    alerts = AlertManager(eve_path=eve, fast_path=fast,
                          use_color=not args.no_color, quiet=args.quiet)
    responder = Responder(blocklist, actions, enforce=args.enforce)
    engine = Engine(ruleset, variables, alerts, responder,
                    active_response=args.active_response)

    start = time.time()
    if args.pcap:
        print("[*] Reading %s" % args.pcap)
        engine.run_pcap(args.pcap)
    else:
        engine.run_live(args.iface, count=args.count)
    elapsed = time.time() - start

    print("\n[=] Processed %d packets in %.2fs" % (engine.packets, elapsed))
    print("[=] %d alerts  (HIGH:%d MEDIUM:%d LOW:%d)" % (
        alerts.count, alerts.by_priority.get(1, 0),
        alerts.by_priority.get(2, 0), alerts.by_priority.get(3, 0)))
    if alerts.by_sig:
        print("[=] Top signatures:")
        for sig, c in sorted(alerts.by_sig.items(), key=lambda kv: -kv[1])[:8]:
            print("      %3d x  %s" % (c, sig))
    if responder.blocked:
        print("[=] Response: %d source IP(s) blocked -> %s" % (
            len(responder.blocked), os.path.relpath(blocklist, ROOT)))
    print("[=] Alerts written to %s" % os.path.relpath(eve, ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
