"""
alert.py - alert sinks for the NIDS.

Emits three outputs, mirroring Suricata's own logging:
  * console  - human-readable, colourised, one line per alert
  * eve.json - one JSON object per line (Suricata "eve" event format)
  * fast.log - terse classic Snort/Suricata fast-alert text
"""

import json
import os
from datetime import datetime, timezone

# ANSI colours by priority (1 = most severe).
_COLOR = {1: "\033[91m", 2: "\033[93m", 3: "\033[96m"}
_RESET = "\033[0m"
_SEVERITY = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}


class AlertManager:
    def __init__(self, eve_path=None, fast_path=None, use_color=True, quiet=False):
        self.eve_path = eve_path
        self.fast_path = fast_path
        self.use_color = use_color
        self.quiet = quiet
        self.count = 0
        self.by_sig = {}
        self.by_priority = {1: 0, 2: 0, 3: 0}
        if eve_path:
            os.makedirs(os.path.dirname(eve_path), exist_ok=True)
            open(eve_path, "w").close()  # truncate on start
        if fast_path:
            os.makedirs(os.path.dirname(fast_path), exist_ok=True)
            open(fast_path, "w").close()

    def alert(self, rule, pkt):
        self.count += 1
        self.by_sig[rule.msg] = self.by_sig.get(rule.msg, 0) + 1
        self.by_priority[rule.priority] = self.by_priority.get(rule.priority, 0) + 1

        ts = datetime.fromtimestamp(pkt.ts, tz=timezone.utc)
        ts_iso = ts.isoformat()

        if not self.quiet:
            self._console(rule, pkt, ts)
        if self.eve_path:
            self._eve(rule, pkt, ts_iso)
        if self.fast_path:
            self._fast(rule, pkt, ts)

    def _console(self, rule, pkt, ts):
        sev = _SEVERITY.get(rule.priority, "LOW")
        col = _COLOR.get(rule.priority, "") if self.use_color else ""
        rst = _RESET if self.use_color else ""
        src = "%s:%s" % (pkt.src_ip, pkt.src_port) if pkt.src_port else pkt.src_ip
        dst = "%s:%s" % (pkt.dst_ip, pkt.dst_port) if pkt.dst_port else pkt.dst_ip
        print("%s[%s]%s %s  [%s] %s  {%s}  %s -> %s  (sid:%d)" % (
            col, sev, rst, ts.strftime("%H:%M:%S"), rule.priority, rule.msg,
            pkt.proto.upper(), src, dst, rule.sid))

    def _eve(self, rule, pkt, ts_iso):
        event = {
            "timestamp": ts_iso,
            "event_type": "alert",
            "src_ip": pkt.src_ip,
            "src_port": pkt.src_port,
            "dest_ip": pkt.dst_ip,
            "dest_port": pkt.dst_port,
            "proto": pkt.proto.upper(),
            "alert": {
                "action": rule.action,
                "signature_id": rule.sid,
                "rev": rule.rev,
                "signature": rule.msg,
                "category": rule.classtype,
                "severity": rule.priority,
            },
        }
        with open(self.eve_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event) + "\n")

    def _fast(self, rule, pkt, ts):
        line = "%s  [**] [1:%d:%d] %s [**] [Priority: %d] {%s} %s:%s -> %s:%s\n" % (
            ts.strftime("%m/%d-%H:%M:%S"), rule.sid, rule.rev, rule.msg,
            rule.priority, pkt.proto.upper(), pkt.src_ip, pkt.src_port or 0,
            pkt.dst_ip, pkt.dst_port or 0)
        with open(self.fast_path, "a", encoding="utf-8") as fh:
            fh.write(line)
