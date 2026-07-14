"""
response.py - basic automated response actions.

When a rule whose action is 'drop' or 'reject' fires (or when --active-response
is on for any alert), the responder records the offending source IP and emits
the firewall command that would block it. By design it is *non-destructive*:
it writes a blocklist and logs the exact command, but does not execute it
unless run with --enforce and sufficient privileges. This keeps the demo safe
while showing a real response workflow.
"""

import os
import platform
import subprocess
from datetime import datetime, timezone


class Responder:
    def __init__(self, blocklist_path, actions_log, enforce=False):
        self.blocklist_path = blocklist_path
        self.actions_log = actions_log
        self.enforce = enforce
        self.blocked = set()
        for p in (blocklist_path, actions_log):
            os.makedirs(os.path.dirname(p), exist_ok=True)
        open(blocklist_path, "w").close()
        open(actions_log, "w").close()

    def _firewall_command(self, ip):
        """Return the platform-appropriate block command as an argument list."""
        if platform.system() == "Windows":
            return [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=NIDS-block-%s" % ip, "dir=in", "action=block",
                "remoteip=%s" % ip,
            ]
        return ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    def respond(self, rule, pkt):
        ip = pkt.src_ip
        if not ip or ip in self.blocked:
            return
        self.blocked.add(ip)
        cmd = self._firewall_command(ip)
        ts = datetime.now(timezone.utc).isoformat()

        with open(self.blocklist_path, "a", encoding="utf-8") as fh:
            fh.write("%s\n" % ip)
        with open(self.actions_log, "a", encoding="utf-8") as fh:
            fh.write("%s  BLOCK %-15s  (sid:%d %s)  cmd: %s\n" % (
                ts, ip, rule.sid, rule.msg, " ".join(cmd)))

        status = "enforced" if self.enforce else "simulated"
        print("  \033[95m>> RESPONSE (%s): block %s  [%s]\033[0m" % (
            status, ip, " ".join(cmd)))

        if self.enforce:
            try:
                subprocess.run(cmd, check=False, shell=False,
                               capture_output=True, timeout=10)
            except Exception as exc:  # noqa: BLE001
                print("     enforcement failed: %s" % exc)
