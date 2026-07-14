"""
verify.py - end-to-end self-test for the NIDS.

Regenerates the demo pcap, runs the engine over it in-process, then asserts:
  * every rule in local.rules fired at least once on the crafted attack,
  * benign hosts produced zero alerts,
  * the automated responder blocked the web-shell attacker.

Exit code 0 only if every assertion holds. Run:  python tools/verify.py
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from nids.alert import AlertManager
from nids.engine import Engine
from nids.response import Responder
from nids import rules as R

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(ok)
    print("[%s] %s%s" % ("OK  " if ok else "FAIL", name,
                         ("  - " + detail) if detail else ""))


# 1. (Re)generate the demo pcap.
subprocess.run([sys.executable, os.path.join(ROOT, "tools", "generate_pcap.py")],
               check=True, capture_output=True)

# 2. Run the engine in-process against it.
pcap = os.path.join(ROOT, "pcaps", "attacks.pcap")
eve = os.path.join(ROOT, "logs", "eve_verify.json")
blocklist = os.path.join(ROOT, "logs", "blocked_verify.txt")
actions = os.path.join(ROOT, "logs", "actions_verify.log")

cfg = json.load(open(os.path.join(ROOT, "config", "nids.json"), encoding="utf-8"))
ruleset, errors = R.load_rules(os.path.join(ROOT, "rules", "local.rules"))

check("all rules parse cleanly", not errors,
      "%d parse errors" % len(errors) if errors else "%d rules" % len(ruleset))

alerts = AlertManager(eve_path=eve, fast_path=None, use_color=False, quiet=True)
responder = Responder(blocklist, actions, enforce=False)
engine = Engine(ruleset, cfg["vars"], alerts, responder, active_response=False)
engine.run_pcap(pcap)

# 3. Collect the fired signatures and sources from the eve log.
events = [json.loads(l) for l in open(eve, encoding="utf-8") if l.strip()]
fired_sids = {e["alert"]["signature_id"] for e in events}
alert_srcs = {e["src_ip"] for e in events}

expected_sids = {r.sid for r in ruleset}
missing = expected_sids - fired_sids
check("every rule fired at least once", not missing,
      "missing sids: %s" % sorted(missing) if missing else
      "%d/%d signatures fired" % (len(expected_sids & fired_sids), len(expected_sids)))

# 4. Threshold rules should NOT fire before their count is reached.
scan_alerts = [e for e in events if e["alert"]["signature_id"] == 1000002]
check("port scan alerts only after threshold (15/5s)", len(scan_alerts) == 6,
      "%d scan alerts from a 20-SYN scan (first 14 suppressed)" % len(scan_alerts))
ssh_alerts = [e for e in events if e["alert"]["signature_id"] == 1000004]
check("ssh brute alerts only after threshold (5/30s)", len(ssh_alerts) == 2,
      "%d alerts from 6 attempts (first 4 suppressed)" % len(ssh_alerts))

# 5. Benign hosts must be silent.
for benign in ("198.51.100.20", "8.8.8.8"):
    check("benign host %s produced no alerts" % benign, benign not in alert_srcs)

# 6. Automated response blocked the web-shell attacker.
blocked = open(blocklist, encoding="utf-8").read().split()
check("responder blocked web-shell attacker", "198.51.100.7" in blocked,
      "blocklist: %s" % blocked)

# 7. Severity classification is populated.
sev = {e["alert"]["severity"] for e in events}
check("alerts span High/Medium/Low severities", {1, 2, 3} <= sev,
      "severities present: %s" % sorted(sev))

# Cleanup verify-only artefacts.
for p in (eve, blocklist, actions):
    if os.path.exists(p):
        os.remove(p)

print("\n%d/%d checks passed." % (sum(RESULTS), len(RESULTS)))
sys.exit(0 if all(RESULTS) else 1)
