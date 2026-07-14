"""
run_demo.py - one-command end-to-end demo:
  1. generate the synthetic attack pcap
  2. run the NIDS engine over it (alerts + automated response)
  3. build the HTML dashboard

    python run_demo.py

Then open dashboard/report.html in a browser.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable


def step(title, args):
    print("\n\033[1m== %s ==\033[0m" % title)
    subprocess.run([PY] + args, check=True, cwd=ROOT)


def main():
    step("1/3  Generating attack traffic", ["tools/generate_pcap.py"])
    step("2/3  Running intrusion detection",
         ["-m", "nids.engine", "--pcap", "pcaps/attacks.pcap", "--active-response"])
    step("3/3  Building dashboard", ["tools/dashboard.py"])
    print("\nDone. Open dashboard/report.html to view detected attacks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
