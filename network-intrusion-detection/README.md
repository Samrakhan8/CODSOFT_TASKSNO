# NIDS — Network Intrusion Detection System

A working network intrusion detection system with a Snort/Suricata-compatible
rule engine. It captures/reads network traffic, matches it against customisable
detection rules, raises severity-ranked alerts, takes basic automated response
actions, and renders an HTML dashboard of detected attacks.

The same rule files run under **real Suricata** (`config/suricata.yaml`) and
under the bundled Python engine — so the detection logic is portable to the
industry-standard tool, while the Python engine keeps the whole project
runnable and testable offline (no driver install, no admin rights).

## Highlights

- **Snort/Suricata rule syntax** — `action proto src port -> dst port (options)`
  with `content` (incl. `|hex|` and `nocase`), `pcre`, `flags`, `itype`,
  `dsize`, `flow`, `detection_filter`/`threshold`, `classtype`, `sid`, and more.
- **Two traffic sources** — read a `.pcap`, or capture live from an interface
  (live needs [Npcap](https://npcap.com) on Windows).
- **Suricata-style output** — `eve.json` (JSON events), `fast.log`, and a
  colourised console.
- **Automated response** — `drop`/`reject` rules (or `--active-response`) record
  the attacker IP to a blocklist and emit the firewall block command;
  non-destructive by default, `--enforce` actually applies it.
- **Dashboard (bonus)** — a self-contained HTML report: KPI cards, timeline,
  and charts of severity, top signatures, top attacker IPs and target ports.

## Quick start

```
pip install -r requirements.txt      # scapy
python run_demo.py                   # generate traffic -> detect -> dashboard
```

Then open **`dashboard/report.html`**. `run_demo.py` runs three steps you can
also run individually:

```
python tools/generate_pcap.py                        # craft pcaps/attacks.pcap
python -m nids.engine --pcap pcaps/attacks.pcap      # detect (add --active-response)
python tools/dashboard.py                            # build the dashboard
```

Live monitoring (needs Npcap/libpcap and admin/root):

```
python -m nids.engine --iface "Ethernet"
```

## Verify it works

```
python tools/verify.py
```

This regenerates the demo traffic, runs detection in-process, and asserts that
every rule fires, that the threshold rules stay quiet until their count is
reached, that benign hosts produce no alerts, and that the responder blocks the
web-shell attacker. Expected result: **8/8 checks passed**.

## Project layout

```
network-intrusion-detection/
├── nids/
│   ├── engine.py      # capture/replay, packet extraction, detection pipeline, CLI
│   ├── rules.py       # Snort/Suricata rule parser + address/port/content matching
│   ├── alert.py       # console + eve.json + fast.log alert sinks
│   └── response.py    # blocklist + firewall-command response actions
├── rules/local.rules  # the detection rules (customise these)
├── config/
│   ├── nids.json       # engine config: HOME_NET/EXTERNAL_NET vars, log paths
│   └── suricata.yaml   # run the SAME rules under real Suricata
├── tools/
│   ├── generate_pcap.py # craft a synthetic attack+benign pcap for testing
│   ├── dashboard.py     # build the HTML dashboard from eve.json
│   └── verify.py        # end-to-end self-test (8 assertions)
├── pcaps/  logs/  dashboard/
├── run_demo.py
└── README.md
```

## Detection rules

`rules/local.rules` ships 14 rules covering the common attack classes:

| SID | Detects | Severity | Technique |
|-----|---------|----------|-----------|
| 1000001 | ICMP ping / host discovery | Low | `itype:8` |
| 1000002 | TCP SYN port scan | Low | `flags:S` + `detection_filter` 15/5s |
| 1000003 | TCP NULL scan | Medium | `flags:0` |
| 1000004 | SSH brute force | High | port 22 + `detection_filter` 5/30s |
| 1000005 | Cleartext Telnet (policy) | Medium | outbound port 23 |
| 1000010 | SQL injection (UNION SELECT) | High | multi-`content` `nocase` |
| 1000011 | SQL injection (OR 1=1) | High | `content` |
| 1000012 | Directory traversal (`../`) | High | `content:"|2e 2e 2f|"` |
| 1000013 | Cross-site scripting | High | `content:"<script"` |
| 1000014 | Web scanner user-agent | Medium | `pcre` (sqlmap/nikto/nmap…) |
| 1000020 | Web shell command exec | High | **drop** + response |
| 1000021 | Cleartext credentials leaving net | Medium | outbound `password=` |
| 1000022 | Large ICMP payload (tunnel/exfil) | Medium | `dsize:>800` |
| 1000023 | EICAR test-file transfer | High | `content` |

### Writing your own rule

```
alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"MySQL access from outside"; \
    flags:S; classtype:policy-violation; sid:1000100; rev:1;)
```

Drop it in `local.rules` and rerun the engine — no code changes needed.
`$HOME_NET`/`$EXTERNAL_NET` are defined in `config/nids.json`.

## How it works

1. **Capture** — packets are read from a pcap (or sniffed live) via scapy and
   normalised into a backend-independent `Packet` (IPs, ports, TCP flags, ICMP
   type, payload).
2. **Detect** — each packet is tested against every rule: protocol, direction,
   address/port (with CIDR and `$VAR` expansion), then options (content, pcre,
   flags, dsize, itype). Stateful `detection_filter`/`threshold` rules use a
   per-source sliding window so scans and brute-force only alert once their rate
   is exceeded.
3. **Alert** — matches are written to the console, `eve.json`, and `fast.log`,
   tagged with severity derived from `classtype`/`priority`.
4. **Respond** — for `drop`/`reject` rules (or with `--active-response`), the
   attacker IP is added to a blocklist and the firewall command is logged
   (executed only with `--enforce`).
5. **Visualise** — `dashboard.py` aggregates `eve.json` into an HTML report.

## Notes and scope

- The bundled engine implements a practical **subset** of the Suricata language,
  chosen to cover the common detection patterns above. For full protocol
  analysis and the complete rule language, run the rules under real Suricata
  with `config/suricata.yaml`.
- Response actions are **non-destructive by default**. `--enforce` runs real
  `netsh`/`iptables` commands and requires administrator/root privileges.
- All demo traffic is synthetic and self-contained; nothing is sent on a real
  network.
