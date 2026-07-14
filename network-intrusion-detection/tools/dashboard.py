"""
dashboard.py - build a self-contained HTML dashboard from the NIDS alert log.

Reads logs/eve.json (the Suricata-style event log the engine writes) and
renders dashboard/report.html: KPI cards, charts (severity, top signatures,
top attacker IPs, top target ports, an alert timeline) and a detail table.
The output has no external dependencies - all CSS/JS is inlined - so it opens
straight from disk.

    python tools/dashboard.py
"""

import html
import json
import os
from collections import Counter, defaultdict
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVE = os.path.join(ROOT, "logs", "eve.json")
OUT = os.path.join(ROOT, "dashboard", "report.html")

SEV_NAME = {1: "High", 2: "Medium", 3: "Low"}
SEV_COLOR = {1: "#ff5470", 2: "#ffb02e", 3: "#33c4ff"}


def load_events(path):
    events = []
    if not os.path.exists(path):
        return events
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def bar_rows(counter, color_fn=None, limit=8):
    """Return HTML for a horizontal bar list from a Counter."""
    if not counter:
        return '<p class="empty">No data.</p>'
    top = counter.most_common(limit)
    mx = max(v for _, v in top)
    rows = []
    for label, val in top:
        pct = int(val / mx * 100)
        color = color_fn(label) if color_fn else "#33c4ff"
        rows.append(
            '<div class="bar-row">'
            '<span class="bar-label" title="{lab}">{lab}</span>'
            '<span class="bar-track"><span class="bar-fill" '
            'style="width:{pct}%;background:{c}"></span></span>'
            '<span class="bar-val">{v}</span></div>'.format(
                lab=html.escape(str(label)), pct=pct, c=color, v=val))
    return "\n".join(rows)


def timeline(events, buckets=24):
    if not events:
        return '<p class="empty">No data.</p>'
    times = []
    for e in events:
        try:
            times.append(datetime.fromisoformat(e["timestamp"]))
        except (ValueError, KeyError):
            pass
    if not times:
        return '<p class="empty">No data.</p>'
    lo, hi = min(times), max(times)
    span = (hi - lo).total_seconds() or 1
    counts = [0] * buckets
    for t in times:
        idx = min(buckets - 1, int((t - lo).total_seconds() / span * buckets))
        counts[idx] += 1
    mx = max(counts) or 1
    bars = []
    for c in counts:
        h = int(c / mx * 100)
        bars.append('<span class="tl-bar" style="height:{h}%" '
                    'title="{c} alerts"></span>'.format(h=max(h, 2), c=c))
    return ('<div class="timeline">%s</div>'
            '<div class="tl-axis"><span>%s</span><span>%s</span></div>' % (
                "".join(bars), lo.strftime("%H:%M:%S"), hi.strftime("%H:%M:%S")))


def table_rows(events, limit=100):
    rows = []
    for e in events[:limit]:
        a = e.get("alert", {})
        sev = a.get("severity", 3)
        rows.append(
            "<tr>"
            "<td>{ts}</td>"
            "<td><span class='pill' style='background:{c}'>{sv}</span></td>"
            "<td>{sig}</td>"
            "<td class='mono'>{src}:{sp}</td>"
            "<td class='mono'>{dst}:{dp}</td>"
            "<td class='mono'>{proto}</td>"
            "<td>{sid}</td>"
            "</tr>".format(
                ts=html.escape(str(e.get("timestamp", ""))[11:19]),
                c=SEV_COLOR.get(sev, "#888"), sv=SEV_NAME.get(sev, "?"),
                sig=html.escape(a.get("signature", "")),
                src=html.escape(str(e.get("src_ip", ""))),
                sp=e.get("src_port") or "",
                dst=html.escape(str(e.get("dest_ip", ""))),
                dp=e.get("dest_port") or "",
                proto=html.escape(str(e.get("proto", ""))),
                sid=a.get("signature_id", "")))
    return "\n".join(rows)


def build(events):
    sev_counter = Counter(SEV_NAME.get(e.get("alert", {}).get("severity", 3), "Low")
                          for e in events)
    sig_counter = Counter(e.get("alert", {}).get("signature", "?") for e in events)
    src_counter = Counter(e.get("src_ip", "?") for e in events)
    port_counter = Counter(str(e.get("dest_port")) for e in events
                           if e.get("dest_port"))
    total = len(events)
    high = sev_counter.get("High", 0)
    med = sev_counter.get("Medium", 0)
    low = sev_counter.get("Low", 0)
    unique_src = len(set(e.get("src_ip") for e in events if e.get("src_ip")))
    gen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sev_color = lambda name: {"High": "#ff5470", "Medium": "#ffb02e",  # noqa: E731
                              "Low": "#33c4ff"}.get(name, "#888")

    return TEMPLATE.format(
        gen=gen, total=total, high=high, med=med, low=low, unique_src=unique_src,
        sev_bars=bar_rows(sev_counter, sev_color),
        sig_bars=bar_rows(sig_counter),
        src_bars=bar_rows(src_counter, limit=8),
        port_bars=bar_rows(port_counter, limit=8),
        timeline=timeline(events),
        table=table_rows(events))


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NIDS Dashboard</title>
<style>
  :root {{
    --bg:#0d1117; --panel:#161b22; --edge:#232b36; --ink:#e6edf3;
    --muted:#8b949e; --accent:#33c4ff;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--ink);
    font-family:"Segoe UI",system-ui,sans-serif; }}
  .mono {{ font-family:"Cascadia Code",Consolas,monospace; }}
  header {{ padding:24px 28px; border-bottom:1px solid var(--edge);
    display:flex; justify-content:space-between; align-items:baseline;
    flex-wrap:wrap; gap:8px; }}
  header h1 {{ margin:0; font-size:20px; letter-spacing:.3px; }}
  header h1 span {{ color:var(--accent); }}
  header .gen {{ color:var(--muted); font-size:13px; }}
  main {{ padding:24px 28px; max-width:1200px; margin:0 auto; }}
  .kpis {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
    gap:14px; margin-bottom:24px; }}
  .kpi {{ background:var(--panel); border:1px solid var(--edge);
    border-radius:10px; padding:16px 18px; }}
  .kpi .n {{ font-size:30px; font-weight:600; }}
  .kpi .l {{ color:var(--muted); font-size:12px; text-transform:uppercase;
    letter-spacing:.6px; margin-top:4px; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px;
    margin-bottom:24px; }}
  .panel {{ background:var(--panel); border:1px solid var(--edge);
    border-radius:10px; padding:18px; }}
  .panel h2 {{ margin:0 0 14px; font-size:14px; font-weight:600;
    color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }}
  .bar-row {{ display:grid; grid-template-columns:180px 1fr 40px;
    align-items:center; gap:10px; margin:7px 0; font-size:13px; }}
  .bar-label {{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .bar-track {{ background:#0d1117; border-radius:5px; height:16px;
    overflow:hidden; }}
  .bar-fill {{ display:block; height:100%; border-radius:5px; }}
  .bar-val {{ text-align:right; color:var(--muted); }}
  .timeline {{ display:flex; align-items:flex-end; gap:3px; height:90px; }}
  .tl-bar {{ flex:1; background:var(--accent); border-radius:2px 2px 0 0;
    min-height:2px; opacity:.8; }}
  .tl-axis {{ display:flex; justify-content:space-between; color:var(--muted);
    font-size:11px; margin-top:6px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--edge); }}
  th {{ color:var(--muted); font-weight:600; text-transform:uppercase;
    font-size:11px; letter-spacing:.5px; }}
  .pill {{ color:#0d1117; font-weight:700; font-size:11px; padding:2px 8px;
    border-radius:20px; }}
  .empty {{ color:var(--muted); font-size:13px; }}
  .table-wrap {{ overflow-x:auto; }}
  @media (max-width:760px) {{ .grid {{ grid-template-columns:1fr; }}
    .bar-row {{ grid-template-columns:120px 1fr 34px; }} }}
</style></head>
<body>
<header>
  <h1><span>&#9673;</span> NIDS Dashboard <span class="mono">/ TaskVault SOC</span></h1>
  <div class="gen">generated {gen}</div>
</header>
<main>
  <section class="kpis">
    <div class="kpi"><div class="n">{total}</div><div class="l">Total alerts</div></div>
    <div class="kpi"><div class="n" style="color:#ff5470">{high}</div><div class="l">High severity</div></div>
    <div class="kpi"><div class="n" style="color:#ffb02e">{med}</div><div class="l">Medium severity</div></div>
    <div class="kpi"><div class="n" style="color:#33c4ff">{low}</div><div class="l">Low severity</div></div>
    <div class="kpi"><div class="n">{unique_src}</div><div class="l">Unique sources</div></div>
  </section>

  <section class="panel" style="margin-bottom:16px">
    <h2>Alert timeline</h2>
    {timeline}
  </section>

  <section class="grid">
    <div class="panel"><h2>Alerts by severity</h2>{sev_bars}</div>
    <div class="panel"><h2>Top signatures</h2>{sig_bars}</div>
    <div class="panel"><h2>Top attacker IPs</h2>{src_bars}</div>
    <div class="panel"><h2>Top targeted ports</h2>{port_bars}</div>
  </section>

  <section class="panel">
    <h2>Alert detail</h2>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Time</th><th>Severity</th><th>Signature</th>
        <th>Source</th><th>Destination</th><th>Proto</th><th>SID</th></tr></thead>
      <tbody>
      {table}
      </tbody>
    </table>
    </div>
  </section>
</main>
</body></html>
"""


def main():
    events = load_events(EVE)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(build(events))
    print("Dashboard written to %s  (%d alerts)" % (
        os.path.relpath(OUT, ROOT), len(events)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
