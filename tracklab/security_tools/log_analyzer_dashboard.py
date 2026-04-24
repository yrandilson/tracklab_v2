#!/usr/bin/env python3
"""Dashboard simples para analise centralizada de logs em arquivo JSONL.
Uso:
  python security_tools/log_analyzer_dashboard.py --log-file security_events.jsonl
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template_string

APP = Flask(__name__)
LOG_FILE = Path("security_events.jsonl")

HTML = """
<!doctype html>
<html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Security Log Analyzer</title>
<script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js\"></script>
<style>
body{font-family:monospace;background:#0b0c10;color:#e7eaf0;padding:20px}
.card{background:#12141a;padding:16px;border-radius:10px;border:1px solid #2a2f3a;margin-bottom:14px}
</style>
</head><body>
<h2>Security Log Analyzer</h2>
<div class=\"card\"><canvas id=\"types\" height=\"120\"></canvas></div>
<div class=\"card\"><canvas id=\"ips\" height=\"120\"></canvas></div>
<div class=\"card\"><canvas id=\"severity\" height=\"120\"></canvas></div>
<div class=\"card\"><canvas id=\"risk\" height=\"120\"></canvas></div>
<div class=\"card\"><h3>Eventos Criticos Recentes</h3><div id=\"criticalList\"></div></div>
<script>
async function load(){
  const d = await (await fetch('/api/log-stats')).json();
  new Chart(document.getElementById('types'), {type:'bar', data:{labels:d.types.labels, datasets:[{label:'Eventos', data:d.types.values}]}});
  new Chart(document.getElementById('ips'), {type:'bar', data:{labels:d.top_ips.labels, datasets:[{label:'Top IPs', data:d.top_ips.values}]}});
  new Chart(document.getElementById('severity'), {type:'doughnut', data:{labels:d.severity.labels, datasets:[{label:'Severidade', data:d.severity.values}]}});
  new Chart(document.getElementById('risk'), {type:'line', data:{labels:d.risk_timeline.labels, datasets:[{label:'Score medio', data:d.risk_timeline.values}]}});

  const list = document.getElementById('criticalList');
  if (!d.critical_recent.length) {
    list.innerHTML = '<div>Nenhum evento critico recente</div>';
  } else {
    list.innerHTML = d.critical_recent.map(e => `<div style=\"padding:8px 0;border-bottom:1px solid #2a2f3a\">[${e.ts}] score=${e.risk_score} type=${e.type} source=${e.source}<br><small>${e.details || ''}</small></div>`).join('');
  }
}
load();
</script>
</body></html>
"""


def read_events() -> list[dict]:
    if not LOG_FILE.exists():
        return []
    events = []
    for line in LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


@APP.route("/")
def index():
    return render_template_string(HTML)


@APP.route("/api/log-stats")
def stats():
    events = read_events()
    type_counter = Counter(e.get("type", "unknown") for e in events)
    ip_counter = Counter(e.get("ip", "unknown") for e in events if e.get("ip"))
    severity_counter = Counter(e.get("severity", "unknown") for e in events)

    risk_labels = []
    risk_values = []
    chunk = 20
    for idx in range(0, len(events), chunk):
        part = events[idx:idx + chunk]
        if not part:
            continue
        scores = [int(e.get("risk_score", 0)) for e in part]
        risk_labels.append(str((idx // chunk) + 1))
        risk_values.append(round(sum(scores) / len(scores), 2))

    critical_recent = [
        {
            "ts": e.get("ts"),
            "type": e.get("type"),
            "source": e.get("source"),
            "risk_score": e.get("risk_score", 0),
            "details": str(e.get("details", ""))[:180],
        }
        for e in events if e.get("severity") == "critical"
    ][-20:][::-1]

    return jsonify({
        "types": {"labels": list(type_counter.keys()), "values": list(type_counter.values())},
        "top_ips": {
            "labels": [k for k, _ in ip_counter.most_common(10)],
            "values": [v for _, v in ip_counter.most_common(10)],
        },
        "severity": {
            "labels": list(severity_counter.keys()),
            "values": list(severity_counter.values()),
        },
        "risk_timeline": {
            "labels": risk_labels,
            "values": risk_values,
        },
        "critical_recent": critical_recent,
    })


def main() -> None:
    global LOG_FILE
    ap = argparse.ArgumentParser(description="Log analyzer dashboard")
    ap.add_argument("--log-file", default="security_events.jsonl")
    ap.add_argument("--port", type=int, default=5055)
    args = ap.parse_args()

    LOG_FILE = Path(args.log_file)
    APP.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()
