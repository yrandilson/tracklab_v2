#!/usr/bin/env python3
"""Notificacao em tempo real para eventos criticos via webhook.
Uso:
  set TRACKLAB_ALERT_WEBHOOK_URL=https://...
  python security_tools/critical_notifier.py --log-file security_events.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

import requests


SENT_CACHE: set[str] = set()


def event_key(ev: dict) -> str:
    return f"{ev.get('ts')}|{ev.get('type')}|{ev.get('details')}|{ev.get('risk_score')}"


def send_webhook(url: str, ev: dict) -> None:
    payload = {
        "text": (
            f"[TrackLab ALERT] severity={ev.get('severity')} score={ev.get('risk_score')} "
            f"type={ev.get('type')} source={ev.get('source')} details={ev.get('details')}"
        )
    }
    requests.post(url, json=payload, timeout=8)


def parse_line(line: str) -> dict | None:
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def follow(path: Path):
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Critical event notifier")
    ap.add_argument("--log-file", default="security_events.jsonl")
    args = ap.parse_args()

    webhook = os.environ.get("TRACKLAB_ALERT_WEBHOOK_URL")
    if not webhook:
        raise SystemExit("Defina TRACKLAB_ALERT_WEBHOOK_URL")

    path = Path(args.log_file)
    path.touch(exist_ok=True)

    print(f"[INFO] Notificador monitorando {path}")
    for line in follow(path):
        ev = parse_line(line)
        if not ev:
            continue
        if ev.get("severity") != "critical":
            continue
        key = event_key(ev)
        if key in SENT_CACHE:
            continue
        try:
            send_webhook(webhook, ev)
            SENT_CACHE.add(key)
            print(f"[NOTIFY] Critico enviado: {ev.get('type')} score={ev.get('risk_score')}")
        except Exception as e:
            print(f"[WARN] Falha ao notificar: {e}")


if __name__ == "__main__":
    main()
