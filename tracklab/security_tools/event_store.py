#!/usr/bin/env python3
"""Banco de eventos unificado com normalizacao e score de risco.
Uso:
  from event_store import append_event
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

EVENT_LOG_DEFAULT = Path("security_events.jsonl")

BASE_SCORE_BY_TYPE = {
    "ids_alert": 85,
    "edr_alert": 90,
    "dns_tunnel": 80,
    "arp_spoof": 85,
    "port_new": 65,
    "vuln_found": 75,
    "fim_changed": 80,
    "honeypot_conn": 70,
    "honeypot_payload": 78,
    "process_anomaly": 72,
    "info": 25,
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clamp_score(score: int) -> int:
    return max(0, min(100, int(score)))


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def score_event(event_type: str, details: str = "") -> int:
    base = BASE_SCORE_BY_TYPE.get(event_type, 40)
    low = details.lower()
    if "ransom" in low or "mimikatz" in low:
        base += 10
    if "failed" in low and "ssh" in low:
        base += 5
    if "dry-run" in low:
        base -= 10
    return clamp_score(base)


def normalize_event(event: dict) -> dict:
    e = dict(event)
    e.setdefault("ts", utc_now())
    e.setdefault("host", "local")
    e.setdefault("type", "info")
    e.setdefault("source", "unknown")
    e.setdefault("details", "")

    if "risk_score" not in e:
        e["risk_score"] = score_event(e["type"], str(e.get("details", "")))
    e["risk_score"] = clamp_score(int(e["risk_score"]))
    e["severity"] = severity_from_score(e["risk_score"])
    return e


def append_event(event: dict, log_file: Path | str = EVENT_LOG_DEFAULT) -> dict:
    path = Path(log_file)
    normalized = normalize_event(event)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(normalized, ensure_ascii=True) + "\n")
    return normalized
