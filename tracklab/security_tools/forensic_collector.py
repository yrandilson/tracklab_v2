#!/usr/bin/env python3
"""Coletor de evidencias forenses basico em JSON.
Uso:
  python security_tools/forensic_collector.py --output forensic_snapshot.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform

import psutil


def collect() -> dict:
    data = {
        "timestamp": dt.datetime.utcnow().isoformat() + "Z",
        "platform": platform.platform(),
        "boot_time": dt.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
        "users": [u._asdict() for u in psutil.users()],
        "processes": [],
        "connections": [],
    }

    for p in psutil.process_iter(["pid", "name", "username", "cmdline", "create_time"]):
        try:
            info = p.info
            info["cmdline"] = " ".join(info.get("cmdline") or [])
            data["processes"].append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    for c in psutil.net_connections(kind="inet"):
        try:
            data["connections"].append({
                "fd": c.fd,
                "family": str(c.family),
                "type": str(c.type),
                "laddr": str(c.laddr),
                "raddr": str(c.raddr),
                "status": c.status,
                "pid": c.pid,
            })
        except Exception:
            continue

    return data


def main() -> None:
    ap = argparse.ArgumentParser(description="Forensic collector")
    ap.add_argument("--output", default="forensic_snapshot.json")
    args = ap.parse_args()

    snapshot = collect()
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2)

    print(f"[OK] Snapshot forense salvo em {args.output}")


if __name__ == "__main__":
    main()
