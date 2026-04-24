#!/usr/bin/env python3
"""Monitor avancado de portas em escuta e processos donos.
Uso:
  python security_tools/advanced_port_monitor.py --interval 5
"""

from __future__ import annotations

import argparse
import json
import platform
import socket
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import psutil


@dataclass(frozen=True)
class PortRecord:
    proto: str
    ip: str
    port: int
    pid: int | None
    process: str


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "local"


def get_listening_ports() -> dict[tuple[str, int, str], PortRecord]:
    records: dict[tuple[str, int, str], PortRecord] = {}
    for conn in psutil.net_connections(kind="inet"):
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        ip = conn.laddr.ip or "0.0.0.0"
        port = int(conn.laddr.port)
        proto = "tcp"
        proc = "unknown"
        pid = conn.pid
        if pid:
            try:
                proc = psutil.Process(pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc = "unknown"
        records[(proto, port, ip)] = PortRecord(proto=proto, ip=ip, port=port, pid=pid, process=proc)
    return records


def process_from_port_windows(port: int) -> str:
    cmd = ["powershell", "-NoProfile", "-Command", f"Get-NetTCPConnection -LocalPort {port} -State Listen | Select-Object -First 1 OwningProcess"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def emit_event(record: PortRecord, reason: str, log_file: Path | None) -> None:
    msg = (
        f"[ALERT] new_listening_port host={get_hostname()} proto={record.proto} ip={record.ip} "
        f"port={record.port} pid={record.pid} process={record.process} reason={reason}"
    )
    print(msg)
    if log_file:
        payload = {
            "type": "port_new",
            "source": "advanced_port_monitor",
            "host": get_hostname(),
            "protocol": record.proto,
            "ip": record.ip,
            "details": msg,
            "port": record.port,
            "pid": record.pid,
            "process": record.process,
        }
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=True) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Advanced port monitor")
    ap.add_argument("--interval", type=int, default=5)
    ap.add_argument("--allow", default="22,80,443")
    ap.add_argument("--log-file", default="security_events.jsonl")
    args = ap.parse_args()

    allow = {int(p) for p in args.allow.split(",") if p.strip()}
    log_file = Path(args.log_file)
    system = platform.system().lower()

    baseline = get_listening_ports()
    print(f"[INFO] Baseline de portas em escuta: {sorted({r.port for r in baseline.values()})}")

    while True:
        current = get_listening_ports()
        new_keys = current.keys() - baseline.keys()
        for key in sorted(new_keys):
            rec = current[key]
            reason = "allowed" if rec.port in allow else "unauthorized"
            emit_event(rec, reason, log_file if rec.port not in allow else None)
        baseline = current
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
