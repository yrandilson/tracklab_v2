#!/usr/bin/env python3
"""Monitor simples de processos suspeitos por assinatura e consumo.
Uso:
  python security_tools/process_anomaly_monitor.py --interval 5
"""

from __future__ import annotations

import argparse
import time

import psutil

SUSPICIOUS_NAMES = {
    "nc", "ncat", "netcat", "mimikatz", "psexec", "powersploit", "meterpreter",
}


def scan_once(cpu_threshold: float, mem_mb_threshold: float) -> None:
    print("[SCAN] Verificando processos")
    for p in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_info", "cmdline"]):
        try:
            name = (p.info.get("name") or "").lower()
            cpu = float(p.info.get("cpu_percent") or 0.0)
            mem = float((p.info.get("memory_info").rss if p.info.get("memory_info") else 0) / (1024 * 1024))
            cmd = " ".join(p.info.get("cmdline") or [])

            reasons = []
            if name in SUSPICIOUS_NAMES:
                reasons.append("nome suspeito")
            if cpu > cpu_threshold:
                reasons.append(f"cpu alta ({cpu:.1f}%)")
            if mem > mem_mb_threshold:
                reasons.append(f"mem alta ({mem:.1f}MB)")

            if reasons:
                print(f"[ALERT] pid={p.pid} user={p.info.get('username')} name={name} reasons={', '.join(reasons)} cmd={cmd[:120]}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def main() -> None:
    ap = argparse.ArgumentParser(description="Process anomaly monitor")
    ap.add_argument("--interval", type=int, default=5)
    ap.add_argument("--cpu-threshold", type=float, default=85.0)
    ap.add_argument("--mem-mb-threshold", type=float, default=1024.0)
    args = ap.parse_args()

    while True:
        scan_once(args.cpu_threshold, args.mem_mb_threshold)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
