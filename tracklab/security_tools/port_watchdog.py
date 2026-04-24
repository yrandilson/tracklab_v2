#!/usr/bin/env python3
"""Monitora portas em escuta e alerta quando uma nova porta aparece.
Uso:
  python security_tools/port_watchdog.py --interval 5
"""

from __future__ import annotations

import argparse
import time

import psutil


def current_listening() -> set[int]:
    ports = set()
    for c in psutil.net_connections(kind="inet"):
        if c.status == psutil.CONN_LISTEN and c.laddr:
            ports.add(int(c.laddr.port))
    return ports


def main() -> None:
    ap = argparse.ArgumentParser(description="Port watchdog")
    ap.add_argument("--interval", type=int, default=5)
    args = ap.parse_args()

    known = current_listening()
    print(f"[INFO] Baseline de portas ouvindo: {sorted(known)}")

    while True:
        now = current_listening()
        new_ports = sorted(now - known)
        if new_ports:
            print(f"[ALERT] Novas portas em escuta: {new_ports}")
            known |= set(new_ports)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
