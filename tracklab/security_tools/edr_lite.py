#!/usr/bin/env python3
"""EDR-lite local com regras simples de deteccao e resposta.
Uso:
  python security_tools/edr_lite.py --kill-suspicious
"""

from __future__ import annotations

import argparse

import psutil

SUSPICIOUS_TOKENS = [
    "powershell -enc",
    "certutil -urlcache",
    "nc -e",
    "bash -i",
]


def evaluate_process(p: psutil.Process) -> tuple[bool, str]:
    try:
        cmd = " ".join(p.cmdline()).lower()
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        return False, ""

    for t in SUSPICIOUS_TOKENS:
        if t in cmd:
            return True, t
    return False, ""


def main() -> None:
    ap = argparse.ArgumentParser(description="EDR-lite")
    ap.add_argument("--kill-suspicious", action="store_true")
    args = ap.parse_args()

    for p in psutil.process_iter(["pid", "name", "username"]):
        flagged, token = evaluate_process(p)
        if not flagged:
            continue

        print(f"[ALERT] Processo suspeito pid={p.pid} user={p.info.get('username')} token='{token}'")
        if args.kill_suspicious:
            try:
                p.kill()
                print(f"[ACTION] Processo finalizado pid={p.pid}")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"[WARN] Nao foi possivel finalizar pid={p.pid}: {e}")


if __name__ == "__main__":
    main()
