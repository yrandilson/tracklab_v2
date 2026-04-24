#!/usr/bin/env python3
"""Detector de mecanismos de persistencia comuns (Linux/Windows).
Uso:
  python security_tools/persistence_checker.py
"""

from __future__ import annotations

import os
import platform
from pathlib import Path


def linux_checks() -> list[str]:
    findings = []
    paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/etc/rc.local",
    ]
    for p in paths:
        path = Path(p)
        if path.exists():
            findings.append(f"presente: {p}")
    return findings


def windows_checks() -> list[str]:
    findings = []
    startup_paths = [
        os.path.expandvars(r"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        os.path.expandvars(r"%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
    ]
    for p in startup_paths:
        path = Path(p)
        if path.exists():
            files = list(path.glob("*"))
            if files:
                findings.append(f"startup entries em {p}: {len(files)}")
    return findings


def main() -> None:
    system = platform.system().lower()
    findings = linux_checks() if system == "linux" else windows_checks()

    if not findings:
        print("[OK] Nenhum indicador simples de persistencia detectado")
        return

    print("[ALERT] Itens para revisao de persistencia:")
    for f in findings:
        print(f"- {f}")


if __name__ == "__main__":
    main()
