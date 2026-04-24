#!/usr/bin/env python3
"""Audita conformidade basica de logs e retencao.
Uso:
  python security_tools/log_compliance_audit.py
"""

from __future__ import annotations

import platform
import subprocess
from pathlib import Path


def check(path: str) -> tuple[bool, str]:
    p = Path(path)
    if not p.exists():
        return False, f"ausente: {path}"
    return True, f"presente: {path}"


def check_win_log(channel: str) -> tuple[bool, str]:
    cmd = ["wevtutil", "gl", channel]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode == 0:
        return True, f"canal ativo: {channel}"
    return False, f"canal indisponivel: {channel}"


def run_linux() -> None:
    checks = [
        ("syslog", "/var/log/syslog"),
        ("authlog", "/var/log/auth.log"),
        ("logrotate", "/etc/logrotate.conf"),
        ("auditd", "/etc/audit/auditd.conf"),
    ]

    ok_count = 0
    print("[INFO] Auditoria basica de compliance de logs (Linux)")
    for name, path in checks:
        ok, detail = check(path)
        status = "OK" if ok else "ALERT"
        print(f"- [{status}] {name}: {detail}")
        if ok:
            ok_count += 1

    print(f"\n[RESUMO] {ok_count}/{len(checks)} itens presentes")


def run_windows() -> None:
    checks = [
        ("event_security", lambda: check_win_log("Security")),
        ("event_system", lambda: check_win_log("System")),
        ("event_application", lambda: check_win_log("Application")),
        ("defender_log", lambda: check(r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx")),
    ]

    ok_count = 0
    print("[INFO] Auditoria basica de compliance de logs (Windows)")
    for name, fn in checks:
        ok, detail = fn()
        status = "OK" if ok else "ALERT"
        print(f"- [{status}] {name}: {detail}")
        if ok:
            ok_count += 1

    print(f"\n[RESUMO] {ok_count}/{len(checks)} itens presentes")


def main() -> None:
    if platform.system().lower() == "windows":
        run_windows()
    else:
        run_linux()


if __name__ == "__main__":
    main()
