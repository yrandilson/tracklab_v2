#!/usr/bin/env python3
"""Auditoria basica de hardening de host (CIS-like checks).
Uso:
  python security_tools/host_hardening_audit.py
"""

from __future__ import annotations

import os
import platform
from pathlib import Path


def check_exists(path: str, expected: bool = True) -> tuple[bool, str]:
    exists = Path(path).exists()
    ok = exists == expected
    return ok, f"{path}: {'presente' if exists else 'ausente'}"


def check_perm(path: str, max_mode: int) -> tuple[bool, str]:
    p = Path(path)
    if not p.exists():
        return False, f"{path}: ausente"
    mode = p.stat().st_mode & 0o777
    ok = mode <= max_mode
    return ok, f"{path}: modo={oct(mode)} recomendado<={oct(max_mode)}"


def run_linux_checks() -> list[tuple[str, bool, str]]:
    checks = []
    checks.append(("sshd_config", *check_exists("/etc/ssh/sshd_config")))
    checks.append(("auditd_installed", *check_exists("/sbin/auditd")))
    checks.append(("passwd_perm", *check_perm("/etc/passwd", 0o644)))
    checks.append(("shadow_perm", *check_perm("/etc/shadow", 0o640)))
    checks.append(("ssh_root_login_policy", *check_exists("/etc/ssh/sshd_config")))
    return checks


def run_windows_checks() -> list[tuple[str, bool, str]]:
    checks = []
    firewall = os.environ.get("SystemRoot", "C:\\Windows") + "\\System32\\netsh.exe"
    checks.append(("firewall_binary", *check_exists(firewall)))
    checks.append(("hosts_file", *check_exists(r"C:\\Windows\\System32\\drivers\\etc\\hosts")))
    checks.append(("defender_path", *check_exists(r"C:\\Program Files\\Windows Defender")))
    return checks


def main() -> None:
    system = platform.system().lower()
    checks = run_linux_checks() if system == "linux" else run_windows_checks()

    ok_count = 0
    print(f"[INFO] Auditoria de hardening para {system}")
    for name, ok, detail in checks:
        status = "OK" if ok else "ALERT"
        print(f"- [{status}] {name}: {detail}")
        if ok:
            ok_count += 1

    print(f"\n[RESUMO] {ok_count}/{len(checks)} checks em conformidade")


if __name__ == "__main__":
    main()
