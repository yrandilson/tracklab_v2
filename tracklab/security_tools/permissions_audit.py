#!/usr/bin/env python3
"""Audita permissoes perigosas (SUID/SGID e world-writable).
Uso:
  python security_tools/permissions_audit.py --root /
"""

from __future__ import annotations

import argparse
import os
import platform
from pathlib import Path

IGNORE = {"/proc", "/sys", "/dev", "/run", "/snap"}


def linux_scan(root: Path) -> None:
    suid_sgid = []
    world_writable = []

    for dirpath, _, files in os.walk(root, topdown=True):
        if any(str(dirpath).startswith(p) for p in IGNORE):
            continue
        for name in files:
            p = Path(dirpath) / name
            try:
                mode = p.stat().st_mode & 0o7777
            except (PermissionError, FileNotFoundError, OSError):
                continue

            if mode & 0o4000 or mode & 0o2000:
                suid_sgid.append((str(p), oct(mode)))
            if mode & 0o002:
                world_writable.append((str(p), oct(mode)))

    print("[RESULT] SUID/SGID:")
    for path, mode in suid_sgid[:200]:
        print(f"- {path} mode={mode}")

    print("\n[RESULT] World-writable:")
    for path, mode in world_writable[:200]:
        print(f"- {path} mode={mode}")

    print(f"\n[RESUMO] suid_sgid={len(suid_sgid)} world_writable={len(world_writable)}")


def windows_scan(root: Path) -> None:
    writable_exec = []
    startup_artifacts = []
    exec_ext = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs"}

    startup_dirs = [
        Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
        Path(os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
    ]

    for sdir in startup_dirs:
        if not sdir.exists():
            continue
        for p in sdir.glob("*"):
            if p.is_file():
                startup_artifacts.append(str(p))

    for dirpath, _, files in os.walk(root, topdown=True):
        for name in files:
            p = Path(dirpath) / name
            try:
                if p.suffix.lower() in exec_ext and os.access(p, os.W_OK):
                    writable_exec.append(str(p))
            except OSError:
                continue

    print("[RESULT] Startup artifacts:")
    for path in startup_artifacts[:200]:
        print(f"- {path}")

    print("\n[RESULT] Executaveis gravaveis pelo usuario atual:")
    for path in writable_exec[:200]:
        print(f"- {path}")

    print(f"\n[RESUMO] startup={len(startup_artifacts)} writable_exec={len(writable_exec)}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Permissions auditor")
    default_root = "C:\\" if platform.system().lower() == "windows" else "/"
    ap.add_argument("--root", default=default_root)
    args = ap.parse_args()

    root = Path(args.root)
    if platform.system().lower() == "windows":
        windows_scan(root)
    else:
        linux_scan(root)


if __name__ == "__main__":
    main()
