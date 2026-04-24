#!/usr/bin/env python3
"""Wrapper para executar ferramentas de rootkit (rkhunter/chkrootkit) e resumir output.
Uso:
  python security_tools/rootkit_wrapper.py --tool rkhunter
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess


def run_tool(tool: str) -> int:
    if tool == "windows-defender":
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            "Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled | Format-List",
        ]
        print(f"[INFO] Executando: {' '.join(cmd)}")
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        print((proc.stdout or "").strip() or "[WARN] Sem output do Defender")
        if proc.stderr:
            print(proc.stderr.strip())
        return proc.returncode

    if shutil.which(tool) is None:
        print(f"[ERR] Ferramenta nao encontrada: {tool}")
        return 2

    if tool == "rkhunter":
        cmd = [tool, "--check", "--sk"]
    else:
        cmd = [tool]

    print(f"[INFO] Executando: {' '.join(cmd)}")
    proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")

    alerts = [ln for ln in out.splitlines() if any(k in ln.lower() for k in ["warning", "infected", "suspicious"])]
    if alerts:
        print("[ALERT] Indicadores encontrados:")
        for ln in alerts[:80]:
            print(f"- {ln}")
    else:
        print("[OK] Sem alertas obvios no output")

    return proc.returncode


def main() -> None:
    sys_name = platform.system().lower()
    default_tool = "windows-defender" if sys_name == "windows" else "rkhunter"
    ap = argparse.ArgumentParser(description="Rootkit scanner wrapper")
    ap.add_argument("--tool", choices=["rkhunter", "chkrootkit", "windows-defender"], default=default_tool)
    args = ap.parse_args()
    raise SystemExit(run_tool(args.tool))


if __name__ == "__main__":
    main()
