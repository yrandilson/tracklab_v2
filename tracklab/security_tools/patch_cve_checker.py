#!/usr/bin/env python3
"""Verificador simples de patching com apoio de pip-audit para Python deps.
Uso:
  python security_tools/patch_cve_checker.py --requirements requirements.txt
"""

from __future__ import annotations

import argparse
import subprocess


def main() -> None:
    ap = argparse.ArgumentParser(description="Patch/CVE checker")
    ap.add_argument("--requirements", default="requirements.txt")
    args = ap.parse_args()

    print("[INFO] Executando auditoria de CVEs em dependencias Python")
    cmd = ["pip-audit", "-r", args.requirements]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)

    if res.stdout.strip():
        print(res.stdout.strip())
    if res.stderr.strip():
        print(res.stderr.strip())

    if res.returncode == 0:
        print("[OK] Sem vulnerabilidades conhecidas nas deps Python")
    elif res.returncode == 1:
        print("[ALERT] Vulnerabilidades encontradas")
    else:
        print("[ERR] Falha ao executar pip-audit")


if __name__ == "__main__":
    main()
