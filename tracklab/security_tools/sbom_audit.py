#!/usr/bin/env python3
"""Gerador simples de SBOM + auditoria de vulnerabilidades via pip-audit.
Uso:
  python security_tools/sbom_audit.py --requirements requirements.txt --output sbom.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def parse_requirements(req_file: Path) -> list[dict[str, str]]:
    deps = []
    for line in req_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
        elif ">=" in line:
            name, version = line.split(">=", 1)
            version = f">={version}"
        else:
            name, version = line, "unspecified"
        deps.append({"name": name.strip(), "version": version.strip()})
    return deps


def run_pip_audit(requirements: Path) -> str:
    cmd = ["pip-audit", "-r", str(requirements), "-f", "json"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode not in (0, 1):
        return json.dumps({"error": res.stderr.strip() or res.stdout.strip()})
    return res.stdout.strip() or "[]"


def main() -> None:
    ap = argparse.ArgumentParser(description="SBOM + auditoria")
    ap.add_argument("--requirements", default="requirements.txt")
    ap.add_argument("--output", default="sbom.json")
    args = ap.parse_args()

    req = Path(args.requirements)
    deps = parse_requirements(req)
    audit_raw = run_pip_audit(req)

    report = {
        "source": str(req),
        "dependencies": deps,
        "vulnerability_audit": json.loads(audit_raw),
    }

    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[OK] SBOM gerado em {args.output} com {len(deps)} dependencias")


if __name__ == "__main__":
    main()
