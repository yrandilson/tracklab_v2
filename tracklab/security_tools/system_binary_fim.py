#!/usr/bin/env python3
"""FIM para binarios de sistema.
Uso:
  python security_tools/system_binary_fim.py baseline --output system_bins_baseline.json
  python security_tools/system_binary_fim.py verify --baseline system_bins_baseline.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

LINUX_DIRS = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]
WINDOWS_DIRS = [r"C:\\Windows\\System32"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def collect(paths: list[Path]) -> dict[str, str]:
    snap = {}
    for root in paths:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_file():
                try:
                    snap[str(p)] = sha256_file(p)
                except (PermissionError, OSError):
                    continue
    return snap


def main() -> None:
    ap = argparse.ArgumentParser(description="System binary FIM")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("baseline")
    b.add_argument("--output", default="system_bins_baseline.json")
    v = sub.add_parser("verify")
    v.add_argument("--baseline", default="system_bins_baseline.json")
    args = ap.parse_args()

    paths = [Path(p) for p in (LINUX_DIRS + WINDOWS_DIRS)]

    if args.cmd == "baseline":
        snap = collect(paths)
        Path(args.output).write_text(json.dumps(snap, indent=2), encoding="utf-8")
        print(f"[OK] baseline salvo: {args.output} itens={len(snap)}")
        return

    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    current = collect(paths)

    changed = [k for k in baseline.keys() & current.keys() if baseline[k] != current[k]]
    added = list(current.keys() - baseline.keys())
    removed = list(baseline.keys() - current.keys())

    if not (changed or added or removed):
        print("[OK] Nenhuma alteracao em binarios monitorados")
        return

    print("[ALERT] Alteracoes detectadas")
    print(f"- changed={len(changed)} added={len(added)} removed={len(removed)}")


if __name__ == "__main__":
    main()
