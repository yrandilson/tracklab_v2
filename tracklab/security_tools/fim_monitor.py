#!/usr/bin/env python3
"""Monitor de integridade de arquivos (FIM) baseado em hash SHA-256.
Uso:
  python security_tools/fim_monitor.py baseline --paths backend frontend --output fim_baseline.json
  python security_tools/fim_monitor.py verify --paths backend frontend --baseline fim_baseline.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

IGNORE_DIRS = {".git", "__pycache__", "node_modules", "database"}


def iter_files(paths: list[Path]):
    for root in paths:
        if root.is_file():
            yield root
            continue
        for p in root.rglob("*"):
            if p.is_dir() and p.name in IGNORE_DIRS:
                continue
            if p.is_file():
                if any(part in IGNORE_DIRS for part in p.parts):
                    continue
                yield p


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def build_snapshot(paths: list[Path]) -> dict[str, str]:
    snap = {}
    for p in iter_files(paths):
        snap[str(p)] = sha256_file(p)
    return snap


def cmd_baseline(paths: list[Path], output: Path) -> None:
    snap = build_snapshot(paths)
    output.write_text(json.dumps(snap, indent=2), encoding="utf-8")
    print(f"[OK] Baseline gerado com {len(snap)} arquivos em {output}")


def cmd_verify(paths: list[Path], baseline_path: Path) -> None:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    current = build_snapshot(paths)

    baseline_keys = set(baseline)
    current_keys = set(current)

    added = sorted(current_keys - baseline_keys)
    removed = sorted(baseline_keys - current_keys)
    changed = sorted(k for k in baseline_keys & current_keys if baseline[k] != current[k])

    if not (added or removed or changed):
        print("[OK] Integridade valida: nenhuma alteracao detectada")
        return

    print("[ALERT] Alteracoes detectadas:")
    if added:
        print("\n[+] Arquivos adicionados:")
        for f in added:
            print(f"- {f}")
    if removed:
        print("\n[-] Arquivos removidos:")
        for f in removed:
            print(f"- {f}")
    if changed:
        print("\n[~] Arquivos modificados:")
        for f in changed:
            print(f"- {f}")


def main() -> None:
    ap = argparse.ArgumentParser(description="FIM monitor")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("baseline")
    b.add_argument("--paths", nargs="+", required=True)
    b.add_argument("--output", default="fim_baseline.json")

    v = sub.add_parser("verify")
    v.add_argument("--paths", nargs="+", required=True)
    v.add_argument("--baseline", default="fim_baseline.json")

    args = ap.parse_args()

    if args.cmd == "baseline":
        cmd_baseline([Path(p) for p in args.paths], Path(args.output))
    else:
        cmd_verify([Path(p) for p in args.paths], Path(args.baseline))


if __name__ == "__main__":
    main()
