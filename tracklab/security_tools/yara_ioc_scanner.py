#!/usr/bin/env python3
"""Scanner de IOC com YARA.
Uso:
  python security_tools/yara_ioc_scanner.py --rules rules.yar --path .
"""

from __future__ import annotations

import argparse
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser(description="YARA IOC scanner")
    ap.add_argument("--rules", required=True)
    ap.add_argument("--path", required=True)
    args = ap.parse_args()

    try:
        import yara
    except ImportError:
        raise SystemExit("Instale yara-python para usar este scanner")

    rules = yara.compile(filepath=args.rules)
    target = Path(args.path)

    hits = 0
    if target.is_file():
        matches = rules.match(str(target))
        if matches:
            print(f"[ALERT] {target}: {[m.rule for m in matches]}")
            hits += 1
    else:
        for p in target.rglob("*"):
            if not p.is_file():
                continue
            try:
                matches = rules.match(str(p))
                if matches:
                    print(f"[ALERT] {p}: {[m.rule for m in matches]}")
                    hits += 1
            except Exception:
                continue

    if hits == 0:
        print("[OK] Nenhum match de IOC")
    else:
        print(f"[RESUMO] arquivos com match: {hits}")


if __name__ == "__main__":
    main()
