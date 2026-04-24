#!/usr/bin/env python3
"""Scanner de portas e servicos para rede interna.
Uso:
  python security_tools/port_service_scanner.py --host 192.168.0.10 --ports 1-1024 --allow 22,80,443
"""

from __future__ import annotations

import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
}


def parse_ports(spec: str) -> list[int]:
    if "-" in spec:
        start, end = spec.split("-", 1)
        return list(range(int(start), int(end) + 1))
    return [int(p.strip()) for p in spec.split(",") if p.strip()]


def scan_port(host: str, port: int, timeout: float) -> tuple[int, bool, str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = COMMON.get(port, "unknown")
                return port, True, service
    except OSError:
        pass
    return port, False, ""


def main() -> None:
    ap = argparse.ArgumentParser(description="Scanner de portas e servicos")
    ap.add_argument("--host", required=True)
    ap.add_argument("--ports", default="1-1024")
    ap.add_argument("--timeout", type=float, default=0.4)
    ap.add_argument("--workers", type=int, default=200)
    ap.add_argument("--allow", default="", help="Portas permitidas separadas por virgula")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    allowed = {int(p) for p in args.allow.split(",") if p.strip()}

    print(f"[INFO] Escaneando {args.host} portas={len(ports)}")
    open_ports: list[tuple[int, str]] = []

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(scan_port, args.host, p, args.timeout) for p in ports]
        for f in as_completed(futs):
            port, is_open, service = f.result()
            if is_open:
                open_ports.append((port, service))

    open_ports.sort(key=lambda x: x[0])
    if not open_ports:
        print("[OK] Nenhuma porta aberta encontrada no range")
        return

    print("\n[RESULT] Portas abertas:")
    for port, service in open_ports:
        status = "AUTORIZADA" if (not allowed or port in allowed) else "NAO AUTORIZADA"
        print(f"- {port:<5} {service:<12} {status}")


if __name__ == "__main__":
    main()
