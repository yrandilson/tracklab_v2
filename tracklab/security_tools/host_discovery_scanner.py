#!/usr/bin/env python3
"""Scanner de descoberta de hosts e servicos estilo Nmap, com fallback inteligente.
Uso:
  python security_tools/host_discovery_scanner.py --targets 192.168.0.0/24 --ports 22,80,443
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def parse_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def ping_host(host: str, timeout_ms: int = 700) -> bool:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000 + 1)), host]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.returncode == 0


def tcp_scan(host: str, port: int, timeout: float = 0.4) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                banner = ""
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(128).decode(errors="ignore").strip()
                except OSError:
                    pass
                return {"host": host, "port": port, "service": service, "banner": banner}
    except OSError:
        return None
    return None


def nmap_scan(targets: str, ports: list[int]) -> list[dict] | None:
    if not subprocess.run(["where" if platform.system().lower() == "windows" else "which", "nmap"], capture_output=True, text=True, check=False).returncode == 0:
        return None
    port_spec = ",".join(str(p) for p in ports)
    cmd = ["nmap", "-Pn", "-sS", "-sV", "-p", port_spec, "-oX", "-", targets]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0 or not proc.stdout.strip():
        return None
    # Parse minimal XML-ish markers without extra dependency.
    results: list[dict] = []
    current_host = None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("<address addr=") and 'addrtype="ipv4"' in line:
            current_host = line.split('addr="', 1)[1].split('"', 1)[0]
        if line.startswith("<port ") and current_host:
            parts = line.split(' ')
            dport = None
            service = "unknown"
            for p in parts:
                if p.startswith('portid="'):
                    dport = int(p.split('"')[1])
                if p.startswith('name="'):
                    service = p.split('"')[1]
            if dport:
                results.append({"host": current_host, "port": dport, "service": service, "banner": "nmap"})
    return results or None


def cidr_hosts(targets: str) -> list[str]:
    net = ipaddress.ip_network(targets, strict=False)
    return [str(ip) for ip in net.hosts()]


def main() -> None:
    ap = argparse.ArgumentParser(description="Host discovery scanner")
    ap.add_argument("--targets", required=True, help="CIDR ou host unico")
    ap.add_argument("--ports", default="22,80,443,445,3389,8080")
    ap.add_argument("--workers", type=int, default=128)
    ap.add_argument("--log-file", default="security_events.jsonl")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    log_file = Path(args.log_file)

    nmap_results = nmap_scan(args.targets, ports)
    if nmap_results is not None:
        results = nmap_results
    else:
        hosts = [args.targets] if "/" not in args.targets else cidr_hosts(args.targets)
        results = []
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(tcp_scan, host, port) for host in hosts for port in ports]
            for fut in as_completed(futs):
                row = fut.result()
                if row:
                    results.append(row)

    results.sort(key=lambda x: (x["host"], x["port"]))

    print("[RESULT] Hosts/servicos encontrados:")
    for row in results:
        print(f"- {row['host']:<15} port={row['port']:<5} service={row['service']:<10} banner={row['banner'][:60]}")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"type": "host_discovery", "source": "host_discovery_scanner", "details": f"{row['host']}:{row['port']} {row['service']}", "ip": row['host']}) + "\n")

    print(f"\n[RESUMO] total={len(results)}")


if __name__ == "__main__":
    main()
