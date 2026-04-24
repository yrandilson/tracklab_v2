#!/usr/bin/env python3
"""IDS/IPS simples para detectar brute force SSH em logs e opcionalmente bloquear IPs.
Uso:
  python security_tools/ids_ssh_monitor.py --log-file /var/log/auth.log --threshold 5 --window 300 --dry-run
"""

from __future__ import annotations

import argparse
import platform
import re
import subprocess
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

FAILED_RE = re.compile(r"Failed password .* from (?P<ip>\d+\.\d+\.\d+\.\d+)")


@dataclass
class Config:
    source: str
    log_file: Path | None
    threshold: int
    window_seconds: int
    blocker: str
    dry_run: bool
    poll_seconds: int


def block_ip(ip: str, blocker: str, dry_run: bool) -> None:
    if blocker == "windows-firewall":
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name=TrackLab Block {ip}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
        ]
    elif blocker == "ufw":
        cmd = ["ufw", "deny", "from", ip]
    else:
        cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]

    if dry_run:
        print(f"[DRY-RUN] Bloquearia IP: {ip} com: {' '.join(cmd)}")
        return

    subprocess.run(cmd, check=False)
    print(f"[BLOCK] IP bloqueado: {ip}")


def follow(file_path: Path):
    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line.rstrip("\n")


def fetch_failed_ips_windows(last_seconds: int) -> list[str]:
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "$start=(Get-Date).AddSeconds(-" + str(last_seconds) + ");"
            "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$start} -ErrorAction SilentlyContinue | "
            "ForEach-Object { $_.Message }"
        ),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return []

    ips = []
    ip_re = re.compile(r"Source Network Address:\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})")
    for line in proc.stdout.splitlines():
        m = ip_re.search(line)
        if m:
            ips.append(m.group(1))
    return ips


def detect_and_block(ip: str, attempts: dict[str, deque[float]], blocked: set[str], cfg: Config) -> None:
    now = time.time()
    q = attempts[ip]
    q.append(now)

    while q and (now - q[0]) > cfg.window_seconds:
        q.popleft()

    if len(q) >= cfg.threshold and ip not in blocked:
        print(f"[{datetime.now().isoformat()}] [ALERT] Tentativas SSH suspeitas de {ip}: {len(q)}")
        block_ip(ip, cfg.blocker, cfg.dry_run)
        blocked.add(ip)


def monitor_file(cfg: Config) -> None:
    attempts: dict[str, deque[float]] = defaultdict(deque)
    blocked: set[str] = set()

    assert cfg.log_file is not None
    print(f"[INFO] Monitorando arquivo: {cfg.log_file}")
    print(f"[INFO] Janela={cfg.window_seconds}s limiar={cfg.threshold} blocker={cfg.blocker} dry_run={cfg.dry_run}")

    for line in follow(cfg.log_file):
        m = FAILED_RE.search(line)
        if not m:
            continue
        ip = m.group("ip")
        detect_and_block(ip, attempts, blocked, cfg)


def monitor_windows(cfg: Config) -> None:
    attempts: dict[str, deque[float]] = defaultdict(deque)
    blocked: set[str] = set()

    print("[INFO] Monitorando Security Event ID 4625 (Windows)")
    print(f"[INFO] Janela={cfg.window_seconds}s limiar={cfg.threshold} blocker={cfg.blocker} dry_run={cfg.dry_run}")

    while True:
        for ip in fetch_failed_ips_windows(cfg.poll_seconds):
            detect_and_block(ip, attempts, blocked, cfg)
        time.sleep(cfg.poll_seconds)


def parse_args() -> Config:
    sys_name = platform.system().lower()
    default_source = "windows-event" if sys_name == "windows" else "file"
    default_blocker = "windows-firewall" if sys_name == "windows" else "ufw"

    ap = argparse.ArgumentParser(description="IDS/IPS simples para SSH")
    ap.add_argument("--source", choices=["file", "windows-event"], default=default_source)
    ap.add_argument("--log-file", type=Path, help="Arquivo de log (ex: /var/log/auth.log)")
    ap.add_argument("--threshold", type=int, default=5, help="Numero de falhas para alerta/bloqueio")
    ap.add_argument("--window", type=int, default=300, help="Janela de tempo em segundos")
    ap.add_argument("--blocker", choices=["iptables", "ufw", "windows-firewall"], default=default_blocker)
    ap.add_argument("--poll-seconds", type=int, default=5, help="Intervalo de polling para modo windows-event")
    ap.add_argument("--dry-run", action="store_true", help="Nao executa bloqueio real")
    args = ap.parse_args()
    if args.source == "file" and not args.log_file:
        ap.error("--log-file e obrigatorio quando --source=file")
    return Config(args.source, args.log_file, args.threshold, args.window, args.blocker, args.dry_run, args.poll_seconds)


if __name__ == "__main__":
    cfg = parse_args()
    if cfg.source == "windows-event":
        monitor_windows(cfg)
    else:
        monitor_file(cfg)
