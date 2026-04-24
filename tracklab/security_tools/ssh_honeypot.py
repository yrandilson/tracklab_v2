#!/usr/bin/env python3
"""Honeypot TCP simples para telemetria de tentativas (simula endpoint SSH).
Uso:
  python security_tools/ssh_honeypot.py --host 0.0.0.0 --port 2222
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import threading
from pathlib import Path


BANNER = b"SSH-2.0-OpenSSH_8.4\r\n"


def handle_client(conn: socket.socket, addr, log_file: Path) -> None:
    ip, port = addr
    ts = dt.datetime.utcnow().isoformat() + "Z"
    event = {"type": "honeypot_conn", "ip": ip, "port": port, "ts": ts}
    with log_file.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    try:
        conn.sendall(BANNER)
        data = conn.recv(512)
        if data:
            event2 = {"type": "honeypot_payload", "ip": ip, "size": len(data), "ts": ts}
            with log_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event2) + "\n")
    except Exception:
        pass
    finally:
        conn.close()


def main() -> None:
    ap = argparse.ArgumentParser(description="SSH honeypot")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--log", default="security_events.jsonl")
    args = ap.parse_args()

    log_file = Path(args.log)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.listen(50)

    print(f"[INFO] Honeypot escutando em {args.host}:{args.port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr, log_file), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
