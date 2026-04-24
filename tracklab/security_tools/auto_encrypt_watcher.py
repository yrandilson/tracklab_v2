#!/usr/bin/env python3
"""Criptografia automatica de arquivos sensiveis em pasta monitorada.
Uso:
  python security_tools/auto_encrypt_watcher.py --watch ./sensitive
"""

from __future__ import annotations

import argparse
import base64
import os
import time
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

SENSITIVE_EXT = {".txt", ".csv", ".json", ".env", ".pem", ".key"}


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


class EncryptHandler(FileSystemEventHandler):
    def __init__(self, fernet: Fernet):
        self.fernet = fernet

    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix.lower() not in SENSITIVE_EXT:
            return
        if path.name.endswith(".enc"):
            return

        try:
            raw = path.read_bytes()
            enc = self.fernet.encrypt(raw)
            out = path.with_suffix(path.suffix + ".enc")
            out.write_bytes(enc)
            print(f"[ENC] {path} -> {out}")
        except Exception as e:
            print(f"[ERR] Falha ao criptografar {path}: {e}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Auto encryption watcher")
    ap.add_argument("--watch", required=True, help="Pasta monitorada")
    ap.add_argument("--salt-file", default=".encrypt_salt.bin")
    args = ap.parse_args()

    password = os.environ.get("TRACKLAB_ENCRYPT_PASSWORD")
    if not password:
        raise SystemExit("Defina TRACKLAB_ENCRYPT_PASSWORD")

    salt_path = Path(args.salt_file)
    if not salt_path.exists():
        salt_path.write_bytes(os.urandom(16))

    key = derive_key(password, salt_path.read_bytes())
    handler = EncryptHandler(Fernet(key))

    observer = Observer()
    observer.schedule(handler, args.watch, recursive=True)
    observer.start()

    print(f"[INFO] Monitorando pasta: {args.watch}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
