#!/usr/bin/env python3
"""Gerenciador local de segredos com criptografia forte (AES-256 via Fernet).
Uso:
  python security_tools/secrets_cli.py init
  python security_tools/secrets_cli.py set db_password supersecreto
  python security_tools/secrets_cli.py get db_password
"""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

STORE_PATH = Path(".secrets_store.enc")
SALT_PATH = Path(".secrets_salt.bin")


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend(),
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def load_vault(master_password: str) -> dict[str, str]:
    if not STORE_PATH.exists():
        return {}
    if not SALT_PATH.exists():
        raise RuntimeError("Salt nao encontrado")

    salt = SALT_PATH.read_bytes()
    f = Fernet(derive_key(master_password, salt))
    encrypted = STORE_PATH.read_bytes()
    try:
        plain = f.decrypt(encrypted)
    except InvalidToken as e:
        raise RuntimeError("Senha mestra invalida") from e
    return json.loads(plain.decode("utf-8"))


def save_vault(master_password: str, data: dict[str, str]) -> None:
    if not SALT_PATH.exists():
        SALT_PATH.write_bytes(os.urandom(16))
    salt = SALT_PATH.read_bytes()
    f = Fernet(derive_key(master_password, salt))
    enc = f.encrypt(json.dumps(data).encode("utf-8"))
    STORE_PATH.write_bytes(enc)


def main() -> None:
    ap = argparse.ArgumentParser(description="Secrets manager local")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init")

    pset = sub.add_parser("set")
    pset.add_argument("key")
    pset.add_argument("value")

    pget = sub.add_parser("get")
    pget.add_argument("key")

    plist = sub.add_parser("list")

    pdel = sub.add_parser("delete")
    pdel.add_argument("key")

    args = ap.parse_args()
    master = os.environ.get("TRACKLAB_MASTER_PASSWORD")
    if not master:
        raise SystemExit("Defina TRACKLAB_MASTER_PASSWORD antes de executar")

    if args.cmd == "init":
        save_vault(master, {})
        print(f"[OK] Vault inicializado em {STORE_PATH}")
        return

    vault = load_vault(master)

    if args.cmd == "set":
        vault[args.key] = args.value
        save_vault(master, vault)
        print(f"[OK] Segredo salvo: {args.key}")
    elif args.cmd == "get":
        if args.key not in vault:
            raise SystemExit("Chave nao encontrada")
        print(vault[args.key])
    elif args.cmd == "list":
        for k in sorted(vault.keys()):
            print(k)
    elif args.cmd == "delete":
        if args.key in vault:
            del vault[args.key]
            save_vault(master, vault)
            print(f"[OK] Segredo removido: {args.key}")


if __name__ == "__main__":
    main()
