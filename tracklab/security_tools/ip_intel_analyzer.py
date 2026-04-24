#!/usr/bin/env python3
"""Analise de IP com heuristicas locais e enriquecimento opcional.
Uso:
  python security_tools/ip_intel_analyzer.py 8.8.8.8 192.168.0.10
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path

import requests


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def reverse_dns(ip: str) -> str:
    try:
        import socket
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def abuseipdb_lookup(ip: str) -> dict:
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return {}
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    r = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=8)
    if r.ok:
        return r.json().get("data", {})
    return {}


def ipinfo_lookup(ip: str) -> dict:
    token = os.environ.get("IPINFO_TOKEN")
    if token:
        url = f"https://ipinfo.io/{ip}/json?token={token}"
    else:
        url = f"https://ipinfo.io/{ip}/json"
    r = requests.get(url, timeout=8)
    if r.ok:
        return r.json()
    return {}


def analyze_ip(ip: str) -> dict:
    result = {
        "ip": ip,
        "private": is_private(ip),
        "reverse_dns": reverse_dns(ip),
        "geo": {},
        "reputation": {},
    }

    if not result["private"]:
        result["geo"] = ipinfo_lookup(ip)
        result["reputation"] = abuseipdb_lookup(ip)

    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="IP intelligence analyzer")
    ap.add_argument("ips", nargs="+")
    ap.add_argument("--output", default="ip_intel.json")
    args = ap.parse_args()

    rows = [analyze_ip(ip) for ip in args.ips]
    out = Path(args.output)
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    for row in rows:
        print(f"[IP] {row['ip']} private={row['private']} rdns={row['reverse_dns'] or '-'}")
        if row.get("geo"):
            print(f"     geo={row['geo'].get('country','-')}/{row['geo'].get('region','-')} org={row['geo'].get('org','-')}")
        if row.get("reputation"):
            print(f"     abuseScore={row['reputation'].get('abuseConfidenceScore','-')} totalReports={row['reputation'].get('totalReports','-')}")

    print(f"[OK] Relatorio salvo em {out}")


if __name__ == "__main__":
    main()
