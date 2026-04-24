#!/usr/bin/env python3
"""Scanner web defensivo (autorizado) para sinais basicos de XSS/SQLi.
Uso:
  python security_tools/web_vuln_scanner.py --url http://localhost:5000/capture
"""

from __future__ import annotations

import argparse
import urllib.parse

import requests
from bs4 import BeautifulSoup

SQLI_PAYLOAD = "' OR '1'='1"
XSS_PAYLOAD = "<script>alert(1)</script>"
SQL_ERRORS = [
    "sql syntax",
    "sqlite",
    "mysql",
    "postgresql",
    "odbc",
    "unterminated quoted",
]


def test_query_injection(url: str) -> list[str]:
    findings = []
    for payload, typ in [(SQLI_PAYLOAD, "SQLi"), (XSS_PAYLOAD, "XSS")]:
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}q={urllib.parse.quote(payload)}"
        r = requests.get(target, timeout=8)
        body_lower = r.text.lower()

        if typ == "SQLi" and any(err in body_lower for err in SQL_ERRORS):
            findings.append(f"Possivel SQLi refletida/erro SQL em query param: {target}")

        if typ == "XSS" and payload in r.text:
            findings.append(f"Possivel XSS refletido em query param: {target}")
    return findings


def test_forms(url: str) -> list[str]:
    findings = []
    r = requests.get(url, timeout=8)
    soup = BeautifulSoup(r.text, "html.parser")
    forms = soup.find_all("form")

    for i, form in enumerate(forms, start=1):
        action = form.get("action") or url
        method = (form.get("method") or "get").lower()
        target = urllib.parse.urljoin(url, action)
        fields = [inp.get("name") for inp in form.find_all("input") if inp.get("name")]
        if not fields:
            continue

        data_xss = {k: XSS_PAYLOAD for k in fields}
        data_sqli = {k: SQLI_PAYLOAD for k in fields}

        rx = requests.post(target, data=data_xss, timeout=8) if method == "post" else requests.get(target, params=data_xss, timeout=8)
        rs = requests.post(target, data=data_sqli, timeout=8) if method == "post" else requests.get(target, params=data_sqli, timeout=8)

        if XSS_PAYLOAD in rx.text:
            findings.append(f"Possivel XSS refletido no form #{i} ({target})")

        l = rs.text.lower()
        if any(err in l for err in SQL_ERRORS):
            findings.append(f"Possivel SQLi no form #{i} ({target})")

    return findings


def main() -> None:
    ap = argparse.ArgumentParser(description="Scanner web defensivo")
    ap.add_argument("--url", required=True, help="URL autorizada para teste")
    args = ap.parse_args()

    print(f"[INFO] Escaneando: {args.url}")
    findings = []
    findings.extend(test_query_injection(args.url))
    findings.extend(test_forms(args.url))

    if not findings:
        print("[OK] Nenhum sinal basico de SQLi/XSS detectado")
        return

    print("[ALERT] Achados:")
    for f in findings:
        print(f"- {f}")


if __name__ == "__main__":
    main()
