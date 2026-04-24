#!/usr/bin/env python3
"""Orquestrador central de ferramentas com perfis e consolidacao de eventos.
Uso:
  python security_tools/launcher.py --profile laboratorio
  python security_tools/launcher.py --profile producao --notify-critical
  python security_tools/launcher.py --profile forense
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from event_store import append_event


TOOLS = {
    "host_hardening": ["python", "security_tools/host_hardening_audit.py"],
    "log_compliance": ["python", "security_tools/log_compliance_audit.py"],
    "patch_cve": ["python", "security_tools/patch_cve_checker.py", "--requirements", "requirements.txt"],
    "port_scan_local": ["python", "security_tools/port_service_scanner.py", "--host", "127.0.0.1", "--ports", "1-1024"],
    "port_monitor": ["python", "security_tools/advanced_port_monitor.py", "--interval", "5"],
    "sniffer": ["python", "security_tools/network_sniffer.py", "--count", "200"],
    "host_discovery": ["python", "security_tools/host_discovery_scanner.py", "--targets", "127.0.0.1", "--ports", "22,80,443"],
    "ip_intel": ["python", "security_tools/ip_intel_analyzer.py", "8.8.8.8", "1.1.1.1"],
    "permissions": ["python", "security_tools/permissions_audit.py"],
    "fim_verify": ["python", "security_tools/fim_monitor.py", "verify", "--paths", "backend", "frontend", "--baseline", "fim_baseline.json"],
    "forensic": ["python", "security_tools/forensic_collector.py", "--output", "forensic_snapshot.json"],
}

PROFILES = {
    "laboratorio": ["host_hardening", "port_scan_local", "log_compliance"],
    "producao": ["host_hardening", "log_compliance", "patch_cve", "permissions", "fim_verify"],
    "forense": ["forensic", "host_hardening", "permissions", "log_compliance"],
    "rede": ["port_monitor", "sniffer", "host_discovery", "ip_intel"],
}


def event_type_from_line(line: str) -> str:
    low = line.lower()
    if "[alert]" in low:
        if "dns" in low:
            return "dns_tunnel"
        if "arp" in low:
            return "arp_spoof"
        if "fim" in low or "alter" in low:
            return "fim_changed"
        if "vulnerab" in low or "cve" in low:
            return "vuln_found"
        return "ids_alert"
    if "[err]" in low:
        return "edr_alert"
    return "info"


def run_tool(name: str, cmd: list[str], timeout: int, notify_critical: bool) -> int:
    print(f"[RUN] {name}: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    for line in output.splitlines():
        if not line.strip():
            continue
        etype = event_type_from_line(line)
        ev = append_event({
            "type": etype,
            "source": name,
            "details": line[:500],
        })
        if notify_critical and ev.get("severity") == "critical":
            print(f"[CRITICAL] {ev['type']} score={ev['risk_score']} source={name}")

    if proc.returncode == 0:
        append_event({
            "type": "info",
            "source": name,
            "details": "execucao concluida com sucesso",
        })
    else:
        append_event({
            "type": "edr_alert",
            "source": name,
            "details": f"execucao retornou codigo {proc.returncode}",
        })

    print(output.strip()[:4000])
    return proc.returncode


def main() -> None:
    ap = argparse.ArgumentParser(description="TrackLab Security Tools Launcher")
    ap.add_argument("--profile", choices=sorted(PROFILES.keys()), default="laboratorio")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--notify-critical", action="store_true")
    args = ap.parse_args()

    selected = PROFILES[args.profile]
    append_event({
        "type": "info",
        "source": "launcher",
        "details": f"inicio perfil={args.profile}"
    })

    failed = 0
    for key in selected:
        rc = run_tool(key, TOOLS[key], args.timeout, args.notify_critical)
        if rc != 0:
            failed += 1

    append_event({
        "type": "info",
        "source": "launcher",
        "details": f"fim perfil={args.profile} falhas={failed}",
    })
    print(f"[DONE] Perfil {args.profile} finalizado. falhas={failed}")


if __name__ == "__main__":
    main()
