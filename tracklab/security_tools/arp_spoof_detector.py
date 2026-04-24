#!/usr/bin/env python3
"""Detector simples de ARP spoofing comparando MAC por IP ao longo do tempo.
Uso:
  python security_tools/arp_spoof_detector.py --iface eth0
"""

from __future__ import annotations

import argparse
from collections import defaultdict

from scapy.all import ARP, sniff


def main() -> None:
    ap = argparse.ArgumentParser(description="ARP spoof detector")
    ap.add_argument("--iface", default=None)
    args = ap.parse_args()

    ip_mac_history: dict[str, set[str]] = defaultdict(set)

    def on_pkt(pkt):
        if ARP not in pkt:
            return
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        if not ip or not mac:
            return

        seen = ip_mac_history[ip]
        if seen and mac not in seen:
            print(f"[ALERT] Possivel ARP spoofing: IP {ip} agora responde com MAC {mac}; historico={sorted(seen)}")
        seen.add(mac)

    print(f"[INFO] Monitorando ARP iface={args.iface}")
    sniff(filter="arp", prn=on_pkt, store=False, iface=args.iface)


if __name__ == "__main__":
    main()
