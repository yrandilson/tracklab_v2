#!/usr/bin/env python3
"""Sniffer defensivo de pacotes para analise de protocolos.
Uso:
  python security_tools/packet_sniffer.py --iface eth0 --count 50
"""

from __future__ import annotations

import argparse
from collections import Counter

from scapy.all import IP, TCP, UDP, sniff


def main() -> None:
    ap = argparse.ArgumentParser(description="Packet sniffer defensivo")
    ap.add_argument("--iface", default=None)
    ap.add_argument("--count", type=int, default=50)
    ap.add_argument("--filter", default="ip")
    args = ap.parse_args()

    proto_counter: Counter[str] = Counter()

    def on_pkt(pkt):
        if IP not in pkt:
            return
        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt:
            proto = "TCP"
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            dport = pkt[UDP].dport
        else:
            proto = "IP"
            dport = "-"
        proto_counter[proto] += 1
        print(f"{proto:<4} {src:>15} -> {dst:<15} dport={dport}")

    print(f"[INFO] Capturando {args.count} pacotes filtro={args.filter} iface={args.iface}")
    sniff(filter=args.filter, iface=args.iface, prn=on_pkt, store=False, count=args.count)

    print("\n[RESUMO]")
    for proto, count in proto_counter.items():
        print(f"- {proto}: {count}")


if __name__ == "__main__":
    main()
