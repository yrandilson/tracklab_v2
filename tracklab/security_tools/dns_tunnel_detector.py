#!/usr/bin/env python3
"""Detector heuristico de possivel DNS tunneling.
Uso:
  python security_tools/dns_tunnel_detector.py --iface eth0
"""

from __future__ import annotations

import argparse
import math

from scapy.all import DNS, DNSQR, UDP, sniff


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {ch: s.count(ch) / len(s) for ch in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


def main() -> None:
    ap = argparse.ArgumentParser(description="DNS tunnel detector")
    ap.add_argument("--iface", default=None)
    ap.add_argument("--min-len", type=int, default=50)
    ap.add_argument("--min-entropy", type=float, default=3.6)
    args = ap.parse_args()

    def on_pkt(pkt):
        if UDP not in pkt or DNS not in pkt or DNSQR not in pkt:
            return
        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
        e = shannon_entropy(qname)
        if len(qname) >= args.min_len and e >= args.min_entropy:
            print(f"[ALERT] Possivel DNS tunneling qname={qname[:120]} len={len(qname)} entropy={e:.2f}")

    print(f"[INFO] Monitorando consultas DNS iface={args.iface}")
    sniff(filter="udp port 53", iface=args.iface, prn=on_pkt, store=False)


if __name__ == "__main__":
    main()
