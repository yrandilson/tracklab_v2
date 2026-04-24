#!/usr/bin/env python3
"""Sniffer multi-camada para rede com resumo de protocolos e conversas.
Uso:
  python security_tools/network_sniffer.py --iface eth0 --count 200
"""

from __future__ import annotations

import argparse
import json
import socket
from collections import Counter, defaultdict
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, Ether, IP, TCP, UDP, Raw, sniff


def safe_decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return value.decode(errors="ignore")


class Collector:
    def __init__(self, log_file: Path | None):
        self.proto_counter = Counter()
        self.talkers = Counter()
        self.flows = defaultdict(int)
        self.log_file = log_file

    def emit(self, payload: dict) -> None:
        if not self.log_file:
            return
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        with self.log_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=True) + "\n")

    def handle(self, pkt) -> None:
        if Ether in pkt:
            self.proto_counter["eth"] += 1
        if ARP in pkt:
            self.proto_counter["arp"] += 1
            src = getattr(pkt[ARP], "psrc", "")
            dst = getattr(pkt[ARP], "pdst", "")
            self.talkers[src] += 1
            self.talkers[dst] += 1
            self.emit({"type": "arp_seen", "source": "network_sniffer", "protocol": "arp", "ip": src, "peer_ip": dst, "details": f"{src} -> {dst}"})
            return

        if IP not in pkt:
            return

        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        self.talkers[src] += 1
        self.talkers[dst] += 1

        proto = "ip"
        extra = {}
        if TCP in pkt:
            proto = "tcp"
            extra["sport"] = int(pkt[TCP].sport)
            extra["dport"] = int(pkt[TCP].dport)
            flags = str(pkt[TCP].flags)
            extra["flags"] = flags
            if Raw in pkt and extra.get("dport") in {80, 8080, 8000}:
                raw = safe_decode(bytes(pkt[Raw].load))
                if raw.startswith(("GET ", "POST ", "HEAD ", "PUT ")):
                    first = raw.splitlines()[0][:120]
                    extra["http_request"] = first
                    self.emit({"type": "http_seen", "source": "network_sniffer", "protocol": "http", "details": first, "ip": src, "port": extra.get("dport"), "peer_ip": dst})
        elif UDP in pkt:
            proto = "udp"
            extra["sport"] = int(pkt[UDP].sport)
            extra["dport"] = int(pkt[UDP].dport)
            if DNS in pkt and DNSQR in pkt:
                qname = safe_decode(pkt[DNSQR].qname).rstrip('.')
                extra["dns_qname"] = qname
                self.emit({"type": "dns_seen", "source": "network_sniffer", "protocol": "dns", "details": qname, "ip": src, "port": extra.get("dport"), "peer_ip": dst})

        flow_key = f"{src}:{extra.get('sport','?')}->{dst}:{extra.get('dport','?')}:{proto}"
        self.flows[flow_key] += 1
        self.proto_counter[proto] += 1

        print(f"{proto.upper():<4} {src:>15} -> {dst:<15} {extra}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Multi-layer network sniffer")
    ap.add_argument("--iface", default=None)
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--filter", default="ip or arp")
    ap.add_argument("--log-file", default="security_events.jsonl")
    args = ap.parse_args()

    collector = Collector(Path(args.log_file))
    print(f"[INFO] Capturando {args.count} pacotes filtro={args.filter} iface={args.iface}")
    sniff(filter=args.filter, iface=args.iface, prn=collector.handle, store=False, count=args.count)

    print("\n[RESUMO] Protocolos:")
    for proto, count in collector.proto_counter.most_common():
        print(f"- {proto}: {count}")

    print("\n[RESUMO] Top talkers:")
    for host, count in collector.talkers.most_common(10):
        print(f"- {host}: {count}")

    print("\n[RESUMO] Top flows:")
    for flow, count in sorted(collector.flows.items(), key=lambda x: x[1], reverse=True)[:15]:
        print(f"- {flow}: {count}")


if __name__ == "__main__":
    main()
