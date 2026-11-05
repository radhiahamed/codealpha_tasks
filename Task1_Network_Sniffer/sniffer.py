#!/usr/bin/env python3
"""
CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer
Captures network packets and displays source/destination IPs,
protocol, ports and a preview of the payload.

Educational use only: run it on your own network.
"""
import argparse
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, Raw

captured = []


def payload_preview(packet, limit=60):
    """Return a printable preview of the packet payload."""
    if Raw in packet:
        data = bytes(packet[Raw].load)[:limit]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return text
    return "(no payload)"


def process_packet(packet):
    captured.append(packet)
    time = datetime.now().strftime("%H:%M:%S")

    if ARP in packet:
        print(f"[{time}] ARP  {packet[ARP].psrc} -> {packet[ARP].pdst}")
        return

    if IP in packet:
        src, dst = packet[IP].src, packet[IP].dst
    elif IPv6 in packet:
        src, dst = packet[IPv6].src, packet[IPv6].dst
    else:
        return

    proto, ports = "OTHER", ""
    if TCP in packet:
        proto = "TCP"
        ports = f"{packet[TCP].sport} -> {packet[TCP].dport}"
    elif UDP in packet:
        proto = "UDP"
        ports = f"{packet[UDP].sport} -> {packet[UDP].dport}"
    elif ICMP in packet:
        proto = "ICMP"

    print(f"[{time}] {proto:<5} {src} -> {dst}  ports: {ports or '-'}  "
          f"len: {len(packet)}")
    print(f"          payload: {payload_preview(packet)}")


def main():
    parser = argparse.ArgumentParser(description="Basic network sniffer")
    parser.add_argument("-i", "--interface", help="network interface")
    parser.add_argument("-c", "--count", type=int, default=20,
                        help="number of packets to capture (default 20)")
    parser.add_argument("-f", "--filter", default="",
                        help="BPF filter, e.g. 'tcp', 'udp', 'port 80'")
    parser.add_argument("-o", "--output", help="save packets to a .pcap file")
    args = parser.parse_args()

    print(f"Capturing {args.count} packets... (Ctrl+C to stop)\n")
    try:
        sniff(iface=args.interface, filter=args.filter or None,
              prn=process_packet, count=args.count, store=False)
    except KeyboardInterrupt:
        print("\nStopped by user.")

    print(f"\nTotal captured: {len(captured)} packets")
    if args.output and captured:
        wrpcap(args.output, captured)
        print(f"Saved to {args.output}")


if __name__ == "__main__":
    main()
