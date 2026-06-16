#!/usr/bin/env python3
"""
attacker.py — produce REAL network anomalies that QF-IDS picks up
                in pcap mode.

Usage:
    python attacker.py mitm        # bursty mid-rate traffic (interposition)
    python attacker.py flood       # high-rate flood (signal injection)
    python attacker.py jitter      # randomly-spaced bursts (relay-like)

The script sends small UDP packets to a configurable target (default
127.0.0.1:9999). The QF-IDS backend's pcap source, if it has a BPF
filter that matches this traffic, will see the inter-arrival statistics
deform — and the IsolationForest will flag it.

This is real network traffic. The packets you send here are exactly
what will appear in Wireshark captures and what the backend's pcap
source observes. No simulation involved.
"""
from __future__ import annotations

import argparse
import random
import socket
import sys
import time


def send(sock, addr, payload=b"qfids-probe"):
    try:
        sock.sendto(payload, addr)
    except Exception:
        pass


def attack_mitm(sock, addr, duration):
    """
    Simulate a man-in-the-middle by interposing extra packets at a
    moderate, slightly-irregular rate. The IF detects the bias shift.
    """
    end = time.time() + duration
    while time.time() < end:
        send(sock, addr)
        # Slight jitter so it isn't perfectly periodic
        time.sleep(0.04 + random.uniform(-0.01, 0.02))


def attack_flood(sock, addr, duration):
    """
    High-rate flood — a signal-injection-style attack. Inter-arrival
    times collapse, variance shrinks, mean shifts hard.
    """
    end = time.time() + duration
    while time.time() < end:
        send(sock, addr)
        time.sleep(0.005)   # ~200 pps


def attack_jitter(sock, addr, duration):
    """
    Random burst pattern — relay-like, with heavy-tailed gaps.
    Kurtosis of inter-arrival times spikes.
    """
    end = time.time() + duration
    while time.time() < end:
        # Burst of 3-15 packets back to back, then a long pause
        for _ in range(random.randint(3, 15)):
            send(sock, addr)
            time.sleep(0.002)
        time.sleep(random.uniform(0.2, 1.5))


ATTACKS = {
    "mitm":   attack_mitm,
    "flood":  attack_flood,
    "jitter": attack_jitter,
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("mode", choices=ATTACKS.keys(),
                    help="attack pattern to generate")
    ap.add_argument("--host", default="127.0.0.1",
                    help="target host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=9999,
                    help="target UDP port (default: 9999)")
    ap.add_argument("--duration", type=float, default=20.0,
                    help="how long to attack, in seconds (default: 20)")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (args.host, args.port)

    print(f"[attacker] mode={args.mode} target={args.host}:{args.port} "
          f"duration={args.duration}s")
    print(f"[attacker] sending real UDP packets — packet capture on the "
          f"backend will see these")

    try:
        ATTACKS[args.mode](sock, addr, args.duration)
    except KeyboardInterrupt:
        print("\n[attacker] interrupted")
    finally:
        sock.close()
    print("[attacker] done")


if __name__ == "__main__":
    sys.exit(main())
