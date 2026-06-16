"""
PcapFileSource — replays a Wireshark .pcap / .pcapng file.

The user uploads a real Wireshark capture. This source reads it via
scapy.utils.rdpcap, computes inter-arrival times between consecutive
packets, normalises them the same way live PCAP mode does, and feeds
them into the channel.

This is the most direct Wireshark integration possible: take any pcap
the user has captured (in Wireshark, tcpdump, tshark, anywhere), and
replay it through the IDS. Real packet data, real source IPs, real
attacks if the capture contains them.

Note: scapy is required (same as live pcap mode).
"""
from __future__ import annotations

import os
import threading
import time
from typing import Optional

try:
    from scapy.all import rdpcap, IP, TCP, UDP, IPv6  # type: ignore
    _scapy_available = True
except Exception:
    _scapy_available = False
    rdpcap = IP = TCP = UDP = IPv6 = None  # type: ignore


class PcapFileSource:
    """
    Replays a captured pcap file as a sample stream.

    Each tick advances by `samples_per_tick` packets and emits one
    summary value (mean inter-arrival of those packets, normalised).
    The most recent source IP is exposed via recent_attacker() so the
    response engine can block real IPs from the capture.
    """

    def __init__(
        self,
        channel_id: str,
        path: str,
        loop: bool = True,
    ):
        self.channel_id = channel_id
        self.path = path
        self.loop = loop

        self._lock = threading.Lock()
        self._packets: list = []                  # list of (ts, src_ip, src_port)
        self._idx = 0
        self._consumed = 0
        self._loaded = False
        self._error: Optional[str] = None
        self._baseline_iat: Optional[float] = None
        self._iat_window: list[float] = []

        if not _scapy_available:
            self._error = "scapy not installed"
            return

        if not os.path.exists(path):
            self._error = f"file not found: {path}"
            return

        self._load()

    def _load(self):
        try:
            pkts = rdpcap(self.path)
        except Exception as e:
            self._error = f"rdpcap failed: {e}"
            return

        if not pkts:
            self._error = "pcap is empty"
            return

        recs = []
        for p in pkts:
            ts = float(p.time)
            ip, sp = "?", 0
            try:
                if IP in p:
                    ip = p[IP].src
                elif IPv6 in p:
                    ip = p[IPv6].src
                if TCP in p:
                    sp = int(p[TCP].sport)
                elif UDP in p:
                    sp = int(p[UDP].sport)
            except Exception:
                pass
            recs.append((ts, ip, sp))
        self._packets = recs

        # Compute baseline IAT from the early portion of the capture
        if len(recs) > 16:
            iats = [recs[i][0] - recs[i-1][0] for i in range(1, min(len(recs), 50))]
            iats = [x for x in iats if x > 0]
            if iats:
                iats.sort()
                self._baseline_iat = iats[len(iats) // 2]

        self._loaded = True

    def stop(self):
        pass

    @property
    def available(self) -> bool:
        return self._loaded and self._error is None

    @property
    def last_error(self) -> Optional[str]:
        return self._error

    @property
    def packet_count(self) -> int:
        return self._consumed

    @property
    def total_packets(self) -> int:
        return len(self._packets)

    # ── sampling ─────────────────────────────────────────────────────
    def sample(
        self,
        attack_type: Optional[str] = None,
        intensity: float = 0.0,
    ) -> float:
        """One IAT-normalised sample per tick."""
        with self._lock:
            if not self._loaded or not self._packets:
                return 0.0
            if self._idx == 0:
                self._idx = 1
            i = self._idx
            if i >= len(self._packets):
                if self.loop:
                    i = 1
                    self._idx = 1
                else:
                    return 0.0
            iat = self._packets[i][0] - self._packets[i-1][0]
            iat = max(0.0, min(iat, 5.0))
            self._idx += 1
            self._consumed += 1

            # Track for jitter window
            self._iat_window.append(iat)
            if len(self._iat_window) > 30:
                self._iat_window.pop(0)

            if self._baseline_iat is None or self._baseline_iat <= 0:
                return float(iat * 10)

            mean_iat = sum(self._iat_window) / len(self._iat_window)
            rel = (mean_iat - self._baseline_iat) / self._baseline_iat
            n = len(self._iat_window)
            var = sum((x - mean_iat) ** 2 for x in self._iat_window) / n if n > 0 else 0
            jitter_mag = (var ** 0.5) / max(self._baseline_iat, 1e-6)
            return float(rel + 0.5 * jitter_mag)

    def recent_attacker(self) -> Optional[tuple[str, int]]:
        """Most recent source IP/port from the capture."""
        with self._lock:
            if self._idx > 0 and self._idx <= len(self._packets):
                _, ip, port = self._packets[self._idx - 1]
                return (ip, port)
            return None

    def current_segment(self) -> dict:
        with self._lock:
            return {
                "label": os.path.basename(self.path),
                "is_attack": False,    # unknown — caller decides
                "seg_idx": self._idx,
                "n_segs": len(self._packets),
                "pos": self._idx,
                "n_samples": len(self._packets),
            }

    def health(self) -> dict:
        return {
            "kind":           "pcap_file",
            "path":           self.path,
            "loaded":         self._loaded,
            "error":          self._error,
            "total_packets":  len(self._packets),
            "consumed":       self._consumed,
            "baseline_iat":   self._baseline_iat,
        }
