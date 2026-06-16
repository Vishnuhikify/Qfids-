"""
Real packet-capture noise source.

Each channel is bound to a Berkeley Packet Filter (BPF) expression
that selects which packets count as "this channel's traffic". For
example, ch-b filters on `udp port 53` (DNS), so its noise stream
is the inter-arrival jitter of DNS packets seen on the wire.

We record:
  - inter-arrival times (the float stream the detector consumes)
  - the source IP and port of the most recent packets — so when an
    attack is detected we can extract the *real* attacker network
    metadata, not synthesise it.

Privileges: raw packet capture requires root on macOS and Linux. The
caller is expected to start the backend with sudo. If scapy can't
attach to the interface, we raise a clear error.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional, Callable

try:
    from scapy.all import sniff, IP, TCP, UDP, Ether, conf  # type: ignore
    _scapy_available = True
except Exception:  # pragma: no cover
    _scapy_available = False
    sniff = IP = TCP = UDP = Ether = conf = None  # type: ignore


def default_interface() -> Optional[str]:
    """
    Best-effort guess at the interface to sniff. On macOS this is usually
    'en0' (wifi) or the loopback 'lo0' as a privilege-free fallback.
    Returns None if scapy isn't available.
    """
    if not _scapy_available:
        return None
    try:
        # scapy's conf.iface is set at import time on most systems
        iface = str(conf.iface) if conf is not None else None
        return iface
    except Exception:
        return None


@dataclass
class PacketRecord:
    """Per-packet snapshot: timestamp, source identity, size."""
    ts: float
    src_ip: str
    src_port: int
    size: int


class PcapNoiseSource:
    """
    Live pcap source for a single channel.

    Filters packets via BPF and exposes:
      - sample(attack_type, intensity): one float per "tick" representing
        the channel's current jitter / activity statistic. The signature
        mirrors NoiseGenerator so the manager can swap sources transparently.
      - recent_attacker(): the (ip, port) of the most prolific source
        in the last few seconds — used when a detector flags an
        anomaly to identify who to block.
    """

    JITTER_WINDOW = 32         # number of inter-arrival times to keep
    ATTACKER_WINDOW = 4.0      # seconds of recent packets to scan
    PACKETS_KEEP = 256         # rolling buffer of recent packets

    def __init__(
        self,
        channel_id: str,
        interface: Optional[str] = None,
        bpf_filter: str = "",
        on_error: Optional[Callable[[str], None]] = None,
    ):
        self.channel_id = channel_id
        self.bpf_filter = bpf_filter
        self.interface = interface
        self._on_error = on_error or (lambda msg: None)

        self._lock = threading.Lock()
        self._last_ts: Optional[float] = None
        self._iats: deque[float] = deque(maxlen=self.JITTER_WINDOW)
        self._packets: deque[PacketRecord] = deque(maxlen=self.PACKETS_KEEP)
        self._packet_count = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._error: Optional[str] = None

        # Baseline statistics for normalisation. Once we've seen enough
        # packets, we lock in a "typical" mean inter-arrival to compute
        # jitter relative to. Until then sample() returns 0.
        self._baseline_iat: Optional[float] = None
        self._baseline_seen: int = 0

        # Auto-start so the source is ready when first sampled
        if _scapy_available:
            self.start()
        else:
            self._error = "scapy not installed"

    # ── Lifecycle ─────────────────────────────────────────────────────────
    def start(self):
        if self._thread is not None:
            return
        if not _scapy_available:
            self._error = "scapy not installed"
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name=f"pcap-{self.channel_id}", daemon=True
        )
        self._thread.start()

    def stop(self):
        self._stop.set()
        # Don't join — sniff blocks; the thread is daemon, exits with process

    @property
    def available(self) -> bool:
        """True if scapy loaded and no fatal error has occurred."""
        return _scapy_available and self._error is None

    @property
    def last_error(self) -> Optional[str]:
        return self._error

    # ── Capture loop ──────────────────────────────────────────────────────
    def _run(self):
        try:
            sniff(
                filter=self.bpf_filter or None,
                iface=self.interface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except PermissionError:
            self._error = (
                "permission denied — packet capture needs root "
                "(run the backend with sudo)"
            )
            self._on_error(self._error)
        except OSError as e:
            self._error = (
                f"capture failed: {e}. "
                f"interface={self.interface or 'default'} "
                f"filter={self.bpf_filter!r}"
            )
            self._on_error(self._error)
        except Exception as e:  # pragma: no cover
            self._error = f"unexpected capture error: {e}"
            self._on_error(self._error)

    def _on_packet(self, pkt):
        now = time.time()
        try:
            ip = pkt[IP] if IP in pkt else None
            if ip is None:
                return
            sport = 0
            if TCP in pkt:
                sport = int(pkt[TCP].sport)
            elif UDP in pkt:
                sport = int(pkt[UDP].sport)
            size = len(pkt)
            rec = PacketRecord(
                ts=now, src_ip=ip.src, src_port=sport, size=size,
            )
        except Exception:
            return

        with self._lock:
            self._packets.append(rec)
            self._packet_count += 1
            if self._last_ts is not None:
                iat = now - self._last_ts
                # Cap pathological values (idle channels can have huge gaps)
                iat = min(iat, 5.0)
                self._iats.append(iat)
                # Build baseline from first few hundred IATs
                if self._baseline_iat is None and len(self._iats) >= 16:
                    self._baseline_seen = len(self._iats)
                    if self._baseline_seen >= self.JITTER_WINDOW:
                        # Lock baseline as median of accumulated IATs
                        vals = sorted(self._iats)
                        self._baseline_iat = vals[len(vals) // 2]
            self._last_ts = now

    # ── Sampling interface (matches NoiseGenerator) ───────────────────────
    def sample(
        self,
        attack_type: Optional[str] = None,
        intensity: float = 0.0,
    ) -> float:
        """
        Return one synthetic "channel sample" representing current jitter.

        Strategy: take the mean inter-arrival time over the last window,
        subtract the baseline, and scale. Result is roughly zero-mean
        when traffic is steady, positive when traffic is sparser than
        baseline, negative when traffic is denser. Magnitude grows when
        jitter is high.

        attack_type / intensity are accepted for API compatibility with
        NoiseGenerator but ignored — real packet timing already reflects
        whatever is actually happening on the wire.
        """
        with self._lock:
            n = len(self._iats)
            iats = list(self._iats)

        if n < 4:
            # Cold start — return tiny noise so detector can warm up
            return 0.0

        mean_iat = sum(iats) / n
        # Variance — captures jitter
        var = sum((x - mean_iat) ** 2 for x in iats) / n

        if self._baseline_iat is None or self._baseline_iat <= 0:
            # No baseline yet — emit small jitter signal
            return float((var ** 0.5) * 10.0 - mean_iat)

        # Normalised jitter: deviation from baseline IAT, expressed in
        # "baseline units" so different channels (different baseline
        # rates) produce comparable score magnitudes.
        rel = (mean_iat - self._baseline_iat) / self._baseline_iat
        # Add a jitter-magnitude term
        jitter_mag = (var ** 0.5) / max(self._baseline_iat, 1e-6)
        # Scale so values typically sit in roughly [-2, 2]
        return float(rel + 0.5 * jitter_mag)

    def recent_attacker(self) -> Optional[tuple[str, int]]:
        """
        Identify the most likely attacker source in the recent window.

        Returns the (ip, port) tuple that contributed the highest
        packet count in the last ATTACKER_WINDOW seconds, or None if
        no traffic.
        """
        cutoff = time.time() - self.ATTACKER_WINDOW
        counts: dict[tuple[str, int], int] = {}
        with self._lock:
            for rec in self._packets:
                if rec.ts < cutoff:
                    continue
                k = (rec.src_ip, rec.src_port)
                counts[k] = counts.get(k, 0) + 1
        if not counts:
            return None
        return max(counts.items(), key=lambda kv: kv[1])[0]

    @property
    def packet_count(self) -> int:
        with self._lock:
            return self._packet_count

    @property
    def baseline_iat(self) -> Optional[float]:
        with self._lock:
            return self._baseline_iat

    def health(self) -> dict:
        with self._lock:
            return {
                "kind": "pcap",
                "interface": self.interface,
                "filter": self.bpf_filter,
                "packets_seen": self._packet_count,
                "buffer_size": len(self._iats),
                "baseline_iat": self._baseline_iat,
                "error": self._error,
                "scapy_available": _scapy_available,
            }


# Backwards-compatibility alias for the older name used in early drafts.
PcapChannelSource = PcapNoiseSource


# ── Channel-to-filter mapping ─────────────────────────────────────────────
# These define which traffic each channel monitors. Designed to work
# on any machine that has *some* network activity.
DEFAULT_FILTERS = {
    "ch-a": "ip",                          # any IP traffic (catch-all)
    "ch-b":  "udp port 53 or tcp port 53",  # DNS
    "ch-c": "tcp port 443",                # HTTPS
    "ch-d": "icmp or arp or tcp port 80",  # ICMP / ARP / HTTP
}
