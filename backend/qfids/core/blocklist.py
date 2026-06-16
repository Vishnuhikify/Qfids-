"""
Blocklist — in-process IP blocklist that is actually enforced.

This is wired as a FastAPI middleware so that any subsequent request
from a blocked IP gets a 403, exactly as a real iptables rule would
do at the OS level. In a production deployment the same `add()` /
`remove()` methods would shell out to `iptables -A INPUT -s ... -j DROP`
or call a cloud-firewall API; the prototype keeps this in-process so
it runs without root privileges.
"""
from __future__ import annotations

import time
import threading
from dataclasses import dataclass


@dataclass
class BlockEntry:
    ip: str
    reason: str
    added_at: float
    incident_id: str | None = None

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "reason": self.reason,
            "added_at": self.added_at,
            "added_at_iso": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(self.added_at)
            ),
            "incident_id": self.incident_id,
        }


class Blocklist:
    def __init__(self):
        self._entries: dict[str, BlockEntry] = {}
        self._lock = threading.Lock()
        # IPs we never block, even on attack (loopback, the dashboard itself)
        self._allowlist = {"127.0.0.1", "::1", "localhost"}

    def is_blocked(self, ip: str) -> bool:
        if ip in self._allowlist:
            return False
        with self._lock:
            return ip in self._entries

    def add(self, ip: str, reason: str, incident_id: str | None = None):
        if ip in self._allowlist:
            return
        with self._lock:
            self._entries[ip] = BlockEntry(
                ip=ip,
                reason=reason,
                added_at=time.time(),
                incident_id=incident_id,
            )

    def remove(self, ip: str) -> bool:
        with self._lock:
            return self._entries.pop(ip, None) is not None

    def all(self) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in self._entries.values()]

    def clear(self):
        with self._lock:
            self._entries.clear()
