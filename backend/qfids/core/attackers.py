"""
attackers.py — Tracks the systems that launch attacks against QF-IDS.

In the split-dashboard design, attacks come from a *separate* attacker console
running on another machine. This module records each attacking system's identity
(IP, user-agent, platform, a stable fingerprint) and the history of its attempts,
so the defender dashboard can show "who attacked us" and so the system can BLOCK
a returning attacker on their next attempt.

Key behaviours:
  - register_attempt(): called on every attack launch. Records the attacker's
    system details and returns whether they are currently blocked.
  - An attacker who has been blocked (their IP is on the blocklist) is rejected
    BEFORE the attack reaches a channel — this is the "blocked next time" rule.
  - profile(): returns the attacking system's details for display on the
    attacker console ("the system you are attacking from").
"""
from __future__ import annotations

import hashlib
import time
import threading
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AttackAttempt:
    ts: float
    channel_id: str
    attack_type: str
    blocked: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "ts_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.ts)),
            "channel_id": self.channel_id,
            "attack_type": self.attack_type,
            "blocked": self.blocked,
            "reason": self.reason,
        }


@dataclass
class AttackerSystem:
    """One attacking machine, identified by IP."""
    ip: str
    fingerprint: str                       # stable hash of ip+ua+platform
    user_agent: str = ""
    platform: str = ""
    hostname: str = ""
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    attempts: list = field(default_factory=list)
    successful: int = 0
    blocked_count: int = 0
    # ── Real-world attacker lifecycle ──
    #   CLEAR    → can attack normally
    #   DIVERTED → detected; attacks now silently redirected into the honeypot
    #   BLOCKED  → fully profiled in the honeypot; hard-blocked, cannot attack
    status: str = "CLEAR"
    diverted_count: int = 0
    honeypot_session: str = ""             # session id inside the deception engine

    def to_dict(self, include_attempts: bool = True) -> dict:
        d = {
            "ip": self.ip,
            "fingerprint": self.fingerprint,
            "user_agent": self.user_agent,
            "platform": self.platform,
            "hostname": self.hostname,
            "status": self.status,
            "first_seen": self.first_seen,
            "first_seen_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.first_seen)),
            "last_seen": self.last_seen,
            "last_seen_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last_seen)),
            "total_attempts": len(self.attempts),
            "successful": self.successful,
            "diverted_count": self.diverted_count,
            "blocked_count": self.blocked_count,
        }
        if include_attempts:
            d["attempts"] = [a.to_dict() for a in self.attempts[-20:]]
        return d


class AttackerRegistry:
    """Tracks all attacking systems and their attempt history."""

    def __init__(self):
        self._by_ip: dict[str, AttackerSystem] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _fingerprint(ip: str, ua: str, platform: str) -> str:
        raw = f"{ip}|{ua}|{platform}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]

    def identify(self, ip: str, user_agent: str = "", platform: str = "",
                 hostname: str = "") -> AttackerSystem:
        """Register or update an attacking system; returns the record."""
        with self._lock:
            sys = self._by_ip.get(ip)
            if sys is None:
                sys = AttackerSystem(
                    ip=ip,
                    fingerprint=self._fingerprint(ip, user_agent, platform),
                    user_agent=user_agent,
                    platform=platform,
                    hostname=hostname,
                )
                self._by_ip[ip] = sys
            else:
                # refresh details
                sys.last_seen = time.time()
                if user_agent:
                    sys.user_agent = user_agent
                if platform:
                    sys.platform = platform
                if hostname:
                    sys.hostname = hostname
            return sys

    def record_attempt(self, ip: str, channel_id: str, attack_type: str,
                       blocked: bool, reason: str, diverted: bool = False):
        with self._lock:
            sys = self._by_ip.get(ip)
            if sys is None:
                return
            sys.last_seen = time.time()
            sys.attempts.append(AttackAttempt(
                ts=time.time(), channel_id=channel_id,
                attack_type=attack_type, blocked=blocked, reason=reason,
            ))
            if diverted:
                sys.diverted_count += 1
            elif blocked:
                sys.blocked_count += 1
            else:
                sys.successful += 1

    def set_status(self, ip: str, status: str):
        """Advance an attacker's lifecycle: CLEAR → DIVERTED → BLOCKED."""
        with self._lock:
            sys = self._by_ip.get(ip)
            if sys is not None:
                sys.status = status

    def set_honeypot_session(self, ip: str, session_id: str):
        with self._lock:
            sys = self._by_ip.get(ip)
            if sys is not None:
                sys.honeypot_session = session_id

    def get(self, ip: str) -> Optional[AttackerSystem]:
        with self._lock:
            return self._by_ip.get(ip)

    def all(self) -> list[dict]:
        with self._lock:
            return [s.to_dict(include_attempts=False) for s in
                    sorted(self._by_ip.values(), key=lambda x: x.last_seen, reverse=True)]

    def clear(self):
        with self._lock:
            self._by_ip.clear()


# Module singleton
_registry = AttackerRegistry()


def get_registry() -> AttackerRegistry:
    return _registry
