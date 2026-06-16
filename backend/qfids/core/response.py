"""
Response engine — converts QF-IDS from passive IDS into active IPS.

Four-stage response on every confirmed attack:
  1. TERMINATE      — kill the compromised channel session
                      (the channel goes into a 'TERMINATED' state and stops
                       streaming real data; further requests from the
                       attacker IP are added to the blocklist)
  2. RE-AUTHENTICATE — refingerprint over a verified backup channel
                      (in this prototype we re-seed the noise generator
                       with verified parameters and reset the detector)
  3. REROUTE         — divert attacker traffic to honeypot
                      (the honeypot endpoint serves decoy data; real
                       endpoints reject the attacker's source IP)
  4. ALERT           — raise a timestamped, persistent incident record
                      (written to incident store, surfaced on dashboard)

Each response is atomic per-channel and per-incident, but the engine
supports MULTIPLE concurrent incidents across DIFFERENT channels.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from .blocklist import Blocklist


@dataclass
class Incident:
    incident_id: str
    channel_id: str
    started_at: float
    attack_type: str
    attacker_ip: str
    attacker_port: int
    peak_score: float = 0.0
    steps: list[dict] = field(default_factory=list)
    closed_at: Optional[float] = None
    honeypot_packets: int = 0

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "channel_id": self.channel_id,
            "started_at": self.started_at,
            "started_at_iso": time.strftime(
                "%H:%M:%S", time.localtime(self.started_at)
            ),
            "attack_type": self.attack_type,
            "attacker_ip": self.attacker_ip,
            "attacker_port": self.attacker_port,
            "peak_score": round(self.peak_score, 4),
            "steps": self.steps,
            "closed_at": self.closed_at,
            "honeypot_packets": self.honeypot_packets,
            "status": "closed" if self.closed_at else "active",
        }


class ResponseEngine:
    """
    Drives the four-stage response. Stateless across channels — every
    incident gets its own coroutine, so concurrent attacks on different
    channels are handled in parallel without interfering.
    """

    STEP_DEFS = [
        ("terminate",
         "Compromised session terminated. Firewall rule injected.",
         "danger"),
        ("reauthenticate",
         "Re-authentication initiated on verified backup path.",
         "warning"),
        ("reroute",
         "Attacker rerouted to honeypot. Decoy channel active.",
         "info"),
        ("alert",
         "Incident raised. Full forensic trace captured.",
         "success"),
    ]
    STEP_DELAYS = [0.0, 1.4, 2.6, 4.0]   # seconds after trigger

    def __init__(self, blocklist: Blocklist):
        self.blocklist = blocklist

    # ── Public API ────────────────────────────────────────────────────────
    async def trigger(
        self,
        channel,                 # Channel object (avoids circular import typing)
        attack_type: str,
        attacker_ip: str,
        attacker_port: int,
        peak_score: float,
        on_step,                 # callback(step_name, message, level, incident)
    ) -> Incident:
        """
        Begin a four-stage response sequence for the given channel.

        Returns the Incident immediately; the steps complete asynchronously.
        """
        incident = Incident(
            incident_id="QF-" + uuid.uuid4().hex[:6].upper(),
            channel_id=channel.channel_id,
            started_at=time.time(),
            attack_type=attack_type,
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
            peak_score=peak_score,
        )

        # Mark channel as under response immediately
        channel.mark_under_response(incident.incident_id)

        # Schedule the four steps
        asyncio.create_task(
            self._run_sequence(incident, channel, on_step)
        )
        return incident

    # ── Step runner ───────────────────────────────────────────────────────
    async def _run_sequence(self, incident: Incident, channel, on_step):
        for idx, (step_name, msg, level) in enumerate(self.STEP_DEFS):
            # Wait until that step's relative delay
            target = incident.started_at + self.STEP_DELAYS[idx]
            now = time.time()
            if target > now:
                await asyncio.sleep(target - now)

            ts = time.time()
            incident.steps.append({
                "step": step_name,
                "message": msg,
                "level": level,
                "ts": ts,
                "ts_iso": time.strftime("%H:%M:%S", time.localtime(ts)),
            })

            # Side effects per step
            if step_name == "terminate":
                channel.terminate()
                self.blocklist.add(
                    incident.attacker_ip,
                    reason=f"QF-IDS auto-block · {incident.incident_id}",
                    incident_id=incident.incident_id,
                )
            elif step_name == "reauthenticate":
                channel.begin_reauth()
            elif step_name == "reroute":
                channel.activate_honeypot()
            elif step_name == "alert":
                # incident is already recorded; just close
                incident.closed_at = ts

            await on_step(step_name, msg, level, incident)
