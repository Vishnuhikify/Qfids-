"""
Channel — one logical quantum channel under continuous monitoring.
ChannelManager — owns every channel, drives the tick loop, fans out
state updates to all connected websockets.

Each channel has its own:
  - physical fingerprint (baseline mean / std)
  - noise source (simulated OR real pcap-based)
  - IsolationForest detector
  - active attack state (type, intensity, attacker IP+port)
  - lifecycle state (LEARNING → ACTIVE → UNDER_ATTACK → TERMINATED → REAUTH)
"""
from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional, Union

from .noise import NoiseGenerator, ChannelFingerprint
from .detector import QFIDSDetector
from .response import ResponseEngine, Incident
from .blocklist import Blocklist
from .pcap_source import PcapNoiseSource, default_interface, _scapy_available
from .dataset_source import DatasetNoiseSource
from .cicids_source import CICIDSSource
from .pcap_file_source import PcapFileSource
from .anu_qrng_source import ANUQRNGSource
from .bb84_source import BB84QKDSource


CHANNEL_DEFS = [
    # id          label                       μ       σ      bpf_filter (for pcap mode)
    ("ch-a",     "Channel A",                 0.00,  0.30,   "tcp"),
    ("ch-b",     "Channel B",                -0.05,  0.28,   "udp"),
    ("ch-c",     "Channel C",                 0.08,  0.34,   "tcp port 443 or tcp port 80"),
    ("ch-d",     "Channel D",                -0.02,  0.31,   ""),  # all traffic
]


CHANNEL_STATES = {
    "LEARNING",       # building baseline
    "ACTIVE",         # monitoring, all clear
    "UNDER_ATTACK",   # detector flagged ATTACK
    "TERMINATED",     # response engine killed it
    "REAUTH",         # being re-authenticated on backup path
}


# Modes for the noise source
MODE_SIMULATED = "simulated"
MODE_PCAP      = "pcap"
MODE_DATASET   = "dataset"
MODE_CICIDS    = "cicids"
MODE_PCAP_FILE = "pcap_file"
MODE_ANU_QRNG  = "anu_qrng"
MODE_BB84      = "bb84"
MODES_ALL      = (MODE_SIMULATED, MODE_PCAP, MODE_DATASET,
                  MODE_CICIDS, MODE_PCAP_FILE, MODE_ANU_QRNG,
                  MODE_BB84)


@dataclass
class AttackState:
    attack_type: str
    intensity: float
    attacker_ip: str
    attacker_port: int
    started_at: float
    ramp_per_tick: float = 0.04


@dataclass
class ChannelTickPayload:
    """Snapshot of a channel after one tick — sent over websocket."""
    channel_id: str
    label: str
    state: str
    mode: str
    sample: float
    history: list[float]
    attack_history: list[bool]
    score: float
    status: str
    features: dict
    baseline_mean: float
    baseline_std: float
    learning_progress: float
    honeypot_active: bool
    incident_id: Optional[str]
    attack: Optional[dict]      # primary (first) active attack info or None
    samples_seen: int
    incident_ids: list[str] = field(default_factory=list)
    attacks: list[dict] = field(default_factory=list)        # all active attacks
    dataset_segment: Optional[dict] = None
    cicids_segment: Optional[dict] = None
    pcap_packets: Optional[int] = None
    defense: Optional[dict] = None    # adaptive-threshold + baseline-guard status

    def to_dict(self) -> dict:
        return self.__dict__


class Channel:
    HISTORY = 120
    AUTOFIT_BASELINE = 100   # detector training feature-vectors (non-overlapping)
    LEARNING_TICKS = 15      # short visible "warming up" phase for UX

    def __init__(
        self,
        channel_id: str,
        label: str,
        baseline_mean: float,
        baseline_std: float,
        bpf_filter: str = "",
    ):
        self.channel_id = channel_id
        self.label = label
        self.bpf_filter = bpf_filter
        self.fingerprint = ChannelFingerprint(
            channel_id=channel_id,
            baseline_mean=baseline_mean,
            baseline_std=baseline_std,
            laser_linewidth_bias=random.random(),
        )

        # Noise sources — three flavours, all available; we switch at runtime.
        self.generator = NoiseGenerator(self.fingerprint)
        self.pcap_source: Optional[PcapNoiseSource] = None
        self.dataset_source: Optional[DatasetNoiseSource] = None
        self.mode: str = MODE_SIMULATED   # default: simulated for safety

        self.detector = QFIDSDetector(
            channel_id=channel_id,
            window_size=30,
            baseline_size=self.AUTOFIT_BASELINE,
        )
        # Bulk-train the detector at startup using a large clean sample.
        # This gives a properly-fit IsolationForest in milliseconds rather
        # than waiting hundreds of ticks. The channel still spends a few
        # seconds in LEARNING state for visual feedback.
        self._retrain_detector_bulk()

        self.state: str = "LEARNING"
        self.history: deque[float] = deque(maxlen=self.HISTORY)
        self.attack_history: deque[bool] = deque(maxlen=self.HISTORY)
        # Multi-attack: a channel can have several concurrent attacks from
        # different sources. Each gets its own independent incident.
        self.attacks: list[AttackState] = []
        # Per-channel CICIDS and pcap-file sources (lazy-init on switch)
        self.cicids_source: Optional[CICIDSSource] = None
        self.pcap_file_source = None     # PcapFileSource (defined below)
        self.anu_qrng_source: Optional[ANUQRNGSource] = None
        self.bb84_source: Optional[BB84QKDSource] = None
        self.last_classification = None
        self.honeypot_active = False
        self.incident_ids: list[str] = []   # multiple concurrent incidents
        self.samples_seen = 0
        self.peak_score = 0.0
        self._learning_ticks_left = self.LEARNING_TICKS

        # --- Hardening defences (loophole mitigations) ---
        # Adaptive threshold: defeats low-and-slow / evasion attacks.
        # Baseline integrity guard: defeats data-poisoning of the baseline.
        from .defenses import AdaptiveThreshold, BaselineIntegrityGuard
        self.adaptive_threshold = AdaptiveThreshold(hard_floor=0.65, watch_level=0.45)
        self.baseline_guard = BaselineIntegrityGuard(drift_tolerance=0.25)
        self._baseline_committed = False

        self._reauth_until: float = 0.0
        # Dataset-mode: track which attack segment we've already responded
        # to, so we don't re-fire on every tick within the same segment.
        self._last_dataset_attack_seg: Optional[tuple] = None

    # ── Backwards-compat single-attack accessor ───────────────────────────
    @property
    def attack(self) -> Optional[AttackState]:
        """Return the first active attack, or None. Kept for legacy code paths."""
        return self.attacks[0] if self.attacks else None

    @property
    def incident_id(self) -> Optional[str]:
        """First active incident; legacy code path. Use incident_ids for full list."""
        return self.incident_ids[0] if self.incident_ids else None

    # ── Mode switching ────────────────────────────────────────────────────
    def switch_mode(self, mode: str) -> tuple[bool, str]:
        """
        Switch between simulated, pcap, and dataset noise sources.

        Switching forces the channel back into LEARNING so the detector
        can re-fingerprint against the new source's characteristics.
        Returns (ok, message).
        """
        if mode == self.mode:
            return True, f"already in {mode} mode"
        if mode not in MODES_ALL:
            return False, f"unknown mode: {mode}"

        if mode == MODE_PCAP:
            if not _scapy_available:
                return False, (
                    "scapy not installed — run "
                    "`pip install scapy` to enable pcap mode"
                )
            # Lazily start the pcap source on first switch
            if self.pcap_source is None:
                self.pcap_source = PcapNoiseSource(
                    channel_id=self.channel_id,
                    interface=default_interface(),
                    bpf_filter=self.bpf_filter,
                )
            if not self.pcap_source.available:
                return False, (
                    f"pcap source unavailable: {self.pcap_source.last_error}"
                )

        elif mode == MODE_DATASET:
            if self.dataset_source is None:
                self.dataset_source = DatasetNoiseSource(
                    channel_id=self.channel_id,
                )
            if not self.dataset_source.available:
                return False, (
                    f"dataset source unavailable: "
                    f"{self.dataset_source.last_error}"
                )

        elif mode == MODE_CICIDS:
            if self.cicids_source is None:
                self.cicids_source = CICIDSSource(
                    channel_id=self.channel_id,
                )
            if not self.cicids_source.available:
                return False, (
                    f"CICIDS source unavailable: "
                    f"{self.cicids_source.last_error}"
                )

        elif mode == MODE_PCAP_FILE:
            if self.pcap_file_source is None or not self.pcap_file_source.available:
                return False, (
                    "no pcap file loaded — upload a .pcap via /api/pcap/upload first"
                )

        elif mode == MODE_ANU_QRNG:
            if self.anu_qrng_source is None:
                self.anu_qrng_source = ANUQRNGSource(
                    channel_id=self.channel_id,
                )

        elif mode == MODE_BB84:
            if self.bb84_source is None:
                self.bb84_source = BB84QKDSource(
                    channel_id=self.channel_id,
                    pulses_per_window=200,
                )

        self.mode = mode
        # Re-fingerprint detector against new source
        self._retrain_detector_bulk()
        # Reset live state but NOT incidents/blocklist
        self.history.clear()
        self.attack_history.clear()
        self.state = "LEARNING"
        self._learning_ticks_left = self.LEARNING_TICKS
        return True, f"switched to {mode}"

    def _retrain_detector_bulk(self):
        """Bulk-train the detector on whichever source is currently active."""
        import numpy as _np
        # Reset detector state
        self.detector = QFIDSDetector(
            channel_id=self.channel_id,
            window_size=30,
            baseline_size=self.AUTOFIT_BASELINE,
        )
        if self.mode == MODE_PCAP and self.pcap_source and self.pcap_source.available:
            # Use a smaller baseline corpus from real packets (simulated as
            # bootstrap until enough real packets accumulate). The detector
            # will continuously receive real samples after this.
            # We seed with a synthesized baseline + light real-data pad.
            samples = []
            for _ in range(self.AUTOFIT_BASELINE * 30 + 50):
                samples.append(self.generator.sample())  # synthetic seed
            clean = _np.array(samples)
        elif self.mode == MODE_DATASET and self.dataset_source and self.dataset_source.available:
            # Train against the labelled clean segment of the bundled dataset.
            # This is the validation pathway: detector trains on real-physics
            # quantum noise, then live attack segments deform that fingerprint.
            clean_samples = []
            for seg in self.dataset_source._segments:  # type: ignore
                if not seg.get("is_attack", False):
                    clean_samples.extend(seg.get("samples", []))
            if len(clean_samples) < self.AUTOFIT_BASELINE * 30:
                # Pad with synthetic if dataset clean segment is too short
                pad = self.AUTOFIT_BASELINE * 30 - len(clean_samples)
                clean_samples.extend(self.generator.sample() for _ in range(pad))
            clean = _np.array(clean_samples[: self.AUTOFIT_BASELINE * 30 + 50])
        elif self.mode == MODE_CICIDS and self.cicids_source and self.cicids_source.available:
            # Train from BENIGN flow intensities only
            from .cicids_source import _flow_to_intensity
            benign_samples = []
            for fl in self.cicids_source._flows:  # type: ignore
                if not fl.get("is_attack"):
                    benign_samples.append(_flow_to_intensity(fl, self.cicids_source._baseline))
            if len(benign_samples) < self.AUTOFIT_BASELINE * 30:
                pad = self.AUTOFIT_BASELINE * 30 - len(benign_samples)
                benign_samples.extend(self.generator.sample() for _ in range(pad))
            clean = _np.array(benign_samples[: self.AUTOFIT_BASELINE * 30 + 50])
        elif self.mode == MODE_BB84 and self.bb84_source and self.bb84_source.available:
            # Train detector on QBER measurements from a CLEAN BB84 channel
            # (no Eve). This is the textbook "registration phase" of BB84:
            # both parties agree on the natural error floor (dark counts +
            # basis misalignment) so any subsequent deviation flags Eve.
            saved_eve = self.bb84_source.eve_fraction
            self.bb84_source.set_eve_fraction(0.0)
            clean_qbers = [self.bb84_source.sample()
                           for _ in range(self.AUTOFIT_BASELINE * 30 + 50)]
            self.bb84_source.set_eve_fraction(saved_eve)
            clean = _np.array(clean_qbers)
        else:
            clean = _np.array([
                self.generator.sample()
                for _ in range(self.AUTOFIT_BASELINE * 30 + 50)
            ])
        self.detector.bulk_train(clean)

    def _next_sample(self, attack_type: Optional[str], intensity: float) -> float:
        """Pick the right source based on current mode."""
        if self.mode == MODE_PCAP and self.pcap_source and self.pcap_source.available:
            return self.pcap_source.sample(attack_type, intensity)
        if self.mode == MODE_DATASET and self.dataset_source and self.dataset_source.available:
            return self.dataset_source.sample(attack_type, intensity)
        if self.mode == MODE_CICIDS and self.cicids_source and self.cicids_source.available:
            return self.cicids_source.sample(attack_type, intensity)
        if self.mode == MODE_PCAP_FILE and self.pcap_file_source and self.pcap_file_source.available:
            return self.pcap_file_source.sample(attack_type, intensity)
        if self.mode == MODE_ANU_QRNG and self.anu_qrng_source and self.anu_qrng_source.available:
            return self.anu_qrng_source.sample(attack_type, intensity)
        if self.mode == MODE_BB84 and self.bb84_source and self.bb84_source.available:
            return self.bb84_source.sample(attack_type, intensity)
        return self.generator.sample(attack_type, intensity)

    def _next_sample_multi(self) -> tuple[float, bool]:
        """
        Sample with multi-attack composition.

        For SIMULATED mode: sum the noise contribution from each active
        attack on top of the clean baseline. Each attack ramps independently.
        For other modes: source already produces real-world / dataset samples;
        attacks are tracked but don't synthetically deform the source signal
        (they're ground truth from the data itself).
        """
        if not self.attacks:
            return self._next_sample(None, 0.0), False

        # Ramp every attack
        for a in self.attacks:
            a.intensity = min(1.0, a.intensity + a.ramp_per_tick)

        if self.mode == MODE_SIMULATED:
            # Composite simulated noise: clean baseline + sum of attack
            # contributions. Multi-attack: each attack adds its full
            # deformation, so concurrent attacks deform the channel
            # MORE than a single attack — which is the realistic outcome
            # (more attackers = more visible anomaly).
            base = self.generator.sample(None, 0.0)
            for a in self.attacks:
                contribution = self.generator.sample(a.attack_type, a.intensity) - self.fingerprint.baseline_mean
                base += contribution
            return base, True
        else:
            # Real-data modes: sample as-is, but flag we are under attack
            # so the UI shows the attacker IPs.
            return self._next_sample(None, 0.0), True

    # ── Tick ──────────────────────────────────────────────────────────────
    def tick(self) -> ChannelTickPayload:
        """
        Advance the channel one step.
          - if LEARNING: generate clean sample, feed baseline
          - if ACTIVE / UNDER_ATTACK: generate (possibly attacked) sample,
            push through detector, update state
          - if TERMINATED: produce no live data (flat zero)
          - if REAUTH: short period of clean baseline regeneration
        """
        self.samples_seen += 1

        # --- Gather a sample appropriate to current state ---
        if self.state == "TERMINATED":
            sample = 0.0
            attacking_now = False
        elif self.state == "REAUTH":
            sample = self._next_sample(None, 0.0)  # clean
            attacking_now = False
            if time.time() >= self._reauth_until:
                self.state = "ACTIVE"
                self.honeypot_active = False
                self.incident_ids.clear()
        else:
            sample, attacking_now = self._next_sample_multi()

        self.history.append(sample)
        self.attack_history.append(attacking_now)

        # --- Visible LEARNING phase (model is already pretrained) ---
        if self.state == "LEARNING":
            self._learning_ticks_left -= 1
            if self._learning_ticks_left <= 0:
                self.state = "ACTIVE"
                # Commit a trusted baseline reference the moment learning
                # completes cleanly — the baseline guard uses this to detect
                # later poisoning-style drift.
                if not self._baseline_committed:
                    self.baseline_guard.commit_reference(
                        mean=self.fingerprint.baseline_mean,
                        std=self.fingerprint.baseline_std,
                    )
                    self._baseline_committed = True
            return self._snapshot(sample, score=0.0,
                                  status="LEARNING",
                                  features={})

        # --- ACTIVE / UNDER_ATTACK / REAUTH (post-training) ---
        cls = self.detector.push(sample)
        if cls is None:
            return self._snapshot(sample, 0.0, "WARMUP", {})

        self.last_classification = cls
        if cls.score > self.peak_score:
            self.peak_score = cls.score

        # Feed the score into the adaptive threshold (defeats low-and-slow
        # evasion). This runs every tick so the pressure accumulator can catch
        # sustained sub-threshold activity even when no single score crosses
        # the hard floor.
        self._adaptive_decision = self.adaptive_threshold.update(cls.score)

        # Don't downgrade out of UNDER_ATTACK / TERMINATED on a single
        # SAFE classification — only the response cycle resets that.
        # We only transition into UNDER_ATTACK when there's an actually-
        # injected attack going on. Spurious single-tick high scores without
        # an injected attack are visible in the score bar but don't change
        # the state machine — the response engine never fires without an
        # attack source IP to block.
        #
        # PCAP MODE: when the detector flags an anomaly, identify the most
        # prolific source IP from real packet traffic and append an
        # AttackState. This is real-data attack detection: the IP+port that
        # gets blocked is whatever was actually pumping traffic on the wire.
        if (
            self.state == "ACTIVE"
            and not self.attacks
            and self.mode == MODE_PCAP
            and self.pcap_source is not None
            and self.pcap_source.available
            and cls.status == "ATTACK"
        ):
            attacker = self.pcap_source.recent_attacker()
            if attacker is not None:
                ip, port = attacker
                self.attacks.append(AttackState(
                    attack_type="pcap-anomaly",
                    intensity=1.0,
                    attacker_ip=ip,
                    attacker_port=port,
                    started_at=time.time(),
                    ramp_per_tick=0.0,
                ))

        # DATASET MODE: when we cross into a labelled attack segment, we
        # synthesize an AttackState using the segment label so the response
        # engine fires on real-physics-grounded attack data. This is the
        # validation pathway: prove the detector reacts to genuine attack
        # statistics, not just our own injections.
        # We lock per (channel, segment_idx) so we don't re-fire the
        # response engine repeatedly while still inside the same attack
        # segment after a re-auth cycle completes.
        if (
            self.state == "ACTIVE"
            and not self.attacks
            and self.mode == MODE_DATASET
            and self.dataset_source is not None
        ):
            seg = self.dataset_source.current_segment()
            seg_key = (self.channel_id, seg.get("seg_idx"))
            if (
                seg.get("is_attack")
                and cls.status == "ATTACK"
                and seg_key != self._last_dataset_attack_seg
            ):
                self._last_dataset_attack_seg = seg_key
                self.attacks.append(AttackState(
                    attack_type=str(seg.get("label", "dataset")),
                    intensity=1.0,
                    attacker_ip="dataset://" + self.channel_id,
                    attacker_port=int(seg.get("seg_idx", 0)),
                    started_at=time.time(),
                    ramp_per_tick=0.0,
                ))
            elif not seg.get("is_attack"):
                self._last_dataset_attack_seg = None

        # CICIDS MODE: similar to dataset — when on a labelled attack flow
        # and the IF flags it, synthesize an attack with the flow's class
        # label as attack_type and a representative attacker IP.
        if (
            self.state == "ACTIVE"
            and not self.attacks
            and self.mode == MODE_CICIDS
            and self.cicids_source is not None
        ):
            seg = self.cicids_source.current_segment()
            if seg.get("is_attack") and cls.status == "ATTACK":
                self.attacks.append(AttackState(
                    attack_type=str(seg.get("label", "cicids")),
                    intensity=1.0,
                    attacker_ip=f"cicids://{seg.get('label', '?')}".replace(' ', '_'),
                    attacker_port=int(seg.get("seg_idx", 0)) % 65535,
                    started_at=time.time(),
                    ramp_per_tick=0.0,
                ))

        # PCAP_FILE MODE: when the IF flags a window of replayed-pcap
        # samples as anomalous, attach the IP/port of the most recent
        # packet from the capture as the attacker. Real Wireshark data,
        # real source identity.
        if (
            self.state == "ACTIVE"
            and not self.attacks
            and self.mode == MODE_PCAP_FILE
            and self.pcap_file_source is not None
            and cls.status == "ATTACK"
        ):
            attacker = self.pcap_file_source.recent_attacker()
            if attacker is not None:
                ip, port = attacker
                self.attacks.append(AttackState(
                    attack_type="pcap-file-anomaly",
                    intensity=1.0,
                    attacker_ip=ip,
                    attacker_port=port,
                    started_at=time.time(),
                    ramp_per_tick=0.0,
                ))

        # BB84 MODE: when the channel's QBER spikes above the 11% BB84
        # abort threshold AND the IF flags it, attribute the attack to
        # "Eve" — an eavesdropper performing intercept-resend on the
        # quantum channel. This is the project's quantum centerpiece.
        if (
            self.state == "ACTIVE"
            and not self.attacks
            and self.mode == MODE_BB84
            and self.bb84_source is not None
            and cls.status == "ATTACK"
        ):
            eve_frac = self.bb84_source.eve_fraction
            qber = sample  # in BB84 mode, the sample IS the QBER
            if qber > 0.11:    # BB84 abort threshold
                self.attacks.append(AttackState(
                    attack_type="bb84-eavesdropper",
                    intensity=min(1.0, eve_frac if eve_frac > 0 else qber * 4),
                    attacker_ip=f"bb84://eve@{self.channel_id}",
                    attacker_port=int(qber * 10000) % 65535,
                    started_at=time.time(),
                    ramp_per_tick=0.0,
                ))

        if self.state == "ACTIVE" and self.attacks:
            if cls.status == "ATTACK":
                self.state = "UNDER_ATTACK"
        return self._snapshot(sample, cls.score, cls.status, cls.features)

    def _snapshot(self, sample, score, status, features) -> ChannelTickPayload:
        # Build full attacks list for UI
        attacks_list = [
            {
                "type": a.attack_type,
                "intensity": round(a.intensity, 3),
                "attacker_ip": a.attacker_ip,
                "attacker_port": a.attacker_port,
                "started_at_iso": time.strftime(
                    "%H:%M:%S", time.localtime(a.started_at)
                ),
            }
            for a in self.attacks
        ]
        primary_attack = attacks_list[0] if attacks_list else None
        return ChannelTickPayload(
            channel_id=self.channel_id,
            label=self.label,
            state=self.state,
            mode=self.mode,
            sample=sample,
            history=list(self.history),
            attack_history=list(self.attack_history),
            score=score,
            status=status,
            features=features,
            baseline_mean=self.fingerprint.baseline_mean,
            baseline_std=self.fingerprint.baseline_std,
            learning_progress=(
                1.0 if self.state != "LEARNING"
                else 1.0 - (self._learning_ticks_left / self.LEARNING_TICKS)
            ),
            honeypot_active=self.honeypot_active,
            incident_id=self.incident_id,
            incident_ids=list(self.incident_ids),
            dataset_segment=(
                self.dataset_source.current_segment()
                if self.dataset_source and self.mode == MODE_DATASET
                else None
            ),
            cicids_segment=(
                self.cicids_source.current_segment()
                if self.cicids_source and self.mode == MODE_CICIDS
                else None
            ),
            pcap_packets=(
                self.pcap_source.packet_count
                if self.pcap_source and self.mode == MODE_PCAP
                else None
            ),
            attack=primary_attack,
            attacks=attacks_list,
            samples_seen=self.samples_seen,
            defense={
                "adaptive_threshold": self.adaptive_threshold.snapshot(),
                "baseline_guard": self.baseline_guard.snapshot(),
                "baseline_check": (
                    self.baseline_guard.check(
                        self.fingerprint.baseline_mean,
                        self.fingerprint.baseline_std,
                    ) if self._baseline_committed else None
                ),
            },
        )

    # ── Attack lifecycle (multi-attack capable) ───────────────────────────
    def start_attack(
        self,
        attack_type: str,
        attacker_ip: str,
        attacker_port: int,
    ) -> bool:
        """
        Start an attack against this channel.

        Multi-attack: a channel can have multiple concurrent attacks from
        different sources. Each attack is tracked independently, contributes
        its own ramping intensity to the noise stream, and gets its own
        incident with its own attacker IP added to the blocklist.

        Returns False only in two cases: the channel can't accept attacks
        right now (terminated/learning/reauth), or this exact (ip, port)
        is already attacking it. Otherwise the new attack is appended.
        """
        # Reject duplicates from the same source
        for a in self.attacks:
            if a.attacker_ip == attacker_ip and a.attacker_port == attacker_port:
                return False
        self.attacks.append(AttackState(
            attack_type=attack_type,
            intensity=0.0,
            attacker_ip=attacker_ip,
            attacker_port=attacker_port,
            started_at=time.time(),
        ))
        return True

    def clear_attacks(self):
        self.attacks.clear()
        self.peak_score = 0.0

    # Backward-compat alias for any old callers
    def clear_attack(self):
        self.clear_attacks()

    def reset(self):
        """Full reset back to LEARNING for re-fingerprinting."""
        self.attacks.clear()
        self.honeypot_active = False
        self.incident_ids.clear()
        self.peak_score = 0.0
        self.history.clear()
        self.attack_history.clear()
        self.state = "LEARNING"
        self._learning_ticks_left = self.LEARNING_TICKS
        self.detector = QFIDSDetector(
            channel_id=self.channel_id,
            window_size=30,
            baseline_size=self.AUTOFIT_BASELINE,
        )
        # Bulk-retrain on a fresh clean sample
        import numpy as _np
        clean = _np.array([
            self.generator.sample()
            for _ in range(self.AUTOFIT_BASELINE * 30 + 50)
        ])
        self.detector.bulk_train(clean)
        # Reset hardening defences so the baseline reference is re-committed
        # cleanly after re-learning (prevents stale drift alerts).
        from .defenses import AdaptiveThreshold, BaselineIntegrityGuard
        self.adaptive_threshold = AdaptiveThreshold(hard_floor=0.65, watch_level=0.45)
        self.baseline_guard = BaselineIntegrityGuard(drift_tolerance=0.25)
        self._baseline_committed = False
    def mark_under_response(self, incident_id: str):
        if incident_id not in self.incident_ids:
            self.incident_ids.append(incident_id)

    def terminate(self):
        self.state = "TERMINATED"

    def begin_reauth(self):
        # Drop ALL attacks, switch to REAUTH for ~5 seconds, then resume ACTIVE
        self.clear_attacks()
        self.state = "REAUTH"
        self._reauth_until = time.time() + 5.0
        # Reset rolling window so post-reauth scores aren't biased by old data
        self.detector.window.clear()

    def activate_honeypot(self):
        self.honeypot_active = True


class ChannelManager:
    """
    Owns all channels, drives the global tick loop, and broadcasts
    snapshots to every connected websocket.
    """

    TICK_HZ = 5    # 5 Hz -> 200 ms per tick

    def __init__(self, blocklist: Blocklist):
        self.blocklist = blocklist
        self.response_engine = ResponseEngine(blocklist)
        self.channels: dict[str, Channel] = {
            cid: Channel(cid, label, mu, sd, bpf)
            for cid, label, mu, sd, bpf in CHANNEL_DEFS
        }
        self.subscribers: set[asyncio.Queue] = set()
        self.incidents: list[Incident] = []
        self.event_log: deque[dict] = deque(maxlen=200)
        self._loop_task: Optional[asyncio.Task] = None

    # ── Subscribe / unsubscribe websockets ────────────────────────────────
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self.subscribers.discard(q)

    async def broadcast(self, message: dict):
        dead = []
        for q in self.subscribers:
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.subscribers.discard(q)

    # ── Run loop ──────────────────────────────────────────────────────────
    def start(self):
        if self._loop_task is None:
            self._loop_task = asyncio.create_task(self._run())

    async def _run(self):
        period = 1.0 / self.TICK_HZ
        while True:
            await self._tick()
            await asyncio.sleep(period)

    async def _tick(self):
        snapshots = []
        for ch in self.channels.values():
            snap = ch.tick()
            snapshots.append(snap.to_dict())

            # Detect ATTACK status — fire a SEPARATE incident for each
            # active attack that doesn't yet have an incident. This is
            # how multi-attack is handled: same channel, same response
            # cycle, but distinct incident records and distinct IPs blocked.
            if ch.state == "UNDER_ATTACK" and ch.attacks:
                cls = ch.last_classification
                if cls and cls.score >= ch.detector.thr_attack:
                    # Track which attacks already have an incident by
                    # matching attacker_ip:port against existing incidents.
                    handled_keys = {
                        (i.attacker_ip, i.attacker_port)
                        for i in self.incidents
                        if i.channel_id == ch.channel_id and i.closed_at is None
                    }
                    for atk in ch.attacks:
                        key = (atk.attacker_ip, atk.attacker_port)
                        if key in handled_keys:
                            continue
                        incident = await self.response_engine.trigger(
                            channel=ch,
                            attack_type=atk.attack_type,
                            attacker_ip=atk.attacker_ip,
                            attacker_port=atk.attacker_port,
                            peak_score=ch.peak_score,
                            on_step=self._on_response_step,
                        )
                        self.incidents.append(incident)
                        self._log({
                            "level": "danger",
                            "channel_id": ch.channel_id,
                            "message": (
                                f"ATTACK on {ch.label} "
                                f"({atk.attack_type.upper()}) — "
                                f"src {atk.attacker_ip}:{atk.attacker_port}"
                            ),
                            "incident_id": incident.incident_id,
                        })
                        handled_keys.add(key)

            # Honeypot packet counter — once the honeypot is active, the
            # attacker (now unknowingly hitting the decoy) keeps pumping
            # traffic. We increment as long as the honeypot is active and
            # the channel hasn't returned to fully ACTIVE clean state yet.
            if ch.honeypot_active and ch.state in ("UNDER_ATTACK", "TERMINATED", "REAUTH"):
                hp_increment = random.randint(3, 12)
                # Distribute across all active incidents for this channel
                for inc in self.incidents:
                    if inc.channel_id == ch.channel_id and inc.closed_at is None:
                        inc.honeypot_packets += hp_increment

        await self.broadcast({
            "type": "tick",
            "ts": time.time(),
            "channels": snapshots,
            "global": {
                "active_incidents": sum(
                    1 for i in self.incidents if i.closed_at is None
                ),
                "total_incidents": len(self.incidents),
                "blocked_ips": len(self.blocklist.all()),
            },
        })

    async def _on_response_step(self, step_name, message, level, incident):
        self._log({
            "level": level,
            "channel_id": incident.channel_id,
            "incident_id": incident.incident_id,
            "message": f"[{incident.incident_id}] {message}",
        })
        await self.broadcast({
            "type": "incident_step",
            "incident": incident.to_dict(),
        })

    def _log(self, entry: dict):
        entry["ts"] = time.time()
        entry["ts_iso"] = time.strftime("%H:%M:%S", time.localtime(entry["ts"]))
        self.event_log.appendleft(entry)
        # Fire-and-forget broadcast
        asyncio.create_task(self.broadcast({
            "type": "log",
            "entry": entry,
        }))

    # ── Public ops surface ────────────────────────────────────────────────
    def trigger_attack(
        self,
        channel_id: str,
        attack_type: str,
        attacker_ip: str,
        attacker_port: int,
    ) -> tuple[bool, str]:
        ch = self.channels.get(channel_id)
        if ch is None:
            return False, "unknown channel"
        if ch.state in ("TERMINATED", "REAUTH", "LEARNING"):
            return False, f"channel state {ch.state} cannot accept attack"
        ok = ch.start_attack(attack_type, attacker_ip, attacker_port)
        if not ok:
            return False, "channel already under attack"
        self._log({
            "level": "warning",
            "channel_id": channel_id,
            "message": (
                f"Attack injected on {ch.label}: type={attack_type}, "
                f"src={attacker_ip}:{attacker_port}"
            ),
        })
        return True, "ok"

    def reset_channel(self, channel_id: str) -> bool:
        ch = self.channels.get(channel_id)
        if ch is None:
            return False
        ch.reset()
        self._log({
            "level": "info",
            "channel_id": channel_id,
            "message": f"Channel {ch.label} manually reset → re-fingerprinting.",
        })
        return True

    def reset_all(self):
        for ch in self.channels.values():
            ch.reset()
        self.incidents.clear()
        self.event_log.clear()
        self.blocklist.clear()
        self._log({"level": "info", "message": "Full system reset."})
