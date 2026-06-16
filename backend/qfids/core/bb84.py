"""
BB84 quantum key distribution protocol simulator.

This is the *genuinely quantum* core of QF-IDS. It implements the BB84
protocol (Bennett & Brassard, 1984) — the foundational protocol for
quantum key distribution — and feeds its Quantum Bit Error Rate (QBER)
into the detector as a fingerprint of channel integrity.

WHY THIS MATTERS FOR YOUR PROJECT
─────────────────────────────────
The original QF-IDS pitch was about detecting attacks on quantum
communication channels by their statistical fingerprint. The most
fundamental such attack is the intercept-resend eavesdropper (Eve).
In BB84, an eavesdropper who measures and re-sends each photon
introduces a ~25% QBER (one of the foundational results in quantum
cryptography). This module simulates that exactly and feeds the
resulting QBER stream through QF-IDS's IsolationForest, demonstrating
that the detector flags eavesdropping the moment QBER deviates from
the channel's natural error floor.

THE PROTOCOL (BB84 in plain words)
────────────────────────────────────
1. Alice generates a random bit + a random basis (rectilinear or
   diagonal) per pulse.
2. She encodes the bit on a photon polarised according to that basis.
3. Bob measures each incoming photon in a randomly chosen basis.
4. They publicly compare bases (not bit values). Where bases matched,
   Bob's bit should equal Alice's — these form the sifted key.
5. They sample a fraction of the sifted key to compute QBER. If QBER
   exceeds a threshold (~11% in BB84 with error correction), they
   abort — an eavesdropper is present.

EAVESDROPPER MODEL
──────────────────
Intercept-resend: Eve picks a random basis per photon, measures
(collapsing the state), then re-emits to Bob. Half the time her basis
matches Alice's — those photons go through unchanged. Half the time
it doesn't — those photons are projected into a random eigenstate of
the wrong basis. When Bob then measures in Alice's basis on these
disturbed photons, he gets a wrong answer 50% of the time.
Net effect: 25% bit error rate visible in QBER. Textbook BB84 result.

REFERENCES
──────────
Bennett, C. H. & Brassard, G. (1984). Quantum cryptography: Public key
distribution and coin tossing. Proceedings of IEEE International
Conference on Computers, Systems and Signal Processing, 175–179.

Bennett, C. H., Brassard, G., & Mermin, N. D. (1992). Quantum
cryptography without Bell's theorem. Physical Review Letters, 68(5),
557. (For the security analysis showing intercept-resend → 25% QBER.)
"""
from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

import numpy as np


# ── Basis & bit representations ──────────────────────────────────────────
# Rectilinear basis (Z, "+"): |0⟩ and |1⟩
# Diagonal basis (X, "×"):    |+⟩ = (|0⟩+|1⟩)/√2,  |-⟩ = (|0⟩-|1⟩)/√2
BASIS_RECTILINEAR = 0
BASIS_DIAGONAL    = 1


@dataclass
class BB84RunStats:
    """One window of BB84 statistics."""
    n_pulses_sent:     int
    n_received:        int           # photons that survived channel loss
    n_sifted:          int           # bases matched
    n_errors_sampled:  int           # disagreements in publicly-revealed sample
    n_sample_size:     int           # size of revealed sample
    qber:              float         # n_errors / n_sample
    eve_present:       bool          # ground truth for evaluation
    eve_fraction:      float         # fraction of photons Eve intercepts
    timestamp:         float


class BB84Channel:
    """
    A simulated BB84 quantum channel.

    Each call to .run_window(n_pulses) runs one BB84 session of n_pulses,
    optionally with an intercept-resend eavesdropper, and returns the
    measured QBER.

    Channel parameters reflect realistic optical fibre QKD:
      - dark_count_rate:   detector clicks per pulse with no signal
      - channel_loss:      fraction of photons lost in the fibre
      - detector_eff:      detector quantum efficiency

    The "natural" QBER (no eavesdropper) is set by dark counts and
    detector noise; published QKD systems run at 1-5% baseline QBER.
    """

    # Baseline channel parameters (typical metro-scale fibre QKD)
    DARK_COUNT_PROB    = 0.005   # 0.5% dark count rate per pulse
    CHANNEL_LOSS       = 0.30    # 30% photons lost (typical fibre)
    DETECTOR_EFF       = 0.85    # 85% detector efficiency
    BASIS_MISALIGNMENT = 0.015   # 1.5% intrinsic mismatch (real systems)
    QBER_THRESHOLD     = 0.11    # standard BB84 abort threshold (11%)

    def __init__(self, channel_id: str, seed: Optional[int] = None):
        self.channel_id = channel_id
        self.rng = np.random.default_rng(seed)
        self.history: deque[BB84RunStats] = deque(maxlen=500)
        self._lock = threading.Lock()

    # ── Single-pulse simulation ───────────────────────────────────────────
    def _send_pulse(
        self,
        alice_bit: int,
        alice_basis: int,
        bob_basis: int,
        eve_fraction: float,
    ) -> tuple[bool, Optional[int]]:
        """
        Simulate one photon: Alice → (Eve?) → channel → Bob.
        Returns (received, bob_bit).  bob_bit is None if photon lost.
        """
        # 1. Possible Eve interception (intercept-resend attack)
        eve_acts = self.rng.random() < eve_fraction
        if eve_acts:
            eve_basis = int(self.rng.integers(0, 2))
            if eve_basis != alice_basis:
                # Eve measured in wrong basis → state is now random in
                # the *new* basis. When Bob later measures in alice_basis,
                # the result is random.
                effective_bit = int(self.rng.integers(0, 2))
            else:
                effective_bit = alice_bit
        else:
            effective_bit = alice_bit

        # 2. Channel loss + detector inefficiency
        survive_prob = (1 - self.CHANNEL_LOSS) * self.DETECTOR_EFF
        if self.rng.random() > survive_prob:
            # photon lost. But a dark count may still produce a click.
            if self.rng.random() < self.DARK_COUNT_PROB:
                return True, int(self.rng.integers(0, 2))
            return False, None

        # 3. Bob measures using the bob_basis chosen at the protocol level
        if bob_basis == alice_basis:
            # Same basis as Alice → Bob gets effective_bit, with possible
            # basis-misalignment error (real-system optical imperfection)
            bit = effective_bit
            if self.rng.random() < self.BASIS_MISALIGNMENT:
                bit ^= 1
        else:
            # Different basis → 50/50 random outcome (these are sifted out
            # of the key anyway, but we still need a value for the array)
            bit = int(self.rng.integers(0, 2))

        return True, bit

    # ── One BB84 run (window) ─────────────────────────────────────────────
    def run_window(
        self,
        n_pulses: int = 200,
        eve_fraction: float = 0.0,
        sample_fraction: float = 0.5,
    ) -> BB84RunStats:
        """
        Run one window of BB84 with `n_pulses` photons, optionally with
        an eavesdropper intercepting `eve_fraction` of them. Compute the
        sifted key, sample `sample_fraction` of it for QBER estimation,
        and return the statistics.
        """
        # 1. Alice's random bits and bases
        alice_bits   = self.rng.integers(0, 2, n_pulses)
        alice_bases  = self.rng.integers(0, 2, n_pulses)

        # 2. Send each pulse through the channel
        received = np.zeros(n_pulses, dtype=bool)
        bob_bits = np.full(n_pulses, -1, dtype=int)
        bob_bases = self.rng.integers(0, 2, n_pulses)

        for i in range(n_pulses):
            got, bit = self._send_pulse(
                int(alice_bits[i]),
                int(alice_bases[i]),
                int(bob_bases[i]),
                eve_fraction,
            )
            received[i] = got
            if got and bit is not None:
                bob_bits[i] = bit

        # 3. Sift: keep only positions where Bob received AND bases match
        sifted_mask = received & (alice_bases == bob_bases)
        n_sifted    = int(sifted_mask.sum())

        if n_sifted < 4:
            stats = BB84RunStats(
                n_pulses_sent=n_pulses,
                n_received=int(received.sum()),
                n_sifted=n_sifted,
                n_errors_sampled=0,
                n_sample_size=0,
                qber=0.0,
                eve_present=eve_fraction > 0,
                eve_fraction=eve_fraction,
                timestamp=time.time(),
            )
            with self._lock:
                self.history.append(stats)
            return stats

        sifted_alice = alice_bits[sifted_mask]
        sifted_bob   = bob_bits[sifted_mask]

        # 4. Publicly reveal a random sample to estimate QBER
        n_sample = max(2, int(n_sifted * sample_fraction))
        idx      = self.rng.choice(n_sifted, n_sample, replace=False)
        errors   = int((sifted_alice[idx] != sifted_bob[idx]).sum())
        qber     = errors / n_sample

        stats = BB84RunStats(
            n_pulses_sent=n_pulses,
            n_received=int(received.sum()),
            n_sifted=n_sifted,
            n_errors_sampled=errors,
            n_sample_size=n_sample,
            qber=float(qber),
            eve_present=eve_fraction > 0,
            eve_fraction=eve_fraction,
            timestamp=time.time(),
        )
        with self._lock:
            self.history.append(stats)
        return stats

    # ── Statistics ────────────────────────────────────────────────────────
    def recent_history(self, n: int = 50) -> list[BB84RunStats]:
        with self._lock:
            return list(self.history)[-n:]

    def health(self) -> dict:
        with self._lock:
            hist = list(self.history)
        recent_qber = [s.qber for s in hist[-30:]]
        return {
            "channel_id":       self.channel_id,
            "windows_run":      len(hist),
            "recent_qber_mean": float(np.mean(recent_qber)) if recent_qber else 0.0,
            "recent_qber_max":  float(np.max(recent_qber)) if recent_qber else 0.0,
            "qber_threshold":   self.QBER_THRESHOLD,
            "baseline_loss":    self.CHANNEL_LOSS,
            "dark_count_prob":  self.DARK_COUNT_PROB,
            "detector_eff":     self.DETECTOR_EFF,
            "abort_threshold":  self.QBER_THRESHOLD,
        }


# ─────────────────────────────────────────────────────────────────────────
# THEORETICAL RESULTS FOR REFERENCE
# ─────────────────────────────────────────────────────────────────────────
# Expected QBER under intercept-resend with Eve intercepting fraction f:
#
#     QBER ≈ baseline_qber + 0.25 * f
#
# where baseline_qber ≈ 0.5 * DARK_COUNT_PROB + BASIS_MISALIGNMENT
# (the floor due to detector noise and optical imperfection).
#
# Full intercept (f=1.0) gives QBER ≈ 25-27% in our parameters.
# QBER > 11% triggers the BB84 abort condition.
def expected_qber(eve_fraction: float,
                  baseline: float = 0.024) -> float:
    """The theoretical QBER for a given eavesdropper coverage."""
    return baseline + 0.25 * eve_fraction
