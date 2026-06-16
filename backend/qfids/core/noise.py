"""
Quantum channel noise generator.

Each physical channel has its OWN baseline fingerprint (mean, std).
This is what makes channels distinguishable — replacing a channel
or interposing an attacker shifts these statistics measurably.

Different attack classes leave different noise signatures:
  - mitm:        bias shift + variance inflation
  - replace:     entirely different baseline (different fiber)
  - relay:       timing-jitter footprint (heavy tails -> high kurtosis)
  - inject:      periodic bursts on top of baseline
"""
from __future__ import annotations

import math
import time
import numpy as np
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ChannelFingerprint:
    """Per-channel physical fingerprint. Stable for a legitimate channel."""
    channel_id: str
    baseline_mean: float
    baseline_std: float
    # microscopic per-device imperfections — small but characteristic
    detector_jitter: float = 0.02
    laser_linewidth_bias: float = 0.0


class NoiseGenerator:
    """
    Samples the physical-layer noise of a quantum channel.

    A channel's clean fingerprint is Gaussian(mean, std) plus tiny
    device-specific perturbations. Attacks deform this distribution
    in a way that anomaly detection can pick up.
    """

    def __init__(self, fingerprint: ChannelFingerprint, seed: Optional[int] = None):
        self.fp = fingerprint
        self.rng = np.random.default_rng(seed)
        self._t0 = time.time()

    # ── Sampling ──────────────────────────────────────────────────────────
    def sample(
        self,
        attack_type: Optional[str] = None,
        intensity: float = 0.0,
    ) -> float:
        """
        Return one noise sample.

        attack_type: None | 'mitm' | 'replace' | 'relay' | 'inject'
        intensity:   0.0 (no effect) → 1.0 (full strength)
        """
        fp = self.fp
        if not attack_type or intensity <= 0:
            # Clean draw + tiny detector jitter
            base = self.rng.normal(fp.baseline_mean, fp.baseline_std)
            return float(base + self.rng.normal(0, fp.detector_jitter))

        if attack_type == "mitm":
            # Interposition introduces bias and inflates variance
            mu = fp.baseline_mean + 1.4 * intensity
            sd = fp.baseline_std * (1.0 + 1.8 * intensity)
            return float(self.rng.normal(mu, sd))

        if attack_type == "replace":
            # Entirely different fiber: different mean & std altogether
            mu = fp.baseline_mean + 2.0 * intensity * np.sign(
                fp.laser_linewidth_bias - 0.5
            )
            sd = fp.baseline_std * (0.5 + 1.5 * intensity)
            return float(self.rng.normal(mu, sd))

        if attack_type == "relay":
            # Capture-and-replay creates fat-tailed jitter (Student's t)
            df = max(2.5, 6.0 - 4.0 * intensity)   # lower df -> heavier tails
            base = self.rng.standard_t(df) * fp.baseline_std * (1.0 + intensity)
            return float(fp.baseline_mean + base)

        if attack_type == "inject":
            # Periodic injection on top of baseline noise
            base = self.rng.normal(fp.baseline_mean, fp.baseline_std)
            phase = (time.time() - self._t0) * 4.0
            burst = math.sin(phase) * 1.6 * intensity
            return float(base + burst)

        # Unknown attack → fall through to clean
        return float(self.rng.normal(fp.baseline_mean, fp.baseline_std))

    def reseed(self, seed: int):
        self.rng = np.random.default_rng(seed)
