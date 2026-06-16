"""
BB84QKDSource — feeds Quantum Bit Error Rate from a BB84 simulator
through QF-IDS's detector pipeline.

This is the genuinely quantum mode. Each tick runs one BB84 window
(~200 photon pulses) through the simulator and emits the measured QBER
as the channel sample. When an eavesdropper is active (set via
`set_eve_fraction`), QBER jumps from the natural ~2% noise floor to
~25% under full intercept-resend, which the IsolationForest detector
flags as ATTACK.

This demonstrates the project's central thesis: the same statistical
fingerprinting that detects classical channel anomalies also catches
quantum eavesdropping, when fed QBER as the channel sample.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

from .bb84 import BB84Channel, BB84RunStats


class BB84QKDSource:
    """
    Runs a BB84 simulator and emits one QBER sample per tick.

    Set eve_fraction > 0 to inject an eavesdropper. The detector,
    trained on clean-channel QBER (no Eve), will flag the deviation.
    """

    def __init__(
        self,
        channel_id: str,
        pulses_per_window: int = 200,
        sample_fraction: float = 0.5,
        seed: Optional[int] = None,
    ):
        self.channel_id = channel_id
        self.pulses_per_window = pulses_per_window
        self.sample_fraction = sample_fraction
        self.bb84 = BB84Channel(channel_id, seed=seed)

        self._lock = threading.Lock()
        self.eve_fraction: float = 0.0
        self._total_pulses_sent = 0
        self._total_windows = 0
        self._last_stats: Optional[BB84RunStats] = None
        self._error: Optional[str] = None

    # ── lifecycle ────────────────────────────────────────────────────
    def stop(self):
        pass

    @property
    def available(self) -> bool:
        return True

    @property
    def last_error(self) -> Optional[str]:
        return self._error

    # ── Eavesdropper control ─────────────────────────────────────────
    def set_eve_fraction(self, frac: float):
        """Set the eavesdropper interception fraction (0.0 = no Eve)."""
        with self._lock:
            self.eve_fraction = max(0.0, min(1.0, float(frac)))

    # ── sampling ─────────────────────────────────────────────────────
    def sample(
        self,
        attack_type: Optional[str] = None,
        intensity: float = 0.0,
    ) -> float:
        """
        Run one BB84 window and return the QBER as the channel sample.
        attack_type / intensity are ignored — Eve is controlled via
        set_eve_fraction (or the BB84-specific API endpoint).
        """
        with self._lock:
            eve = self.eve_fraction
        stats = self.bb84.run_window(
            n_pulses=self.pulses_per_window,
            eve_fraction=eve,
            sample_fraction=self.sample_fraction,
        )
        with self._lock:
            self._last_stats = stats
            self._total_pulses_sent += stats.n_pulses_sent
            self._total_windows += 1
        # QBER is naturally in [0, 1]. The detector trained on clean
        # data (mean ~0.02) will flag anything above the threshold.
        return float(stats.qber)

    # ── introspection ────────────────────────────────────────────────
    def current_segment(self) -> dict:
        """For UI parity with other sources."""
        with self._lock:
            s = self._last_stats
            eve = self.eve_fraction
        is_attack = eve > 0
        label = "BB84 · clean" if not is_attack else f"BB84 · Eve {int(eve*100)}%"
        return {
            "label":     label,
            "is_attack": is_attack,
            "seg_idx":   self._total_windows,
            "n_segs":    self._total_windows,
            "pos":       self._total_windows,
            "n_samples": self._total_windows,
            "qber":      s.qber if s else 0.0,
            "n_sifted":  s.n_sifted if s else 0,
        }

    def health(self) -> dict:
        with self._lock:
            s = self._last_stats
            eve = self.eve_fraction
        return {
            "kind":              "bb84",
            "windows_run":       self._total_windows,
            "pulses_sent":       self._total_pulses_sent,
            "eve_fraction":      eve,
            "last_qber":         s.qber if s else 0.0,
            "last_n_sifted":     s.n_sifted if s else 0,
            "last_n_received":   s.n_received if s else 0,
            "pulses_per_window": self.pulses_per_window,
            "bb84_params":       self.bb84.health(),
        }
