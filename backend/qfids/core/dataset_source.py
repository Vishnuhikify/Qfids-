"""
DatasetNoiseSource — replays a recorded quantum-noise dataset.

The bundled dataset (data/quantum_noise_dataset.json) is generated using
real single-photon-detector physics (Poissonian shot noise, real dark-
count rate, afterpulsing, dead-time effects) with parameters drawn from
the Excelitas SPCM-AQRH-14 datasheet — the detector model used in many
production QKD systems.

Three scenarios are labelled in the dataset:
  * clean    — legitimate channel
  * mitm     — man-in-the-middle (extra loss + excess noise)
  * replace  — different physical channel (different statistics)

This is the validation pathway for the project. The detector trains on
the clean baseline and we then play back labelled attack segments to
demonstrate that physical-fingerprint detection actually works on
physically grounded data — not just synthetic noise.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Optional


def _default_dataset_path() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(
        os.path.join(here, "..", "..", "data",
                     "quantum_noise_dataset.json"),
    )


class DatasetNoiseSource:
    """
    Replays a labelled dataset segment by segment.

    Each call to .sample() returns the next sample. The current segment
    label and is_attack flag are surfaced via .health() so the UI can show
    the operator what the detector is currently being fed.
    """

    def __init__(
        self,
        channel_id: str,
        path: Optional[str] = None,
        loop: bool = True,
    ):
        self.channel_id = channel_id
        self.path = path or _default_dataset_path()
        self.loop = loop

        self._lock = threading.Lock()
        self._segments: list[dict] = []
        self._meta: dict = {}
        self._seg_idx = 0
        self._sample_idx = 0
        self._loaded = False
        self._error: Optional[str] = None
        self._total_samples = 0
        self._consumed = 0

        self._load()

    # ── lifecycle ────────────────────────────────────────────────────
    def _load(self):
        try:
            with open(self.path) as f:
                raw = json.load(f)
            self._meta = raw.get("metadata", {})
            self._segments = raw.get("segments", [])
            if not self._segments:
                self._error = "dataset has no segments"
                return
            self._total_samples = sum(
                len(s.get("samples", [])) for s in self._segments
            )
            self._loaded = True
        except FileNotFoundError:
            self._error = f"dataset not found: {self.path}"
        except Exception as e:
            self._error = f"could not load dataset: {e}"

    def stop(self):
        # Nothing to release.
        pass

    @property
    def available(self) -> bool:
        return self._loaded and self._error is None

    @property
    def last_error(self) -> Optional[str]:
        return self._error

    # ── sampling ─────────────────────────────────────────────────────
    def sample(
        self,
        attack_type: Optional[str] = None,
        intensity: float = 0.0,
    ) -> float:
        """
        Return the next dataset sample. attack_type/intensity are accepted
        for API compatibility but ignored — the dataset already has its
        own ground-truth labels for which segments are attacks.
        """
        with self._lock:
            if not self._loaded or not self._segments:
                return 0.0
            seg = self._segments[self._seg_idx]
            samples = seg.get("samples", [])
            if self._sample_idx >= len(samples):
                self._seg_idx += 1
                self._sample_idx = 0
                if self._seg_idx >= len(self._segments):
                    if self.loop:
                        self._seg_idx = 0
                    else:
                        self._seg_idx = len(self._segments) - 1
                        return 0.0
                seg = self._segments[self._seg_idx]
                samples = seg.get("samples", [])
            v = float(samples[self._sample_idx]) if samples else 0.0
            self._sample_idx += 1
            self._consumed += 1
            return v

    def current_segment(self) -> dict:
        """Label and ground-truth attack flag for the current segment."""
        with self._lock:
            if not self._segments:
                return {"label": "—", "is_attack": False}
            seg = self._segments[self._seg_idx]
            return {
                "label":     seg.get("label", "?"),
                "is_attack": bool(seg.get("is_attack", False)),
                "seg_idx":   self._seg_idx,
                "n_segs":    len(self._segments),
                "pos":       self._sample_idx,
                "n_samples": len(seg.get("samples", [])),
            }

    def health(self) -> dict:
        return {
            "kind":            "dataset",
            "path":            self.path,
            "loaded":          self._loaded,
            "error":           self._error,
            "total_samples":   self._total_samples,
            "consumed":        self._consumed,
            "current_segment": self.current_segment(),
            "metadata":        self._meta,
        }
