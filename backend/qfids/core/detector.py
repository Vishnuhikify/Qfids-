"""
QF-IDS detector — real sklearn IsolationForest trained per-channel.

Pipeline:
  raw window  →  feature vector (7 statistical descriptors)
              →  IsolationForest.score_samples → normalised [0, 1]
              →  classify(SAFE / SUSPICIOUS / ATTACK)
"""
from __future__ import annotations

import numpy as np
from collections import deque
from dataclasses import dataclass
from scipy import stats as sp_stats
from sklearn.ensemble import IsolationForest


FEATURE_NAMES = (
    "mean", "variance", "std",
    "skewness", "kurtosis",
    "p2p_range", "iqr",
)


def extract_features(window: np.ndarray) -> np.ndarray:
    """7-dim statistical fingerprint of a sliding window."""
    if window.size < 3:
        return np.zeros(7, dtype=float)
    arr = window.astype(float)
    mean = float(np.mean(arr))
    var = float(np.var(arr))
    std = float(np.std(arr))
    skew = float(sp_stats.skew(arr))
    kurt = float(sp_stats.kurtosis(arr))
    p2p = float(np.ptp(arr))
    q75, q25 = np.percentile(arr, [75, 25])
    iqr = float(q75 - q25)
    return np.array([mean, var, std, skew, kurt, p2p, iqr], dtype=float)


@dataclass
class Classification:
    status: str               # SAFE | SUSPICIOUS | ATTACK
    score: float              # normalised [0, 1] anomaly score
    features: dict            # named feature values
    raw_iforest_score: float  # sklearn's score_samples output (negative-ish)


class QFIDSDetector:
    """
    Per-channel Isolation Forest detector.

    Lifecycle:
      1. accumulate `baseline_size` clean samples → train IF
      2. on each new sample push it into rolling window
      3. extract features → score_samples → normalise → classify
    """

    BASELINE_DEFAULT = 80         # number of training feature-vectors
    WINDOW_DEFAULT   = 30
    THR_SUSPICIOUS   = 0.45
    THR_ATTACK       = 0.65

    def __init__(
        self,
        channel_id: str,
        window_size: int = WINDOW_DEFAULT,
        baseline_size: int = BASELINE_DEFAULT,
        thr_suspicious: float = THR_SUSPICIOUS,
        thr_attack: float = THR_ATTACK,
        contamination: float = 0.04,
    ):
        self.channel_id = channel_id
        self.window_size = window_size
        self.baseline_size = baseline_size
        self.thr_suspicious = thr_suspicious
        self.thr_attack = thr_attack

        self.window: deque[float] = deque(maxlen=window_size)
        # Training pool: each "training sample" is a feature vector
        # extracted from a NON-OVERLAPPING window of clean noise. We need
        # non-overlap so the IF sees real distributional spread, not
        # heavily-correlated near-duplicates.
        self._train_pool: list[np.ndarray] = []
        self._raw_pool: list[float] = []
        self._iforest: IsolationForest | None = None
        self._score_min: float = -0.5
        self._score_max: float = 0.5
        self.trained = False

    # ── Training ──────────────────────────────────────────────────────────
    def bulk_train(self, samples: np.ndarray):
        """
        Train all at once from a long array of clean baseline samples.
        Faster than feed_baseline() for startup.
        """
        if self.trained:
            return
        n_windows = len(samples) // self.window_size
        for i in range(n_windows):
            chunk = samples[i * self.window_size : (i + 1) * self.window_size]
            self._train_pool.append(extract_features(chunk))
        # Also seed _raw_pool so progress reads as complete
        self._raw_pool = list(samples[: n_windows * self.window_size])
        if len(self._train_pool) >= self.baseline_size:
            self._fit()

    def feed_baseline(self, sample: float) -> bool:
        """
        Feed one clean baseline sample. Returns True once training completes.

        We accumulate raw samples and emit one feature vector for every
        full *non-overlapping* window of `window_size`. That keeps the
        IF training corpus diverse.
        """
        if self.trained:
            return True
        self._raw_pool.append(sample)
        # Emit a feature vector once per filled window
        if len(self._raw_pool) >= (len(self._train_pool) + 1) * self.window_size:
            start = len(self._train_pool) * self.window_size
            window = np.array(self._raw_pool[start : start + self.window_size])
            self._train_pool.append(extract_features(window))
        if len(self._train_pool) >= self.baseline_size:
            self._fit()
        return self.trained

    def _fit(self):
        X = np.vstack(self._train_pool)
        self._iforest = IsolationForest(
            n_estimators=120,
            contamination=0.04,
            random_state=42,
        )
        self._iforest.fit(X)
        # Calibrate so that ordinary clean noise sits near 0 and only
        # genuine outliers approach 1. We use the 5th percentile of
        # training scores as "comfortably normal" (anomaly ≈ 0.0) and
        # extrapolate the upper bound from the baseline std of those
        # scores so that scores beyond ~3σ on the low side reach ~0.7.
        raw = self._iforest.score_samples(X)
        median = float(np.median(raw))
        # raw scores: higher = more normal. Lower (more negative) = more anomalous.
        # The threshold below median that should map to anomaly_score=1.0:
        spread = float(np.std(raw))
        self._score_max = median                          # at median → score=0
        self._score_min = median - max(spread * 4.0, 0.1) # 4σ below → score=1
        self.trained = True

    # ── Inference ─────────────────────────────────────────────────────────
    def push(self, sample: float) -> Classification | None:
        """
        Push a live sample. Returns a Classification once the window is full
        AND the model is trained; otherwise None (still warming up).
        """
        self.window.append(sample)
        if not self.trained or len(self.window) < self.window_size:
            return None

        feats = extract_features(np.array(self.window))
        raw_score = float(self._iforest.score_samples(feats.reshape(1, -1))[0])

        # Normalise: higher raw = more normal; we want anomaly_score where
        # 1 = highly anomalous, 0 = highly normal.
        denom = max(self._score_max - self._score_min, 1e-9)
        normal_score = (raw_score - self._score_min) / denom
        anomaly_score = float(np.clip(1.0 - normal_score, 0.0, 1.0))

        status = self._classify(anomaly_score)

        return Classification(
            status=status,
            score=anomaly_score,
            features=dict(zip(FEATURE_NAMES, feats.tolist())),
            raw_iforest_score=raw_score,
        )

    def _classify(self, score: float) -> str:
        if score >= self.thr_attack:
            return "ATTACK"
        if score >= self.thr_suspicious:
            return "SUSPICIOUS"
        return "SAFE"

    # ── Introspection (for the API) ───────────────────────────────────────
    @property
    def baseline_progress(self) -> float:
        if self.trained:
            return 1.0
        # We need baseline_size non-overlapping windows of window_size raw samples
        target = self.baseline_size * self.window_size
        return min(1.0, len(self._raw_pool) / max(1, target))
