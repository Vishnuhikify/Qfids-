"""
ANUQRNGSource — fetches real quantum random numbers from the
Australian National University's live QRNG service.

The ANU QRNG is a real physics experiment: it measures vacuum
fluctuations (quantum shot noise from an empty optical mode) using a
balanced homodyne detector, then publishes the digitised samples as
random numbers via a public API.

This is genuinely real measured quantum noise — the same kind of
fluctuation that limits any optical communication channel — fetched
from a live experimental apparatus running 24/7 at ANU.

API:    https://qrng.anu.edu.au/API/
Docs:   https://qrng.anu.edu.au/contact/api-documentation/

Behaviour:
- Fetches a buffer of `block_size` uint8 samples on demand.
- Each sample is normalised to roughly zero mean, unit-ish spread.
- Network failures are non-fatal — falls back to silence (sample=0)
  until the next refill succeeds. The error is reported via .health().
- A background thread refills the buffer when it drops below a
  threshold so the main tick loop never blocks on the network.
"""
from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Optional


ANU_API = (
    "https://qrng.anu.edu.au/API/jsonI.php"
    "?length={length}&type=uint8"
)


class ANUQRNGSource:
    """
    Real quantum-noise source backed by ANU's live QRNG service.

    Attribute:
      buffer (deque[float])  — pre-fetched normalised samples
      total_fetched (int)    — count of bytes pulled from the API so far
      last_fetch_at (float)  — timestamp of last successful refill
      _error (str | None)    — last network error if any
    """

    BLOCK_SIZE = 256          # bytes per API call
    REFILL_BELOW = 64         # refill when buffer drops to this level
    HARD_BUFFER_CAP = 2048    # don't accumulate more than this in memory
    REFILL_BACKOFF_S = 5.0    # retry interval after a failed fetch
    REQUEST_TIMEOUT_S = 6.0

    def __init__(
        self,
        channel_id: str,
        api_url: Optional[str] = None,
        block_size: Optional[int] = None,
    ):
        self.channel_id = channel_id
        self.api_url_template = api_url or ANU_API
        self.block_size = block_size or self.BLOCK_SIZE

        self._lock = threading.Lock()
        self._buffer: deque[float] = deque(maxlen=self.HARD_BUFFER_CAP)
        self._error: Optional[str] = None
        self._refilling = threading.Event()
        self._stop = threading.Event()
        self._refill_thread: Optional[threading.Thread] = None

        self.total_fetched = 0
        self.last_fetch_at: float = 0.0
        self._first_fetch_done = threading.Event()

        # Kick off the first refill in the background so __init__ returns
        # immediately and the manager can fingerprint with whatever's
        # available
        self._start_refill_thread()

    # ── lifecycle ────────────────────────────────────────────────────
    def stop(self):
        self._stop.set()

    @property
    def available(self) -> bool:
        # Available even if the very first fetch hasn't completed —
        # `sample()` returns 0.0 in that case, which is fine for the
        # detector's startup. The error state is for diagnostics only.
        return True

    @property
    def last_error(self) -> Optional[str]:
        return self._error

    # ── API fetch ────────────────────────────────────────────────────
    def _fetch_block(self) -> list[int]:
        """One blocking call to the ANU API. Returns list of uint8."""
        url = self.api_url_template.format(length=self.block_size)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "QF-IDS/1.0 (anomaly-detection-research)",
                "Accept": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=self.REQUEST_TIMEOUT_S) as r:
            payload = json.loads(r.read())
        if not payload.get("success"):
            raise RuntimeError(f"ANU API returned success=false: {payload}")
        data = payload.get("data", [])
        if not isinstance(data, list) or not data:
            raise RuntimeError(f"ANU API returned no data: {payload}")
        return [int(x) for x in data]

    def _normalise_byte(self, b: int) -> float:
        """Map uint8 (0..255) to roughly zero-mean unit-spread float."""
        # Centre at 127.5, divide by 64 → roughly N(0, 1) in shape
        return (b - 127.5) / 64.0

    # ── refill loop ──────────────────────────────────────────────────
    def _start_refill_thread(self):
        if self._refill_thread is None or not self._refill_thread.is_alive():
            self._refill_thread = threading.Thread(
                target=self._refill_loop,
                name=f"anu-qrng-refill-{self.channel_id}",
                daemon=True,
            )
            self._refill_thread.start()

    def _refill_loop(self):
        while not self._stop.is_set():
            with self._lock:
                need_refill = len(self._buffer) < self.REFILL_BELOW
            if not need_refill:
                time.sleep(0.5)
                continue
            try:
                bytes_ = self._fetch_block()
                with self._lock:
                    for b in bytes_:
                        self._buffer.append(self._normalise_byte(b))
                    self.total_fetched += len(bytes_)
                    self.last_fetch_at = time.time()
                self._error = None
                self._first_fetch_done.set()
            except urllib.error.URLError as e:
                self._error = f"network: {e.reason}"
                time.sleep(self.REFILL_BACKOFF_S)
            except Exception as e:
                self._error = f"fetch failed: {e}"
                time.sleep(self.REFILL_BACKOFF_S)

    # ── sampling ─────────────────────────────────────────────────────
    def sample(
        self,
        attack_type: Optional[str] = None,
        intensity: float = 0.0,
    ) -> float:
        """One real quantum-random sample. Returns 0.0 if buffer empty."""
        with self._lock:
            if self._buffer:
                return self._buffer.popleft()
        return 0.0

    # ── introspection ────────────────────────────────────────────────
    def current_segment(self) -> dict:
        """For UI parity with dataset/CICIDS sources."""
        return {
            "label": "ANU QRNG (live)",
            "is_attack": False,
            "seg_idx": 0,
            "n_segs": 1,
            "pos": self.total_fetched,
            "n_samples": self.total_fetched,
        }

    def health(self) -> dict:
        with self._lock:
            buffered = len(self._buffer)
        return {
            "kind":          "anu_qrng",
            "buffered":      buffered,
            "total_fetched": self.total_fetched,
            "last_fetch_at": self.last_fetch_at,
            "last_fetch_iso": (
                time.strftime("%H:%M:%S", time.localtime(self.last_fetch_at))
                if self.last_fetch_at else None
            ),
            "first_fetch":   self._first_fetch_done.is_set(),
            "error":         self._error,
            "api":           "qrng.anu.edu.au",
        }
