"""
CICIDSSource — replays a CICIDS-2017-format dataset through the detector.

CICIDS-2017 (Sharafaldin et al., 2018, "Toward Generating a New Intrusion
Detection Dataset and Intrusion Traffic Characterization") is the canonical
modern benchmark for network intrusion detection. The bundled JSON file
(data/cicids2017_subset.json) follows the exact CICIDS feature schema with
labelled flows for BENIGN traffic and four real attack classes:
DoS Hulk, PortScan, DDoS, and SSH-Patator.

How it integrates with QF-IDS's detector pipeline
--------------------------------------------------
The detector consumes a 1D float stream. To bridge the multi-dimensional
flow features into that interface, this source emits one summary
"anomaly intensity" sample per flow, computed as a weighted combination
of features that distinguish attack flows from benign. The detector then
treats the resulting stream the same way it treats any other source.

To use the actual published CICIDS CSV files:
  python tools/convert_cicids.py path/to/MachineLearningCSV
"""
from __future__ import annotations

import json
import math
import os
import threading
from typing import Optional


def _default_path() -> str:
    """
    Resolve the dataset path. If `cicids2017_real.json` (produced by the
    converter from the actual UNB CIC CSVs) exists, use that; otherwise
    fall back to the bundled schema-only subset. The user can also
    override with the QF-IDS_CICIDS_PATH env var.
    """
    override = os.environ.get("QF-IDS_CICIDS_PATH")
    if override:
        return os.path.abspath(override)
    here = os.path.dirname(os.path.abspath(__file__))
    real = os.path.abspath(os.path.join(
        here, "..", "..", "data", "cicids2017_real.json",
    ))
    if os.path.exists(real):
        return real
    return os.path.abspath(os.path.join(
        here, "..", "..", "data", "cicids2017_subset.json",
    ))


def _flow_to_intensity(flow: dict, baseline: dict) -> float:
    """
    Map a flow's feature vector to a 1D anomaly intensity in roughly
    [-3, +5] range. Attack flows produce larger values than benign.

    Logic: attacks tend to differ from benign baseline in two ways —
    rate (packets/sec, bytes/sec) and structure (packet size, IAT,
    flag pattern). We compute a z-score-like distance from baseline
    on the most discriminative dimensions.
    """
    f = flow.get("features", {})
    z = 0.0
    # Packet rate — attacks usually elevate this dramatically
    pps = max(f.get("flow_packets_per_s", 0.1), 0.1)
    z += math.log10(pps / max(baseline["flow_packets_per_s"], 0.1)) * 0.6
    # Byte rate — same idea
    bps = max(f.get("flow_bytes_per_s", 0.1), 0.1)
    z += math.log10(bps / max(baseline["flow_bytes_per_s"], 0.1)) * 0.4
    # SYN-flag dominance — port scans / DoS exhibit this
    syn = f.get("syn_flag_count", 0)
    if syn > 0:
        z += 0.6
    # Asymmetry — scans/DDoS have very few backward packets
    fwd = f.get("total_fwd_packets", 1)
    bwd = f.get("total_bwd_packets", 1)
    if fwd > 0 and bwd / max(fwd, 1) < 0.3:
        z += 0.5
    # Tiny-packet attacks (port scans)
    if f.get("fwd_packet_len_mean", 100) < 80:
        z += 0.7
    return float(z)


class CICIDSSource:
    """
    Streams flows from a CICIDS-2017-format dataset.

    Each tick emits one sample = the intensity score of the next flow.
    The current flow's label and is_attack flag are exposed via
    .current_segment() so the UI can show ground truth.
    """

    def __init__(
        self,
        channel_id: str,
        path: Optional[str] = None,
        loop: bool = True,
    ):
        self.channel_id = channel_id
        self.path = path or _default_path()
        self.loop = loop

        self._lock = threading.Lock()
        self._flows: list[dict] = []
        self._meta: dict = {}
        self._idx = 0
        self._loaded = False
        self._error: Optional[str] = None
        self._consumed = 0
        self._baseline: dict = {}

        self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                raw = json.load(f)
            self._meta = raw.get("metadata", {})
            self._flows = raw.get("flows", [])
            if not self._flows:
                self._error = "dataset is empty"
                return
            # Compute baseline from BENIGN flows for intensity normalisation
            benign = [fl for fl in self._flows if not fl.get("is_attack")]
            if benign:
                self._baseline = {
                    "flow_packets_per_s": _median(benign, "flow_packets_per_s"),
                    "flow_bytes_per_s":   _median(benign, "flow_bytes_per_s"),
                }
            else:
                self._baseline = {"flow_packets_per_s": 1.0,
                                  "flow_bytes_per_s": 1000.0}
            self._loaded = True
        except FileNotFoundError:
            self._error = f"dataset not found: {self.path}"
        except Exception as e:
            self._error = f"load error: {e}"

    def stop(self):
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
        """Emit one flow's anomaly intensity. attack_type/intensity ignored."""
        with self._lock:
            if not self._loaded or not self._flows:
                return 0.0
            flow = self._flows[self._idx]
            self._idx += 1
            if self._idx >= len(self._flows):
                if self.loop:
                    self._idx = 0
                else:
                    self._idx = len(self._flows) - 1
            self._consumed += 1
            return _flow_to_intensity(flow, self._baseline)

    def current_segment(self) -> dict:
        """The flow currently being emitted — analogous to dataset_source's."""
        with self._lock:
            if not self._flows:
                return {"label": "—", "is_attack": False}
            idx = (self._idx - 1) % len(self._flows) if self._idx > 0 else 0
            flow = self._flows[idx]
            return {
                "label":     flow.get("label", "?"),
                "is_attack": bool(flow.get("is_attack", False)),
                "seg_idx":   idx,
                "n_segs":    len(self._flows),
                "pos":       self._idx,
                "n_samples": len(self._flows),
            }

    def health(self) -> dict:
        return {
            "kind":     "cicids",
            "path":     self.path,
            "loaded":   self._loaded,
            "error":    self._error,
            "n_flows":  len(self._flows),
            "consumed": self._consumed,
            "current":  self.current_segment(),
            "metadata": self._meta,
        }


def _median(items: list[dict], key: str) -> float:
    vals = sorted(it.get("features", {}).get(key, 0.0) for it in items)
    if not vals:
        return 0.0
    n = len(vals)
    return float(vals[n // 2])
