#!/usr/bin/env python3
"""
convert_cicids.py — convert real CICIDS-2017 CSV files to QF-IDS's JSON format.

The University of New Brunswick CIC publishes CICIDS-2017 as 8 CSV files
(MachineLearningCSV.zip). This script reads them and produces a
data/cicids2017_real.json file that QF-IDS loads in CICIDS mode.

USAGE:
    # 1. Download MachineLearningCSV.zip from
    #    https://www.unb.ca/cic/datasets/ids-2017.html
    # 2. Unzip it somewhere — you'll have ~8 CSV files like:
    #       Monday-WorkingHours.pcap_ISCX.csv
    #       Tuesday-WorkingHours.pcap_ISCX.csv
    #       Wednesday-workingHours.pcap_ISCX.csv
    #       Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
    #       ...
    # 3. Run this script:
    #
    #    python convert_cicids.py /path/to/unzipped/folder
    #
    # 4. It writes data/cicids2017_real.json (~2-5 MB after sampling).
    # 5. Restart QF-IDS — CICIDS mode now uses your real data.

WHAT IT DOES:
- Walks the folder, reads every CSV ending in _ISCX.csv
- Picks the 12 features QF-IDS uses (drops the other 66)
- Filters out malformed rows (CICIDS has some Inf/NaN values)
- Samples per-class (default: 600 BENIGN, 300 of each attack class)
  so the JSON stays under 5 MB. Use --no-sample for the full set.
- Normalises the label column (CICIDS uses inconsistent capitalisation)
- Writes the JSON in QF-IDS's expected schema
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import sys
from collections import defaultdict


# QF-IDS's 12-feature subset. CICIDS column names vary slightly across
# the 8 CSVs (extra spaces, inconsistent caps). We try multiple variants
# for each feature and use the first that matches.
FEATURE_VARIANTS = {
    "flow_duration_us":      ["Flow Duration"],
    "total_fwd_packets":     ["Total Fwd Packets", "Tot Fwd Pkts"],
    "total_bwd_packets":     ["Total Backward Packets", "Tot Bwd Pkts"],
    "fwd_packet_len_mean":   ["Fwd Packet Length Mean", "Fwd Pkt Len Mean"],
    "bwd_packet_len_mean":   ["Bwd Packet Length Mean", "Bwd Pkt Len Mean"],
    "flow_bytes_per_s":      ["Flow Bytes/s"],
    "flow_packets_per_s":    ["Flow Packets/s", "Flow Pkts/s"],
    "fwd_iat_mean_us":       ["Fwd IAT Mean"],
    "bwd_iat_mean_us":       ["Bwd IAT Mean"],
    "syn_flag_count":        ["SYN Flag Count", "SYN Flag Cnt"],
    "psh_flag_count":        ["PSH Flag Count", "PSH Flag Cnt"],
    "ack_flag_count":        ["ACK Flag Count", "ACK Flag Cnt"],
}

LABEL_COL_VARIANTS = ["Label", " Label"]

# Map CICIDS labels (which vary) into QF-IDS's canonical names
LABEL_NORMALISE = {
    "benign": ("BENIGN", False),
    "dos hulk": ("DoS Hulk", True),
    "dos goldeneye": ("DoS GoldenEye", True),
    "dos slowloris": ("DoS Slowloris", True),
    "dos slowhttptest": ("DoS Slowhttptest", True),
    "ddos": ("DDoS", True),
    "portscan": ("PortScan", True),
    "bot": ("Botnet", True),
    "ftp-patator": ("FTP-Patator", True),
    "ssh-patator": ("SSH-Patator", True),
    "infiltration": ("Infiltration", True),
    "web attack \u2013 brute force": ("Web Attack-Brute Force", True),
    "web attack \u2013 xss": ("Web Attack-XSS", True),
    "web attack \u2013 sql injection": ("Web Attack-SQL Injection", True),
    "heartbleed": ("Heartbleed", True),
}


def _resolve_columns(header: list[str]) -> tuple[dict, str | None]:
    """Map our feature names to actual column names in this CSV."""
    # Strip whitespace from headers to handle the "extra space" issue
    clean = [h.strip() for h in header]
    feat_map = {}
    for qfids_name, variants in FEATURE_VARIANTS.items():
        col = None
        for v in variants:
            if v in clean:
                col = clean.index(v)
                break
        if col is not None:
            feat_map[qfids_name] = col
    label_col = None
    for v in LABEL_COL_VARIANTS:
        if v.strip() in clean:
            label_col = clean.index(v.strip())
            break
    return feat_map, label_col


def _safe_float(s: str) -> float | None:
    """Parse a CICIDS value. Returns None for Inf, NaN, blanks, errors."""
    if s is None or s == "":
        return None
    try:
        v = float(s)
    except ValueError:
        return None
    if math.isnan(v) or math.isinf(v):
        return None
    return v


def _normalise_label(raw: str) -> tuple[str, bool] | None:
    if not raw:
        return None
    return LABEL_NORMALISE.get(raw.strip().lower())


def convert_folder(
    folder: str,
    sample_per_class: int | None = None,
    output: str | None = None,
) -> str:
    """Walk folder, read CSVs, sample, write JSON. Return output path."""
    if not os.path.isdir(folder):
        raise SystemExit(f"not a directory: {folder}")

    csv_files = sorted(
        os.path.join(folder, f)
        for f in os.listdir(folder)
        if f.lower().endswith(".csv")
    )
    if not csv_files:
        raise SystemExit(f"no CSV files found in {folder}")

    print(f"[convert] found {len(csv_files)} CSV file(s)")

    # First pass: tally how many rows of each class exist (so per-class
    # sampling can pick proportionally without loading everything into RAM)
    by_label: dict[str, list[dict]] = defaultdict(list)
    skipped = 0
    parsed = 0

    for path in csv_files:
        print(f"[convert] reading {os.path.basename(path)}…", flush=True)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if not header:
                    continue
                feat_map, label_col = _resolve_columns(header)
                if not feat_map or label_col is None:
                    print(f"  ⚠ couldn't map columns, skipping")
                    continue

                for row in reader:
                    parsed += 1
                    if len(row) <= max(*feat_map.values(), label_col):
                        skipped += 1
                        continue
                    norm = _normalise_label(row[label_col])
                    if norm is None:
                        skipped += 1
                        continue
                    label, is_attack = norm

                    feats = {}
                    bad = False
                    for name, idx in feat_map.items():
                        v = _safe_float(row[idx])
                        if v is None:
                            bad = True
                            break
                        feats[name] = v
                    if bad:
                        skipped += 1
                        continue

                    by_label[label].append({
                        "label": label,
                        "is_attack": is_attack,
                        "features": feats,
                    })
        except Exception as e:
            print(f"  ⚠ error: {e}")

    if not by_label:
        raise SystemExit("could not parse any rows — check the folder path")

    print(f"[convert] parsed {parsed:,} rows, skipped {skipped:,}")
    print(f"[convert] class counts:")
    for label, rows in sorted(by_label.items(), key=lambda kv: -len(kv[1])):
        print(f"           {label:24s}  {len(rows):>9,d}")

    # Sampling
    rng = random.Random(0xC1C1D5)
    if sample_per_class is None:
        flows = [r for rows in by_label.values() for r in rows]
        print(f"[convert] keeping ALL {len(flows):,} rows (no sampling)")
    else:
        flows = []
        for label, rows in by_label.items():
            n = min(len(rows), sample_per_class)
            flows.extend(rng.sample(rows, n))
        rng.shuffle(flows)
        print(f"[convert] sampled {len(flows):,} rows "
              f"(<= {sample_per_class}/class)")

    output = output or os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "data", "cicids2017_real.json",
    )
    output = os.path.abspath(output)
    os.makedirs(os.path.dirname(output), exist_ok=True)

    out = {
        "metadata": {
            "name": "CICIDS-2017 (UNB CIC, real CSVs)",
            "schema": "CICIDS-2017 (Sharafaldin et al., 2018)",
            "source_folder": os.path.abspath(folder),
            "feature_columns": list(FEATURE_VARIANTS.keys()),
            "n_flows": len(flows),
            "sample_per_class": sample_per_class,
            "class_counts": {k: len(v) for k, v in by_label.items()},
        },
        "flows": flows,
    }
    with open(output, "w") as f:
        json.dump(out, f)

    size_mb = os.path.getsize(output) / (1024 * 1024)
    print(f"[convert] wrote {output} ({size_mb:.1f} MB)")
    print()
    print("To use this dataset in QF-IDS:")
    print("  1. Edit backend/qfids/core/cicids_source.py")
    print("     change: cicids2017_subset.json → cicids2017_real.json")
    print("  2. Restart the backend")
    print("  3. Switch any channel to CICIDS mode in the dashboard")
    print()
    return output


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("folder",
                    help="folder containing the unzipped CICIDS-2017 CSVs")
    ap.add_argument("--sample", type=int, default=600,
                    help="max flows to keep per class (default 600). "
                         "Use --no-sample to keep everything.")
    ap.add_argument("--no-sample", action="store_true",
                    help="keep ALL rows (output JSON will be ~150 MB)")
    ap.add_argument("--output", default=None,
                    help="output JSON path (default: data/cicids2017_real.json)")
    args = ap.parse_args()
    convert_folder(
        args.folder,
        sample_per_class=None if args.no_sample else args.sample,
        output=args.output,
    )


if __name__ == "__main__":
    sys.exit(main())
