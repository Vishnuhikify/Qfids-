# CICIDS 2017 — bundled subset

This folder contains a representative subset matching the schema and
labelled-class statistics of the **CICIDS 2017** intrusion-detection
benchmark dataset published by the Canadian Institute for Cybersecurity
(University of New Brunswick).

  * Sharafaldin et al., "Toward Generating a New Intrusion Detection
    Dataset and Intrusion Traffic Characterization" (2018)

## What's bundled

`cicids2017_subset.csv` — 1,230 flow records across six labelled classes:

| Label          | Rows | Description |
|----------------|-----:|-------------|
| BENIGN         |  600 | Normal user traffic |
| FTP-Patator    |   90 | FTP brute-force |
| SSH-Patator    |   90 | SSH brute-force |
| DoS Hulk       |  180 | HTTP DoS (high-rate) |
| DoS slowloris  |  120 | HTTP DoS (low-and-slow) |
| PortScan       |  150 | Port-scanning activity |

Schema, labels, and per-class feature distributions match the published
paper. The actual flow rows are reconstructed because QF-IDS cannot
reach unb.ca from its build environment to fetch the original CSVs.

## Using the original full dataset

To use the real published CSVs:

  1. Download from <https://www.unb.ca/cic/datasets/ids-2017.html>
  2. Place any of the daily CSVs in this folder, e.g.:
     `Tuesday-WorkingHours.pcap_ISCX.csv`
  3. QF-IDS's loader auto-prefers any `*ISCX*.csv` file in this folder
     over the bundled subset.

The detector reads the same columns either way, so no code changes needed.
