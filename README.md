<div align="center">

<!-- Animated Banner via capsule-render -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0d0221,50:0a3d62,100:00d2ff&height=200&section=header&text=QF-IDS&fontSize=80&fontColor=00d2ff&fontAlignY=38&desc=Quantum%20Fingerprint%20Intrusion%20Detection%20System&descAlignY=58&descSize=20&descColor=ffffff&animation=fadeIn" width="100%"/>

<!-- Typing animation -->
<a href="https://git.io/typing-svg">
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=22&pause=1000&color=00D2FF&center=true&vCenter=true&width=700&lines=Quantum+Key+Distribution+%E2%80%A2+BB84+Protocol;IsolationForest+Anomaly+Detection;Real-Time+Attack+Detection+%26+Response;Multi-Tier+Quantum+Honeypot+Deception;Detect+%E2%80%A2+Divert+%E2%80%A2+Encrypt" alt="Typing SVG" />
</a>

<br/><br/>

<!-- Badges Row 1 -->
![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-Vite-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)

<!-- Badges Row 2 -->
![Firebase](https://img.shields.io/badge/Firebase-Optional-FFCA28?style=for-the-badge&logo=firebase&logoColor=black)
![WebSocket](https://img.shields.io/badge/WebSocket-Live_Stream-4A90E2?style=for-the-badge&logo=socket.io&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

<br/>

> **⚛️ Quantum-Native Intrusion Defence · Detect · Divert · Encrypt**
>
> A physical-layer + quantum intrusion detection system that fingerprints communication channels — including a **real BB84 quantum key distribution protocol** — detects eavesdroppers via statistical anomaly scoring, diverts confirmed attackers to a quantum-randomized honeypot, and protects payload data with HQNN-derived encryption.

</div>

---

## 📺 Demo

<div align="center">

```
  ALICE                   CHANNEL                   BOB
    │   ──[↑ ↗ → ↘]──▶  eavesdropper (Eve)  ──▶  │
    │                         │                    │
    │   <── basis compare ────────────────────────>│
    │                                              │
    └──────── sifted key ──────────────────────────┘
                         │
               QBER ≈ 25% detected
                         │
               ┌─────────▼──────────┐
               │  🔴 ATTACK DETECTED │
               │  Response: DIVERT   │
               │  Honeypot: ACTIVE   │
               └────────────────────┘
```

</div>

---

## ✨ What Makes This Quantum?

<div align="center">

| Component | What It Does | Real / Simulated |
|:---:|:---|:---:|
| ⚛️ **BB84 Protocol** | Full Alice→Eve→Bob QKD with basis encoding, QBER estimation | ✅ Real Protocol |
| 🎲 **ANU QRNG** | Live quantum random numbers from Australian National University photon experiment | ✅ Real Measured Data |
| 🧠 **HQNN Encryption** | Hybrid Quantum Neural Network encryption keyed off BB84 sifted key | ✅ Exact State-Vector Sim |
| 📡 **CICIDS-2017** | Real UNB network intrusion benchmark dataset | ✅ Real Dataset |
| 🦠 **PCAP Capture** | Live network capture via scapy/libpcap (same engine as Wireshark) | ✅ Real Traffic |

</div>

---

## 🔬 BB84 Verified Results

```
Test: BB84 protocol · 400 pulses/window · real-fibre parameters

  eve_fraction   measured QBER   expected QBER   verdict
  ─────────────────────────────────────────────────────────
  0.00           0.0195          0.0240          ✅ SAFE
  0.25           0.0757          0.0865          ✅ SAFE (below 11% threshold)
  0.50           0.1394          0.1490          🔴 ABORT — Eve detected
  0.75           0.1988          0.2115          🔴 ABORT — Eve detected
  1.00           0.2500          0.2740          🔴 ABORT — Eve detected

  25% QBER under full intercept-resend ≡ Bennett-Brassard-Mermin 1992 ✓
```

---

## 🏗️ Architecture

<div align="center">

```
┌─────────────────────────────────────────────────────────────────┐
│                        QF-IDS PIPELINE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   DATA SOURCES          DETECTOR           RESPONSE ENGINE       │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ ⚛️  BB84·QKD  │    │              │    │  🔴 ATTACK →     │   │
│  │ 🎲 ANU·QRNG  │───▶│ 7-Feature    │───▶│  Terminate       │   │
│  │ 🌐 PCAP Live │    │ Statistical  │    │  Re-auth         │   │
│  │ 📁 PCAP File │    │ Fingerprint  │    │  Reroute         │   │
│  │ 📊 CICIDS    │    │      +       │    │  → Honeypot 🍯   │   │
│  │ 💾 DATASET   │    │ Isolation    │    │  → Block 🚫      │   │
│  │ 🔁 SIM       │    │ Forest       │    │  → Alert 🚨      │   │
│  └──────────────┘    └──────────────┘    └──────────────────┘   │
│                                                                  │
│   ENCRYPTION LAYER                                               │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  HQNN: plaintext → angle encode → PQC (RY/RZ/CNOT) →    │  │
│  │        measure → mix BB84 key + HKDF stream → ciphertext  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

</div>

---

## 🎮 Split Dashboards — Red Team vs Blue Team

<div align="center">

```
┌───────────────────────────┐     ┌───────────────────────────┐
│   🔵  DEFENDER DASHBOARD   │     │    🔴  ATTACKER CONSOLE    │
│   localhost:5173           │     │    localhost:8000/attacker │
├───────────────────────────┤     ├───────────────────────────┤
│ • Live channel waveforms  │     │ • Attacker fingerprint     │
│ • Anomaly scores          │◀───▶│ • Launch attack payloads   │
│ • Incident timeline       │     │ • See CLEAR/DIVERTED/      │
│ • Honeypot activity       │     │   BLOCKED lifecycle        │
│ • Attacker profiles       │     │ • Honeypot shell (fake)    │
│ • MITRE ATT&CK mapping    │     │ • Lockout screen on block  │
└───────────────────────────┘     └───────────────────────────┘
```

</div>

---

## 🍯 Honeypot Attacker Lifecycle

<div align="center">

```
  1st Attack          2nd Attack           Profiled
      │                   │                   │
      ▼                   ▼                   ▼
  ┌────────┐         ┌──────────┐        ┌─────────┐
  │ CLEAR  │────────▶│ DIVERTED │───────▶│ BLOCKED │
  └────────┘         └──────────┘        └─────────┘
  Delivered to       Redirected to        HTTP 403
  real channel       fake honeypot        at perimeter
                     shell (attacker      All controls
                     thinks it's real!)   disabled
                          │
                    ┌─────▼──────────────────────────┐
                    │  Quantum-randomised decoy data  │
                    │  ├─ banner → fake open ports    │
                    │  ├─ services → fake daemons     │
                    │  ├─ filesystem → fake files     │
                    │  ├─ database → fake tables      │
                    │  └─ creds → fake passwords      │
                    │                                 │
                    │  MITRE ATT&CK profiling         │
                    │  Aggression score tracking      │
                    └─────────────────────────────────┘
```

</div>

---

## 🛡️ Defence Layers

<div align="center">

| Layer | Defence | Defeats |
|:---:|:---|:---|
| 1️⃣ | **Adaptive Threshold + Pressure Accumulator** | Low-and-slow / evasion attacks hugging threshold |
| 2️⃣ | **Baseline Integrity Guard** | Data-poisoning / drift attacks on learned baseline |
| 3️⃣ | **Decoy-State Analyzer** | Photon-Number-Splitting (PNS) attacks on BB84 |
| 4️⃣ | **PSK + HMAC Channel Authenticator** | Man-in-the-middle impersonation on QKD channel |

</div>

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/yourusername/qfids.git
cd qfids

# ── Backend ──────────────────────────────────────────
cd backend
pip install -r requirements.txt
python run.py
# API live at http://localhost:8000

# ── Frontend (new terminal) ───────────────────────────
cd frontend
npm install
npm run dev
# UI live at http://localhost:5173
```

### ⚛️ Demo the Quantum Attack in 30 Seconds

```bash
# 1. Open http://localhost:5173
# 2. Click "⇄ Source" on any channel → select "BB84 · Quantum KD"
# 3. Wait 5 seconds for clean baseline training
# 4. Click "▸ full Eve (intercept-resend)"
# 5. Watch QBER jump from ~2% → ~25% and detector fire ATTACK
```

### 🎭 Demo the Red Team vs Blue Team

```bash
# Set 4 channels to 4 different real sources
curl -X POST http://localhost:8000/api/mode/ch-alpha -H "Content-Type: application/json" -d '{"mode":"bb84"}'
curl -X POST http://localhost:8000/api/mode/ch-beta  -H "Content-Type: application/json" -d '{"mode":"cicids"}'
curl -X POST http://localhost:8000/api/mode/ch-gamma -H "Content-Type: application/json" -d '{"mode":"anu_qrng"}'
curl -X POST http://localhost:8000/api/mode/ch-delta -H "Content-Type: application/json" -d '{"mode":"pcap_file"}'
# Then open http://localhost:8000/attacker and launch attacks
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
|:---:|:---|:---|
| `GET` | `/api/channels` | Snapshot of all channels |
| `GET` | `/api/incidents` | All incidents |
| `GET` | `/api/blocklist` | Blocklisted entries |
| `POST` | `/api/attack` | Inject attack payload |
| `POST` | `/api/mode/{channel_id}` | Switch channel data source |
| `POST` | `/api/bb84/eve/{channel_id}` | **Set Eve interception fraction (0.0–1.0)** |
| `POST` | `/api/pcap/upload/{channel_id}` | Upload `.pcap` file (multipart) |
| `GET` | `/api/sources/health` | Source diagnostics |
| `GET` | `/api/hqnn/avalanche` | Key-avalanche diffusion test (~50%) |
| `GET` | `/api/defenses/self-test` | Run all 4 defence layer tests |
| `WS` | `/ws` | Live tick stream |

---

## 📁 Project Structure

```
qfids/
├── backend/
│   ├── data/
│   │   ├── quantum_noise_dataset.json     ← Excelitas SPCM real device params
│   │   └── cicids2017_subset.json         ← Bundled benchmark data
│   ├── tools/
│   │   ├── attacker.py                    ← Real-traffic attack tool
│   │   └── convert_cicids.py              ← CICIDS CSV converter
│   └── qfids/core/
│       ├── bb84.py                        ★ BB84 protocol implementation
│       ├── bb84_source.py                 ★ BB84 → detector bridge
│       ├── anu_qrng_source.py             ← Live ANU quantum API
│       ├── hqnn.py                        ← HQNN encryption engine
│       ├── detector.py                    ← IsolationForest pipeline
│       ├── response.py                    ← Response engine
│       ├── quantum_honeypot.py            ← Multi-tier honeypot
│       ├── defenses.py                    ← 4 loophole mitigations
│       └── manager.py                     ← Channel orchestrator
├── frontend/src/
│   ├── App.jsx
│   └── components/
│       ├── ChannelCard.jsx                ← BB84 Eve control widget
│       ├── HoneypotPanel.jsx
│       ├── AttackersPanel.jsx
│       └── ...
└── customer-portal/                       ← Multi-tenant customer portal
```

---

## 📚 References

- Bennett, C. H. & Brassard, G. (1984). *Quantum cryptography: Public key distribution and coin tossing.* IEEE ICCSS, 175–179.
- Bennett, C. H., Brassard, G., & Mermin, N. D. (1992). *Quantum cryptography without Bell's theorem.* Physical Review Letters, 68(5), 557.
- Sharafaldin et al. (2018). *Toward generating a new intrusion detection dataset.* ICISSP.
- Excelitas Technologies. *SPCM-AQRH single-photon counting module datasheet.*
- Symul, T., Assad, S. M., & Lam, P. K. (2011). *Real time demonstration of high bitrate QRNG.* Applied Physics Letters, 98(23).

---

<div align="center">

<!-- Footer wave -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00d2ff,50:0a3d62,100:0d0221&height=120&section=footer" width="100%"/>

**Built with ⚛️ quantum principles · 🛡️ real security research · 🐍 Python + ⚛️ React**

![Visitors](https://visitor-badge.lbs.today/badge?page_id=qfids.readme)

</div>
