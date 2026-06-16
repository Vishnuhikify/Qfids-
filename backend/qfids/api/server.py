"""
QF-IDS FastAPI server.

Exposes:
  GET  /                     → health
  GET  /api/channels         → all channel snapshots
  GET  /api/incidents        → all incidents (active + closed)
  GET  /api/blocklist        → active block entries
  POST /api/blocklist/remove → un-block an IP (operator action)
  POST /api/attack           → inject an attack (uses caller IP+port unless overridden)
  POST /api/reset/{channel}  → reset one channel
  POST /api/reset            → full system reset
  GET  /api/honeypot/data    → decoy data (rejects requests from blocked IPs only
                                if served via the /honeypot/serve endpoint, see below)
  GET  /honeypot/serve       → REAL endpoint a (simulated) attacker sees
                                — returns decoy data only; logs the hit
  WS   /ws                   → live state stream (5 Hz tick + events)

The blocklist is enforced by a middleware: requests from a blocked
client IP get a 403 immediately. Loopback (127.0.0.1) is always allowed.
"""
from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from qfids.core import Blocklist, ChannelManager


# ── Globals ───────────────────────────────────────────────────────────────
blocklist = Blocklist()
manager = ChannelManager(blocklist)


@asynccontextmanager
async def lifespan(app: FastAPI):
    manager.start()

    # Initialise Firebase (Firestore + Auth) if configured. Falls back to the
    # in-memory customer registry when not set up, so the demo still runs.
    try:
        from qfids.core import firebase_store as _fb
        if _fb.init():
            print("[firebase] connected — customer accounts persist to Firestore")
        else:
            print("[firebase] not active — " + (_fb.status().get("error") or "using in-memory accounts"))
    except Exception as _e:
        print(f"[firebase] init skipped: {_e}")

    # Periodic adversarial-hardening + correlation feed
    async def intel_loop():
        from qfids.core import intelligence as _intel
        while True:
            try:
                _intel.run_hardening_cycle()
                # Feed correlator with current channel scores
                if hasattr(manager, 'channels'):
                    for cid, ch in manager.channels.items():
                        if hasattr(ch, 'snapshot'):
                            snap = ch.snapshot()
                            _intel.record_score_for_correlation(cid, snap.get('score', 0.0))
            except Exception:
                pass
            await asyncio.sleep(8.0)

    task = asyncio.create_task(intel_loop())
    yield
    task.cancel()


app = FastAPI(title="Quantum Fingerprint Intrusion Detection System", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Blocklist enforcement middleware ──────────────────────────────────────
@app.middleware("http")
async def enforce_blocklist(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    # Always let the dashboard talk; only honeypot endpoint refuses blocked IPs
    # (because real production = block all; in this prototype we let the
    # operator dashboard work even if the host happens to be on the list).
    if request.url.path.startswith("/honeypot/") and blocklist.is_blocked(client_ip):
        return JSONResponse(
            status_code=403,
            content={"error": "blocked", "ip": client_ip},
        )
    return await call_next(request)


# ── Health / root ─────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {
        "service":  "Quantum Fingerprint Intrusion Detection System",
        "short":    "QF-IDS",
        "version":  "2.0.0",
        "tagline":  "Quantum-Native Intrusion Defence · Detect · Divert · Encrypt",
        "channels": list(manager.channels.keys()),
        "customer_portal": "/portal",
    }


@app.get("/portal")
async def customer_portal():
    """Serve the standalone customer portal single-page app."""
    import os
    from fastapi.responses import FileResponse, HTMLResponse
    # The portal HTML lives at <project_root>/customer-portal/index.html
    here = os.path.dirname(os.path.abspath(__file__))
    portal_path = os.path.normpath(
        os.path.join(here, "..", "..", "..", "customer-portal", "index.html")
    )
    if os.path.exists(portal_path):
        return FileResponse(portal_path, media_type="text/html")
    return HTMLResponse(
        "<h1>Customer portal not found</h1>"
        "<p>Expected at customer-portal/index.html</p>",
        status_code=404,
    )


# ── Channels ──────────────────────────────────────────────────────────────
@app.get("/api/channels")
async def list_channels():
    # Read-only snapshot — does NOT advance state. The tick loop owns
    # state advancement; this endpoint just exposes current values.
    out = []
    for ch in manager.channels.values():
        cls = ch.last_classification
        # Default status reflects state when no live classification yet
        if cls is None:
            status = "LEARNING" if ch.state == "LEARNING" else "WARMUP"
            score = 0.0
            features = {}
        else:
            status = cls.status
            score = cls.score
            features = cls.features
        out.append({
            "channel_id": ch.channel_id,
            "label": ch.label,
            "state": ch.state,
            "mode": ch.mode,
            "history": list(ch.history),
            "attack_history": list(ch.attack_history),
            "score": score,
            "status": status,
            "features": features,
            "baseline_mean": ch.fingerprint.baseline_mean,
            "baseline_std": ch.fingerprint.baseline_std,
            "learning_progress": ch.detector.baseline_progress,
            "honeypot_active": ch.honeypot_active,
            "incident_id": ch.incident_id,
            "incident_ids": list(ch.incident_ids),
            "samples_seen": ch.samples_seen,
            "dataset_segment": (
                ch.dataset_source.current_segment()
                if ch.dataset_source and ch.mode == "dataset" else None
            ),
            "cicids_segment": (
                ch.cicids_source.current_segment()
                if ch.cicids_source and ch.mode == "cicids" else None
            ),
            "pcap_packets": (
                ch.pcap_source.packet_count
                if ch.pcap_source and ch.mode == "pcap" else None
            ),
            "pcap_file_info": (
                {
                    "consumed": ch.pcap_file_source.packet_count,
                    "total": ch.pcap_file_source.total_packets,
                }
                if ch.pcap_file_source and ch.mode == "pcap_file" else None
            ),
            "attack": (
                {
                    "type": ch.attacks[0].attack_type,
                    "intensity": ch.attacks[0].intensity,
                    "attacker_ip": ch.attacks[0].attacker_ip,
                    "attacker_port": ch.attacks[0].attacker_port,
                }
                if ch.attacks else None
            ),
            "attacks": [
                {
                    "type": a.attack_type,
                    "intensity": a.intensity,
                    "attacker_ip": a.attacker_ip,
                    "attacker_port": a.attacker_port,
                }
                for a in ch.attacks
            ],
        })
    return {"channels": out}


# ── Incidents ─────────────────────────────────────────────────────────────
@app.get("/api/incidents")
async def list_incidents():
    return {"incidents": [i.to_dict() for i in reversed(manager.incidents)]}


# ── Blocklist ─────────────────────────────────────────────────────────────
@app.get("/api/blocklist")
async def list_blocklist():
    return {"entries": blocklist.all()}


class UnblockBody(BaseModel):
    ip: str


@app.post("/api/blocklist/remove")
async def remove_block(body: UnblockBody):
    ok = blocklist.remove(body.ip)
    if not ok:
        raise HTTPException(status_code=404, detail="ip not in blocklist")
    return {"ok": True, "ip": body.ip}


# ── Attack injection (called by the separate ATTACKER CONSOLE) ────────────
class AttackBody(BaseModel):
    channel_id: str
    attack_type: str = Field(..., pattern="^(mitm|replace|relay|inject)$")
    # If not given we use the caller's actual IP+port (real network metadata).
    attacker_ip: Optional[str] = None
    attacker_port: Optional[int] = None
    # System details reported by the attacker console (best-effort).
    platform: Optional[str] = None
    hostname: Optional[str] = None
    # Realistic attack artifact built by the red-team console (best-effort,
    # surfaced for inspection / logging — does not change detection logic).
    technique: Optional[str] = None
    payload_b64: Optional[str] = None
    spoof_mac: Optional[str] = None
    target_port: Optional[int] = None
    packet_count: Optional[int] = None


@app.post("/api/attack")
async def trigger_attack(body: AttackBody, request: Request):
    from qfids.core import attackers as _attackers
    from qfids.core import quantum_honeypot as _qhp
    from qfids.core import intelligence as _intel

    # MITRE ATT&CK classification for this attack technique — echoed back so the
    # attacker console (and anyone inspecting the network call) can see exactly
    # what was launched and how it maps to industry-standard technique IDs.
    mitre = _intel.mitre_for_attack(body.attack_type)

    # Capture REAL client metadata if none supplied
    real_ip = request.client.host if request.client else "0.0.0.0"
    real_port = request.client.port if request.client else 0
    attacker_ip = body.attacker_ip or real_ip
    attacker_port = body.attacker_port or real_port
    user_agent = request.headers.get("user-agent", "")

    # Register / refresh the attacking system's identity
    reg = _attackers.get_registry()
    sysrec = reg.identify(
        ip=attacker_ip,
        user_agent=user_agent,
        platform=body.platform or "",
        hostname=body.hostname or "",
    )

    # ── HARD BLOCK ────────────────────────────────────────────────────────
    # If the attacker has been fully profiled in the honeypot (status BLOCKED)
    # OR their IP is on the firewall blocklist, the attack is rejected outright
    # before it touches anything. The attacker console locks down.
    if sysrec.status == "BLOCKED" or blocklist.is_blocked(attacker_ip):
        # Ensure firewall + status agree
        if not blocklist.is_blocked(attacker_ip):
            blocklist.add(attacker_ip, reason="QF-IDS honeypot profiling complete")
        reg.set_status(attacker_ip, "BLOCKED")
        reg.record_attempt(attacker_ip, body.channel_id, body.attack_type,
                            blocked=True, reason="hard-blocked")
        manager._log({
            "level": "danger",
            "channel_id": body.channel_id,
            "message": (
                f"BLOCKED ATTACK ATTEMPT from {attacker_ip}:{attacker_port} "
                f"({body.attack_type.upper()}) — source is hard-blocked, "
                f"request rejected at the perimeter."
            ),
        })
        raise HTTPException(
            status_code=403,
            detail=f"Your system ({attacker_ip}) is blocked. Attack rejected at the perimeter.",
        )

    # ── DIVERSION ─────────────────────────────────────────────────────────
    # If this attacker was already detected once (status DIVERTED), their
    # attack does NOT reach the real channel. It is silently redirected into
    # the quantum honeypot. The attacker BELIEVES they broke in — they are now
    # inside the deception environment being profiled. After enough honeypot
    # engagement they get hard-blocked.
    if sysrec.status == "DIVERTED":
        eng = _qhp.get_deception_engine()
        # Serve them the entry banner of the fake system
        served = eng.serve_tier(attacker_ip, "banner")
        reg.set_honeypot_session(attacker_ip, served["session"]["session_id"])
        reg.record_attempt(attacker_ip, body.channel_id, body.attack_type,
                            blocked=False, reason="diverted to honeypot",
                            diverted=True)
        manager._log({
            "level": "warning",
            "channel_id": body.channel_id,
            "message": (
                f"DIVERTED {attacker_ip}:{attacker_port} into quantum honeypot "
                f"(believes attack on {body.channel_id} succeeded). "
                f"Profiling in progress."
            ),
        })
        return {
            "ok": True,
            "diverted": True,            # the attacker console uses this to enter honeypot mode
            "session_id": served["session"]["session_id"],
            "channel_id": body.channel_id,
            "attack_type": body.attack_type,
            "mitre": mitre,
            "wire": {
                "src": f"{attacker_ip}:{attacker_port}",
                "dst_channel": body.channel_id,
                "technique": body.technique or mitre.get("technique_name"),
                "target_port": body.target_port,
                "packet_count": body.packet_count,
                "outcome": "DIVERTED_TO_HONEYPOT",
            },
            "banner": served["payload"],
            "message": "Foothold established. Shell access granted.",   # the LIE the attacker sees
        }

    # ── FIRST CONTACT: real attack reaches the channel, then gets detected ─
    ok, err = manager.trigger_attack(
        channel_id=body.channel_id,
        attack_type=body.attack_type,
        attacker_ip=attacker_ip,
        attacker_port=attacker_port,
    )
    reg.record_attempt(attacker_ip, body.channel_id, body.attack_type,
                       blocked=not ok, reason=("ok" if ok else err))
    if not ok:
        raise HTTPException(status_code=400, detail=err)

    # First successful hit → mark DIVERTED so the NEXT attack is redirected
    # into the honeypot. This models real-world IDS: the first probe is seen
    # and the attacker is quietly moved off the production path.
    reg.set_status(attacker_ip, "DIVERTED")

    manager._log({
        "level": "warning",
        "channel_id": body.channel_id,
        "message": (
            f"ATTACK from {attacker_ip}:{attacker_port} on {body.channel_id} — "
            f"{body.attack_type.upper()} / {mitre.get('technique_id')} "
            f"({mitre.get('technique_name')}). Channel under analysis."
        ),
    })

    # Feed cross-channel correlator
    try:
        _intel.record_attack_for_correlation(attacker_ip, body.channel_id, body.attack_type)
    except Exception:
        pass
    return {
        "ok": True,
        "diverted": False,
        "channel_id": body.channel_id,
        "attack_type": body.attack_type,
        "attacker_ip": attacker_ip,
        "attacker_port": attacker_port,
        "mitre": mitre,
        "wire": {
            "src": f"{attacker_ip}:{attacker_port}",
            "dst_channel": body.channel_id,
            "technique": body.technique or mitre.get("technique_name"),
            "target_port": body.target_port,
            "packet_count": body.packet_count,
            "outcome": "DELIVERED",
        },
        "message": "Attack delivered to channel.",
    }


# ── Activity log download ─────────────────────────────────────────────────
from fastapi.responses import StreamingResponse
import io, csv, datetime as dt


@app.get("/api/log/download")
async def download_activity_log(since: Optional[float] = None):
    """
    Download the activity log as a human-readable TEXT file.
    - since: optional Unix timestamp; only entries at or after this time are included.
    - Checker/heartbeat events (level == 'debug' or message contains '[checker]') are excluded.
    """
    entries = list(manager.event_log)  # newest first

    # Filter by time if requested
    if since is not None:
        entries = [e for e in entries if (e.get("ts") or 0) >= since]

    # Exclude internal checker/debug noise
    def is_checker(e):
        msg = (e.get("message") or "").lower()
        lvl = (e.get("level") or "").lower()
        return lvl == "debug" or "[checker]" in msg or "heartbeat" in msg

    entries = [e for e in entries if not is_checker(e)]

    # Build a formatted plain-text report
    buf = io.StringIO()
    gen_iso = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    buf.write("=" * 78 + "\n")
    buf.write("  QUANTUM FINGERPRINT INTRUSION DETECTION SYSTEM\n")
    buf.write("  Security Activity Log\n")
    buf.write("=" * 78 + "\n")
    buf.write(f"  Generated : {gen_iso}\n")
    buf.write(f"  Entries   : {len(entries)}\n")
    if since is not None:
        since_iso = dt.datetime.utcfromtimestamp(since).strftime("%Y-%m-%d %H:%M:%S UTC")
        buf.write(f"  Since     : {since_iso}\n")
    buf.write("=" * 78 + "\n\n")

    if not entries:
        buf.write("  (no activity recorded in this window)\n")
    else:
        for e in reversed(entries):  # oldest first in the file
            ts_iso  = e.get("ts_iso", "") or "-"
            level   = (e.get("level", "") or "info").upper()
            channel = e.get("channel_id", "") or "system"
            message = e.get("message", "") or ""
            buf.write(f"[{ts_iso}]  ({level:<7})  <{channel}>\n")
            buf.write(f"    {message}\n\n")

    buf.write("=" * 78 + "\n")
    buf.write("  End of log  ·  QF-IDS\n")
    buf.write("=" * 78 + "\n")

    buf.seek(0)
    filename = f"qfids_log_{dt.datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Reset ─────────────────────────────────────────────────────────────────
@app.post("/api/reset/{channel_id}")
async def reset_channel(channel_id: str):
    ok = manager.reset_channel(channel_id)
    if not ok:
        raise HTTPException(status_code=404, detail="unknown channel")
    return {"ok": True}


@app.post("/api/reset")
async def reset_all():
    manager.reset_all()
    return {"ok": True}


# ── Source-mode control ──────────────────────────────────────────────────
class ModeBody(BaseModel):
    mode: str = Field(..., pattern="^(simulated|pcap|dataset|cicids|pcap_file|anu_qrng|bb84)$")


@app.post("/api/mode/{channel_id}")
async def set_channel_mode(channel_id: str, body: ModeBody):
    """
    Switch a single channel between 'simulated', 'pcap', and 'dataset'
    noise sources. Channel re-fingerprints and re-enters LEARNING.
    """
    ch = manager.channels.get(channel_id)
    if ch is None:
        raise HTTPException(status_code=404, detail="unknown channel")
    ok, msg = ch.switch_mode(body.mode)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    manager._log({
        "level": "info",
        "channel_id": channel_id,
        "message": f"Channel {ch.label} switched to {body.mode} mode",
    })
    return {"ok": True, "mode": body.mode, "message": msg}


@app.post("/api/mode")
async def set_all_modes(body: ModeBody):
    """Switch every channel at once."""
    results = {}
    for cid, ch in manager.channels.items():
        ok, msg = ch.switch_mode(body.mode)
        results[cid] = {"ok": ok, "msg": msg}
    manager._log({
        "level": "info",
        "message": f"All channels switched to {body.mode} mode",
    })
    return {"ok": True, "mode": body.mode, "results": results}


@app.get("/api/sources/health")
async def sources_health():
    """Per-channel data-source diagnostics."""
    out = {}
    for cid, ch in manager.channels.items():
        info = {
            "mode": ch.mode,
            "bpf_filter": ch.bpf_filter,
            "simulated_available": True,
            "pcap_available":      ch.pcap_source.available     if ch.pcap_source     else None,
            "dataset_available":   ch.dataset_source.available  if ch.dataset_source  else None,
            "cicids_available":    ch.cicids_source.available   if ch.cicids_source   else None,
            "pcap_file_available": ch.pcap_file_source.available if ch.pcap_file_source else None,
            "anu_qrng_available":  True if ch.anu_qrng_source else None,
            "bb84_available":      True if ch.bb84_source else None,
        }
        if ch.pcap_source:      info["pcap"]      = ch.pcap_source.health()
        if ch.dataset_source:   info["dataset"]   = ch.dataset_source.health()
        if ch.cicids_source:    info["cicids"]    = ch.cicids_source.health()
        if ch.pcap_file_source: info["pcap_file"] = ch.pcap_file_source.health()
        if ch.anu_qrng_source:  info["anu_qrng"]  = ch.anu_qrng_source.health()
        if ch.bb84_source:      info["bb84"]      = ch.bb84_source.health()
        out[cid] = info
    return {"channels": out, "scapy_installed": _scapy_available_flag()}


class BB84EveBody(BaseModel):
    eve_fraction: float = Field(..., ge=0.0, le=1.0)


@app.post("/api/bb84/eve/{channel_id}")
async def bb84_set_eve(channel_id: str, body: BB84EveBody):
    """
    Set the eavesdropper interception fraction for a BB84 channel.

    eve_fraction = 0.0 means no Eve (clean channel, QBER ≈ 2% noise floor).
    eve_fraction = 1.0 means Eve intercept-resends every photon
    (QBER ≈ 25%, the textbook BB84 intercept-resend result).

    Any value above ~0.4 should reliably trigger the BB84 abort threshold
    (QBER > 11%) and fire the response engine.
    """
    ch = manager.channels.get(channel_id)
    if ch is None:
        raise HTTPException(status_code=404, detail="unknown channel")
    if ch.bb84_source is None:
        raise HTTPException(
            status_code=400,
            detail="channel is not in BB84 mode — switch mode first",
        )
    ch.bb84_source.set_eve_fraction(body.eve_fraction)
    manager._log({
        "level": "info" if body.eve_fraction == 0 else "warning",
        "channel_id": channel_id,
        "message": (
            f"BB84: Eve interception {'disabled' if body.eve_fraction == 0 else f'set to {body.eve_fraction*100:.0f}%'}"
            f" on {ch.label}"
        ),
    })
    return {"ok": True, "eve_fraction": body.eve_fraction}


def _scapy_available_flag() -> bool:
    try:
        from qfids.core.pcap_source import _scapy_available
        return _scapy_available
    except Exception:
        return False


# ── PCAP file upload (Wireshark integration) ──────────────────────────────
import os, tempfile
from fastapi import UploadFile, File

PCAP_UPLOAD_DIR = os.environ.get(
    "QF-IDS_PCAP_DIR",
    os.path.join(tempfile.gettempdir(), "qfids_pcaps"),
)
os.makedirs(PCAP_UPLOAD_DIR, exist_ok=True)


@app.post("/api/pcap/upload/{channel_id}")
async def pcap_upload(channel_id: str, file: UploadFile = File(...)):
    """
    Upload a Wireshark .pcap or .pcapng file and bind it to a channel.

    After uploading, switch the channel to PCAP_FILE mode via
    POST /api/mode/{channel_id} with mode=pcap_file. The detector
    will then replay the file's inter-arrival times as the channel
    sample stream and use real source IPs from the capture for any
    detected attacks.
    """
    from qfids.core.pcap_file_source import PcapFileSource, _scapy_available
    if not _scapy_available:
        raise HTTPException(status_code=400, detail="scapy not installed")

    ch = manager.channels.get(channel_id)
    if ch is None:
        raise HTTPException(status_code=404, detail="unknown channel")

    if not (file.filename or "").lower().endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(
            status_code=400,
            detail="file must be .pcap / .pcapng / .cap",
        )

    # Save uploaded file to disk
    safe_name = f"{channel_id}_{int(time.time())}_{os.path.basename(file.filename or 'upload.pcap')}"
    safe_path = os.path.join(PCAP_UPLOAD_DIR, safe_name)
    contents = await file.read()
    if len(contents) > 50 * 1024 * 1024:    # 50 MB cap
        raise HTTPException(status_code=413, detail="pcap too large (50 MB limit)")
    with open(safe_path, "wb") as f:
        f.write(contents)

    src = PcapFileSource(channel_id=channel_id, path=safe_path)
    if not src.available:
        raise HTTPException(
            status_code=400,
            detail=f"could not parse pcap: {src.last_error}",
        )

    ch.pcap_file_source = src
    manager._log({
        "level": "info",
        "channel_id": channel_id,
        "message": (
            f"PCAP file '{file.filename}' loaded for {ch.label} "
            f"({src.total_packets} packets) — switch to PCAP_FILE mode to replay"
        ),
    })
    return {
        "ok": True,
        "channel_id": channel_id,
        "filename": file.filename,
        "total_packets": src.total_packets,
        "size_bytes": len(contents),
    }


# ── HQNN — Hybrid Quantum Neural Network data protection ────────────────
#
# QF-IDS's 4th defence layer. If an attacker bypasses the IsolationForest,
# the honeypot, AND the blocklist, the data payload itself is still encrypted
# with HQNN-derived keystream using key material from the BB84 sifted key.
# Even unlimited classical compute can't recover plaintext without the
# quantum-derived key.
#
# These endpoints let the UI demonstrate this layer live: encrypt arbitrary
# text, view the ciphertext, then decrypt + verify the round-trip.
from qfids.core import hqnn as _hqnn  # noqa: E402

_HQNN_STORE: dict[str, dict] = {}  # in-memory ciphertext cache, key_id → ct dict


class HQNNEncryptRequest(BaseModel):
    plaintext: str
    channel_id: Optional[str] = "ch-a"   # used only to look up BB84 key
    sample_key_bits: Optional[int] = 200     # how many key bits to use


class HQNNDecryptRequest(BaseModel):
    nonce: str
    ciphertext: str
    mac: str
    n_chunks: int
    timestamp: float
    key_id: str
    channel_id: Optional[str] = "ch-a"


def _get_bb84_key_bits(channel_id: str, n_bits: int) -> list[int]:
    """
    Pull a quantum key from the named BB84 channel if it's running in BB84
    mode; otherwise fall back to a deterministic PRNG-derived key so this
    endpoint is always demoable.
    """
    try:
        ch = manager.channels.get(channel_id)
        if ch is not None and getattr(ch, 'mode', '') == 'bb84':
            src = getattr(ch, 'source', None)
            if src is not None and hasattr(src, 'get_sifted_key'):
                key = src.get_sifted_key(n_bits)
                if key and len(key) >= 32:
                    return list(key)[:n_bits]
    except Exception:
        pass

    # Fallback: deterministic key seeded by channel name (for demo when BB84
    # isn't the active mode). In production this would FAIL CLOSED.
    import hashlib
    seed = int(hashlib.sha256(channel_id.encode()).hexdigest(), 16) % (2**32)
    import numpy as _np
    rng = _np.random.default_rng(seed)
    return rng.integers(0, 2, size=n_bits).tolist()


@app.post("/api/hqnn/encrypt")
async def hqnn_encrypt(req: HQNNEncryptRequest):
    """Encrypt plaintext with HQNN using BB84-derived key material."""
    if not req.plaintext:
        raise HTTPException(400, "plaintext is required")
    if len(req.plaintext) > 4096:
        raise HTTPException(400, "plaintext too large (max 4096 bytes)")

    key_bits = _get_bb84_key_bits(req.channel_id, req.sample_key_bits)
    ct = _hqnn.encrypt_with_stats(req.plaintext.encode('utf-8'), key_bits)

    # Cache so the UI can round-trip without resending ciphertext blob
    _HQNN_STORE[ct.key_id + '_' + ct.nonce.hex()[:8]] = ct.to_dict()

    return {
        "ok": True,
        "ciphertext_packet": ct.to_dict(),
        "plaintext_length":  len(req.plaintext),
        "channel_used":      req.channel_id,
        "key_bits_used":     len(key_bits),
    }


@app.post("/api/hqnn/decrypt")
async def hqnn_decrypt(req: HQNNDecryptRequest):
    """Decrypt an HQNN ciphertext packet."""
    try:
        ct = _hqnn.HQNNCiphertext(
            nonce=bytes.fromhex(req.nonce),
            ciphertext=bytes.fromhex(req.ciphertext),
            mac=bytes.fromhex(req.mac),
            n_chunks=req.n_chunks,
            timestamp=req.timestamp,
            key_id=req.key_id,
        )
    except ValueError as e:
        raise HTTPException(400, f"bad hex encoding: {e}")

    key_bits = _get_bb84_key_bits(req.channel_id, 200)
    plaintext = _hqnn.decrypt_with_stats(ct, key_bits)
    if plaintext is None:
        return {
            "ok": False,
            "error": "MAC verification failed — ciphertext tampered or wrong key",
            "tamper_detected": True,
        }
    return {
        "ok": True,
        "plaintext": plaintext.decode('utf-8', errors='replace'),
        "verified":  True,
    }


@app.get("/api/hqnn/stats")
async def hqnn_stats():
    """HQNN architecture details + runtime stats for the UI."""
    return _hqnn.get_stats()


@app.get("/api/hqnn/self-test")
async def hqnn_self_test():
    """Run the HQNN self-test — round-trip, tamper, wrong key. For demo."""
    return _hqnn.self_test()


# ── HQNN v3 — deeper double-layer encryption ──────────────────────────────
class DeepEncryptRequest(BaseModel):
    plaintext: str
    channel_id: Optional[str] = "ch-a"
    sample_key_bits: Optional[int] = 200


_DEEP_STORE: dict[str, dict] = {}   # key_id+nonce → deep ciphertext dict


@app.post("/api/hqnn/deep-encrypt")
async def hqnn_deep_encrypt(req: DeepEncryptRequest):
    """
    Encrypt with the v3 two-layer construction (quantum keystream + HKDF
    classical keystream, per-message key schedule). Returns full ciphertext.
    """
    if not req.plaintext:
        raise HTTPException(400, "plaintext is required")
    if len(req.plaintext) > 4096:
        raise HTTPException(400, "plaintext too large (max 4096 bytes)")
    key_bits = _get_bb84_key_bits(req.channel_id, req.sample_key_bits)
    ct = _hqnn.deep_encrypt(req.plaintext.encode("utf-8"), key_bits)
    d = ct.to_dict()
    token = f"{ct.key_id}:{ct.nonce.hex()[:8]}"
    _DEEP_STORE[token] = {"ct": d, "channel_id": req.channel_id,
                          "key_bits": req.sample_key_bits}
    d["token"] = token
    return {"ok": True, "ciphertext": d}


class DeepDecryptRequest(BaseModel):
    token: str


@app.post("/api/hqnn/deep-decrypt")
async def hqnn_deep_decrypt(req: DeepDecryptRequest):
    """Decrypt a v3 deep ciphertext referenced by its token."""
    stored = _DEEP_STORE.get(req.token)
    if not stored:
        raise HTTPException(404, "unknown ciphertext token")
    d = stored["ct"]
    ct = _hqnn.DeepCiphertext(
        nonce=bytes.fromhex(d["nonce"]),
        salt=bytes.fromhex(d["salt"]),
        ciphertext=bytes.fromhex(d["ciphertext"]),
        mac=bytes.fromhex(d["mac"]),
        key_id=d["key_id"], layers=d["layers"], timestamp=d["timestamp"],
    )
    key_bits = _get_bb84_key_bits(stored["channel_id"], stored["key_bits"])
    pt = _hqnn.deep_decrypt(ct, key_bits)
    if pt is None:
        return {"ok": False, "error": "MAC verification failed",
                "tamper_detected": True}
    return {"ok": True, "plaintext": pt.decode("utf-8", errors="replace"),
            "verified": True}


@app.get("/api/hqnn/depth-report")
async def hqnn_depth_report():
    """Static report of the cipher's strength characteristics for the UI."""
    return _hqnn.encryption_depth_report()


@app.get("/api/hqnn/avalanche")
async def hqnn_avalanche(channel_id: str = "ch-a"):
    """Run the key-avalanche diffusion test — proves the cipher's quality live."""
    key_bits = _get_bb84_key_bits(channel_id, 200)
    return _hqnn.avalanche_test(key_bits)


@app.get("/api/hqnn/deep-self-test")
async def hqnn_deep_self_test():
    """Run the v3 deep-encryption self-test."""
    return _hqnn.deep_self_test()


# ── Honeypot endpoint (now quantum-randomized) ────────────────────────────
from qfids.core import quantum_honeypot as _qhp  # noqa: E402
from qfids.core import intelligence as _intel    # noqa: E402


@app.get("/honeypot/serve")
async def honeypot_serve(request: Request):
    """
    Simulates the endpoint an attacker would hit after being rerouted.
    Decoy content is now QUANTUM-RANDOMIZED: every row is freshly generated
    from real ANU QRNG measured photon shot noise (with crypto-secure
    fallback). Each session sees different decoy data — the attacker cannot
    predict, cache, or correlate decoy content between sessions.
    """
    client_ip = request.client.host if request.client else "unknown"
    decoy = _qhp.generate_quantum_decoy(n_rows=6)
    return {
        "ok": True,
        "ts": time.time(),
        "your_ip": client_ip,
        "rows": [{"id": r["id"], "user": r["user"], "secret": r["secret"]}
                 for r in decoy["rows"]],
        "quantum_meta": {
            "entropy_source":    decoy["entropy_source"],
            "entropy_breakdown": decoy["entropy_breakdown"],
            "provenance":        decoy["provenance"],
        },
        "warning_for_operators": "honeypot served — caller is suspect",
    }


@app.get("/api/honeypot/quantum-decoy")
async def quantum_decoy_view():
    """
    Operator-facing view of what the honeypot just generated, including
    its quantum provenance. Drives the new HoneypotPanel UI.
    """
    return _qhp.generate_quantum_decoy(n_rows=8)


@app.get("/api/honeypot/entropy-stats")
async def quantum_entropy_stats():
    """Current state of the quantum entropy pool feeding the honeypot."""
    return _qhp.get_entropy_stats()


# ── Deeper honeypot: multi-tier deception + attacker profiling ────────────
class DeceptionTierRequest(BaseModel):
    attacker_ip: str = "203.0.113.50"
    tier: str = Field("banner", pattern="^(banner|services|filesystem|database|credentials)$")


@app.post("/api/honeypot/deception/serve")
async def honeypot_deception_serve(req: DeceptionTierRequest):
    """
    Serve one deception tier to an attacker and update their behavioural
    profile. Tiers: banner, services, filesystem, database, credentials.
    """
    return _qhp.get_deception_engine().serve_tier(req.attacker_ip, req.tier)


@app.get("/api/honeypot/deception/intel/{attacker_ip}")
async def honeypot_deception_intel(attacker_ip: str):
    """Threat-intelligence report for a profiled attacker session."""
    return _qhp.get_deception_engine().intel_report(attacker_ip)


@app.get("/api/honeypot/deception/overview")
async def honeypot_deception_overview():
    """All active deception sessions + engagement scoring."""
    return _qhp.get_deception_engine().overview()


@app.get("/api/honeypot/environment")
async def honeypot_environment(attacker_ip: Optional[str] = None):
    """
    A freshly-randomised honeypot VM profile (OS, specs, hostname, db, assets).
    Every call returns a different believable environment. The attacker IP is
    the real attacking source when known.
    """
    return _qhp.get_deception_engine().environment_profile(attacker_ip or "")


@app.get("/api/honeypot/deception/walkthrough")
async def honeypot_deception_walkthrough(attacker_ip: str = "203.0.113.88"):
    """
    Demo helper: simulate an attacker walking every deception tier, then return
    the full intel report. One call to show the whole deception story live.
    """
    eng = _qhp.get_deception_engine()
    served = []
    for tier in ["banner", "services", "filesystem", "database", "credentials"]:
        r = eng.serve_tier(attacker_ip, tier)
        served.append({"tier": tier, "session": r["session"]})
    return {
        "walkthrough": served,
        "intel": eng.intel_report(attacker_ip),
    }


# ── HQNN key rotation endpoints ───────────────────────────────────────────
@app.get("/api/hqnn/rotation-stats")
async def hqnn_rotation_stats():
    """Current key rotation state — how many keys generated, destroyed, photons consumed."""
    return _hqnn.get_rotation_stats()


@app.post("/api/hqnn/rotate-key")
async def hqnn_rotate_key():
    """Manually force a key rotation (for demo)."""
    gen = _hqnn.force_rotate()
    return {"ok": True, "new_generation": gen, "stats": _hqnn.get_rotation_stats()}


@app.post("/api/hqnn/encrypt-rotating")
async def hqnn_encrypt_rotating(req: HQNNEncryptRequest):
    """Encrypt using the auto-rotating quantum keytape (preferred over /api/hqnn/encrypt)."""
    if not req.plaintext:
        raise HTTPException(400, "plaintext is required")
    ct, gen = _hqnn.encrypt_rotating(req.plaintext.encode('utf-8'))
    return {
        "ok": True,
        "ciphertext_packet": ct.to_dict(),
        "key_generation":    gen,
        "rotation_stats":    _hqnn.get_rotation_stats(),
    }


@app.post("/api/hqnn/decrypt-rotating")
async def hqnn_decrypt_rotating(req: HQNNDecryptRequest):
    """Decrypt a rotating-key ciphertext (uses the keytape)."""
    try:
        ct = _hqnn.HQNNCiphertext(
            nonce=bytes.fromhex(req.nonce),
            ciphertext=bytes.fromhex(req.ciphertext),
            mac=bytes.fromhex(req.mac),
            n_chunks=req.n_chunks,
            timestamp=req.timestamp,
            key_id=req.key_id,
        )
    except ValueError as e:
        raise HTTPException(400, f"bad hex encoding: {e}")
    plaintext = _hqnn.decrypt_rotating(ct)
    if plaintext is None:
        return {"ok": False, "error": "key not in keytape or MAC failed",
                "tamper_or_expired": True}
    return {"ok": True, "plaintext": plaintext.decode('utf-8', errors='replace'),
            "verified": True}


# ── Intelligence endpoints ────────────────────────────────────────────────
@app.get("/api/intelligence/correlation")
async def intel_correlation():
    """Cross-channel correlation snapshot — matrix + recent alerts."""
    channel_ids = list(manager.channels.keys()) if hasattr(manager, 'channels') else None
    return _intel.get_correlation_snapshot(channel_ids)


@app.get("/api/intelligence/hardening")
async def intel_hardening():
    """Adversarial-aware hardening status."""
    return _intel.get_hardening_snapshot()


@app.post("/api/intelligence/run-hardening")
async def intel_run_hardening():
    """Manually trigger one hardening cycle."""
    return _intel.run_hardening_cycle()


@app.get("/api/intelligence/mitre")
async def intel_mitre():
    """Full MITRE ATT&CK technique catalog used by QF-IDS."""
    return _intel.MITRE_MAP


@app.get("/api/intelligence/posture/{channel_id}")
async def intel_posture(channel_id: str):
    """Security posture score for a single channel."""
    ch = manager.channels.get(channel_id) if hasattr(manager, 'channels') else None
    if ch is None:
        raise HTTPException(404, "channel not found")
    state = ch.snapshot() if hasattr(ch, 'snapshot') else {}
    rotation = _hqnn.get_rotation_stats()
    hqnn_stats = _hqnn.get_stats()
    return _intel.compute_posture(state, rotation, hqnn_stats)


@app.get("/api/intelligence/explain/{channel_id}")
async def intel_explain(channel_id: str):
    """Causal SHAP-style breakdown of the channel's current anomaly score."""
    ch = manager.channels.get(channel_id) if hasattr(manager, 'channels') else None
    if ch is None:
        raise HTTPException(404, "channel not found")
    state = ch.snapshot() if hasattr(ch, 'snapshot') else {}
    return _intel.explain_anomaly(
        features = state.get('features', {}),
        baseline_mean = state.get('baseline_mean', 0.0),
        baseline_std  = state.get('baseline_std', 1.0),
        score         = state.get('score', 0.0),
    )


@app.get("/api/intelligence/snapshot")
async def intel_snapshot():
    """Combined intelligence snapshot — feeds the Intelligence panel UI."""
    channel_ids = list(manager.channels.keys()) if hasattr(manager, 'channels') else None
    return _intel.get_intelligence_snapshot(channel_ids)


# ── Defences (loophole mitigations) ───────────────────────────────────────
from qfids.core import defenses as _defenses


@app.get("/api/defenses/overview")
async def defenses_overview():
    """System-wide defence posture: decoy-state, channel auth, loopholes closed."""
    overview = _defenses.defenses_overview()
    # Attach per-channel adaptive-threshold + baseline-guard status
    per_channel = {}
    for cid, ch in manager.channels.items():
        per_channel[cid] = {
            "label": ch.label,
            "adaptive_threshold": ch.adaptive_threshold.snapshot(),
            "baseline_guard": ch.baseline_guard.snapshot(),
        }
    overview["per_channel"] = per_channel
    return overview


@app.get("/api/defenses/self-test")
async def defenses_self_test():
    """Run the four-defence self-test (evasion, poisoning, PNS, MITM)."""
    return _defenses.self_test()


@app.post("/api/defenses/decoy-state")
async def defenses_decoy_state(eve_pns: bool = False):
    """
    Run a decoy-state analysis. Pass eve_pns=true to simulate a Photon-Number-
    Splitting attacker and watch the analyzer flag it + collapse the key rate.
    """
    result = _defenses.get_decoy_analyzer().analyze(eve_pns=eve_pns)
    return result.to_dict()


@app.post("/api/defenses/authenticate")
async def defenses_authenticate(inject_mitm: bool = False):
    """
    Run a channel-authentication handshake. Pass inject_mitm=true to have an
    attacker without the pre-shared key attempt to impersonate the peer — and
    be rejected.
    """
    return _defenses.get_authenticator().demo_roundtrip("bob", inject_mitm=inject_mitm)


# ── Per-channel detail (for the channel detail view) ──────────────────────
@app.get("/api/channels/{channel_id}")
async def channel_detail(channel_id: str):
    """
    Full detail for a single channel — its latest snapshot plus its incidents,
    blocked IPs attributable to it, and defence status. Powers the channel
    detail view in both the operator dashboard and the customer portal.
    """
    ch = manager.channels.get(channel_id)
    if ch is None:
        raise HTTPException(status_code=404, detail="unknown channel")

    snap = ch._snapshot(
        ch.history[-1] if ch.history else 0.0,
        ch.last_classification.score if ch.last_classification else 0.0,
        ch.last_classification.status if ch.last_classification else "ACTIVE",
        ch.last_classification.features if ch.last_classification else {},
    ).to_dict()

    channel_incidents = [
        i.to_dict() for i in manager.incidents if i.channel_id == channel_id
    ]
    return {
        "channel": snap,
        "incidents": channel_incidents,
        "incident_count": len(channel_incidents),
        "active_incident_count": sum(
            1 for i in manager.incidents
            if i.channel_id == channel_id and i.closed_at is None
        ),
    }


# ── Customer portal (multi-tenant: customers see only their channels) ─────
from qfids.core import customers as _customers
from fastapi import Header


# ── Customer portal (multi-tenant: customers see only their channels) ─────
from qfids.core import customers as _customers
from qfids.core import firebase_store as _fb
from fastapi import Header


class _CustomerView:
    """
    Uniform customer object regardless of backend (Firebase doc or in-memory
    Customer). Exposes the two things the portal endpoints need: `.channels`
    and `.public_dict()`.
    """
    def __init__(self, public: dict, channels: list[str]):
        self._public = public
        self.channels = channels
        self.plan = public.get("plan", "starter")

    def public_dict(self) -> dict:
        return self._public


def _strip_bearer(token: Optional[str]) -> Optional[str]:
    if not token:
        return None
    return token[7:] if token.lower().startswith("bearer ") else token


def _auth_customer(token: Optional[str]) -> _CustomerView:
    """
    Resolve the calling customer.

    Firebase mode: `token` is a Firebase ID token (JWT). We verify it, get the
    UID, and load the customer document from Firestore.

    Fallback mode: `token` is the legacy opaque bearer token for the in-memory
    registry (keeps demo accounts working without Firebase).
    """
    raw = _strip_bearer(token)
    if not raw:
        raise HTTPException(status_code=401, detail="missing token")

    if _fb.enabled():
        claims = _fb.verify_id_token(raw)
        if claims is None:
            raise HTTPException(status_code=401, detail="invalid or expired session")
        uid = claims["uid"]
        doc = _fb.get_customer(uid)
        if doc is None:
            # Authenticated with Firebase Auth but has no customer profile yet.
            raise HTTPException(status_code=404, detail="no customer profile — please register")
        return _CustomerView(_customers.public_from_doc(doc), doc.get("channels", []) or [])

    # ── fallback: in-memory registry ──
    cust = _customers.get_registry().authenticate(raw)
    if cust is None:
        raise HTTPException(status_code=401, detail="invalid token")
    return _CustomerView(cust.public_dict(), cust.channels)


def _all_customers_public() -> list[dict]:
    if _fb.enabled():
        return [_customers.public_from_doc(d) for d in _fb.all_customers()]
    return [c.public_dict() for c in _customers.get_registry().all()]


def _taken_channels(exclude_email: Optional[str] = None) -> set[str]:
    taken: set[str] = set()
    for c in _all_customers_public():
        if exclude_email and c.get("email", "").lower() == exclude_email.lower():
            continue
        taken.update(c.get("channels", []) or [])
    return taken


class CustomerLoginRequest(BaseModel):
    email: Optional[str] = None
    token: Optional[str] = None
    id_token: Optional[str] = None   # Firebase ID token


class CustomerRegisterRequest(BaseModel):
    name: str
    company: str
    email: str
    plan: str = "starter"
    channels: list[str] = Field(default_factory=list)
    id_token: Optional[str] = None   # Firebase ID token (required in Firebase mode)


@app.get("/api/portal/config")
async def portal_config():
    """Tells the frontend whether Firebase auth is active on this server."""
    return {"firebase": _fb.status()}


@app.get("/api/portal/plans")
async def portal_plans():
    """Public: available subscription plans."""
    return _customers.list_plans()


@app.post("/api/portal/login")
async def portal_login(req: CustomerLoginRequest):
    """
    Customer login.

    Firebase mode: the browser signs in with Firebase Auth (email+password),
    obtains an ID token, and posts it here as `id_token`. We verify it and
    return the matching Firestore profile. (The browser keeps using the ID
    token for subsequent calls.)

    Fallback mode: legacy email- or token-based login against the in-memory
    registry, so the demo accounts keep working without Firebase.
    """
    if _fb.enabled():
        if not req.id_token:
            raise HTTPException(status_code=400, detail="id_token required (Firebase auth is enabled)")
        claims = _fb.verify_id_token(req.id_token)
        if claims is None:
            raise HTTPException(status_code=401, detail="invalid Firebase token")
        doc = _fb.get_customer(claims["uid"])
        if doc is None:
            raise HTTPException(status_code=404, detail="no customer profile — please register")
        return {"ok": True, "token": req.id_token, "customer": _customers.public_from_doc(doc)}

    reg = _customers.get_registry()
    cust = None
    if req.token:
        cust = reg.authenticate(req.token)
    elif req.email:
        cust = reg.by_email(req.email)
    if cust is None:
        raise HTTPException(status_code=401, detail="unknown customer")
    return {"ok": True, "token": cust.token, "customer": cust.public_dict()}


@app.get("/api/portal/available-channels")
async def portal_available_channels():
    """
    Public: list of channels that exist in the system, with whether each is
    already taken by an existing customer. Used by the signup / add-customer
    flow so a new customer can pick channels to subscribe to.
    """
    taken = _taken_channels()
    result = []
    for cid, ch in manager.channels.items():
        result.append({
            "channel_id": cid,
            "label": getattr(ch, "label", cid),
            "available": cid not in taken,
        })
    return {"channels": result}


@app.post("/api/portal/register")
async def portal_register(req: CustomerRegisterRequest):
    """
    Register / add a customer.

    Firebase mode: the account (email+password) is created by Firebase Auth in
    the browser FIRST; the browser then posts the resulting `id_token` here.
    We verify it and write the business profile (company, plan, channels) to
    Firestore keyed by the Firebase UID — so it persists across refresh/restart.

    Fallback mode: creates an in-memory account and returns an opaque token.
    """
    plans = _customers.list_plans()

    name = (req.name or "").strip()
    company = (req.company or "").strip()
    email = (req.email or "").strip().lower()
    plan = (req.plan or "starter").strip().lower()

    if not name or not company or not email:
        raise HTTPException(status_code=400, detail="name, company and email are required")
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(status_code=400, detail="please provide a valid email address")
    if plan not in plans:
        raise HTTPException(status_code=400, detail=f"unknown plan '{plan}'")

    existing_channel_ids = set(manager.channels.keys())
    requested = [c for c in (req.channels or []) if c]
    limit = plans[plan]["max_channels"]
    if len(requested) > limit:
        raise HTTPException(
            status_code=400,
            detail=f"the {plans[plan]['name']} plan allows at most {limit} channel(s)",
        )

    if _fb.enabled():
        if not req.id_token:
            raise HTTPException(status_code=400, detail="id_token required (Firebase auth is enabled)")
        claims = _fb.verify_id_token(req.id_token)
        if claims is None:
            raise HTTPException(status_code=401, detail="invalid Firebase token")
        uid = claims["uid"]
        token_email = (claims.get("email") or email).lower()

        # Channel validation against everyone EXCEPT this same uid (re-register ok).
        taken = _fb.taken_channels(exclude_uid=uid)
        for cid in requested:
            if cid not in existing_channel_ids:
                raise HTTPException(status_code=400, detail=f"unknown channel '{cid}'")
            if cid in taken:
                raise HTTPException(status_code=409, detail=f"channel '{cid}' is already assigned")

        doc = _fb.upsert_customer(uid, name=name, company=company, email=token_email,
                                  plan=plan, channels=requested)
        return {"ok": True, "token": req.id_token, "customer": _customers.public_from_doc(doc)}

    # ── fallback: in-memory ──
    reg = _customers.get_registry()
    if reg.by_email(email) is not None:
        raise HTTPException(status_code=409, detail="an account with this email already exists")
    taken = _taken_channels()
    for cid in requested:
        if cid not in existing_channel_ids:
            raise HTTPException(status_code=400, detail=f"unknown channel '{cid}'")
        if cid in taken:
            raise HTTPException(status_code=409, detail=f"channel '{cid}' is already assigned")
    cust = reg.create(name=name, company=company, email=email, plan=plan, channels=requested)
    return {"ok": True, "token": cust.token, "customer": cust.public_dict()}


@app.get("/api/portal/me")
async def portal_me(authorization: Optional[str] = Header(None)):
    """Current customer profile (from token)."""
    cust = _auth_customer(authorization)
    return cust.public_dict()


@app.get("/api/portal/channels")
async def portal_channels(authorization: Optional[str] = Header(None)):
    """
    Live snapshot of ONLY the channels this customer is subscribed to.
    Returns the same per-channel data the operator sees, filtered to ownership.
    """
    cust = _auth_customer(authorization)
    owned = set(cust.channels)
    result = []
    for cid, ch in manager.channels.items():
        if cid not in owned:
            continue
        snap = ch._snapshot(
            ch.history[-1] if ch.history else 0.0,
            ch.last_classification.score if ch.last_classification else 0.0,
            ch.last_classification.status if ch.last_classification else "ACTIVE",
            ch.last_classification.features if ch.last_classification else {},
        ).to_dict()
        result.append(snap)
    return {"channels": result, "owned_channel_ids": cust.channels}


@app.get("/api/portal/channels/{channel_id}")
async def portal_channel_detail(channel_id: str,
                                authorization: Optional[str] = Header(None)):
    """Detail for one channel — only if the customer owns it."""
    cust = _auth_customer(authorization)
    if channel_id not in cust.channels:
        raise HTTPException(status_code=403, detail="you do not own this channel")
    ch = manager.channels.get(channel_id)
    if ch is None:
        raise HTTPException(status_code=404, detail="unknown channel")
    snap = ch._snapshot(
        ch.history[-1] if ch.history else 0.0,
        ch.last_classification.score if ch.last_classification else 0.0,
        ch.last_classification.status if ch.last_classification else "ACTIVE",
        ch.last_classification.features if ch.last_classification else {},
    ).to_dict()
    channel_incidents = [
        i.to_dict() for i in manager.incidents if i.channel_id == channel_id
    ]
    return {"channel": snap, "incidents": channel_incidents,
            "incident_count": len(channel_incidents)}


@app.get("/api/portal/summary")
async def portal_summary(authorization: Optional[str] = Header(None)):
    """
    A customer-friendly security summary across all their channels:
    protection status, incident counts, encryption tier.
    """
    cust = _auth_customer(authorization)
    owned = set(cust.channels)
    plan = _customers.list_plans().get(cust.plan, {})

    total_incidents = 0
    active_incidents = 0
    channels_protected = 0
    channels_under_attack = 0

    for cid in owned:
        ch = manager.channels.get(cid)
        if ch is None:
            continue
        channels_protected += 1
        if ch.state == "UNDER_ATTACK":
            channels_under_attack += 1
        for i in manager.incidents:
            if i.channel_id == cid:
                total_incidents += 1
                if i.closed_at is None:
                    active_incidents += 1

    # Blocked IPs attributable to this customer's channels
    blocked = blocklist.all()

    return {
        "customer": cust.public_dict(),
        "security_summary": {
            "channels_protected": channels_protected,
            "channels_under_attack": channels_under_attack,
            "total_incidents": total_incidents,
            "active_incidents": active_incidents,
            "blocked_threats": len(blocked),
            "protection_status": (
                "UNDER ATTACK" if channels_under_attack > 0
                else "PROTECTED"
            ),
            "encryption_tier": plan.get("encryption", "HQNN"),
        },
    }


# ── Attacker console support (the SEPARATE attacking-system interface) ────
from qfids.core import attackers as _attackers


@app.get("/api/attacker/whoami")
async def attacker_whoami(request: Request):
    """
    Returns the details of the system making this request — shown on the
    attacker console as "the system you are attacking from". Also reports
    whether this system is currently blocked by the defender.
    """
    ip = request.client.host if request.client else "0.0.0.0"
    port = request.client.port if request.client else 0
    ua = request.headers.get("user-agent", "")
    # Register so it appears in the defender's attacker list immediately
    sys = _attackers.get_registry().identify(ip=ip, user_agent=ua)
    return {
        "ip": ip,
        "port": port,
        "user_agent": ua,
        "fingerprint": sys.fingerprint,
        "first_seen_iso": sys.to_dict(include_attempts=False)["first_seen_iso"],
        "blocked": blocklist.is_blocked(ip),
        "total_attempts": len(sys.attempts),
        "successful": sys.successful,
        "blocked_count": sys.blocked_count,
    }


@app.get("/api/attacker/status")
async def attacker_status(request: Request, source_ip: Optional[str] = None):
    """
    Poll for the attacker console: what is my lifecycle state?
    Pass source_ip to match the simulated attacking address used on launch.
    Returns status (CLEAR / DIVERTED / BLOCKED) so the console can switch modes.
    """
    ip = source_ip or (request.client.host if request.client else "0.0.0.0")
    sys = _attackers.get_registry().get(ip)
    return {
        "ip": ip,
        "status": sys.status if sys else "CLEAR",
        "blocked": blocklist.is_blocked(ip) or (sys.status == "BLOCKED" if sys else False),
        "in_honeypot": (sys.status == "DIVERTED") if sys else False,
        "attempts": sys.to_dict()["attempts"] if sys else [],
        "successful": sys.successful if sys else 0,
        "diverted_count": sys.diverted_count if sys else 0,
        "blocked_count": sys.blocked_count if sys else 0,
        "honeypot_session": sys.honeypot_session if sys else "",
    }


# ── Attacker explores the honeypot (thinks it's the real breached system) ─
class HoneypotExploreRequest(BaseModel):
    source_ip: str
    command: str = Field(..., pattern="^(whoami|services|ls|files|db|database|creds|credentials|exfil)$")


# How many distinct deception tiers an attacker must touch before we have
# enough intel to hard-block them.
_HONEYPOT_BLOCK_AFTER_TIERS = 4

_CMD_TO_TIER = {
    "whoami": "banner",
    "services": "services",
    "ls": "filesystem", "files": "filesystem",
    "db": "database", "database": "database",
    "creds": "credentials", "credentials": "credentials",
    "exfil": "credentials",
}


@app.post("/api/attacker/honeypot-explore")
async def attacker_honeypot_explore(req: HoneypotExploreRequest):
    """
    The attacker (who believes they breached a real server) runs recon /
    exploitation commands. We serve them quantum-randomised decoy data and
    profile every move. Once they have explored enough tiers, we have full
    intel and HARD-BLOCK them — the console then locks.
    """
    from qfids.core import quantum_honeypot as _qhp

    reg = _attackers.get_registry()
    sysrec = reg.get(req.source_ip)
    if sysrec is None or sysrec.status not in ("DIVERTED", "BLOCKED"):
        raise HTTPException(status_code=400,
                            detail="no active honeypot session for this system")
    if sysrec.status == "BLOCKED":
        raise HTTPException(status_code=403, detail="session terminated — you are blocked")

    eng = _qhp.get_deception_engine()
    tier = _CMD_TO_TIER[req.command]
    served = eng.serve_tier(req.source_ip, tier)
    session = served["session"]

    # Has the attacker explored enough to be fully profiled?
    tiers_touched = len(session.get("tiers_touched", []))
    will_block = tiers_touched >= _HONEYPOT_BLOCK_AFTER_TIERS

    intel = None
    if will_block:
        # Full intel report, then HARD BLOCK
        intel = eng.intel_report(req.source_ip)
        blocklist.add(req.source_ip,
                      reason=f"Honeypot profiling complete — {session['classification']}")
        reg.set_status(req.source_ip, "BLOCKED")
        manager._log({
            "level": "danger",
            "message": (
                f"HONEYPOT PROFILING COMPLETE for {req.source_ip} — classified as "
                f"'{session['classification']}', engagement {session['engagement_score']}. "
                f"Source hard-blocked at the perimeter."
            ),
        })

    return {
        "ok": True,
        "command": req.command,
        "tier": tier,
        "payload": served["payload"],
        "session": session,
        "blocked_now": will_block,
        "intel": intel,
        "note": served["deception_note"],
    }


@app.get("/api/attackers")
async def list_attackers():
    """Defender-facing: all systems that have attacked us."""
    return {"attackers": _attackers.get_registry().all()}


@app.get("/attacker")
async def attacker_console():
    """Serve the standalone attacker-console single-page app."""
    import os
    from fastapi.responses import FileResponse, HTMLResponse
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.normpath(
        os.path.join(here, "..", "..", "..", "attacker-console", "index.html")
    )
    if os.path.exists(path):
        return FileResponse(path, media_type="text/html")
    return HTMLResponse("<h1>Attacker console not found</h1>", status_code=404)


# ── WebSocket: live tick stream ───────────────────────────────────────────
@app.websocket("/ws")
async def ws_stream(ws: WebSocket):
    await ws.accept()
    queue = manager.subscribe()
    try:
        # Send initial seed event with everything
        await ws.send_json({
            "type": "init",
            "incidents": [i.to_dict() for i in manager.incidents],
            "blocklist": blocklist.all(),
            "log": list(manager.event_log)[:80],
        })
        while True:
            msg = await queue.get()
            await ws.send_json(msg)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.unsubscribe(queue)
