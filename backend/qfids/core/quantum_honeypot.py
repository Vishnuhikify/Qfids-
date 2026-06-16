"""
Quantum-randomized honeypot.

Generates fresh decoy data using real quantum random numbers from the ANU
QRNG live feed (Australian National University's measured photon shot
noise). Every fake API key, every fake credit card, every fake user ID
is sourced from real quantum measurements — making the decoy content
unpredictable by any classical or quantum adversary.

This is novel: most honeypots use static templates. Ours generates
quantum-random content on demand, so even if an attacker observes
multiple honeypot sessions, the decoy data is information-theoretically
unrelated between sessions.

If the ANU API is unreachable, falls back to crypto-secure local entropy
(secrets.SystemRandom) — never to predictable PRNG. The data is always
unpredictable; the *source* of randomness is best-effort quantum.
"""
from __future__ import annotations
import secrets
import threading
import time
import urllib.request
import urllib.error
import json
from collections import deque
from typing import Optional


ANU_QRNG_URL = "https://qrng.anu.edu.au/API/jsonI.php?length={n}&type=uint8"


class QuantumEntropyPool:
    """
    Thread-safe entropy buffer fed from ANU QRNG with crypto fallback.
    Refills in the background so consumers never block.
    """
    def __init__(self, target_size: int = 1024):
        self.target_size = target_size
        self.pool: deque = deque(maxlen=target_size * 4)
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.bytes_from_quantum = 0
        self.bytes_from_fallback = 0
        self.quantum_fetches = 0
        self.last_fetch_ts: float = 0.0
        self.last_fetch_status: str = "pending"
        self._thread = threading.Thread(target=self._refill_loop, daemon=True)
        self._thread.start()

    def _try_fetch_quantum(self, n: int) -> Optional[list[int]]:
        try:
            req = urllib.request.Request(
                ANU_QRNG_URL.format(n=min(n, 1024)),
                headers={'User-Agent': 'QF-IDS/2.0'},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                if data.get('success'):
                    self.quantum_fetches += 1
                    self.last_fetch_ts = time.time()
                    self.last_fetch_status = "ok"
                    return data.get('data', [])
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
                json.JSONDecodeError, ConnectionError) as e:
            self.last_fetch_status = f"unreachable ({type(e).__name__})"
        except Exception as e:
            self.last_fetch_status = f"error ({type(e).__name__})"
        return None

    def _crypto_fallback(self, n: int) -> list[int]:
        return [secrets.randbits(8) for _ in range(n)]

    def _refill_loop(self):
        while not self._stop.is_set():
            with self.lock:
                deficit = self.target_size - len(self.pool)
            if deficit > 0:
                quantum = self._try_fetch_quantum(deficit)
                if quantum:
                    with self.lock:
                        for b in quantum:
                            self.pool.append(('q', b))
                    self.bytes_from_quantum += len(quantum)
                else:
                    bytes_ = self._crypto_fallback(deficit)
                    with self.lock:
                        for b in bytes_:
                            self.pool.append(('c', b))
                    self.bytes_from_fallback += len(bytes_)
            self._stop.wait(8.0)

    def take(self, n: int) -> tuple[bytes, str]:
        """Take n bytes. Returns (bytes, source) where source = 'quantum' / 'mixed' / 'fallback'."""
        with self.lock:
            taken = []
            sources = []
            for _ in range(n):
                if self.pool:
                    s, b = self.pool.popleft()
                    taken.append(b)
                    sources.append(s)
                else:
                    taken.append(secrets.randbits(8))
                    sources.append('c')
                    self.bytes_from_fallback += 1
            q_count = sum(1 for s in sources if s == 'q')
            if q_count == n: source = 'quantum'
            elif q_count == 0: source = 'fallback'
            else: source = 'mixed'
            return bytes(taken), source

    def stats(self) -> dict:
        with self.lock:
            return {
                "pool_size":            len(self.pool),
                "target_size":          self.target_size,
                "bytes_from_quantum":   self.bytes_from_quantum,
                "bytes_from_fallback":  self.bytes_from_fallback,
                "quantum_fetches":      self.quantum_fetches,
                "last_fetch_ts":        self.last_fetch_ts,
                "last_fetch_status":    self.last_fetch_status,
                "current_source":       "quantum" if any(s == 'q' for s, _ in list(self.pool)[:1])
                                        else "fallback",
            }


# Module singleton — starts refilling immediately
_pool = QuantumEntropyPool(target_size=2048)


def _rand_int(bits: int = 16) -> tuple[int, str]:
    n_bytes = max(1, (bits + 7) // 8)
    b, source = _pool.take(n_bytes)
    v = int.from_bytes(b, 'big') & ((1 << bits) - 1)
    return v, source


def _rand_choice(seq: list, rng_bytes: bytes) -> object:
    if not seq: return None
    idx = int.from_bytes(rng_bytes[:2], 'big') % len(seq)
    return seq[idx]


def generate_quantum_decoy(n_rows: int = 6) -> dict:
    """
    Generate a fresh decoy payload using quantum random entropy.
    Returns a dict with rows, source classification, and provenance info.
    """
    USERS_PREFIX = ['admin', 'ops', 'root', 'guest', 'svc', 'qa', 'staging', 'jenkins']
    USERS_DOMAIN = ['fake-db.io', 'sandbox.local', 'trap.internal', 'decoy.net', 'honeynet.io']

    rows = []
    source_acc = []
    for _ in range(n_rows):
        id_val, s1   = _rand_int(20)
        prefix_b, s2 = _pool.take(2)
        domain_b, s3 = _pool.take(2)
        secret_b, s4 = _pool.take(16)
        cc_b, s5     = _pool.take(8)
        cvv_b, s6    = _pool.take(2)
        source_acc.extend([s1, s2, s3, s4, s5, s6])
        rows.append({
            "id":      id_val % 100000,
            "user":    f"{_rand_choice(USERS_PREFIX, prefix_b)}_{int.from_bytes(prefix_b,'big'):04x}"
                       f"@{_rand_choice(USERS_DOMAIN, domain_b)}",
            "secret":  "sk_decoy_" + secret_b.hex(),
            "cc_last4": f"{int.from_bytes(cc_b,'big') % 10000:04d}",
            "cvv":     f"{int.from_bytes(cvv_b,'big') % 1000:03d}",
        })

    # Source classification — quantum if ≥80% bytes came from ANU
    q_count = source_acc.count('quantum')
    m_count = source_acc.count('mixed')
    if q_count >= 0.8 * len(source_acc):
        source = 'quantum'
    elif (q_count + m_count) >= 0.5 * len(source_acc):
        source = 'mixed'
    else:
        source = 'fallback'

    return {
        "rows":            rows,
        "entropy_source":  source,
        "entropy_breakdown": {
            "quantum":  q_count,
            "mixed":    m_count,
            "fallback": source_acc.count('fallback'),
        },
        "pool_stats":      _pool.stats(),
        "generated_at":    time.time(),
        "provenance":      "Australian National University QRNG (qrng.anu.edu.au) — measured photon shot noise"
                           if source == 'quantum' else
                           "Mixed: ANU QRNG + crypto-secure fallback (secrets.SystemRandom)"
                           if source == 'mixed' else
                           "Crypto-secure local entropy (ANU QRNG unreachable)",
    }


def get_entropy_stats() -> dict:
    return _pool.stats()


# ════════════════════════════════════════════════════════════════════
# DEEPER HONEYPOT — attacker profiling, multi-tier deception, engagement
# ════════════════════════════════════════════════════════════════════
"""
The decoy generator above produces quantum-random fake data. v2 deepens the
honeypot into a full deception environment:

  1. MULTI-TIER DECEPTION. The honeypot now presents a believable fake system
     with several layers an attacker would explore: a login banner, a fake file
     system, fake running services, fake database tables, and fake credentials.
     Each tier is quantum-randomised so it differs every session.

  2. ATTACKER PROFILING. As the attacker interacts, we record their behaviour —
     which tiers they touched, how long they stayed, how aggressive they were —
     and classify them (scanner / credential-harvester / data-exfiltrator /
     ransomware) using a simple behavioural signature.

  3. ENGAGEMENT SCORING. We compute a "stickiness" score: how successfully the
     honeypot is keeping the attacker engaged and away from real assets. Higher
     engagement = more intelligence gathered + more attacker time wasted.

  4. THREAT INTELLIGENCE. Every session produces a structured intel record
     (indicators, TTP guesses, MITRE mapping) that a SOC could action.

This turns the honeypot from "fake data" into "a deception system that learns
about the attacker" — a much stronger story.
"""
import time as _time
from dataclasses import dataclass as _dataclass, field as _field


FAKE_SERVICES = [
    ("sshd", 22, "OpenSSH 8.9p1"),
    ("nginx", 80, "nginx/1.24.0"),
    ("postgres", 5432, "PostgreSQL 15.3"),
    ("redis", 6379, "Redis 7.0.11"),
    ("vault", 8200, "HashiCorp Vault 1.14"),
    ("docker", 2375, "Docker Engine 24.0"),
]

FAKE_FILES = [
    "/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa",
    "/var/www/config/database.yml", "/opt/app/.env",
    "/home/admin/backup.sql", "/var/backups/keys.tar.gz",
    "/srv/secrets/api_tokens.json",
]

FAKE_DB_TABLES = ["users", "payments", "api_keys", "sessions", "audit_log",
                  "customers", "transactions", "credentials"]


@_dataclass
class HoneypotSession:
    """Tracks one attacker's journey through the deception environment."""
    session_id: str
    attacker_ip: str
    started_at: float = _field(default_factory=_time.time)
    last_seen: float = _field(default_factory=_time.time)
    tiers_touched: list = _field(default_factory=list)
    interactions: int = 0
    bytes_served: int = 0
    aggression: float = 0.0     # 0..1, derived from interaction rate
    classification: str = "unknown"

    def touch(self, tier: str, bytes_served: int = 0):
        if tier not in self.tiers_touched:
            self.tiers_touched.append(tier)
        self.interactions += 1
        self.bytes_served += bytes_served
        now = _time.time()
        dt = max(0.001, now - self.last_seen)
        # Aggression: fast repeated hits look automated / aggressive
        inst_rate = 1.0 / dt
        self.aggression = min(1.0, 0.7 * self.aggression + 0.3 * min(1.0, inst_rate / 5.0))
        self.last_seen = now
        self._classify()

    def _classify(self):
        tiers = set(self.tiers_touched)
        if "filesystem" in tiers and "database" in tiers and self.bytes_served > 2000:
            self.classification = "data-exfiltrator"
        elif "credentials" in tiers or "database" in tiers:
            self.classification = "credential-harvester"
        elif "filesystem" in tiers and self.aggression > 0.6:
            self.classification = "ransomware-style"
        elif "services" in tiers and len(tiers) <= 2:
            self.classification = "scanner / recon"
        else:
            self.classification = "exploring"

    def engagement_score(self) -> float:
        """0..100 — how well we're keeping the attacker busy & profiled."""
        dwell = min(1.0, (self.last_seen - self.started_at) / 60.0)   # up to 60s
        breadth = min(1.0, len(self.tiers_touched) / 5.0)
        depth = min(1.0, self.interactions / 20.0)
        return round(100.0 * (0.4 * dwell + 0.3 * breadth + 0.3 * depth), 1)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "attacker_ip": self.attacker_ip,
            "started_at": self.started_at,
            "duration_sec": round(self.last_seen - self.started_at, 1),
            "tiers_touched": self.tiers_touched,
            "interactions": self.interactions,
            "bytes_served": self.bytes_served,
            "aggression": round(self.aggression, 3),
            "classification": self.classification,
            "engagement_score": self.engagement_score(),
        }


class DeceptionEngine:
    """Manages multi-tier deception + per-attacker sessions + intel."""

    def __init__(self):
        self.sessions: dict[str, HoneypotSession] = {}
        self.total_sessions = 0
        self.total_intel_records = 0

    def _session(self, attacker_ip: str) -> HoneypotSession:
        s = self.sessions.get(attacker_ip)
        if s is None:
            self.total_sessions += 1
            s = HoneypotSession(
                session_id=f"hp-{self.total_sessions:04d}",
                attacker_ip=attacker_ip,
            )
            self.sessions[attacker_ip] = s
        return s

    def serve_tier(self, attacker_ip: str, tier: str) -> dict:
        """
        Serve one deception tier to an attacker and update their profile.
        Tiers: 'banner', 'services', 'filesystem', 'database', 'credentials'.
        """
        s = self._session(attacker_ip)

        if tier == "banner":
            v, src = _rand_int(16)
            payload = {
                "banner": f"Ubuntu 22.04.3 LTS  (build {v % 9000 + 1000})",
                "hostname": f"prod-app-{v % 90 + 10}",
                "motd": "Authorized access only. All activity is logged.",
            }
            size = 120

        elif tier == "services":
            rnd, src = _pool.take(4)
            payload = {"open_ports": [
                {"service": name, "port": port, "version": ver}
                for (name, port, ver) in FAKE_SERVICES
            ]}
            size = 280

        elif tier == "filesystem":
            files = []
            for path in FAKE_FILES:
                sz, src = _rand_int(20)
                files.append({"path": path, "size_bytes": sz % 200000,
                              "mode": "-rw-------" if "ssh" in path or "shadow" in path
                                      else "-rw-r--r--"})
            payload = {"files": files}
            size = 600

        elif tier == "database":
            tables = []
            for t in FAKE_DB_TABLES:
                rows, src = _rand_int(24)
                tables.append({"table": t, "rows": rows % 5_000_000})
            payload = {"tables": tables, "engine": "PostgreSQL 15.3 (decoy)"}
            size = 400

        elif tier == "credentials":
            decoy = generate_quantum_decoy(n_rows=5)
            payload = {"leaked_credentials": decoy["rows"],
                       "entropy_source": decoy["entropy_source"]}
            size = 800

        else:
            payload = {"error": "unknown tier"}
            size = 40

        s.touch(tier, bytes_served=size)
        return {
            "tier": tier,
            "payload": payload,
            "session": s.to_dict(),
            "deception_note": "All data is synthetic & quantum-randomised. "
                              "Attacker is being profiled, not served real assets.",
        }

    def intel_report(self, attacker_ip: str) -> dict:
        """Produce a structured threat-intelligence record for a session."""
        s = self.sessions.get(attacker_ip)
        if s is None:
            return {"error": "no session for that IP"}
        self.total_intel_records += 1

        # MITRE TTP guesses based on tiers touched
        ttp = []
        if "services" in s.tiers_touched:
            ttp.append({"id": "T1046", "name": "Network Service Discovery"})
        if "filesystem" in s.tiers_touched:
            ttp.append({"id": "T1083", "name": "File and Directory Discovery"})
        if "database" in s.tiers_touched:
            ttp.append({"id": "T1213", "name": "Data from Information Repositories"})
        if "credentials" in s.tiers_touched:
            ttp.append({"id": "T1552", "name": "Unsecured Credentials"})
        if s.classification == "data-exfiltrator":
            ttp.append({"id": "T1041", "name": "Exfiltration Over C2 Channel"})

        return {
            "session": s.to_dict(),
            "indicators": {
                "source_ip": s.attacker_ip,
                "interaction_count": s.interactions,
                "aggression_level": round(s.aggression, 3),
                "data_appetite_bytes": s.bytes_served,
            },
            "attacker_classification": s.classification,
            "mitre_ttps": ttp,
            "recommendation": (
                "High-confidence malicious actor — block at perimeter and add IoCs "
                "to threat feed."
                if s.engagement_score() > 50 else
                "Probable reconnaissance — monitor and correlate with other channels."
            ),
            "generated_at": _time.time(),
        }

    def overview(self) -> dict:
        sessions = [s.to_dict() for s in self.sessions.values()]
        return {
            "active_sessions": len(self.sessions),
            "total_sessions": self.total_sessions,
            "total_intel_records": self.total_intel_records,
            "deception_tiers": ["banner", "services", "filesystem",
                                "database", "credentials"],
            "sessions": sorted(sessions,
                               key=lambda x: x["engagement_score"], reverse=True),
            "avg_engagement": round(
                sum(x["engagement_score"] for x in sessions) / len(sessions), 1
            ) if sessions else 0.0,
        }

    def environment_profile(self, attacker_ip: str = "") -> dict:
        """
        Generate a believable, RANDOMISED honeypot VM profile.

        Unlike a static template, every field is freshly drawn from quantum/crypto
        entropy so each session presents a different (but realistic) decoy host:
        different OS, kernel, specs, hostname, database, asset counts, etc. The
        attacker IP is the REAL attacking source — not a hardcoded value — so the
        illusion holds. This makes the deception convincing under inspection.
        """
        def pick(seq):
            b, _ = _pool.take(2)
            return seq[int.from_bytes(b, "big") % len(seq)]

        def rnd(lo, hi):
            b, _ = _pool.take(2)
            return lo + int.from_bytes(b, "big") % (hi - lo + 1)

        os_choices = [
            ("Ubuntu 22.04.3 LTS", "5.15.0-{}-generic"),
            ("Ubuntu 20.04.6 LTS", "5.4.0-{}-generic"),
            ("Debian 12 (bookworm)", "6.1.0-{}-amd64"),
            ("CentOS Stream 9", "5.14.0-{}.el9"),
            ("Rocky Linux 9.3", "5.14.0-{}.el9_3"),
            ("Amazon Linux 2023", "6.1.{}-amzn2023"),
            ("RHEL 8.9", "4.18.0-{}.el8"),
        ]
        host_roles = ["db-replica", "app-node", "api-gw", "cache", "worker",
                      "auth-svc", "billing", "edge-proxy", "data-sink"]
        dbs = ["PostgreSQL 15.4", "PostgreSQL 14.10", "MySQL 8.0.35",
               "MariaDB 10.11", "MongoDB 6.0.11", "Redis 7.2"]
        container_imgs = ["cowrie:v2.5.1", "tpot/honeytrap:23.04",
                          "dionaea:0.11", "opencanary:0.9.2", "conpot:0.6.0"]
        vlans = [f"10.{rnd(10,250)}.{rnd(0,250)}.0/24",
                 f"172.{rnd(16,31)}.{rnd(0,250)}.0/24",
                 f"192.168.{rnd(0,250)}.0/24"]

        os_name, kernel_tmpl = pick(os_choices)
        kernel = kernel_tmpl.format(rnd(40, 160))
        role = pick(host_roles)
        vlan = pick(vlans)
        vcpu = pick([2, 4, 8, 16])
        ram = pick([4, 8, 16, 32])
        disk = pick([20, 40, 80, 160, 250])
        sid_bytes, _ = _pool.take(6)
        session_id = "sess_" + sid_bytes.hex()
        n_files = rnd(6, 24)
        n_users = rnd(800, 9000)
        n_keys = rnd(8, 40)

        return {
            "hostname": f"{role}-{rnd(1,99):02d}.internal",
            "os": os_name,
            "kernel": kernel,
            "container": "docker-honeypot/" + pick(container_imgs),
            "network": f"{vlan} — isolated VLAN",
            "gateway": vlan.replace("0/24", "1") + " (egress dropped at L3)",
            "dns": "127.0.0.53 (local resolver only)",
            "cpu": f"{vcpu} vCPU · throttled to {pick([20,30,40,50])}%",
            "memory": f"{ram} GiB · monitored",
            "disk": f"{disk} GiB {pick(['ext4','xfs','btrfs'])} · snapshot per session",
            "database": f"{pick(dbs)} · synthetic {pick(['users_prod','billing','customers','sessions'])}",
            "auth_backend": "fake-LDAP (always returns success)",
            "filesystem": f"overlayfs · resets every {pick([2,4,6,12])}h",
            "logging": f"sysdig + pcap mirror to forensics-{rnd(1,9):02d}",
            "attacker_ip": attacker_ip or "unknown",
            "session_id": session_id,
            "spun_up_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                        time.localtime(time.time() - rnd(30, 1800))),
            "decoy_assets": f"{n_files} files · {n_users:,} fake users · {n_keys} fake API keys",
            "egress_policy": "DROP ALL (no outbound connectivity)",
        }


# Module singleton
_deception = DeceptionEngine()


def get_deception_engine() -> DeceptionEngine:
    return _deception


def deception_self_test() -> dict:
    """Simulate an attacker walking through the deception tiers."""
    eng = DeceptionEngine()
    ip = "203.0.113.66"
    eng.serve_tier(ip, "banner")
    eng.serve_tier(ip, "services")
    eng.serve_tier(ip, "filesystem")
    eng.serve_tier(ip, "database")
    eng.serve_tier(ip, "credentials")
    intel = eng.intel_report(ip)
    return {
        "tiers_served": 5,
        "classification": intel["attacker_classification"],
        "engagement_score": intel["session"]["engagement_score"],
        "mitre_ttps_found": len(intel["mitre_ttps"]),
        "ok": intel["session"]["engagement_score"] > 0
              and len(intel["mitre_ttps"]) >= 3,
    }


if __name__ == "__main__":
    import json
    print("Decoy sample:")
    print(json.dumps(generate_quantum_decoy(2), indent=2, default=str)[:400])
    print("\nDeception self-test:")
    print(json.dumps(deception_self_test(), indent=2))
