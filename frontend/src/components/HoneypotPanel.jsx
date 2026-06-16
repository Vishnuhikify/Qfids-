import React, { useEffect, useState } from 'react'
import { api } from '../lib/api'

export default function HoneypotPanel() {
  const [data, setData]       = useState(null)
  const [err, setErr]         = useState('')
  const [loading, setLoading] = useState(false)
  const [view, setView]       = useState('environment')

  const fetchHoneypot = async () => {
    setLoading(true); setErr('')
    try {
      const r = await api.honeypot()
      setData(r)
    } catch (e) { setErr(e.message) }
    setLoading(false)
  }

  useEffect(() => { fetchHoneypot() }, [])

  return (
    <div style={{ padding: '14px 16px' }}>
      <DiversionDiagram />

      <div className="hp-tabs">
        <button className={`hp-tab ${view === 'environment' ? 'active' : ''}`} onClick={() => setView('environment')}>
          ⬢ Virtual Environment
        </button>
        <button className={`hp-tab ${view === 'quantum-decoy' ? 'active' : ''}`} onClick={() => setView('quantum-decoy')}>
          ✦ Quantum Decoy
        </button>
        <button className={`hp-tab ${view === 'env-details' ? 'active' : ''}`} onClick={() => setView('env-details')}>
          ◈ System Details
        </button>
        <button className={`hp-tab ${view === 'response' ? 'active' : ''}`} onClick={() => setView('response')}>
          ▣ Decoy Response
        </button>
      </div>

      {view === 'environment'   && <VirtualEnvironmentView callerIP={data?.your_ip} />}
      {view === 'quantum-decoy' && <QuantumDecoyView />}
      {view === 'env-details'   && <EnvironmentDetails callerIP={data?.your_ip} />}
      {view === 'response'      && <ResponseView data={data} err={err} loading={loading} onRefetch={fetchHoneypot} />}
    </div>
  )
}

function DiversionDiagram() {
  return (
    <div className="diversion-diagram">
      <div className="dd-node dd-attacker">
        <div className="dd-icon">☠</div>
        <div className="dd-label">ATTACKER</div>
        <div className="dd-sub">203.0.113.42</div>
      </div>

      <div className="dd-link">
        <div className="dd-link-line dd-link-blocked" />
        <div className="dd-link-x">✕ BLOCKED</div>
      </div>

      <div className="dd-node dd-real">
        <div className="dd-icon">⬢</div>
        <div className="dd-label">REAL SYSTEM</div>
        <div className="dd-sub">production</div>
      </div>

      <div className="dd-diversion">
        <svg width="100%" height="60" viewBox="0 0 240 60" preserveAspectRatio="none">
          <defs>
            <linearGradient id="ddg" x1="0" x2="1">
              <stop offset="0%"   stopColor="#ff9900" stopOpacity="0"/>
              <stop offset="50%"  stopColor="#ff9900" stopOpacity="1"/>
              <stop offset="100%" stopColor="#ff9900" stopOpacity="0"/>
            </linearGradient>
          </defs>
          <path d="M0,15 Q120,55 240,15" fill="none" stroke="url(#ddg)" strokeWidth="1.5" strokeDasharray="4 3" className="dd-diversion-path"/>
          <text x="120" y="50" textAnchor="middle" fill="#ff9900" fontFamily="Space Mono, monospace" fontSize="9" letterSpacing="0.12em">
            ↓ DIVERTED ↓
          </text>
        </svg>
      </div>

      <div className="dd-node dd-honeypot">
        <div className="dd-icon">◈</div>
        <div className="dd-label">VIRTUAL ENV</div>
        <div className="dd-sub">honeypot-vm-03</div>
        <div className="dd-pulse" />
      </div>
    </div>
  )
}

function VirtualEnvironmentView({ callerIP }) {
  const [packets, setPackets] = useState(0)
  const [keystrokes, setKeystrokes] = useState(0)
  const [commands, setCommands] = useState(0)

  useEffect(() => {
    const iv = setInterval(() => {
      setPackets(p => p + Math.floor(Math.random() * 4) + 1)
      if (Math.random() > 0.5) setKeystrokes(k => k + Math.floor(Math.random() * 8) + 1)
      if (Math.random() > 0.85) setCommands(c => c + 1)
    }, 800)
    return () => clearInterval(iv)
  }, [])

  return (
    <div className="ve-container">
      <div className="ve-banner">
        <span className="ve-banner-dot" />
        <span className="ve-banner-text">
          ATTACKER ACTIVELY ENGAGED IN VIRTUAL SANDBOX · LIVE MONITORING
        </span>
      </div>

      <div className="ve-vm-card">
        <div className="ve-vm-hd">
          <div className="ve-vm-title">
            <span className="ve-vm-icon">⬢</span> honeypot-vm-03.isolated.local
          </div>
          <span className="ve-vm-status">RUNNING · ISOLATED</span>
        </div>

        <div className="ve-vm-bd">
          <div className="ve-terminal">
            <div className="ve-term-line"><span className="ve-prompt">attacker@db-replica-03:~$</span> ls -la /var/secrets/</div>
            <div className="ve-term-line ve-term-out">total 48</div>
            <div className="ve-term-line ve-term-out">-rw-r--r--  1 root root  1247 Mar 14  2024 api_keys.json</div>
            <div className="ve-term-line ve-term-out">-rw-r--r--  1 root root   892 Mar 14  2024 db_credentials.yml</div>
            <div className="ve-term-line ve-term-out">-rw-r--r--  1 root root  3104 Mar 14  2024 ssh_private.pem</div>
            <div className="ve-term-line"><span className="ve-prompt">attacker@db-replica-03:~$</span> cat api_keys.json</div>
            <div className="ve-term-line ve-term-out ve-term-fake">{`{ "stripe_live": "sk_live_DECOY_xJ8k4Pm2nQ...",`}</div>
            <div className="ve-term-line ve-term-out ve-term-fake">{`  "aws_secret": "DECOY_wJalrXUtnFEMI/K7M...",`}</div>
            <div className="ve-term-line ve-term-out ve-term-fake">{`  "internal_db": "postgres://decoy:fake@..." }`}</div>
            <div className="ve-term-line"><span className="ve-prompt">attacker@db-replica-03:~$</span> <span className="ve-term-cursor">█</span></div>
          </div>

          <div className="ve-stats">
            <div className="ve-stat">
              <div className="ve-stat-k">Packets intercepted</div>
              <div className="ve-stat-v">{packets.toLocaleString()}</div>
            </div>
            <div className="ve-stat">
              <div className="ve-stat-k">Keystrokes logged</div>
              <div className="ve-stat-v">{keystrokes.toLocaleString()}</div>
            </div>
            <div className="ve-stat">
              <div className="ve-stat-k">Commands executed</div>
              <div className="ve-stat-v">{commands}</div>
            </div>
            <div className="ve-stat">
              <div className="ve-stat-k">Source IP</div>
              <div className="ve-stat-v ve-stat-ip">{callerIP || '203.0.113.42'}</div>
            </div>
          </div>
        </div>

        <div className="ve-vm-floor" />
      </div>

      <div className="ve-footnote">
        All data inside this environment is synthetic. Real credentials, tokens, and PII
        are never present. Every keystroke and packet is logged for forensic analysis
        while the attacker believes they have compromised a production system.
      </div>
    </div>
  )
}

function EnvironmentDetails({ callerIP }) {
  const [profile, setProfile] = React.useState(null)
  const [loading, setLoading] = React.useState(true)

  const loadProfile = React.useCallback(async () => {
    setLoading(true)
    try {
      const q = callerIP ? `?attacker_ip=${encodeURIComponent(callerIP)}` : ''
      const r = await fetch('/api/honeypot/environment' + q)
      const d = await r.json()
      setProfile(d)
    } catch { /* keep last */ }
    setLoading(false)
  }, [callerIP])

  React.useEffect(() => { loadProfile() }, [loadProfile])

  const details = profile ? [
    { k: 'Hostname',          v: profile.hostname },
    { k: 'OS',                v: `${profile.os} (kernel ${profile.kernel})` },
    { k: 'Container',         v: profile.container },
    { k: 'Network',           v: profile.network },
    { k: 'Gateway',           v: profile.gateway },
    { k: 'DNS',               v: profile.dns },
    { k: 'CPU',               v: profile.cpu },
    { k: 'Memory',            v: profile.memory },
    { k: 'Disk',              v: profile.disk },
    { k: 'Database',          v: profile.database },
    { k: 'Auth backend',      v: profile.auth_backend },
    { k: 'Filesystem',        v: profile.filesystem },
    { k: 'Logging',           v: profile.logging },
    { k: 'Attacker IP',       v: profile.attacker_ip },
    { k: 'Session ID',        v: profile.session_id },
    { k: 'Spun up at',        v: profile.spun_up_at },
    { k: 'Decoy data assets', v: profile.decoy_assets },
    { k: 'Egress policy',     v: profile.egress_policy },
  ] : []

  return (
    <div className="env-details">
      <div className="env-section-title" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>⬢ VIRTUAL MACHINE PROFILE</span>
        <button className="btn tiny" onClick={loadProfile} disabled={loading} style={{ fontSize: 10 }}>
          {loading ? '…' : '↻ new session'}
        </button>
      </div>
      <div className="env-grid">
        {loading && !profile && <div className="env-row"><span className="env-v">Provisioning decoy VM…</span></div>}
        {details.map(d => (
          <div key={d.k} className="env-row">
            <span className="env-k">{d.k}</span>
            <span className="env-v">{d.v}</span>
          </div>
        ))}
      </div>

      <div className="env-section-title" style={{ marginTop: 14 }}>◈ ACTIVE COUNTERMEASURES</div>
      <div className="env-cm-list">
        <CMItem code="CM-01" name="Network isolation"     desc="VM runs in VLAN with all egress dropped at L3" />
        <CMItem code="CM-02" name="Synthetic data only"   desc="All credentials, tokens, and PII are fake — zero real assets exposed" />
        <CMItem code="CM-03" name="Session recording"     desc="Every keystroke, packet, and syscall logged to forensics host" />
        <CMItem code="CM-04" name="Time-bounded sandbox"  desc="Filesystem resets periodically via overlayfs" />
        <CMItem code="CM-05" name="Throttled resources"   desc="CPU, RAM, and disk capped — attacker cannot exhaust host" />
        <CMItem code="CM-06" name="Snapshot per session"  desc="Forensic image captured on session close" />
      </div>
    </div>
  )
}

function CMItem({ code, name, desc }) {
  return (
    <div className="env-cm">
      <span className="env-cm-code">{code}</span>
      <div>
        <div className="env-cm-name">{name}</div>
        <div className="env-cm-desc">{desc}</div>
      </div>
    </div>
  )
}

function ResponseView({ data, err, loading, onRefetch }) {
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
        <button className="btn tiny" onClick={onRefetch} disabled={loading}>
          {loading ? 'Fetching…' : '↻ Re-fetch /honeypot/serve'}
        </button>
        <span style={{ fontFamily: 'Space Mono, monospace', fontSize: 10, color: 'var(--text-3)' }}>
          GET /honeypot/serve
        </span>
      </div>
      {err && (
        <div style={{ padding: 10, color: 'var(--danger)', fontFamily: 'Space Mono, monospace', fontSize: 11 }}>
          Error: {err}
        </div>
      )}
      {data && (
        <pre style={{
          background: 'var(--bg-0)', border: '1px solid var(--border)',
          padding: 12, margin: 0, fontSize: 11,
          fontFamily: 'Space Mono, monospace',
          color: '#ff00aa', borderRadius: 4, overflow: 'auto', maxHeight: 280,
        }}>
{`-- honeypot/serve response --
caller_ip : ${data.your_ip}
served_at : ${new Date((data.ts || 0) * 1000).toLocaleTimeString()}
endpoint  : GET /honeypot/serve
status    : 200 OK  (attacker sees legitimate response)

SELECT id, email, api_secret FROM users LIMIT ${data.rows?.length || 0};

 id    | email                         | api_secret
-------+-------------------------------+-----------------------------
${(data.rows || []).map(r =>
  ` ${String(r.id).padEnd(6)}| ${r.user.padEnd(29)} | ${r.secret}`
).join('\n')}

(${data.rows?.length || 0} rows)

-- note: all data is synthetic decoy payload --
-- operator alert: suspect IP ${data.your_ip} is being monitored --`}
        </pre>
      )}
    </div>
  )
}

/* ── Quantum-randomized decoy view ────────────────────────────── */
function QuantumDecoyView() {
  const [decoy, setDecoy]   = useState(null)
  const [stats, setStats]   = useState(null)
  const [busy, setBusy]     = useState(false)

  const fetchDecoy = async () => {
    setBusy(true)
    try {
      const [r1, r2] = await Promise.all([
        fetch('/api/honeypot/quantum-decoy'),
        fetch('/api/honeypot/entropy-stats'),
      ])
      if (r1.ok) setDecoy(await r1.json())
      if (r2.ok) setStats(await r2.json())
    } catch {}
    setBusy(false)
  }

  useEffect(() => { fetchDecoy() }, [])
  useEffect(() => {
    const iv = setInterval(() => {
      fetch('/api/honeypot/entropy-stats').then(r => r.ok && r.json().then(setStats)).catch(() => {})
    }, 3000)
    return () => clearInterval(iv)
  }, [])

  return (
    <div className="qd-container">
      <div className="qd-banner">
        <span className="qd-banner-icon">✦</span>
        <div>
          <div className="qd-banner-title">QUANTUM-RANDOMIZED DECOY CONTENT</div>
          <div className="qd-banner-sub">
            Every fake credential, fake user, and fake API key is freshly
            generated from real ANU QRNG measured photon shot noise.
            No two sessions see the same decoys.
          </div>
        </div>
      </div>

      {/* Entropy source meter */}
      {stats && (
        <div className="qd-entropy">
          <div className="qd-entropy-row">
            <span className="qd-entropy-k">ANU QRNG status</span>
            <span className={`qd-entropy-v qd-status-${stats.last_fetch_status === 'ok' ? 'ok' : 'fail'}`}>
              {stats.last_fetch_status === 'ok' ? '✓ live' : '⚠ fallback'} · {stats.last_fetch_status}
            </span>
          </div>
          <div className="qd-entropy-row">
            <span className="qd-entropy-k">Bytes from quantum</span>
            <span className="qd-entropy-v">{stats.bytes_from_quantum?.toLocaleString() || 0}</span>
          </div>
          <div className="qd-entropy-row">
            <span className="qd-entropy-k">Bytes from crypto fallback</span>
            <span className="qd-entropy-v">{stats.bytes_from_fallback?.toLocaleString() || 0}</span>
          </div>
          <div className="qd-entropy-row">
            <span className="qd-entropy-k">Quantum fetches</span>
            <span className="qd-entropy-v">{stats.quantum_fetches}</span>
          </div>
          <div className="qd-entropy-row">
            <span className="qd-entropy-k">Pool buffered</span>
            <span className="qd-entropy-v">{stats.pool_size} / {stats.target_size} bytes</span>
          </div>
          {/* Bar showing quantum vs fallback ratio */}
          <div className="qd-ratio-bar">
            {(() => {
              const q = stats.bytes_from_quantum || 0
              const f = stats.bytes_from_fallback || 0
              const total = q + f
              const qPct = total ? (q / total) * 100 : 0
              return (
                <>
                  <div className="qd-ratio-q" style={{ width: `${qPct}%` }} />
                  <div className="qd-ratio-f" style={{ width: `${100 - qPct}%` }} />
                </>
              )
            })()}
          </div>
          <div className="qd-ratio-lbl">
            <span style={{ color: 'var(--primary)' }}>■ quantum</span>
            <span style={{ color: 'var(--amber)' }}>■ crypto fallback</span>
          </div>
        </div>
      )}

      <button className="btn primary" onClick={fetchDecoy} disabled={busy}
        style={{ width: '100%', marginBottom: 12 }}>
        {busy ? '⟳ Generating decoy with quantum entropy…' : '✦ Regenerate decoy (consume quantum entropy)'}
      </button>

      {decoy && (
        <>
          <div className="qd-source-tag" data-source={decoy.entropy_source}>
            ENTROPY SOURCE: <strong>{decoy.entropy_source.toUpperCase()}</strong>
            <span style={{ marginLeft: 8, color: 'var(--text-3)' }}>
              ({decoy.entropy_breakdown.quantum}Q · {decoy.entropy_breakdown.mixed}M · {decoy.entropy_breakdown.fallback}F)
            </span>
          </div>

          <div className="qd-provenance">
            {decoy.provenance}
          </div>

          <div className="qd-rows">
            {decoy.rows.map((r, i) => (
              <div key={i} className="qd-row">
                <div className="qd-row-id">#{r.id}</div>
                <div className="qd-row-main">
                  <div className="qd-row-user">{r.user}</div>
                  <div className="qd-row-secret">{r.secret}</div>
                  <div className="qd-row-meta">card ****{r.cc_last4} · cvv {r.cvv}</div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
