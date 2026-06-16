import React, { useEffect, useState } from 'react'

/**
 * IntelligencePanel — showcases the differentiating features:
 *   - Cross-channel correlation matrix (heatmap)
 *   - Adversarial-aware hardening status
 *   - Per-channel security posture scores (A-F grade)
 *   - MITRE ATT&CK technique catalog
 */
export default function IntelligencePanel({ channels = [] }) {
  const [view, setView] = useState('posture')
  const [snap, setSnap]  = useState(null)
  const [postures, setPostures] = useState({})

  useEffect(() => {
    const fetch1 = async () => {
      try {
        const r = await fetch('/api/intelligence/snapshot')
        if (r.ok) setSnap(await r.json())
      } catch {}
    }
    fetch1()
    const iv = setInterval(fetch1, 2500)
    return () => clearInterval(iv)
  }, [])

  // Fetch posture for each channel
  useEffect(() => {
    if (!channels.length) return
    const fetchPostures = async () => {
      const out = {}
      for (const c of channels) {
        try {
          const r = await fetch(`/api/intelligence/posture/${c.channel_id}`)
          if (r.ok) out[c.channel_id] = await r.json()
        } catch {}
      }
      setPostures(out)
    }
    fetchPostures()
    const iv = setInterval(fetchPostures, 3000)
    return () => clearInterval(iv)
  }, [channels])

  return (
    <div className="panel">
      <div className="panel-hd">
        <div>
          <div className="eyebrow">Defence intelligence</div>
          <div className="title">Cross-channel · adversarial · MITRE</div>
        </div>
        <div className="eyebrow mono" style={{ fontSize: 9 }}>
          qfids-intel · v2.0
        </div>
      </div>

      <div className="intel-tabs">
        <button className={`intel-tab ${view === 'posture' ? 'active' : ''}`} onClick={() => setView('posture')}>
          ◆ Posture scores
        </button>
        <button className={`intel-tab ${view === 'correlation' ? 'active' : ''}`} onClick={() => setView('correlation')}>
          ⬢ Cross-channel
        </button>
        <button className={`intel-tab ${view === 'hardening' ? 'active' : ''}`} onClick={() => setView('hardening')}>
          ◈ Adversarial hardening
        </button>
        <button className={`intel-tab ${view === 'mitre' ? 'active' : ''}`} onClick={() => setView('mitre')}>
          ▣ MITRE ATT&amp;CK
        </button>
      </div>

      <div className="panel-bd">
        {view === 'posture'     && <PostureView channels={channels} postures={postures} />}
        {view === 'correlation' && <CorrelationView snap={snap} />}
        {view === 'hardening'   && <HardeningView snap={snap} />}
        {view === 'mitre'       && <MitreView snap={snap} />}
      </div>
    </div>
  )
}

/* ── Posture scores per channel ───────────────────────────────── */
function PostureView({ channels, postures }) {
  if (!channels.length) {
    return <div style={{ color: 'var(--text-3)' }}>Awaiting channels…</div>
  }
  return (
    <div className="intel-posture-grid">
      {channels.map(ch => {
        const p = postures[ch.channel_id]
        if (!p) return (
          <div key={ch.channel_id} className="posture-card">
            <div className="posture-channel">{ch.channel_id}</div>
            <div className="posture-grade">—</div>
          </div>
        )
        return (
          <div key={ch.channel_id} className={`posture-card grade-${p.grade}`}>
            <div className="posture-channel">{ch.channel_id}</div>
            <div className="posture-grade">{p.grade}</div>
            <div className="posture-score">{p.score}<span className="posture-of">/100</span></div>
            <div className="posture-factors">
              {Object.entries(p.factors).map(([k, v]) => (
                <div key={k} className="posture-factor">
                  <span className="posture-factor-k">{k.replace(/_/g, ' ')}</span>
                  <div className="posture-factor-bar">
                    <div className="posture-factor-fill" style={{ width: `${v}%` }} />
                    <span className="posture-factor-v">{Math.round(v)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

/* ── Cross-channel correlation matrix ─────────────────────────── */
function CorrelationView({ snap }) {
  if (!snap || !snap.correlation) {
    return <div style={{ color: 'var(--text-3)' }}>Loading correlation…</div>
  }
  const c = snap.correlation
  const channelOrder = c.channel_order || []
  const matrix = c.correlation_matrix || []

  return (
    <div className="intel-correlation">
      <div className="intel-section-title">⬢ CHANNEL-PAIR CO-SUSPICION MATRIX</div>
      <div className="intel-explainer">
        Values show co-occurrence of anomalies between channel pairs over the
        last {c.window_seconds}s. Bright cells indicate <em>coordinated</em> attacks
        across multiple channels — invisible to any per-channel detector.
      </div>

      {channelOrder.length > 0 && (
        <div className="corr-matrix-wrap">
          <table className="corr-matrix">
            <thead>
              <tr>
                <th></th>
                {channelOrder.map(c => <th key={c}>{c.replace('ch-', '')}</th>)}
              </tr>
            </thead>
            <tbody>
              {matrix.map((row, i) => (
                <tr key={i}>
                  <th>{channelOrder[i]?.replace('ch-', '')}</th>
                  {row.map((v, j) => {
                    const intensity = v
                    const bg = i === j
                      ? 'rgba(124,245,255,0.05)'
                      : `rgba(255, ${Math.round(255 - intensity * 200)}, ${Math.round(170 - intensity * 100)}, ${0.1 + intensity * 0.7})`
                    return (
                      <td key={j} style={{ background: bg }}>
                        {v.toFixed(2)}
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="intel-section-title" style={{ marginTop: 14 }}>
        ⚠ FANOUT ALERTS ({c.total_correlations} total)
      </div>
      {(c.recent_alerts || []).length === 0 ? (
        <div className="intel-empty">
          No cross-channel attacks detected. Single-channel attacks appear in the
          Incidents tab.
        </div>
      ) : (
        <div className="corr-alerts">
          {c.recent_alerts.slice().reverse().map((a, i) => (
            <div key={i} className={`corr-alert sev-${a.severity}`}>
              <div className="corr-alert-hd">
                <span className="corr-alert-ip">{a.ip}</span>
                <span className="corr-alert-sev">{a.severity?.toUpperCase()}</span>
              </div>
              <div className="corr-alert-body">{a.summary}</div>
              <div className="corr-alert-meta">
                channels: {(a.channels || []).join(' · ')}
                {' · '}touches: {a.count}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/* ── Adversarial hardening view ───────────────────────────────── */
function HardeningView({ snap }) {
  const [busy, setBusy] = useState(false)
  if (!snap || !snap.hardening) {
    return <div style={{ color: 'var(--text-3)' }}>Loading hardening status…</div>
  }
  const h = snap.hardening

  const runCycle = async () => {
    setBusy(true)
    try { await fetch('/api/intelligence/run-hardening', { method: 'POST' }) } catch {}
    setBusy(false)
  }

  return (
    <div className="intel-hardening">
      <div className="intel-section-title">◈ DETECTOR ROBUSTNESS</div>
      <div className="hardening-score-wrap">
        <div className="hardening-score-ring">
          <svg viewBox="0 0 100 100" width="120" height="120">
            <circle cx="50" cy="50" r="42" fill="none" stroke="var(--bg-3)" strokeWidth="6"/>
            <circle cx="50" cy="50" r="42" fill="none"
              stroke="url(#hardGrad)" strokeWidth="6" strokeLinecap="round"
              strokeDasharray={`${(h.robustness_score / 100) * 264} 264`}
              transform="rotate(-90 50 50)"/>
            <defs>
              <linearGradient id="hardGrad" x1="0" x2="1">
                <stop offset="0%"  stopColor="#00ddff"/>
                <stop offset="100%" stopColor="#ff00aa"/>
              </linearGradient>
            </defs>
            <text x="50" y="46" textAnchor="middle" fill="var(--text-0)"
              fontFamily="Rajdhani, sans-serif" fontWeight="700" fontSize="20">
              {Math.round(h.robustness_score)}
            </text>
            <text x="50" y="62" textAnchor="middle" fill="var(--text-3)"
              fontFamily="Space Mono, monospace" fontSize="8" letterSpacing="0.10em">
              /100
            </text>
          </svg>
        </div>
        <div className="hardening-info">
          <div className="hardening-row"><span>Hardening cycles</span><span>{h.total_hardening_cycles}</span></div>
          <div className="hardening-row"><span>Near-miss samples</span><span>{h.total_near_misses_generated}</span></div>
          <div className="hardening-row"><span>Mean threshold margin</span><span>{h.mean_margin}</span></div>
          <div className="hardening-row"><span>Last cycle</span><span>{new Date(h.last_cycle_ts * 1000).toLocaleTimeString()}</span></div>
        </div>
      </div>

      <div className="intel-explainer">
        Every 8 seconds, the system synthesizes adversarial "near-miss" samples — attacks
        designed to score just below the 0.65 threshold — and feeds them back as
        negative training signal. This pushes the detector's decision boundary so
        attackers must use ever-lower intensities to remain undetected. Robustness
        score climbs as cycles accumulate.
      </div>

      <button className="btn primary" onClick={runCycle} disabled={busy}>
        {busy ? 'Running…' : '◆ Run hardening cycle now'}
      </button>
    </div>
  )
}

/* ── MITRE ATT&CK catalog ─────────────────────────────────────── */
function MitreView({ snap }) {
  if (!snap || !snap.mitre_catalog) {
    return <div style={{ color: 'var(--text-3)' }}>Loading MITRE catalog…</div>
  }
  const catalog = snap.mitre_catalog
  return (
    <div className="intel-mitre">
      <div className="intel-section-title">▣ MITRE ATT&amp;CK MAPPING</div>
      <div className="intel-explainer">
        Every detection in this system is tagged with the corresponding MITRE ATT&amp;CK
        technique ID — the industry-standard taxonomy for adversarial behaviour.
        This makes incidents directly compatible with SIEM, SOAR, and threat-intel
        platforms.
      </div>
      <div className="mitre-grid">
        {Object.entries(catalog).map(([key, t]) => (
          <a key={key} className="mitre-card" href={t.url} target="_blank" rel="noopener noreferrer">
            <div className="mitre-id">{t.technique_id}</div>
            <div className="mitre-name">{t.technique_name}</div>
            <div className="mitre-tactic">{t.tactic}</div>
            <div className="mitre-phase">↳ {t.kill_chain_phase}</div>
            <div className="mitre-key">qfids: <code>{key}</code></div>
          </a>
        ))}
      </div>
    </div>
  )
}
