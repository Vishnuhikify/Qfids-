import React, { useMemo } from 'react'

/**
 * ChannelDetail — a full-screen detail view for a single selected channel.
 * Shows a large waveform, live score, defence status (adaptive threshold +
 * baseline integrity guard), feature breakdown, and the channel's incidents.
 *
 * Driven entirely by the live `channel` object from the websocket stream plus
 * the `incidents` array, so it updates in real time with no extra fetching.
 */
export default function ChannelDetail({ channel, incidents, onClose }) {
  if (!channel) return null

  const channelIncidents = (incidents || []).filter(
    (i) => i.channel_id === channel.channel_id
  )

  const stateLabel = channel.state || 'ACTIVE'
  const score = channel.score || 0
  const defense = channel.defense || {}
  const at = defense.adaptive_threshold || {}
  const bg = defense.baseline_guard || {}
  const bc = defense.baseline_check || null

  const scorePct = Math.min(100, Math.round(score * 100))
  const effThr = at.effective_threshold != null ? at.effective_threshold : 0.65
  const pressurePct = at.pressure_capacity
    ? Math.min(100, Math.round((at.pressure / at.pressure_capacity) * 100))
    : 0

  return (
    <div className="cd-overlay" onClick={onClose}>
      <div className="cd-modal" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="cd-header">
          <div>
            <div className="cd-eyebrow mono">{channel.channel_id} · live detail</div>
            <div className="cd-title">{channel.label}</div>
          </div>
          <div className="cd-header-right">
            <span className={`state-tag ${stateLabel}`}>{stateLabel}</span>
            <button className="cd-close" onClick={onClose}>✕</button>
          </div>
        </div>

        <div className="cd-body">
          {/* Large waveform */}
          <div className="cd-section">
            <div className="cd-section-title">Live signal waveform</div>
            <BigWaveform
              history={channel.history}
              attackHistory={channel.attack_history}
            />
            <div className="cd-wave-legend mono">
              <span><i className="dot dot-normal" /> normal sample</span>
              <span><i className="dot dot-attack" /> flagged sample</span>
              <span>baseline μ {fmt(channel.baseline_mean)} · σ {fmt(channel.baseline_std)}</span>
            </div>
          </div>

          {/* Score + defence grid */}
          <div className="cd-grid">
            {/* Anomaly score */}
            <div className="cd-card">
              <div className="cd-card-title">Anomaly score</div>
              <div className={`cd-bignum ${score >= effThr ? 'danger' : ''}`}>
                {score.toFixed(3)}
              </div>
              <div className="cd-bar">
                <div
                  className="cd-bar-fill"
                  style={{
                    width: `${scorePct}%`,
                    background: score >= effThr ? 'var(--danger)' : 'var(--primary)',
                  }}
                />
                <div className="cd-bar-thr" style={{ left: `${effThr * 100}%` }} />
              </div>
              <div className="cd-card-note mono">
                trigger at {effThr.toFixed(3)} (adaptive)
              </div>
            </div>

            {/* Adaptive threshold defence */}
            <div className="cd-card">
              <div className="cd-card-title">
                Adaptive threshold
                <span className="cd-tag">anti-evasion</span>
              </div>
              <div className="cd-kv">
                <span>Effective threshold</span><b>{effThr.toFixed(3)}</b>
              </div>
              <div className="cd-kv">
                <span>Hard floor</span><b>{(at.hard_floor ?? 0.65).toFixed(2)}</b>
              </div>
              <div className="cd-kv">
                <span>Pressure (low-and-slow)</span>
                <b>{(at.pressure ?? 0).toFixed(2)} / {at.pressure_capacity ?? 4}</b>
              </div>
              <div className="cd-bar small">
                <div className="cd-bar-fill" style={{
                  width: `${pressurePct}%`,
                  background: pressurePct > 75 ? 'var(--danger)' : 'var(--warn, #f5a623)',
                }} />
              </div>
              <div className="cd-card-note mono">
                boundary trips {at.boundary_trips ?? 0} · pressure trips {at.pressure_trips ?? 0}
              </div>
            </div>

            {/* Baseline integrity guard */}
            <div className="cd-card">
              <div className="cd-card-title">
                Baseline integrity
                <span className="cd-tag">anti-poisoning</span>
              </div>
              <div className="cd-kv">
                <span>Reference committed</span>
                <b className={bg.reference_committed ? 'ok' : ''}>
                  {bg.reference_committed ? 'yes' : 'learning…'}
                </b>
              </div>
              <div className="cd-kv">
                <span>Reference hash</span>
                <b className="mono">{bg.reference_hash || '—'}</b>
              </div>
              <div className="cd-kv">
                <span>Live drift</span>
                <b className={bc && bc.poisoning_suspected ? 'danger' : 'ok'}>
                  {bc ? bc.drift.toFixed(3) : '—'}
                  {' / '}
                  {(bg.drift_tolerance ?? 0.25).toFixed(2)}
                </b>
              </div>
              <div className="cd-kv">
                <span>Drift alerts</span><b>{bg.drift_alerts ?? 0}</b>
              </div>
              <div className="cd-card-note mono">
                {bc ? (bc.poisoning_suspected
                  ? '⚠ possible poisoning — drift exceeds tolerance'
                  : 'baseline stable') : 'reference not yet committed'}
              </div>
            </div>

            {/* Feature breakdown */}
            <div className="cd-card">
              <div className="cd-card-title">Detector features</div>
              {channel.features && Object.keys(channel.features).length > 0 ? (
                Object.entries(channel.features).slice(0, 6).map(([k, v]) => (
                  <div className="cd-kv" key={k}>
                    <span>{k}</span>
                    <b>{typeof v === 'number' ? v.toFixed(3) : String(v)}</b>
                  </div>
                ))
              ) : (
                <div className="cd-card-note mono">
                  no features yet (channel may be learning)
                </div>
              )}
            </div>
          </div>

          {/* Active attacks */}
          {channel.attacks && channel.attacks.length > 0 && (
            <div className="cd-section">
              <div className="cd-section-title">Active attacks ({channel.attacks.length})</div>
              <div className="cd-attacks">
                {channel.attacks.map((a, idx) => (
                  <div className="cd-attack-row" key={idx}>
                    <span className="cd-attack-type">{(a.type || '').toUpperCase()}</span>
                    <span className="mono">{a.attacker_ip}:{a.attacker_port}</span>
                    <span className="mono">int {fmt(a.intensity)}</span>
                    <span className="mono">{a.started_at_iso}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Incidents */}
          <div className="cd-section">
            <div className="cd-section-title">
              Incidents for this channel ({channelIncidents.length})
            </div>
            {channelIncidents.length === 0 ? (
              <div className="cd-card-note mono">no incidents recorded</div>
            ) : (
              <div className="cd-incidents">
                {channelIncidents.slice(0, 8).map((inc) => (
                  <div className="cd-incident" key={inc.incident_id}>
                    <div className="cd-incident-top">
                      <span className="mono cd-incident-id">{inc.incident_id}</span>
                      <span className={`cd-incident-state ${inc.closed_at ? 'closed' : 'open'}`}>
                        {inc.closed_at ? 'resolved' : 'active'}
                      </span>
                    </div>
                    <div className="cd-incident-meta mono">
                      {(inc.attack_type || '').toUpperCase()} ·
                      {' '}{inc.attacker_ip}:{inc.attacker_port} ·
                      {' '}honeypot pkts {inc.honeypot_packets ?? 0}
                      {inc.mitre_technique && ` · ${inc.mitre_technique}`}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function fmt(v) {
  return typeof v === 'number' ? v.toFixed(3) : (v ?? '—')
}

/* Large waveform for the detail view */
function BigWaveform({ history, attackHistory }) {
  const W = 800
  const H = 160
  const data = history || []
  const attacks = attackHistory || []

  const { path, points } = useMemo(() => {
    if (data.length < 2) return { path: '', points: [] }
    const min = Math.min(...data)
    const max = Math.max(...data)
    const range = max - min || 1
    const stepX = W / (data.length - 1)
    const pts = data.map((v, i) => {
      const x = i * stepX
      const y = H - ((v - min) / range) * (H - 20) - 10
      return { x, y, attack: attacks[i] }
    })
    const path = pts.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ')
    return { path, points: pts }
  }, [data, attacks])

  return (
    <div className="cd-bigwave">
      <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
        <line x1="0" y1={H / 2} x2={W} y2={H / 2} stroke="var(--border)" strokeWidth="1" strokeDasharray="4 4" />
        {path && <path d={path} fill="none" stroke="var(--primary)" strokeWidth="1.5" />}
        {points.filter((p) => p.attack).map((p, i) => (
          <circle key={i} cx={p.x} cy={p.y} r="3" fill="var(--danger)" />
        ))}
      </svg>
    </div>
  )
}
