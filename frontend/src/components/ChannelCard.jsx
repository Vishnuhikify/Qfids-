import React, { useMemo, useState, useRef, useEffect, useLayoutEffect } from 'react'
import { createPortal } from 'react-dom'
import { api } from '../lib/api'

export default function ChannelCard({ channel, onSelect }) {
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [showMode, setShowMode] = useState(false)

  const resetChannel = async () => {
    setBusy(true)
    try { await api.resetChannel(channel.channel_id) } catch {}
    setBusy(false)
  }

  const klass = ['channel']
  if (channel.state === 'UNDER_ATTACK' || channel.status === 'ATTACK')
    klass.push('under-attack')
  else if (channel.status === 'SUSPICIOUS')
    klass.push('suspicious')
  if (channel.state === 'TERMINATED') klass.push('terminated')

  const stateLabel = channel.state === 'ACTIVE' && channel.status !== 'ACTIVE'
    ? channel.status
    : channel.state

  const attacks = channel.attacks || (channel.attack ? [channel.attack] : [])
  const attackCount = attacks.length

  // Source-data display
  const datasetSeg = channel.dataset_segment
  const cicidsSeg = channel.cicids_segment
  const pcapPackets = channel.pcap_packets
  const pcapFileInfo = channel.pcap_file_info

  return (
    <div className={klass.join(' ')}>
      {/* header */}
      <div className="channel-hd">
        <div
          style={{ minWidth: 0, flex: 1, cursor: onSelect ? 'pointer' : 'default' }}
          onClick={() => onSelect && onSelect(channel.channel_id)}
          title={onSelect ? 'Click to view channel details' : undefined}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="channel-id mono">{channel.channel_id}</span>
            <ModePill mode={channel.mode} />
            {onSelect && <span className="channel-detail-hint">view ›</span>}
          </div>
          <div className="channel-label">{channel.label}</div>
          {datasetSeg && (
            <div className={`source-badge ${datasetSeg.is_attack ? 'attack-segment' : 'benign'}`}>
              ▣ DATASET · seg {datasetSeg.seg_idx + 1}/{datasetSeg.n_segs} ·
              {' '}{datasetSeg.label.toUpperCase()}
              {datasetSeg.is_attack && ' · GROUND-TRUTH ATTACK'}
            </div>
          )}
          {cicidsSeg && (
            <div className={`source-badge ${cicidsSeg.is_attack ? 'attack-segment' : 'benign'}`}>
              ▣ CICIDS · flow {cicidsSeg.seg_idx + 1}/{cicidsSeg.n_segs} ·
              {' '}{cicidsSeg.label.toUpperCase()}
              {cicidsSeg.is_attack && ' · LABELLED ATTACK'}
            </div>
          )}
          {pcapPackets !== null && pcapPackets !== undefined && (
            <div className="source-badge benign">
              ▣ PCAP · {pcapPackets.toLocaleString()} packets captured
            </div>
          )}
          {pcapFileInfo && (
            <div className="source-badge benign">
              ▣ PCAP-FILE · {pcapFileInfo.consumed.toLocaleString()} / {pcapFileInfo.total.toLocaleString()} pkts
            </div>
          )}
          {channel.mode === 'bb84' && <BB84Badge channel={channel} />}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
          <span className={`state-tag ${stateLabel}`}>{stateLabel}</span>
          {channel.honeypot_active && (
            <span className="honeypot-marker">◆ Honeypot</span>
          )}
        </div>
      </div>

      {/* learning progress bar */}
      {channel.state === 'LEARNING' && (
        <div style={{ marginBottom: 8 }}>
          <div style={{
            fontFamily: 'JetBrains Mono', fontSize: 10,
            color: 'var(--text-3)', display: 'flex',
            justifyContent: 'space-between', marginBottom: 4,
          }}>
            <span>Learning fingerprint baseline…</span>
            <span>{Math.round(channel.learning_progress * 100)}%</span>
          </div>
          <div className="score-bar">
            <div
              className="score-bar-fill"
              style={{
                width: `${channel.learning_progress * 100}%`,
                background: 'var(--primary)',
              }}
            />
          </div>
        </div>
      )}

      {/* waveform + KDE */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 70px', gap: 8 }}>
        <Waveform history={channel.history} attackHistory={channel.attack_history} />
        <KDEPlot
          history={channel.history}
          baselineMean={channel.baseline_mean}
          baselineStd={channel.baseline_std}
          attacking={channel.status === 'ATTACK' || channel.state === 'UNDER_ATTACK'}
        />
      </div>

      {/* live stats */}
      <div className="ch-stats">
        <div className="ch-stat">
          <div className="k">μ live</div>
          <div className="v">{fmtNum(channel.features?.mean)}</div>
        </div>
        <div className="ch-stat">
          <div className="k">σ live</div>
          <div className="v">{fmtNum(channel.features?.std)}</div>
        </div>
        <div className="ch-stat">
          <div className="k">score</div>
          <div className="v" style={{ color: scoreColor(channel.score) }}>
            {Math.round(channel.score * 100)}
          </div>
        </div>
      </div>

      <div className="score-bar">
        <div
          className="score-bar-fill"
          style={{
            width: `${channel.score * 100}%`,
            background: scoreColor(channel.score),
          }}
        />
      </div>

      {/* attack ribbon — handles multi-attack */}
      {attackCount > 0 && (
        <div className={`attack-ribbon ${attackCount > 1 ? 'multi' : ''}`}>
          {attackCount === 1 ? (
            <>
              <span>
                ATK · {(attacks[0].type || '').toUpperCase()} ·
                {' '}{attacks[0].attacker_ip}:{attacks[0].attacker_port}
              </span>
              <span>{Math.round((attacks[0].intensity || 0) * 100)}%</span>
            </>
          ) : (
            <>
              <div className="row" style={{ fontSize: 10, color: 'var(--danger)' }}>
                <span style={{ fontWeight: 600 }}>{attackCount} concurrent attackers</span>
                <span>multi-attack</span>
              </div>
              {attacks.map((a, i) => (
                <div key={i} className="row" style={{ fontSize: 10 }}>
                  <span>{a.attacker_ip}:{a.attacker_port}</span>
                  <span>{(a.type || '').toUpperCase()} · {Math.round((a.intensity || 0) * 100)}%</span>
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {/* per-channel actions (defence-only: no attack injection here) */}
      <div className="ch-actions">
        <button
          className="btn tiny"
          disabled={busy}
          onClick={resetChannel}
        >
          ↺ Reset
        </button>
        <ModeSwitcherButton
          channelId={channel.channel_id}
          currentMode={channel.mode}
          busy={busy}
          setBusy={setBusy}
          setErr={setErr}
          open={showMode}
          setOpen={setShowMode}
        />
      </div>

      {err && (
        <div style={{ color: 'var(--danger)', fontSize: 11, marginTop: 6, fontFamily: 'JetBrains Mono' }}>
          {err}
        </div>
      )}

      {channel.mode === 'bb84' && <EveControl channelId={channel.channel_id} />}
    </div>
  )
}

// ── BB84 source badge — shows current QBER and Eve status ─────────────
function BB84Badge({ channel }) {
  // Try to read QBER from channel's latest sample
  const qber = channel.history && channel.history.length > 0
    ? channel.history[channel.history.length - 1]
    : null
  const qberPct = qber !== null ? (qber * 100).toFixed(2) : '—'
  const breaching = qber !== null && qber > 0.11
  return (
    <div className={`source-badge ${breaching ? 'attack-segment' : 'benign'}`}>
      ◈ BB84 · QBER {qberPct}%
      {breaching && ' · ABOVE THRESHOLD (Eve detected)'}
    </div>
  )
}

// ── Eve control: slider/buttons to set eavesdropper fraction ─────────
function EveControl({ channelId }) {
  const [busy, setBusy] = React.useState(false)
  const [lastSet, setLastSet] = React.useState(null)

  const setEve = async (frac) => {
    setBusy(true)
    try {
      await fetch(`/api/bb84/eve/${channelId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ eve_fraction: frac }),
      })
      setLastSet(frac)
    } catch (e) {
      console.error(e)
    }
    setBusy(false)
  }

  return (
    <div style={{
      marginTop: 8,
      padding: '8px 10px',
      background: 'var(--bg-3)',
      border: '1px solid var(--border)',
      borderRadius: 4,
    }}>
      <div style={{
        fontFamily: 'JetBrains Mono', fontSize: 9,
        color: 'var(--text-3)', letterSpacing: '0.1em',
        textTransform: 'uppercase', marginBottom: 6, fontWeight: 600,
      }}>
        Eavesdropper · Quantum Channel
      </div>
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        <button className="btn tiny" disabled={busy}
                onClick={() => setEve(0.0)}
                style={lastSet === 0.0 ? { borderColor: 'var(--safe)', color: 'var(--safe)' } : {}}>
          ⊘ none
        </button>
        <button className="btn tiny" disabled={busy}
                onClick={() => setEve(0.25)}
                style={lastSet === 0.25 ? { borderColor: 'var(--warn)', color: 'var(--warn)' } : {}}>
          ¼ Eve
        </button>
        <button className="btn tiny" disabled={busy}
                onClick={() => setEve(0.5)}
                style={lastSet === 0.5 ? { borderColor: 'var(--warn)', color: 'var(--warn)' } : {}}>
          ½ Eve
        </button>
        <button className="btn tiny danger" disabled={busy}
                onClick={() => setEve(1.0)}
                style={lastSet === 1.0 ? { background: 'var(--danger)', color: 'white' } : {}}>
          ▸ full Eve (intercept-resend)
        </button>
      </div>
      <div style={{
        fontFamily: 'JetBrains Mono', fontSize: 9,
        color: 'var(--text-3)', marginTop: 6, lineHeight: 1.4,
      }}>
        Activate intercept-resend to inject Eve. QBER will jump from{' '}
        <span style={{ color: 'var(--safe)' }}>~2%</span> (clean) to{' '}
        <span style={{ color: 'var(--danger)' }}>~25%</span> (full Eve).
        Detector flags any QBER &gt; 11% (BB84 abort threshold).
      </div>
    </div>
  )
}

// ── ModeSwitcherButton — opens a portal-based dropdown ─────────────────
// The dropdown is rendered into document.body so it escapes parent
// overflow:hidden, then positioned absolutely below the trigger button.
function ModeSwitcherButton({
  channelId, currentMode, busy, setBusy, setErr, open, setOpen,
}) {
  const triggerRef = useRef(null)
  const menuRef    = useRef(null)
  const fileInputRef = useRef(null)
  const [coords, setCoords] = useState({ top: 0, left: 0 })

  // Recompute menu position relative to the trigger button
  const positionMenu = () => {
    const t = triggerRef.current
    if (!t) return
    const r = t.getBoundingClientRect()
    const menuW = 260
    const margin = 8
    let left = r.right - menuW          // align right edges by default
    if (left < margin) left = margin    // clamp to left edge of viewport
    if (left + menuW > window.innerWidth - margin) {
      left = window.innerWidth - menuW - margin
    }
    setCoords({ top: r.bottom + 6, left })
  }

  useLayoutEffect(() => {
    if (!open) return
    positionMenu()
    const handler = () => positionMenu()
    window.addEventListener('resize', handler)
    window.addEventListener('scroll', handler, true) // capture phase = catch scroll on any ancestor
    return () => {
      window.removeEventListener('resize', handler)
      window.removeEventListener('scroll', handler, true)
    }
  }, [open])

  // Close on click outside (anywhere except trigger + menu)
  useEffect(() => {
    if (!open) return
    const onDocClick = (e) => {
      if (triggerRef.current?.contains(e.target)) return
      if (menuRef.current?.contains(e.target)) return
      setOpen(false)
    }
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDocClick)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDocClick)
      document.removeEventListener('keydown', onKey)
    }
  }, [open, setOpen])

  const switchTo = async (mode) => {
    setBusy(true); setErr('')
    try {
      const r = await fetch(`/api/mode/${channelId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      })
      if (!r.ok) {
        const j = await r.json().catch(() => ({}))
        throw new Error(j.detail || `${r.status}`)
      }
    } catch (e) {
      setErr(`mode-switch: ${e.message}`)
    }
    setBusy(false); setOpen(false)
  }

  const handleUpload = async (file) => {
    if (!file) return
    setBusy(true); setErr('')
    try {
      const fd = new FormData()
      fd.append('file', file)
      const r = await fetch(`/api/pcap/upload/${channelId}`, {
        method: 'POST',
        body: fd,
      })
      if (!r.ok) {
        const j = await r.json().catch(() => ({}))
        throw new Error(j.detail || `${r.status}`)
      }
      await switchTo('pcap_file')
    } catch (e) {
      setErr(`upload: ${e.message}`)
      setBusy(false)
      setOpen(false)
    }
  }

  const SOURCES = [
    { id: 'simulated', label: 'SIM',               desc: 'Synthetic baseline + injected attacks' },
    { id: 'dataset',   label: 'DATASET',           desc: 'Quantum noise replay (Excelitas SPCM physics)' },
    { id: 'cicids',    label: 'CICIDS-2017',       desc: '5 attack classes from network IDS benchmark' },
    { id: 'pcap',      label: 'Live PCAP',         desc: 'Real packet capture (requires sudo)' },
    { id: 'anu_qrng',  label: 'ANU QRNG · live',   desc: 'Real quantum random numbers from ANU API' },
    { id: 'bb84',      label: 'BB84 · Quantum KD', desc: 'Real BB84 protocol with QBER monitoring' },
  ]

  // The menu, rendered via portal to document.body so it escapes
  // any overflow:hidden ancestor (panel, channel card, etc.)
  const menu = open && createPortal(
    <div
      ref={menuRef}
      className="mode-menu mode-menu-portal"
      style={{ top: coords.top, left: coords.left }}
      role="menu"
    >
      <div className="mode-menu-hd">SELECT DATA SOURCE</div>
      {SOURCES.map((s) => (
        <button
          key={s.id}
          className={`opt ${currentMode === s.id ? 'current' : ''}`}
          disabled={busy}
          onClick={() => switchTo(s.id)}
          role="menuitem"
        >
          <span>{s.label}</span>
          <span className="desc">{s.desc}</span>
        </button>
      ))}
      <div className="opt opt-pcap-file">
        <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>PCAP · FILE</span>
          {currentMode === 'pcap_file' && (
            <span style={{ fontSize: 9, color: 'var(--primary)' }}>active</span>
          )}
        </span>
        <span className="desc">Upload Wireshark .pcap / .pcapng</span>
        <label className="upload-zone" style={{ marginTop: 6, padding: 8, fontSize: 10 }}>
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng,.cap"
            onChange={(e) => handleUpload(e.target.files?.[0])}
          />
          {busy ? 'Uploading…' : 'Click to choose .pcap'}
        </label>
      </div>
      <button
        className="opt opt-close"
        onClick={() => setOpen(false)}
      >
        <span>✕ Close</span>
      </button>
    </div>,
    document.body
  )

  return (
    <>
      <button
        ref={triggerRef}
        className="btn tiny"
        disabled={busy}
        onClick={(e) => { e.stopPropagation(); setOpen(!open) }}
      >
        ⇄ Source
      </button>
      {menu}
    </>
  )
}

// ── ModePill ─────────────────────────────────────────────────────
function ModePill({ mode }) {
  const map = {
    simulated: 'SIM',
    pcap:      'PCAP',
    dataset:   'DATASET',
    cicids:    'CICIDS',
    pcap_file: 'PCAP_FILE',
    anu_qrng:  'ANU_QRNG',
    bb84:      'BB84',
  }
  const label = map[mode] || 'SIM'
  const display = label === 'PCAP_FILE' ? 'PCAP·F' :
                  label === 'ANU_QRNG'  ? 'ANU·Q'  :
                  label === 'BB84'      ? 'BB84·Q' : label
  return <span className={`mode-pill ${label}`}>{display}</span>
}

// ── Waveform ─────────────────────────────────────────────────────
function Waveform({ history, attackHistory }) {
  const W = 280, H = 76
  const data = history || []

  const path = useMemo(() => {
    if (data.length < 2) return ''
    const yMin = -3.0, yMax = 3.0
    const xStep = W / (data.length - 1)
    return data.map((v, i) => {
      const x = i * xStep
      const y = H - ((v - yMin) / (yMax - yMin)) * H
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${Math.max(0, Math.min(H, y)).toFixed(1)}`
    }).join(' ')
  }, [data])

  const attackSegments = useMemo(() => {
    if (!attackHistory) return []
    const segs = []
    let start = -1
    for (let i = 0; i < attackHistory.length; i++) {
      if (attackHistory[i] && start === -1) start = i
      else if (!attackHistory[i] && start !== -1) {
        segs.push([start, i])
        start = -1
      }
    }
    if (start !== -1) segs.push([start, attackHistory.length])
    return segs
  }, [attackHistory])

  const xStep = data.length > 1 ? W / (data.length - 1) : 0

  return (
    <div className="waveform">
      <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id="waveFade" x1="0" x2="0" y1="0" y2="1">
            <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.5" />
            <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
          </linearGradient>
        </defs>
        <line x1="0" x2={W} y1={H/2} y2={H/2} stroke="rgba(255,255,255,0.08)" strokeDasharray="2 4" strokeWidth="1" />
        {attackSegments.map(([s, e], i) => (
          <rect
            key={i}
            x={s * xStep} y={0}
            width={Math.max(1, (e - s) * xStep)}
            height={H}
            fill="rgba(255, 93, 108, 0.10)"
          />
        ))}
        {path && (
          <path d={`${path} L${W},${H} L0,${H} Z`} fill="url(#waveFade)" stroke="none" opacity="0.7" />
        )}
        {path && (
          <path d={path} fill="none" stroke="var(--primary)" strokeWidth="1.4" strokeLinejoin="round" />
        )}
      </svg>
    </div>
  )
}

// ── KDE plot ──────────────────────────────────────────────────────
function KDEPlot({ history, baselineMean, baselineStd, attacking }) {
  const W = 70, H = 76

  const path = useMemo(() => {
    const data = history || []
    if (data.length < 8) return ''
    const yMin = -3.0, yMax = 3.0
    const N = 32
    const bw = 0.25
    const ys = []
    for (let i = 0; i < N; i++) {
      const y = yMin + (i / (N - 1)) * (yMax - yMin)
      let s = 0
      for (const v of data) {
        const u = (y - v) / bw
        s += Math.exp(-0.5 * u * u)
      }
      s /= (data.length * bw * Math.sqrt(2 * Math.PI))
      ys.push(s)
    }
    const maxV = Math.max(...ys, 1e-6)
    const pts = ys.map((d, i) => {
      const y = H - (i / (N - 1)) * H
      const x = (d / maxV) * (W - 6)
      return [x, y]
    })
    let pathD = `M0,${H} `
    for (const [x, y] of pts) pathD += `L${x.toFixed(1)},${y.toFixed(1)} `
    pathD += `L0,0 Z`
    return pathD
  }, [history])

  const baselinePath = useMemo(() => {
    if (baselineStd === undefined) return ''
    const yMin = -3.0, yMax = 3.0
    const N = 32
    const ys = []
    for (let i = 0; i < N; i++) {
      const y = yMin + (i / (N - 1)) * (yMax - yMin)
      const u = (y - baselineMean) / baselineStd
      ys.push(Math.exp(-0.5 * u * u))
    }
    const maxV = Math.max(...ys, 1e-6)
    const pts = ys.map((d, i) => {
      const y = H - (i / (N - 1)) * H
      const x = (d / maxV) * (W - 6)
      return [x, y]
    })
    return pts.map(([x, y], i) => `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ')
  }, [baselineMean, baselineStd])

  return (
    <div className="waveform" style={{ width: W }}>
      <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
        <line x1="0" x2={W} y1={H/2} y2={H/2} stroke="rgba(255,255,255,0.08)" strokeDasharray="2 4" />
        {baselinePath && (
          <path d={baselinePath} fill="none" stroke="rgba(255,255,255,0.25)" strokeWidth="1" strokeDasharray="3 3" />
        )}
        {path && (
          <path
            d={path}
            fill={attacking ? 'rgba(255,93,108,0.4)' : 'rgba(124,245,255,0.3)'}
            stroke={attacking ? 'var(--danger)' : 'var(--primary)'}
            strokeWidth="1"
          />
        )}
      </svg>
    </div>
  )
}

function fmtNum(v) {
  if (v === undefined || v === null || Number.isNaN(v)) return '—'
  const abs = Math.abs(v)
  if (abs < 0.0001) return '0'
  if (abs >= 100) return v.toFixed(1)
  return v.toFixed(3)
}

function scoreColor(score) {
  if (score >= 0.65) return 'var(--danger)'
  if (score >= 0.45) return 'var(--warn)'
  return 'var(--safe)'
}
