import React, { useState, useRef, useEffect, useLayoutEffect, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { useLiveStream } from './hooks/useLiveStream'
import { useTheme } from './hooks/useTheme'
import { api } from './lib/api'
import ChannelCard from './components/ChannelCard'
import ChannelDetail from './components/ChannelDetail'
import IncidentList from './components/IncidentList'
import BlockList from './components/BlockList'
import AttackersPanel from './components/AttackersPanel'
import EventLog from './components/EventLog'
import HoneypotPanel from './components/HoneypotPanel'
import HQNNPanel from './components/HQNNPanel'
import IntelligencePanel from './components/IntelligencePanel'
import IntroSequence from './components/IntroSequence'
import { QFIDSMark, QFIDSWordmark } from './components/Logo'

export default function App() {
  const { connected, channels, globalState, log, incidents } = useLiveStream()
  const { theme, toggle: toggleTheme } = useTheme()
  const [tab, setTab] = useState('incidents')
  const [resetting, setResetting] = useState(false)
  const [logSince, setLogSince] = useState('')
  const [selectedChannelId, setSelectedChannelId] = useState(null)

  // ── Intro: show once per browser session ──────────────────
  const [showIntro, setShowIntro] = useState(() => {
    try { return !sessionStorage.getItem('qfids_intro_seen') } catch { return true }
  })
  const handleIntroDone = useCallback(() => {
    try { sessionStorage.setItem('qfids_intro_seen', '1') } catch {}
    setShowIntro(false)
  }, [])

  const anyAttack = channels.some(c => c.state === 'UNDER_ATTACK' || c.status === 'ATTACK')
  const anySuspicious = channels.some(c => c.status === 'SUSPICIOUS')

  let pillClass = ''
  let pillText = 'ALL CHANNELS NOMINAL'
  if (anyAttack) {
    pillClass = 'danger'
    pillText = `${globalState.active_incidents} ACTIVE INCIDENT${globalState.active_incidents !== 1 ? 'S' : ''}`
  } else if (anySuspicious) {
    pillClass = 'warn'
    pillText = 'ELEVATED MONITORING'
  }

  const fullReset = async () => {
    if (!window.confirm('Reset every channel, clear blocklist and incidents?')) return
    setResetting(true)
    try { await api.resetAll() } catch {}
    setResetting(false)
  }

  const channelsOnline = channels.filter(c => c.state !== 'TERMINATED').length
  const totalAttacks = channels.reduce((acc, c) => acc + (c.attacks ? c.attacks.length : 0), 0)

  return (
    <>
      {showIntro && <IntroSequence onComplete={handleIntroDone} />}

      <div className="app">
        <div className="topbar">
          <div className="brand">
            <QFIDSMark size={36} />
            <div className="brand-text">
              <QFIDSWordmark size={24} />
              <div className="brand-tagline">Quantum-Native Intrusion Defence · Detect · Divert · Encrypt</div>
            </div>
          </div>
          <div className="topbar-status">
            <div className={`status-pill ${pillClass}`}>
              <span className="dot" />
              <span>{pillText}</span>
            </div>
            <div className="status-pill">
              <span className={`conn-dot ${connected ? '' : 'off'}`} />
              <span>{connected ? 'Stream live · 5 Hz' : 'Reconnecting…'}</span>
            </div>
            <GlobalModeControl channels={channels} />
            <button className="btn tiny" onClick={fullReset} disabled={resetting}>
              {resetting ? 'Resetting…' : '↺ Reset'}
            </button>
            <button className="btn tiny" onClick={() => setShowIntro(true)} title="Replay intro">▶ Intro</button>
            <ThemeToggle theme={theme} onToggle={toggleTheme} />
          </div>
        </div>

        <div className="metrics">
          <div className="metric">
            <div className="k">Channels online</div>
            <div className="v">
              {channelsOnline}
              <span style={{ color: 'var(--text-3)', fontSize: 18, fontFamily: 'Space Mono', marginLeft: 6, fontWeight: 500 }}>
                / {channels.length || 4}
              </span>
            </div>
          </div>
          <div className="metric">
            <div className="k">Active incidents</div>
            <div className="v" style={{ color: globalState.active_incidents > 0 ? 'var(--danger)' : 'var(--text-0)' }}>
              {globalState.active_incidents}
            </div>
            <div className="sub">{totalAttacks} concurrent attacker{totalAttacks !== 1 ? 's' : ''}</div>
          </div>
          <div className="metric">
            <div className="k">Total incidents</div>
            <div className="v mono">{globalState.total_incidents}</div>
          </div>
          <div className="metric">
            <div className="k">Blocked IPs</div>
            <div className="v mono" style={{ color: globalState.blocked_ips > 0 ? 'var(--amber)' : 'var(--text-0)' }}>
              {globalState.blocked_ips}
            </div>
            <div className="sub">enforced via firewall middleware</div>
          </div>
        </div>

        <div className="main-grid">
          <div className="column">
            <div className="panel">
              <div className="panel-hd">
                <div>
                  <div className="eyebrow">Live channel monitor</div>
                  <div className="title">Channels under fingerprint surveillance</div>
                </div>
                <div className="eyebrow mono">
                  isolation forest · 30-sample window · {channels.length || 0} channels
                </div>
              </div>
              <div className="channel-grid">
                {channels.length === 0 && (
                  <div className="blocklist-empty" style={{ gridColumn: '1 / -1' }}>Connecting to stream…</div>
                )}
                {channels.map(ch => <ChannelCard key={ch.channel_id} channel={ch} onSelect={setSelectedChannelId} />)}
              </div>
            </div>

            <div className="panel">
              <div className="panel-hd">
                <div>
                  <div className="eyebrow">Real-time events</div>
                  <div className="title">Operations log</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div className="eyebrow mono">{log.length} entries</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <input type="datetime-local" value={logSince} onChange={e => setLogSince(e.target.value)}
                      style={{ fontSize: 10, fontFamily: 'Space Mono', background: 'var(--bg-2)', border: '1px solid var(--border)', color: 'var(--text-1)', borderRadius: 3, padding: '2px 5px' }} />
                    <button className="btn tiny" onClick={() => {
                      const since = logSince ? new Date(logSince).getTime() / 1000 : null
                      api.downloadLog(since)
                    }}>↓ Download log</button>
                  </div>
                </div>
              </div>
              <EventLog entries={log} />
            </div>

            <HQNNPanel />
            <IntelligencePanel channels={channels} />
          </div>

          <div className="column">
            <div className="panel">
              <div className="tabs">
                <div className={`tab ${tab === 'incidents' ? 'active' : ''}`} onClick={() => setTab('incidents')}>Incidents</div>
                <div className={`tab ${tab === 'attackers' ? 'active' : ''}`} onClick={() => setTab('attackers')}>Attackers</div>
                <div className={`tab ${tab === 'blocklist' ? 'active' : ''}`} onClick={() => setTab('blocklist')}>Blocklist</div>
                <div className={`tab ${tab === 'honeypot' ? 'active' : ''}`} onClick={() => setTab('honeypot')}>Honeypot</div>
              </div>
              {tab === 'incidents' && <IncidentList incidents={incidents} />}
              {tab === 'attackers' && <AttackersPanel />}
              {tab === 'blocklist' && <BlockList />}
              {tab === 'honeypot' && <HoneypotPanel />}
            </div>

            <div className="panel">
              <div className="panel-hd">
                <div>
                  <div className="eyebrow">Pipeline</div>
                  <div className="title">Detection → Response</div>
                </div>
              </div>
              <div className="panel-bd" style={{ fontSize: 13, lineHeight: 1.7, color: 'var(--text-1)' }}>
                <p style={{ margin: '0 0 10px' }}>
                  Each channel learns a physical-layer fingerprint, then a per-channel{' '}
                  <span className="mono" style={{ color: 'var(--primary)' }}>IsolationForest</span>{' '}
                  scores every 30-sample window against that baseline.
                </p>
                <p style={{ margin: '0 0 10px' }}>
                  When the score crosses{' '}<span className="mono" style={{ color: 'var(--danger)' }}>0.65</span>,
                  the response engine fires four asynchronous steps: terminate, re-authenticate,
                  reroute to honeypot, alert.
                </p>
                <div style={{
                  marginTop: 12, padding: '12px 14px',
                  background: 'rgba(255,0,170,0.06)',
                  border: '1px solid rgba(255,0,170,0.25)',
                  borderRadius: 3,
                }}>
                  <div style={{
                    fontFamily: 'Space Mono, monospace', fontSize: 9.5,
                    color: 'var(--magenta)', letterSpacing: '0.14em',
                    fontWeight: 700, marginBottom: 6, textTransform: 'uppercase',
                  }}>⬢ Layer 4 — Data Protection (HQNN)</div>
                  <p style={{ margin: 0, fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>
                    Even if all three prior defences fail, payload data is encrypted
                    with keystream from a 4-qubit hybrid quantum neural network.
                    Key material is derived from the BB84 sifted key. Tampering
                    is caught by HMAC-SHA256. See the HQNN panel for the live demo.
                  </p>
                </div>

                <div style={{
                  marginTop: 12, padding: '12px 14px',
                  background: 'rgba(0,221,255,0.06)',
                  border: '1px solid rgba(0,221,255,0.25)',
                  borderRadius: 3,
                }}>
                  <div style={{
                    fontFamily: 'Space Mono, monospace', fontSize: 9.5,
                    color: 'var(--primary)', letterSpacing: '0.14em',
                    fontWeight: 700, marginBottom: 6, textTransform: 'uppercase',
                  }}>⬢ Why we catch UNKNOWN attacks</div>
                  <p style={{ margin: '0 0 8px', fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>
                    We use <b style={{ color: 'var(--text-1)' }}>anomaly detection</b>, not
                    signature matching. The model is trained only on what <b style={{ color: 'var(--text-1)' }}>normal
                    traffic</b> looks like — it never learns specific attack patterns.
                    Anything that deviates from the learned baseline is flagged,
                    so a brand-new attack never seen in any dataset is still caught
                    because it still looks abnormal.
                  </p>
                  <p style={{ margin: 0, fontSize: 11.5, color: 'var(--text-3)', lineHeight: 1.6 }}>
                    Signature tools (Snort, Suricata) can only catch attacks already
                    in their rule list. Ours flags the unfamiliar — the dataset just
                    teaches it the shape of "normal," not a list of attacks.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {selectedChannelId && (
        <ChannelDetail
          channel={channels.find(c => c.channel_id === selectedChannelId)}
          incidents={incidents}
          onClose={() => setSelectedChannelId(null)}
        />
      )}
    </>
  )
}

function ThemeToggle({ theme, onToggle }) {
  const isDark = theme === 'dark'
  return (
    <button className="theme-toggle" onClick={onToggle} aria-label={isDark ? 'Switch to light' : 'Switch to dark'}>
      {isDark ? (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="4"/>
          <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" strokeLinecap="round"/>
        </svg>
      ) : (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" strokeLinejoin="round"/>
        </svg>
      )}
    </button>
  )
}

function GlobalModeControl({ channels }) {
  const [busy, setBusy] = useState(false)
  const [open, setOpen] = useState(false)
  const triggerRef = useRef(null)
  const menuRef    = useRef(null)
  const [coords, setCoords] = useState({ top: 0, left: 0 })

  const counts = (channels || []).reduce((acc, c) => { acc[c.mode] = (acc[c.mode] || 0) + 1; return acc }, {})
  const modes = Object.keys(counts)
  const summary = modes.length === 1 ? modes[0].toUpperCase() : 'MIXED'

  const positionMenu = () => {
    const t = triggerRef.current
    if (!t) return
    const r = t.getBoundingClientRect()
    const menuW = 260
    const margin = 8
    let left = r.right - menuW
    if (left < margin) left = margin
    if (left + menuW > window.innerWidth - margin) left = window.innerWidth - menuW - margin
    setCoords({ top: r.bottom + 6, left })
  }

  useLayoutEffect(() => {
    if (!open) return
    positionMenu()
    const handler = () => positionMenu()
    window.addEventListener('resize', handler)
    window.addEventListener('scroll', handler, true)
    return () => {
      window.removeEventListener('resize', handler)
      window.removeEventListener('scroll', handler, true)
    }
  }, [open])

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
  }, [open])

  const switchAll = async (mode) => {
    setBusy(true)
    try {
      await fetch('/api/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode }) })
    } catch {}
    setBusy(false); setOpen(false)
  }

  const SOURCES = [
    ['simulated', 'Simulated',         'Synthetic Gaussian baseline + 4 attack classes'],
    ['dataset',   'Quantum dataset',   'Physics-grounded photon-detector replay'],
    ['cicids',    'CICIDS-2017',       'Network IDS benchmark, 5 attack classes'],
    ['pcap',      'Live PCAP',         'Real network capture (requires sudo)'],
    ['anu_qrng',  'ANU QRNG · live',   'Real quantum random numbers from ANU API'],
    ['bb84',      'BB84 · Quantum KD', 'BB84 protocol with QBER eavesdropper detection'],
  ]

  return (
    <div className="status-pill" style={{ position: 'relative' }}>
      <span style={{ fontSize: 9, color: 'var(--text-3)', letterSpacing: '0.12em', fontWeight: 600 }}>ALL · SOURCE</span>
      <span className="mono" style={{ marginLeft: 4 }}>{summary}</span>
      <button
        ref={triggerRef}
        className="btn tiny"
        onClick={(e) => { e.stopPropagation(); setOpen(!open) }}
        disabled={busy}
        style={{ marginLeft: 8, padding: '2px 7px' }}
      >
        {open ? '×' : '⇄'}
      </button>
      {open && createPortal(
        <div
          ref={menuRef}
          className="mode-menu mode-menu-portal"
          style={{ top: coords.top, left: coords.left }}
        >
          <div className="mode-menu-hd">SET ALL CHANNELS · SOURCE</div>
          {SOURCES.map(([id, label, desc]) => (
            <button key={id} className="opt" disabled={busy} onClick={() => switchAll(id)}>
              <span>{label}</span>
              <span className="desc">{desc}</span>
            </button>
          ))}
        </div>,
        document.body
      )}
    </div>
  )
}

