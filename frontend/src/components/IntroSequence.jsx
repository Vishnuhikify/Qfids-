import React, { useEffect, useRef, useState } from 'react'
import { QFIDSMark } from './Logo'

/**
 * Cinematic boot sequence — plays once on load (~5s).
 * Layers:
 *   1. Matrix-style code rain (background)
 *   2. Scanning grid + drifting particles
 *   3. Multi-frequency animated waves with attack spikes
 *   4. Radar sweep + concentric rings
 *   5. Hacker terminal with streaming attack log
 *   6. HUD corners (sys info, geo coords, bios bars)
 *   7. Center brand with progress bar
 *   8. Vignette + scanlines for film grain
 */
export default function IntroSequence({ onComplete }) {
  const matrixRef = useRef(null)
  const waveRef   = useRef(null)
  const [phase, setPhase]       = useState(0)
  const [progress, setProgress] = useState(0)
  const [logLines, setLogLines] = useState([])

  const SCRIPT = [
    { t: 180,  text: '> QF-IDS-CORE v7.2.1 booting...',                         level: 'info'    },
    { t: 380,  text: '> initializing quantum noise detector ............ OK',   level: 'success' },
    { t: 580,  text: '> loading IsolationForest (sklearn 1.4.2) ........ OK',   level: 'success' },
    { t: 780,  text: '> opening 4 fingerprint channels ................. OK',   level: 'success' },
    { t: 1050, text: '> ⚠ INCOMING INTRUSION @ 203.0.113.42:47291',             level: 'danger'  },
    { t: 1280, text: '> ⚠ packet anomaly score 0.87 — ABOVE THRESHOLD',          level: 'danger'  },
    { t: 1510, text: '> ⚠ MITM signature matched on Channel Alpha',                   level: 'danger'  },
    { t: 1750, text: '> [response] TERMINATE → REAUTH → HONEYPOT → ALERT',       level: 'warn'    },
    { t: 1980, text: '> [response] attacker rerouted to /honeypot/serve',        level: 'warn'    },
    { t: 2210, text: '> ✓ blocklist updated · firewall middleware engaged',      level: 'success' },
    { t: 2450, text: '> ✓ BB84 QBER nominal · 2.3% (below 11% threshold)',       level: 'success' },
    { t: 2700, text: '> ✓ ALL CHANNELS SECURED · entering operations console',   level: 'success' },
  ]

  // ── Matrix code rain ────────────────────────────────────────
  useEffect(() => {
    const canvas = matrixRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let w = canvas.width  = window.innerWidth
    let h = canvas.height = window.innerHeight

    const CHARS = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホ◊◈◆▲▼■□░▒▓0101'.split('')
    const fontSize = 14
    const cols = Math.floor(w / fontSize)
    const drops = new Array(cols).fill(0).map(() => Math.random() * -50)
    let raf

    const draw = () => {
      ctx.fillStyle = 'rgba(2,4,8,0.08)'
      ctx.fillRect(0, 0, w, h)
      ctx.font = `${fontSize}px "Space Mono", monospace`
      for (let i = 0; i < drops.length; i++) {
        const ch = CHARS[Math.floor(Math.random() * CHARS.length)]
        const x = i * fontSize
        const y = drops[i] * fontSize
        const head = Math.random() > 0.97
        ctx.fillStyle = head ? '#e8f4ff' : `rgba(0,221,255,${0.35 + Math.random() * 0.45})`
        ctx.fillText(ch, x, y)
        if (y > h && Math.random() > 0.975) drops[i] = 0
        drops[i] += 0.55 + Math.random() * 0.5
      }
      raf = requestAnimationFrame(draw)
    }
    draw()

    const onResize = () => { w = canvas.width = window.innerWidth; h = canvas.height = window.innerHeight }
    window.addEventListener('resize', onResize)
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', onResize) }
  }, [])

  // ── Animated waves (3 layered sines with attack spikes) ────
  useEffect(() => {
    const canvas = waveRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let w = canvas.width  = window.innerWidth
    let h = canvas.height = 240
    let t = 0
    let raf

    const draw = () => {
      ctx.clearRect(0, 0, w, h)
      const waves = [
        { amp: 32, freq: 0.012, speed: 0.04, color: 'rgba(0,221,255,0.7)',  glow: 'rgba(0,221,255,0.4)',  yOff: h / 2 },
        { amp: 20, freq: 0.020, speed: 0.06, color: 'rgba(255,0,170,0.5)',  glow: 'rgba(255,0,170,0.25)', yOff: h / 2 + 22 },
        { amp: 24, freq: 0.008, speed: 0.03, color: 'rgba(255,51,85,0.55)', glow: 'rgba(255,51,85,0.3)',  yOff: h / 2 - 22 },
      ]
      for (const wv of waves) {
        ctx.shadowBlur = 14
        ctx.shadowColor = wv.glow
        ctx.strokeStyle = wv.color
        ctx.lineWidth = 1.9
        ctx.beginPath()
        for (let x = 0; x <= w; x += 2) {
          const spike = Math.random() > 0.993 ? (Math.random() - 0.5) * 45 : 0
          const y = wv.yOff
            + Math.sin(x * wv.freq + t * wv.speed) * wv.amp
            + Math.sin(x * wv.freq * 2.5 + t * wv.speed * 1.5) * wv.amp * 0.3
            + spike
          if (x === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y)
        }
        ctx.stroke()
      }
      ctx.shadowBlur = 0
      t += 1
      raf = requestAnimationFrame(draw)
    }
    draw()

    const onResize = () => { w = canvas.width = window.innerWidth }
    window.addEventListener('resize', onResize)
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', onResize) }
  }, [])

  // ── Stream terminal log lines ──────────────────────────────
  useEffect(() => {
    const timers = SCRIPT.map((line) =>
      setTimeout(() => setLogLines(prev => [...prev, line]), line.t)
    )
    return () => timers.forEach(clearTimeout)
  }, [])

  // ── Progress counter ───────────────────────────────────────
  useEffect(() => {
    const start = Date.now()
    const dur = 3000
    const iv = setInterval(() => {
      const pct = Math.min(100, ((Date.now() - start) / dur) * 100)
      setProgress(pct)
      if (pct >= 100) clearInterval(iv)
    }, 30)
    return () => clearInterval(iv)
  }, [])

  // ── Phase transitions ──────────────────────────────────────
  // Use a ref so changing `onComplete` identity doesn't reset timers
  const onCompleteRef = useRef(onComplete)
  useEffect(() => { onCompleteRef.current = onComplete }, [onComplete])

  useEffect(() => {
    const p1 = setTimeout(() => setPhase(1), 900)    // radar on
    const p2 = setTimeout(() => setPhase(2), 2900)   // "SECURED" stamp
    const p3 = setTimeout(() => setPhase(3), 4000)   // fade-out begins
    const done = setTimeout(() => onCompleteRef.current?.(), 4900)
    return () => { clearTimeout(p1); clearTimeout(p2); clearTimeout(p3); clearTimeout(done) }
    // Run ONCE on mount, not when onComplete identity changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className={`intro-root ${phase === 3 ? 'fading' : ''}`}>
      <canvas ref={matrixRef} className="intro-matrix" />
      <div className="intro-grid" />

      <div className={`intro-radar ${phase >= 1 ? 'active' : ''}`}>
        <div className="radar-ring r1" />
        <div className="radar-ring r2" />
        <div className="radar-ring r3" />
        <div className="radar-sweep" />
        <div className="radar-h" />
        <div className="radar-v" />
        <div className="radar-blip b1" />
        <div className="radar-blip b2" />
        <div className="radar-blip b3" />
      </div>

      <canvas ref={waveRef} className="intro-waves" />

      <div className="intro-hud intro-hud-tl">
        <div className="hud-eyebrow">SYS://qf-ids-core</div>
        <div className="hud-title">QUANTUM FINGERPRINT IDS · v7.2.1</div>
        <div className="hud-meta">node bb84-a · region eu-c1</div>
        <div className="hud-meta">build {Date.now().toString(36).slice(-7).toUpperCase()}</div>
      </div>

      <div className="intro-hud intro-hud-tr">
        <div className="hud-eyebrow">UTC · {new Date().toISOString().slice(11, 19)}</div>
        <div className="hud-meta">lat 50.1109° · lng 08.6821°</div>
        <div className="hud-meta">grid · 32U MA 1234 5678</div>
        <div className="hud-meta">⬢ secure-link / handshake OK</div>
      </div>

      <div className="intro-hud intro-hud-bl">
        <div className="hud-eyebrow">CORE · MEMORY · NETWORK</div>
        <div className="hud-bar"><div className="hud-bar-fill" style={{ width: '92%', background: '#00ddff' }} /></div>
        <div className="hud-bar"><div className="hud-bar-fill" style={{ width: '78%', background: '#ff00aa' }} /></div>
        <div className="hud-bar"><div className="hud-bar-fill" style={{ width: '64%', background: '#ffcc00' }} /></div>
      </div>

      <div className="intro-center">
        <div className="intro-logo-3d">
          <QFIDSMark size={88} primary="#00ddff" animated={true} />
        </div>
        <div className="intro-brand">QUANTUM FINGERPRINT</div>
        <div className="intro-brand-sub">INTRUSION DETECTION SYSTEM</div>
        <div className="intro-sub">QUANTUM-NATIVE INTRUSION DEFENCE · DETECT · DIVERT · ENCRYPT</div>

        <div className="intro-progress-wrap">
          <div className="intro-progress-bar">
            <div className="intro-progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <div className="intro-progress-text">
            <span>{phase < 2 ? 'INITIALIZING SECURITY CORE' : 'ALL SYSTEMS NOMINAL'}</span>
            <span>{Math.floor(progress)}%</span>
          </div>
        </div>

        {phase >= 2 && (
          <div className="intro-stamp">◆ SYSTEM SECURED ◆</div>
        )}
      </div>

      <div className="intro-terminal">
        <div className="term-hd">
          <span className="term-dot tr" />
          <span className="term-dot ty" />
          <span className="term-dot tg" />
          <span className="term-title">qfids@core:~# boot.log</span>
        </div>
        <div className="term-body">
          {logLines.map((line, i) => (
            <div key={i} className={`term-line term-${line.level}`}>
              <span className="term-ts">[{(line.t / 1000).toFixed(2)}s]</span>
              <span className="term-msg">{line.text}</span>
            </div>
          ))}
          {logLines.length < SCRIPT.length && <span className="term-cursor">█</span>}
        </div>
      </div>

      <div className="intro-scanlines" />
      <div className="intro-vignette" />
    </div>
  )
}
