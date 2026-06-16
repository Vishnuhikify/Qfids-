import React, { useEffect, useRef } from 'react'

/**
 * QF-IDS brand mark v3 — "Quantum Aegis"
 *
 * The mark fuses four ideas representing each defence layer:
 *   1. Outer hexagonal shield  → protection / aegis
 *   2. Inner waveform          → signal monitoring & anomaly detection
 *   3. Photon at center        → quantum (BB84 / QRNG) core
 *   4. Lock cutout below       → HQNN data protection
 *
 * Reads as: "quantum-grade protection for monitored channels".
 */
export function QFIDSMark({ size = 36, primary = 'currentColor', animated = true }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'block', filter: 'drop-shadow(0 0 8px rgba(0, 221, 255, 0.45))' }}
      aria-label="Quantum Fingerprint IDS"
    >
      <defs>
        <linearGradient id="aegisG" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0%"   stopColor={primary} stopOpacity="1.0" />
          <stop offset="60%"  stopColor="#ff00aa" stopOpacity="0.85" />
          <stop offset="100%" stopColor={primary} stopOpacity="0.4" />
        </linearGradient>
        <linearGradient id="aegisCore" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%"  stopColor="#ffffff" stopOpacity="1" />
          <stop offset="60%" stopColor={primary} stopOpacity="0.9" />
          <stop offset="100%" stopColor="#ff00aa" stopOpacity="0.5" />
        </linearGradient>
        <radialGradient id="aegisGlow">
          <stop offset="0%"  stopColor={primary} stopOpacity="0.6" />
          <stop offset="80%" stopColor={primary} stopOpacity="0" />
        </radialGradient>
      </defs>

      <circle cx="24" cy="24" r="22" fill="url(#aegisGlow)" />

      {/* Outer hexagonal shield (pointy-top) */}
      <path
        d="M 24 3 L 41 13 L 41 35 L 24 45 L 7 35 L 7 13 Z"
        fill="none"
        stroke="url(#aegisG)"
        strokeWidth="1.8"
        strokeLinejoin="round"
        className={animated ? 'mark-shield' : ''}
      />

      {/* Inner hexagon — depth ring */}
      <path
        d="M 24 8 L 37 15.5 L 37 32.5 L 24 40 L 11 32.5 L 11 15.5 Z"
        fill="none"
        stroke={primary}
        strokeWidth="0.6"
        strokeOpacity="0.35"
        strokeLinejoin="round"
      />

      {/* Monitoring waveform */}
      <path
        d="M 11 24 Q 14 18, 17 24 T 24 24 T 31 24 T 37 24"
        fill="none"
        stroke="url(#aegisG)"
        strokeWidth="1.4"
        strokeLinecap="round"
        className={animated ? 'mark-wave' : ''}
      />

      {/* Photon core */}
      <circle cx="24" cy="24" r="3" fill="url(#aegisCore)" className={animated ? 'mark-photon' : ''} />
      <circle cx="24" cy="24" r="5.5" fill="none" stroke={primary} strokeWidth="0.5" strokeOpacity="0.55" strokeDasharray="1.5 1.5" />

      {/* Lock at base — encryption */}
      <path
        d="M 21 38 Q 21 33, 24 33 Q 27 33, 27 38"
        fill="none"
        stroke="url(#aegisG)"
        strokeWidth="1.4"
        strokeLinecap="round"
      />
      <rect x="20" y="37.5" width="8" height="4.5" rx="1" fill="none" stroke="url(#aegisG)" strokeWidth="1.2" />

      <style>{`
        .mark-photon { transform-origin: 24px 24px; animation: markPhotonPulse 2.4s ease-in-out infinite; }
        @keyframes markPhotonPulse { 0%,100% { transform: scale(1); opacity: 1; } 50% { transform: scale(0.7); opacity: 0.6; } }
        .mark-wave { stroke-dasharray: 4 3; animation: markWaveFlow 2.4s linear infinite; }
        @keyframes markWaveFlow { to { stroke-dashoffset: -14; } }
        .mark-shield { animation: markShieldGlow 4s ease-in-out infinite; }
        @keyframes markShieldGlow { 0%,100% { stroke-opacity: 1; } 50% { stroke-opacity: 0.65; } }
      `}</style>
    </svg>
  )
}

export function QFIDSWordmark({ size = 22, color }) {
  return (
    <div style={{
      fontFamily: '"Rajdhani", "Inter Display", "Inter", system-ui, sans-serif',
      color: color || 'var(--text-0)',
      lineHeight: 1.05,
      textTransform: 'uppercase',
    }}>
      <div style={{
        fontSize: size,
        fontWeight: 700,
        letterSpacing: '0.14em',
      }}>
        Quantum Fingerprint
      </div>
      <div style={{
        fontSize: size * 0.7,
        fontWeight: 600,
        letterSpacing: '0.20em',
        color: 'var(--primary)',
        marginTop: 2,
      }}>
        Intrusion Detection System
      </div>
    </div>
  )
}

export function ParticleField() {
  const canvasRef = useRef(null)
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let w = canvas.width = window.innerWidth
    let h = canvas.height = window.innerHeight
    let raf
    const particles = Array.from({ length: 50 }, () => ({
      x: Math.random() * w, y: Math.random() * h,
      r: Math.random() * 1.2 + 0.3,
      vx: (Math.random() - 0.5) * 0.22, vy: (Math.random() - 0.5) * 0.22,
      alpha: Math.random() * 0.4 + 0.1,
    }))
    const draw = () => {
      ctx.clearRect(0, 0, w, h)
      for (const p of particles) {
        p.x += p.vx; p.y += p.vy
        if (p.x < 0) p.x = w; if (p.x > w) p.x = 0
        if (p.y < 0) p.y = h; if (p.y > h) p.y = 0
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(0,221,255,${p.alpha})`
        ctx.fill()
      }
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x
          const dy = particles[i].y - particles[j].y
          const d = Math.sqrt(dx*dx + dy*dy)
          if (d < 110) {
            ctx.beginPath()
            ctx.moveTo(particles[i].x, particles[i].y)
            ctx.lineTo(particles[j].x, particles[j].y)
            ctx.strokeStyle = `rgba(0,221,255,${0.05 * (1 - d / 110)})`
            ctx.lineWidth = 0.5
            ctx.stroke()
          }
        }
      }
      raf = requestAnimationFrame(draw)
    }
    draw()
    const onResize = () => { w = canvas.width = window.innerWidth; h = canvas.height = window.innerHeight }
    window.addEventListener('resize', onResize)
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', onResize) }
  }, [])
  return <canvas ref={canvasRef} style={{ position:'fixed', inset:0, pointerEvents:'none', zIndex:0, opacity:0.5 }} />
}
