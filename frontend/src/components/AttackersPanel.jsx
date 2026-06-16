import React, { useState, useEffect } from 'react'

/**
 * AttackersPanel — defender-side view of every external system that has
 * attacked us. Shows the attacking machine's details (IP, platform, user-agent
 * fingerprint), how many attempts they made, how many were blocked, and
 * whether they are currently blocked. Polls the backend every few seconds.
 */
export default function AttackersPanel() {
  const [attackers, setAttackers] = useState([])
  const [loaded, setLoaded] = useState(false)

  useEffect(() => {
    let alive = true
    const load = async () => {
      try {
        const r = await fetch('/api/attackers')
        const d = await r.json()
        if (alive) { setAttackers(d.attackers || []); setLoaded(true) }
      } catch { if (alive) setLoaded(true) }
    }
    load()
    const t = setInterval(load, 3000)
    return () => { alive = false; clearInterval(t) }
  }, [])

  if (!loaded) {
    return <div className="blocklist-empty">Loading attacking systems…</div>
  }
  if (attackers.length === 0) {
    return (
      <div className="blocklist-empty">
        No external systems have attacked yet.
        <br />
        <span style={{ fontSize: 11, opacity: 0.7 }}>
          Launch an attack from the attacker console (/attacker) to see it here.
        </span>
      </div>
    )
  }

  return (
    <div className="attackers-list">
      {attackers.map((a) => (
        <div key={a.ip} className={`attacker-row ${a.blocked_count > 0 ? 'flagged' : ''}`}>
          <div className="attacker-top">
            <span className="attacker-ip mono">{a.ip}</span>
            <span className={`attacker-state ${a.blocked_count > 0 ? 'blocked' : 'active'}`}>
              {a.blocked_count > 0 ? `${a.blocked_count} blocked` : 'active'}
            </span>
          </div>
          <div className="attacker-meta mono">
            {a.platform || 'unknown platform'} · fp {a.fingerprint}
          </div>
          <div className="attacker-meta mono" style={{ opacity: 0.6 }}>
            {(a.user_agent || '').slice(0, 56) || 'no user-agent'}
          </div>
          <div className="attacker-stats">
            <span>attempts <b>{a.total_attempts}</b></span>
            <span>delivered <b style={{ color: 'var(--green, #00ff88)' }}>{a.successful}</b></span>
            <span>blocked <b style={{ color: 'var(--danger)' }}>{a.blocked_count}</b></span>
            <span className="attacker-seen">last {a.last_seen_iso}</span>
          </div>
        </div>
      ))}
    </div>
  )
}
