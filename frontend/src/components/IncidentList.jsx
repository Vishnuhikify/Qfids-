import React from 'react'

const STEP_DEFS = [
  { id: 'terminate',      label: '1 · Terminate',       desc: 'Compromised session suspended' },
  { id: 'reauthenticate', label: '2 · Re-authenticate', desc: 'Re-fingerprint over backup path' },
  { id: 'reroute',        label: '3 · Reroute',         desc: 'Attacker → honeypot' },
  { id: 'alert',          label: '4 · Alert',           desc: 'Forensic incident raised' },
]

const LEVEL_BY_STEP = {
  terminate:      'danger',
  reauthenticate: 'warning',
  reroute:        'info',
  alert:          'success',
}

export default function IncidentList({ incidents }) {
  if (!incidents || incidents.length === 0) {
    return (
      <div className="blocklist-empty">
        No incidents recorded — channels secure
      </div>
    )
  }

  return (
    <div style={{ padding: '14px 16px', maxHeight: 480, overflowY: 'auto' }}>
      {incidents.map((inc) => {
        const completed = new Set((inc.steps || []).map((s) => s.step))
        const isActive = inc.status === 'active'
        return (
          <div key={inc.incident_id} className={`incident ${inc.status}`}>
            <div className="incident-hd">
              <div>
                <div className="incident-id mono">{inc.incident_id}</div>
                <div className="incident-meta">
                  {inc.attack_type.toUpperCase()} on{' '}
                  <span style={{ color: 'var(--text-1)' }}>{inc.channel_id}</span>
                  {' · '}
                  src {inc.attacker_ip}:{inc.attacker_port}
                  {' · '}
                  peak {Math.round(inc.peak_score * 100)}/100
                </div>
              </div>
              <span
                className={`state-tag ${isActive ? 'ATTACK' : 'SAFE'}`}
                style={{ marginTop: 2 }}
              >
                {isActive ? 'IN PROGRESS' : 'CLOSED'}
              </span>
            </div>

            <div style={{ marginTop: 8 }}>
              {STEP_DEFS.map((s) => {
                const done = completed.has(s.id)
                const level = LEVEL_BY_STEP[s.id]
                return (
                  <div
                    key={s.id}
                    className={`incident-step ${level} ${done ? 'done' : ''}`}
                  >
                    <span className="stepdot" />
                    <span style={{ minWidth: 130 }}>{s.label}</span>
                    <span style={{ color: 'var(--text-3)' }}>{s.desc}</span>
                  </div>
                )
              })}
            </div>

            {inc.honeypot_packets > 0 && (
              <div
                style={{
                  marginTop: 8,
                  fontFamily: 'JetBrains Mono',
                  fontSize: 10,
                  color: 'var(--magenta)',
                  display: 'flex',
                  justifyContent: 'space-between',
                }}
              >
                <span>◆ honeypot packets intercepted</span>
                <span>{inc.honeypot_packets.toLocaleString()}</span>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
