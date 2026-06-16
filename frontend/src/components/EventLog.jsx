import React from 'react'

export default function EventLog({ entries }) {
  if (!entries || entries.length === 0) {
    return (
      <div className="blocklist-empty">No events yet</div>
    )
  }
  return (
    <div className="logs">
      {entries.slice(0, 60).map((e, i) => (
        <div key={i} className={`log-line ${e.level || ''}`}>
          <span className="lts">{e.ts_iso}</span>
          <span>{e.message}</span>
        </div>
      ))}
    </div>
  )
}
