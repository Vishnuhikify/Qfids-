import React, { useEffect, useState, useCallback } from 'react'
import { api } from '../lib/api'

export default function BlockList() {
  const [entries, setEntries] = useState([])
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      const r = await api.blocklist()
      setEntries(r.entries || [])
    } catch {}
  }, [])

  useEffect(() => {
    refresh()
    const t = setInterval(refresh, 1500)
    return () => clearInterval(t)
  }, [refresh])

  const unblock = async (ip) => {
    setBusy(true)
    try { await api.unblock(ip); await refresh() } catch {}
    setBusy(false)
  }

  if (entries.length === 0) {
    return (
      <div className="blocklist-empty">
        Blocklist is empty — no IPs currently filtered
      </div>
    )
  }

  return (
    <div style={{ maxHeight: 280, overflowY: 'auto' }}>
      {entries.map((e) => (
        <div key={e.ip} className="blocklist-row">
          <div>
            <div className="ip">{e.ip}</div>
            <div className="reason">
              {e.reason} · {e.added_at_iso}
            </div>
          </div>
          <button
            className="btn tiny"
            onClick={() => unblock(e.ip)}
            disabled={busy}
          >
            Unblock
          </button>
        </div>
      ))}
    </div>
  )
}
