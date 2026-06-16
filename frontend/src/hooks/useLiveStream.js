import { useEffect, useRef, useState, useCallback } from 'react'

/**
 * Subscribes to /ws and accumulates the latest tick + log + incident state.
 * Reconnects automatically.
 */
export function useLiveStream() {
  const [connected, setConnected] = useState(false)
  const [channels, setChannels] = useState([])
  const [globalState, setGlobalState] = useState({
    active_incidents: 0,
    total_incidents: 0,
    blocked_ips: 0,
  })
  const [log, setLog] = useState([])
  const [incidents, setIncidents] = useState([])
  const wsRef = useRef(null)

  useEffect(() => {
    let cancelled = false
    let reconnectTimer = null

    const connect = () => {
      if (cancelled) return
      const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
      const url = `${proto}://${window.location.host}/ws`
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
      }

      ws.onmessage = (ev) => {
        let msg
        try { msg = JSON.parse(ev.data) } catch { return }

        if (msg.type === 'tick') {
          setChannels(msg.channels)
          setGlobalState(msg.global)
        } else if (msg.type === 'init') {
          setIncidents(msg.incidents || [])
          setLog(msg.log || [])
        } else if (msg.type === 'log') {
          setLog((prev) => [msg.entry, ...prev].slice(0, 200))
        } else if (msg.type === 'incident_step') {
          setIncidents((prev) => {
            const idx = prev.findIndex(
              (i) => i.incident_id === msg.incident.incident_id,
            )
            if (idx === -1) return [msg.incident, ...prev]
            const copy = [...prev]
            copy[idx] = msg.incident
            return copy
          })
        }
      }

      ws.onclose = () => {
        setConnected(false)
        if (!cancelled) {
          reconnectTimer = setTimeout(connect, 1500)
        }
      }
      ws.onerror = () => { try { ws.close() } catch {} }
    }

    connect()

    return () => {
      cancelled = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      try { wsRef.current?.close() } catch {}
    }
  }, [])

  // Periodically refresh incidents from REST so closed/older ones
  // stay synced (the websocket only pushes new steps).
  const refreshIncidents = useCallback(async () => {
    try {
      const r = await fetch('/api/incidents')
      const j = await r.json()
      setIncidents(j.incidents || [])
    } catch {}
  }, [])

  useEffect(() => {
    const t = setInterval(refreshIncidents, 3000)
    refreshIncidents()
    return () => clearInterval(t)
  }, [refreshIncidents])

  return { connected, channels, globalState, log, incidents, refreshIncidents }
}
