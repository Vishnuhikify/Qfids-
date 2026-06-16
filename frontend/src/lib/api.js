async function jsonFetch(url, opts = {}) {
  const r = await fetch(url, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  })
  if (!r.ok) {
    const txt = await r.text().catch(() => '')
    throw new Error(`${r.status}: ${txt || r.statusText}`)
  }
  return r.json()
}

export const api = {
  attack: (channel_id, attack_type, attacker_ip, attacker_port) =>
    jsonFetch('/api/attack', {
      method: 'POST',
      body: JSON.stringify({
        channel_id,
        attack_type,
        attacker_ip: attacker_ip || null,
        attacker_port: attacker_port || null,
      }),
    }),
  resetChannel: (channel_id) =>
    jsonFetch(`/api/reset/${channel_id}`, { method: 'POST' }),
  resetAll: () => jsonFetch('/api/reset', { method: 'POST' }),
  unblock: (ip) =>
    jsonFetch('/api/blocklist/remove', {
      method: 'POST',
      body: JSON.stringify({ ip }),
    }),
  blocklist: () => jsonFetch('/api/blocklist'),
  channels:  () => jsonFetch('/api/channels'),
  honeypot:  () => jsonFetch('/honeypot/serve'),
  incidents: () => jsonFetch('/api/incidents'),
  attackAll: (attack_type, attacker_ip, attacker_port) =>
    jsonFetch('/api/attack/all', {
      method: 'POST',
      body: JSON.stringify({
        attack_type,
        attacker_ip: attacker_ip || null,
        attacker_port: attacker_port || null,
      }),
    }),
  downloadLog: (since) => {
    const url = since ? `/api/log/download?since=${since}` : '/api/log/download'
    window.open(url, '_blank')
  },
}
