import React, { useEffect, useState } from 'react'

/**
 * HQNNPanel — visual + interactive showcase of QF-IDS's 4th defence layer.
 *
 * Three sub-views:
 *   - "Encrypt"  : type/paste plaintext, watch it become ciphertext, decrypt back
 *   - "Circuit"  : SVG diagram of the 4-qubit HQNN circuit
 *   - "Stats"    : architecture + live runtime stats from /api/hqnn/stats
 */
export default function HQNNPanel() {
  const [view, setView] = useState('encrypt')
  const [stats, setStats] = useState(null)

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const r = await fetch('/api/hqnn/stats')
        if (r.ok) setStats(await r.json())
      } catch {}
    }
    fetchStats()
    const iv = setInterval(fetchStats, 2000)
    return () => clearInterval(iv)
  }, [])

  return (
    <div className="panel">
      <div className="panel-hd">
        <div>
          <div className="eyebrow">Layer 4 · Data protection</div>
          <div className="title">HQNN · Hybrid Quantum Neural Network</div>
        </div>
        <div className="eyebrow mono" style={{ fontSize: 9 }}>
          4 qubits · 2 layers · BB84-keyed
        </div>
      </div>

      <div className="hqnn-tabs">
        <button className={`hqnn-tab ${view === 'encrypt' ? 'active' : ''}`} onClick={() => setView('encrypt')}>
          ⬢ Live encryption
        </button>
        <button className={`hqnn-tab ${view === 'circuit' ? 'active' : ''}`} onClick={() => setView('circuit')}>
          ◈ Circuit diagram
        </button>
        <button className={`hqnn-tab ${view === 'stats' ? 'active' : ''}`} onClick={() => setView('stats')}>
          ▣ Architecture &amp; stats
        </button>
      </div>

      <div className="panel-bd" style={{ paddingTop: 12 }}>
        {view === 'encrypt' && <EncryptDemo />}
        {view === 'circuit' && <CircuitDiagram />}
        {view === 'stats'   && <StatsView stats={stats} />}
      </div>
    </div>
  )
}

/* ── Interactive encrypt/decrypt demo ──────────────────────────── */
function EncryptDemo() {
  const [plaintext, setPlaintext] = useState(
    'Internal customer record: card 4111-1111-1111-1111, CVV 042'
  )
  const [ct, setCt] = useState(null)
  const [recovered, setRecovered] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const [tamperMode, setTamperMode] = useState(false)

  const onEncrypt = async () => {
    setBusy(true); setErr(''); setRecovered(null)
    try {
      const r = await fetch('/api/hqnn/encrypt-rotating', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plaintext, channel_id: 'ch-a' }),
      })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const j = await r.json()
      setCt(j.ciphertext_packet)
    } catch (e) { setErr(`encrypt: ${e.message}`) }
    setBusy(false)
  }

  const onDecrypt = async () => {
    if (!ct) return
    setBusy(true); setErr(''); setRecovered(null)
    try {
      // Optionally tamper with first byte to show MAC catches it
      const sendCt = tamperMode
        ? { ...ct, ciphertext: flipFirstByte(ct.ciphertext) }
        : ct
      const r = await fetch('/api/hqnn/decrypt-rotating', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...sendCt, channel_id: 'ch-a' }),
      })
      const j = await r.json()
      if (j.ok) {
        setRecovered({ ok: true, text: j.plaintext })
      } else {
        setRecovered({ ok: false, error: j.error || 'unknown error' })
      }
    } catch (e) { setErr(`decrypt: ${e.message}`) }
    setBusy(false)
  }

  const onSelfTest = async () => {
    setBusy(true); setErr(''); setRecovered(null)
    try {
      const r = await fetch('/api/hqnn/self-test')
      const j = await r.json()
      setRecovered({
        ok: j.round_trip_ok && j.tamper_detected && j.wrong_key_rejected,
        selfTest: j,
      })
    } catch (e) { setErr(`self-test: ${e.message}`) }
    setBusy(false)
  }

  return (
    <div className="hqnn-encrypt">
      <div className="hqnn-flow">
        <div className="hqnn-flow-stage">
          <div className="hqnn-stage-label">① PLAINTEXT</div>
          <textarea
            className="hqnn-textarea"
            value={plaintext}
            onChange={(e) => setPlaintext(e.target.value)}
            rows={3}
            placeholder="Type any sensitive payload here..."
          />
          <div className="hqnn-meta">
            {plaintext.length} chars · {new Blob([plaintext]).size} bytes
          </div>
        </div>

        <div className="hqnn-arrow">
          <div className="hqnn-arrow-line" />
          <div className="hqnn-arrow-lbl">HQNN<br/>4q · 2L</div>
        </div>

        <div className="hqnn-flow-stage">
          <div className="hqnn-stage-label">② CIPHERTEXT (HQNN-CTR + HMAC)</div>
          <div className="hqnn-cipher-box">
            {ct ? (
              <>
                <div className="hqnn-cipher-line">
                  <span className="hqnn-cipher-k">nonce  </span>
                  <span className="hqnn-cipher-v">{ct.nonce}</span>
                </div>
                <div className="hqnn-cipher-line">
                  <span className="hqnn-cipher-k">cipher </span>
                  <span className="hqnn-cipher-v hqnn-glow">
                    {ct.ciphertext.match(/.{1,32}/g)?.[0]}
                    {ct.ciphertext.length > 32 ? '…' : ''}
                  </span>
                </div>
                <div className="hqnn-cipher-line">
                  <span className="hqnn-cipher-k">mac    </span>
                  <span className="hqnn-cipher-v">{ct.mac.slice(0, 32)}…</span>
                </div>
                <div className="hqnn-cipher-line">
                  <span className="hqnn-cipher-k">key_id </span>
                  <span className="hqnn-cipher-v hqnn-keyid">{ct.key_id}</span>
                </div>
              </>
            ) : (
              <div style={{ color: 'var(--text-3)', fontStyle: 'italic' }}>
                Click "Encrypt" to see the HQNN output…
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="hqnn-actions">
        <button className="btn primary" onClick={onEncrypt} disabled={busy || !plaintext}>
          {busy ? '⟳ Running HQNN…' : '⬢ Encrypt with HQNN'}
        </button>
        <button className="btn" onClick={onDecrypt} disabled={busy || !ct}>
          ⬡ Decrypt
        </button>
        <label className="hqnn-tamper-toggle">
          <input type="checkbox" checked={tamperMode} onChange={e => setTamperMode(e.target.checked)} />
          <span>Tamper ciphertext before decrypt (test MAC)</span>
        </label>
        <button className="btn tiny" onClick={onSelfTest} disabled={busy} style={{ marginLeft: 'auto' }}>
          ◆ Run self-test
        </button>
      </div>

      {recovered && recovered.selfTest && (
        <div className="hqnn-result hqnn-result-test">
          <div className="hqnn-stage-label">SELF-TEST RESULTS</div>
          <div className="hqnn-test-row">
            <span className={recovered.selfTest.round_trip_ok ? 'ok' : 'fail'}>
              {recovered.selfTest.round_trip_ok ? '✓' : '✗'}
            </span>
            <span>Round-trip encryption recovers original plaintext</span>
          </div>
          <div className="hqnn-test-row">
            <span className={recovered.selfTest.tamper_detected ? 'ok' : 'fail'}>
              {recovered.selfTest.tamper_detected ? '✓' : '✗'}
            </span>
            <span>Single-bit tamper detected via HMAC-SHA256 verification</span>
          </div>
          <div className="hqnn-test-row">
            <span className={recovered.selfTest.wrong_key_rejected ? 'ok' : 'fail'}>
              {recovered.selfTest.wrong_key_rejected ? '✓' : '✗'}
            </span>
            <span>Wrong BB84 key rejected (cannot derive correct HQNN weights)</span>
          </div>
        </div>
      )}

      {recovered && !recovered.selfTest && (
        <div className={`hqnn-result ${recovered.ok ? 'hqnn-result-ok' : 'hqnn-result-fail'}`}>
          <div className="hqnn-stage-label">
            ③ {recovered.ok ? 'DECRYPTED · VERIFIED' : 'DECRYPTION FAILED'}
          </div>
          <div className="hqnn-recovered">
            {recovered.ok ? recovered.text : recovered.error}
          </div>
          {!recovered.ok && (
            <div className="hqnn-meta" style={{ color: 'var(--danger)' }}>
              ⚠ Tamper detection working as designed.
              Even one flipped bit invalidates the HMAC and the payload is rejected.
            </div>
          )}
        </div>
      )}

      {err && <div className="hqnn-error">{err}</div>}

      <div className="hqnn-explainer">
        <div className="hqnn-explainer-title">Why this is the 4th layer</div>
        Even if an attacker bypasses the IsolationForest detector, escapes the
        honeypot, and evades the IP blocklist, the data payload itself is encrypted
        with keystream derived from a <code>4-qubit, 2-layer</code> parameterized quantum
        circuit. The 16 rotation angles (RY+RZ) are derived from the
        <code> BB84 sifted key</code> via SHA-256, then mixed through CNOT
        entangling gates. Recovering plaintext requires the BB84 key —
        not a classical computational problem.
      </div>
    </div>
  )
}

/* Helper: flip first byte of a hex string */
function flipFirstByte(hexStr) {
  if (hexStr.length < 2) return hexStr
  const first = parseInt(hexStr.slice(0, 2), 16)
  const flipped = (first ^ 0x01).toString(16).padStart(2, '0')
  return flipped + hexStr.slice(2)
}

/* ── Circuit diagram (SVG) ─────────────────────────────────────── */
function CircuitDiagram() {
  return (
    <div className="hqnn-circuit-wrap">
      <svg viewBox="0 0 720 280" width="100%" style={{ maxHeight: 320 }}>
        <defs>
          <linearGradient id="qline-grad" x1="0" x2="1">
            <stop offset="0%"  stopColor="var(--primary)" stopOpacity="0.2"/>
            <stop offset="50%" stopColor="var(--primary)" stopOpacity="0.8"/>
            <stop offset="100%" stopColor="var(--primary)" stopOpacity="0.2"/>
          </linearGradient>
          <filter id="qglow">
            <feGaussianBlur stdDeviation="1.2"/>
          </filter>
        </defs>

        {/* 4 qubit wires */}
        {[0,1,2,3].map(q => {
          const y = 40 + q * 56
          return (
            <g key={q}>
              <line x1="20" y1={y} x2="700" y2={y}
                    stroke="url(#qline-grad)" strokeWidth="1.5" />
              <text x="10" y={y + 4} fill="var(--text-2)"
                    fontFamily="Space Mono, monospace" fontSize="11" textAnchor="end">
                q{q}
              </text>
              <text x="14" y={y - 6} fill="var(--text-3)"
                    fontFamily="Space Mono, monospace" fontSize="9">|0⟩</text>
            </g>
          )
        })}

        {/* Encoding layer — RY(π·x_i) */}
        <SectionLabel x={75} y={20} text="ENCODE" />
        {[0,1,2,3].map(q => (
          <Gate key={`enc-${q}`} x={75} y={40 + q * 56} label="RY" sub="π·xᵢ" color="#00ddff" />
        ))}

        {/* Layer 1 — RY + RZ + CNOT ring */}
        <SectionLabel x={200} y={20} text="LAYER 1" />
        {[0,1,2,3].map(q => (
          <Gate key={`l1ry-${q}`} x={175} y={40 + q * 56} label="RY" sub="θ" color="#ff00aa" />
        ))}
        {[0,1,2,3].map(q => (
          <Gate key={`l1rz-${q}`} x={225} y={40 + q * 56} label="RZ" sub="θ" color="#ff00aa" />
        ))}
        {/* CNOT ring layer 1 */}
        <CnotRing baseX={280} />

        {/* Layer 2 */}
        <SectionLabel x={420} y={20} text="LAYER 2" />
        {[0,1,2,3].map(q => (
          <Gate key={`l2ry-${q}`} x={395} y={40 + q * 56} label="RY" sub="θ" color="#ff00aa" />
        ))}
        {[0,1,2,3].map(q => (
          <Gate key={`l2rz-${q}`} x={445} y={40 + q * 56} label="RZ" sub="θ" color="#ff00aa" />
        ))}
        <CnotRing baseX={500} />

        {/* Measurement */}
        <SectionLabel x={620} y={20} text="MEASURE" />
        {[0,1,2,3].map(q => (
          <Gate key={`meas-${q}`} x={620} y={40 + q * 56} label="M" sub="⟨Z⟩" color="#00ff88" measure />
        ))}

        {/* Output arrow */}
        {[0,1,2,3].map(q => (
          <g key={`out-${q}`}>
            <line x1="640" y1={40 + q * 56} x2="690" y2={40 + q * 56}
                  stroke="var(--safe)" strokeWidth="1.5" strokeDasharray="3 2"/>
            <text x="695" y={44 + q * 56} fill="var(--safe)"
                  fontFamily="Space Mono, monospace" fontSize="10">→ k{q}</text>
          </g>
        ))}
      </svg>

      <div className="hqnn-circuit-caption">
        <strong>Encoding</strong>: classical chunks angle-encoded onto 4 qubits via RY(π·xᵢ).{' '}
        <strong>Layers</strong>: 2 × [RY(θ) → RZ(θ) → CNOT ring] with 16 trainable angles derived from
        BB84 sifted key.{' '}
        <strong>Measurement</strong>: Pauli-Z expectation on each qubit yields the keystream block.
      </div>
    </div>
  )
}

function SectionLabel({ x, y, text }) {
  return (
    <text x={x} y={y} fill="var(--text-3)"
          fontFamily="Space Mono, monospace" fontSize="9"
          letterSpacing="0.16em" textAnchor="middle">
      {text}
    </text>
  )
}

function Gate({ x, y, label, sub, color, measure }) {
  return (
    <g>
      <rect x={x - 16} y={y - 14} width="32" height="28"
            fill="var(--bg-3)" stroke={color} strokeWidth="1.2" rx="3"/>
      <text x={x} y={y + 1} fill={color}
            fontFamily="Rajdhani, sans-serif" fontWeight="700" fontSize="13"
            textAnchor="middle">{label}</text>
      <text x={x} y={y + 11} fill="var(--text-3)"
            fontFamily="Space Mono, monospace" fontSize="7"
            textAnchor="middle">{sub}</text>
      {measure && (
        <circle cx={x + 11} cy={y - 11} r="2.5" fill={color} opacity="0.8"/>
      )}
    </g>
  )
}

function CnotRing({ baseX }) {
  // Ring CNOTs: 0→1, 1→2, 2→3, 3→0
  const pairs = [[0,1], [1,2], [2,3], [3,0]]
  return pairs.map(([c, t], idx) => {
    const x = baseX + idx * 24
    const cy = 40 + c * 56
    const ty = 40 + t * 56
    return (
      <g key={`cnot-${baseX}-${idx}`}>
        {/* Vertical connector */}
        <line x1={x} y1={cy} x2={x} y2={ty}
              stroke="var(--amber)" strokeWidth="1.2" />
        {/* Control dot */}
        <circle cx={x} cy={cy} r="3.5" fill="var(--amber)" />
        {/* Target circle with cross */}
        <circle cx={x} cy={ty} r="6" fill="none" stroke="var(--amber)" strokeWidth="1.2"/>
        <line x1={x - 6} y1={ty} x2={x + 6} y2={ty} stroke="var(--amber)" strokeWidth="1.2"/>
        <line x1={x} y1={ty - 6} x2={x} y2={ty + 6} stroke="var(--amber)" strokeWidth="1.2"/>
      </g>
    )
  })
}

/* ── Architecture & stats view ─────────────────────────────────── */
function StatsView({ stats }) {
  const [rotation, setRotation] = useState(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    const fetchR = async () => {
      try {
        const r = await fetch('/api/hqnn/rotation-stats')
        if (r.ok) setRotation(await r.json())
      } catch {}
    }
    fetchR()
    const iv = setInterval(fetchR, 1500)
    return () => clearInterval(iv)
  }, [])

  const forceRotate = async () => {
    setBusy(true)
    try {
      const r = await fetch('/api/hqnn/rotate-key', { method: 'POST' })
      if (r.ok) {
        const j = await r.json()
        setRotation(j.stats)
      }
    } catch {}
    setBusy(false)
  }

  if (!stats) return <div style={{ color: 'var(--text-3)' }}>Loading stats…</div>
  const A = stats.architecture || {}
  const R = stats.runtime || {}

  return (
    <div className="hqnn-stats">
      {rotation && (
        <div className="hqnn-stats-section hqnn-rotation-section">
          <div className="hqnn-stats-title">✦ QUANTUM KEY ROTATION · FORWARD SECRECY</div>
          <div className="hqnn-rotation-grid">
            <div className="hqnn-rot-box">
              <div className="hqnn-rot-k">Current generation</div>
              <div className="hqnn-rot-v">g{String(rotation.current_gen).padStart(4, '0')}</div>
            </div>
            <div className="hqnn-rot-box">
              <div className="hqnn-rot-k">Use count</div>
              <div className="hqnn-rot-v">
                {rotation.current_use_count}<span className="hqnn-rot-of">/{rotation.rotate_every}</span>
              </div>
              <div className="hqnn-rot-bar">
                <div className="hqnn-rot-bar-fill" style={{ width: `${(rotation.current_use_count / rotation.rotate_every) * 100}%` }} />
              </div>
            </div>
            <div className="hqnn-rot-box">
              <div className="hqnn-rot-k">Total rotations</div>
              <div className="hqnn-rot-v">{rotation.total_rotations}</div>
            </div>
            <div className="hqnn-rot-box">
              <div className="hqnn-rot-k">Keys destroyed</div>
              <div className="hqnn-rot-v">{rotation.total_keys_destroyed}</div>
            </div>
            <div className="hqnn-rot-box">
              <div className="hqnn-rot-k">Photons consumed</div>
              <div className="hqnn-rot-v hqnn-rot-glow">{rotation.total_photons_consumed?.toLocaleString()}</div>
            </div>
            <div className="hqnn-rot-box">
              <div className="hqnn-rot-k">Forward secrecy</div>
              <div className="hqnn-rot-v" style={{ color: 'var(--safe)' }}>
                {rotation.forward_secrecy_active ? '✓ ACTIVE' : '✗ INACTIVE'}
              </div>
            </div>
          </div>
          <button className="btn tiny" onClick={forceRotate} disabled={busy} style={{ marginTop: 10 }}>
            {busy ? 'Rotating…' : '✦ Force key rotation now'}
          </button>
          <div className="hqnn-rot-explain">
            After {rotation.rotate_every} encryptions the current quantum key is securely
            destroyed (memory-overwritten) and a fresh BB84 session generates a new key.
            Past ciphertexts cannot be decrypted with newer keys → <strong>forward secrecy</strong>.
            This is the strongest cryptographic guarantee — even if a future quantum computer
            recovers one session's key, past sessions remain confidential.
          </div>
        </div>
      )}

      <div className="hqnn-stats-section">
        <div className="hqnn-stats-title">⬢ ARCHITECTURE</div>
        <div className="hqnn-stats-grid">
          <Row k="Qubits"             v={A.n_qubits} />
          <Row k="Variational layers" v={A.n_layers} />
          <Row k="Trainable weights"  v={A.n_weights} />
          <Row k="Gate set"           v={(A.gate_set || []).join(', ')} />
          <Row k="Data encoding"      v={A.encoding} />
          <Row k="Measurement"        v={A.measurement} />
          <Row k="Key source"         v={A.key_source} />
        </div>
      </div>

      <div className="hqnn-stats-section">
        <div className="hqnn-stats-title">▣ RUNTIME</div>
        <div className="hqnn-stats-grid">
          <Row k="Encryptions performed" v={R.encryptions_performed} />
          <Row k="Decryptions performed" v={R.decryptions_performed} />
          <Row k="MAC failures (tamper)" v={R.mac_failures} highlight={R.mac_failures > 0} />
          <Row k="Bytes encrypted"       v={(R.total_bytes_encrypted || 0).toLocaleString()} />
          <Row k="Bytes decrypted"       v={(R.total_bytes_decrypted || 0).toLocaleString()} />
          <Row k="Last key ID"           v={R.last_key_id || '—'} />
          <Row k="Last BB84 key bits"    v={R.last_quantum_key_bits} />
          <Row k="Last encrypt time"     v={R.last_encrypt_ms ? `${R.last_encrypt_ms} ms` : '—'} />
          <Row k="Weight entropy"        v={R.weights_entropy_bits ? `${R.weights_entropy_bits} bits` : '—'} />
        </div>
      </div>

      <div className="hqnn-stats-section">
        <div className="hqnn-stats-title">◈ SECURITY PROPERTIES</div>
        <ul className="hqnn-props">
          <li><strong>Confidentiality</strong> — HQNN-CTR keystream XOR with plaintext. Recovering keystream requires the 16-dim quantum parameter vector.</li>
          <li><strong>Integrity</strong> — HMAC-SHA256 over (nonce ‖ ciphertext) with BB84-derived MAC key. Single-bit tampering detected with negligible false-accept probability.</li>
          <li><strong>Key freshness</strong> — Every encryption uses a fresh 16-byte nonce. Identical plaintexts yield different ciphertexts.</li>
          <li><strong>Quantum dependence</strong> — Weight derivation is one-way via SHA-256. Ciphertext reveals nothing about the BB84 sifted key.</li>
          <li><strong>Forward security</strong> — Compromise of one session's BB84 key does not compromise prior or future sessions.</li>
        </ul>
      </div>
    </div>
  )
}

function Row({ k, v, highlight }) {
  return (
    <div className={`hqnn-row ${highlight ? 'highlight' : ''}`}>
      <span className="hqnn-row-k">{k}</span>
      <span className="hqnn-row-v">{v ?? '—'}</span>
    </div>
  )
}
