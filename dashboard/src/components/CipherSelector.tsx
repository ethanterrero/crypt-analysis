import type { CipherOption } from '../types'

interface Props {
  value: CipherOption
  onChange: (v: CipherOption) => void
}

const CIPHERS: { value: CipherOption; label: string; description: string }[] = [
  {
    value: 'aes256',
    label: 'AES-256-CBC',
    description: 'Block cipher — strong avalanche effect, industry standard',
  },
  {
    value: 'chacha20',
    label: 'ChaCha20',
    description: 'Stream cipher — fast on platforms without AES hardware acceleration',
  },
]

export function CipherSelector({ value, onChange }: Props) {
  return (
    <div style={{ display: 'flex', gap: '12px' }}>
      {CIPHERS.map(c => (
        <label
          key={c.value}
          style={{
            flex: 1,
            border: `2px solid ${value === c.value ? '#6366f1' : '#374151'}`,
            borderRadius: '10px',
            padding: '14px 16px',
            cursor: 'pointer',
            background: value === c.value ? '#1e1b4b' : '#1f2937',
            transition: 'all 0.15s',
          }}
        >
          <input
            type="radio"
            name="cipher"
            value={c.value}
            checked={value === c.value}
            onChange={() => onChange(c.value)}
            style={{ display: 'none' }}
          />
          <div style={{ fontWeight: 700, fontSize: '15px', color: '#f9fafb', marginBottom: '4px' }}>
            {c.label}
          </div>
          <div style={{ fontSize: '12px', color: '#9ca3af' }}>{c.description}</div>
        </label>
      ))}
    </div>
  )
}
