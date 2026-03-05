interface Props {
  title: string
  passed: boolean | null   // null = N/A
  children: React.ReactNode
  note?: string
}

export function MetricCard({ title, passed, children, note }: Props) {
  const borderColor =
    passed === null ? '#6b7280' : passed ? '#22c55e' : '#ef4444'
  const badgeColor =
    passed === null ? '#374151' : passed ? '#14532d' : '#7f1d1d'
  const badgeText =
    passed === null ? 'N/A' : passed ? 'PASS' : 'FAIL'
  const badgeTextColor =
    passed === null ? '#9ca3af' : passed ? '#86efac' : '#fca5a5'

  return (
    <div
      style={{
        border: `1.5px solid ${borderColor}`,
        borderRadius: '10px',
        padding: '16px 20px',
        background: '#111827',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
        <span style={{ fontWeight: 700, fontSize: '14px', color: '#e5e7eb', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
          {title}
        </span>
        <span
          style={{
            background: badgeColor,
            color: badgeTextColor,
            borderRadius: '6px',
            padding: '2px 10px',
            fontSize: '12px',
            fontWeight: 700,
            letterSpacing: '0.08em',
          }}
        >
          {badgeText}
        </span>
      </div>
      {children}
      {note && (
        <div style={{ marginTop: '10px', fontSize: '12px', color: '#6b7280', fontStyle: 'italic' }}>
          {note}
        </div>
      )}
    </div>
  )
}
