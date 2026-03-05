import { BarChart, Bar, XAxis, YAxis, ReferenceLine, Tooltip, ResponsiveContainer, Cell } from 'recharts'

interface Props {
  avg: number
  min: number
  max: number
}

export function AvalancheChart({ avg, min, max }: Props) {
  const data = [
    { name: 'Min', value: parseFloat(min.toFixed(2)) },
    { name: 'Avg', value: parseFloat(avg.toFixed(2)) },
    { name: 'Max', value: parseFloat(max.toFixed(2)) },
  ]

  const getColor = (value: number) => {
    const diff = Math.abs(value - 50)
    if (diff <= 5) return '#22c55e'
    if (diff <= 10) return '#f59e0b'
    return '#ef4444'
  }

  return (
    <div>
      <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '8px' }}>
        Bit change % (ideal: ~50%)
      </div>
      <ResponsiveContainer width="100%" height={120}>
        <BarChart data={data} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
          <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} />
          <YAxis domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 11 }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', color: '#f9fafb' }}
            formatter={(v: number) => [`${v.toFixed(2)}%`, 'Bit change']}
          />
          <ReferenceLine y={50} stroke="#6366f1" strokeDasharray="4 2" label={{ value: '50%', fill: '#818cf8', fontSize: 11 }} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {data.map((d, i) => (
              <Cell key={i} fill={getColor(d.value)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
