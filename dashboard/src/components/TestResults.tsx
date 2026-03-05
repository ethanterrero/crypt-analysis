import type { TestResult } from '../types'
import { MetricCard } from './MetricCard'
import { AvalancheChart } from './AvalancheChart'

interface Props {
  result: TestResult
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ marginBottom: '6px' }}>
      <span style={{ color: '#6b7280', fontSize: '12px' }}>{label}: </span>
      <span style={{ color: '#e5e7eb', fontSize: '13px', fontWeight: 500 }}>{value}</span>
    </div>
  )
}

function EntropyBar({ value }: { value: number }) {
  const pct = Math.min((value / 8) * 100, 100)
  const color = value >= 7.5 ? '#22c55e' : value >= 6.5 ? '#f59e0b' : '#ef4444'
  return (
    <div style={{ marginTop: '8px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: '#9ca3af', marginBottom: '4px' }}>
        <span>0</span>
        <span style={{ color, fontWeight: 700 }}>{value.toFixed(4)} bits/byte</span>
        <span>8.0</span>
      </div>
      <div style={{ background: '#374151', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: '4px', transition: 'width 0.4s' }} />
      </div>
      <div style={{ fontSize: '11px', color: '#6b7280', marginTop: '4px' }}>Ideal ciphertext ≥ 7.5 bits/byte</div>
    </div>
  )
}

function PValueBar({ value }: { value: number }) {
  const pct = value * 100
  const inRange = value >= 0.05 && value <= 0.95
  const color = inRange ? '#22c55e' : '#ef4444'
  return (
    <div style={{ marginTop: '8px' }}>
      <div style={{ position: 'relative', background: '#374151', borderRadius: '4px', height: '16px', overflow: 'visible' }}>
        {/* pass band 5–95% */}
        <div style={{
          position: 'absolute', left: '5%', width: '90%', height: '100%',
          background: '#14532d', borderRadius: '2px', opacity: 0.5,
        }} />
        {/* marker */}
        <div style={{
          position: 'absolute', left: `calc(${pct}% - 3px)`, top: '-3px',
          width: '6px', height: '22px', background: color, borderRadius: '3px',
        }} />
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: '#6b7280', marginTop: '4px' }}>
        <span>0</span>
        <span style={{ color, fontWeight: 700 }}>p = {value.toFixed(4)}</span>
        <span>1</span>
      </div>
      <div style={{ fontSize: '11px', color: '#6b7280' }}>Pass band: 0.05 – 0.95 (green zone)</div>
    </div>
  )
}

export function TestResults({ result }: Props) {
  const formatBytes = (b: number) => b < 1024 ? `${b} B` : `${(b / 1024).toFixed(1)} KB`

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: '20px', padding: '14px 18px', background: '#1f2937', borderRadius: '10px', border: '1px solid #374151' }}>
        <div style={{ color: '#9ca3af', fontSize: '12px', marginBottom: '4px' }}>Test subject</div>
        <div style={{ color: '#f9fafb', fontWeight: 700, fontSize: '16px' }}>{result.file_name}</div>
        <div style={{ color: '#6b7280', fontSize: '12px', marginTop: '2px' }}>
          {formatBytes(result.file_size_bytes)} plaintext → {formatBytes(result.ciphertext_size_bytes)} ciphertext · {result.cipher}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px' }}>

        {/* Integrity */}
        <MetricCard title="Integrity" passed={result.integrity.passed}>
          <Stat label="Encrypt" value={result.integrity.encrypt_success ? '✓ success' : '✗ failed'} />
          <Stat label="Decrypt" value={result.integrity.decrypt_success ? '✓ success' : '✗ failed'} />
          <Stat label="Round-trip" value={result.integrity.roundtrip_match ? '✓ plaintext matches' : '✗ mismatch'} />
        </MetricCard>

        {/* Performance */}
        <MetricCard title="Performance" passed={true}>
          <div style={{ marginBottom: '8px' }}>
            <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '3px' }}>Encrypt</div>
            <Stat label="Speed" value={`${result.performance.encrypt_mb_per_second.toFixed(2)} MB/s`} />
            <Stat label="Cycles/byte" value={result.performance.encrypt_cycles_per_byte.toFixed(1)} />
            <Stat label="Time" value={`${(result.performance.encrypt_seconds * 1000).toFixed(3)} ms`} />
          </div>
          <div>
            <div style={{ fontSize: '12px', color: '#6b7280', marginBottom: '3px' }}>Decrypt</div>
            <Stat label="Speed" value={`${result.performance.decrypt_mb_per_second.toFixed(2)} MB/s`} />
            <Stat label="Cycles/byte" value={result.performance.decrypt_cycles_per_byte.toFixed(1)} />
            <Stat label="Time" value={`${(result.performance.decrypt_seconds * 1000).toFixed(3)} ms`} />
          </div>
        </MetricCard>

        {/* Entropy */}
        <MetricCard title="Shannon Entropy" passed={result.entropy.available ? result.entropy.passed : null}>
          {result.entropy.available ? (
            <>
              <EntropyBar value={result.entropy.entropy_bits_per_byte} />
              <div style={{ marginTop: '10px' }}>
                <Stat label="Total bytes analyzed" value={result.entropy.total_bytes.toLocaleString()} />
              </div>
            </>
          ) : (
            <div style={{ color: '#6b7280', fontSize: '13px' }}>Encryption failed — no data to analyze</div>
          )}
        </MetricCard>

        {/* Frequency */}
        <MetricCard title="Byte Frequency (χ²)" passed={result.frequency.available ? result.frequency.passed : null}>
          {result.frequency.available ? (
            <>
              <PValueBar value={result.frequency.p_value} />
              <div style={{ marginTop: '10px' }}>
                <Stat label="χ² statistic" value={result.frequency.chi_squared.toFixed(2)} />
                <Stat label="Degrees of freedom" value={String(result.frequency.degrees_of_freedom)} />
              </div>
            </>
          ) : (
            <div style={{ color: '#6b7280', fontSize: '13px' }}>Encryption failed — no data to analyze</div>
          )}
        </MetricCard>

        {/* Avalanche — full width */}
        <div style={{ gridColumn: '1 / -1' }}>
          <MetricCard
            title="Avalanche Effect"
            passed={result.avalanche.applicable ? result.avalanche.passed : null}
            note={result.avalanche.note || undefined}
          >
            {result.avalanche.applicable && result.avalanche.available ? (
              <>
                <AvalancheChart
                  avg={result.avalanche.avg_bit_change_pct}
                  min={result.avalanche.min_bit_change_pct}
                  max={result.avalanche.max_bit_change_pct}
                />
                <div style={{ marginTop: '8px', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '8px' }}>
                  <Stat label="Avg change" value={`${result.avalanche.avg_bit_change_pct.toFixed(2)}%`} />
                  <Stat label="Std dev" value={`${result.avalanche.std_dev.toFixed(2)}%`} />
                  <Stat label="Bits tested" value={String(result.avalanche.bits_tested)} />
                </div>
              </>
            ) : (
              <div style={{ color: '#6b7280', fontSize: '13px' }}>
                {result.avalanche.applicable
                  ? 'Encryption failed — no data to analyze'
                  : 'Not applicable for stream ciphers'}
              </div>
            )}
          </MetricCard>
        </div>

      </div>
    </div>
  )
}
