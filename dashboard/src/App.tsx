import { useState } from 'react'
import type { CipherOption, TestResult } from './types'
import { CipherSelector } from './components/CipherSelector'
import { FileUpload } from './components/FileUpload'
import { TestResults } from './components/TestResults'

const SERVER = 'http://localhost:8765'

type Status = 'idle' | 'loading' | 'done' | 'error'

export default function App() {
  const [cipher, setCipher] = useState<CipherOption>('aes256')
  const [file, setFile] = useState<File | null>(null)
  const [status, setStatus] = useState<Status>('idle')
  const [result, setResult] = useState<TestResult | null>(null)
  const [errorMsg, setErrorMsg] = useState('')

  const canRun = file !== null && status !== 'loading'

  const runTest = async () => {
    if (!file) return
    setStatus('loading')
    setResult(null)
    setErrorMsg('')

    const form = new FormData()
    form.append('cipher', cipher)
    form.append('file', file, file.name)

    try {
      const res = await fetch(`${SERVER}/api/test`, { method: 'POST', body: form })
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`Server error ${res.status}: ${text}`)
      }
      const data: TestResult = await res.json()
      setResult(data)
      setStatus('done')
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : String(e))
      setStatus('error')
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0f172a',
      color: '#f9fafb',
      fontFamily: 'system-ui, -apple-system, sans-serif',
      padding: '32px 24px',
    }}>
      <div style={{ maxWidth: '820px', margin: '0 auto' }}>

        {/* Header */}
        <div style={{ marginBottom: '32px' }}>
          <h1 style={{ margin: 0, fontSize: '24px', fontWeight: 800, color: '#f9fafb' }}>
            Crypt Analysis
          </h1>
          <p style={{ margin: '6px 0 0', color: '#6b7280', fontSize: '14px' }}>
            Test cipher integrity, performance, and cryptographic properties
          </p>
        </div>

        {/* Controls */}
        <div style={{ background: '#111827', borderRadius: '12px', padding: '24px', marginBottom: '24px', border: '1px solid #1f2937' }}>
          <div style={{ marginBottom: '20px' }}>
            <label style={{ fontSize: '13px', fontWeight: 600, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '10px' }}>
              Select cipher
            </label>
            <CipherSelector value={cipher} onChange={setCipher} />
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ fontSize: '13px', fontWeight: 600, color: '#9ca3af', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '10px' }}>
              Upload file
            </label>
            <FileUpload file={file} onChange={setFile} />
          </div>

          <button
            onClick={runTest}
            disabled={!canRun}
            style={{
              width: '100%',
              padding: '12px',
              borderRadius: '8px',
              border: 'none',
              background: canRun ? '#6366f1' : '#374151',
              color: canRun ? '#fff' : '#6b7280',
              fontSize: '15px',
              fontWeight: 700,
              cursor: canRun ? 'pointer' : 'not-allowed',
              transition: 'background 0.15s',
            }}
          >
            {status === 'loading' ? 'Running tests…' : 'Run Integrity Test'}
          </button>
        </div>

        {/* Loading */}
        {status === 'loading' && (
          <div style={{ textAlign: 'center', padding: '40px', color: '#6b7280' }}>
            <div style={{ fontSize: '32px', marginBottom: '12px' }}>⏳</div>
            <div>Running encryption, analysis, and profiling…</div>
          </div>
        )}

        {/* Error */}
        {status === 'error' && (
          <div style={{ background: '#7f1d1d', border: '1px solid #ef4444', borderRadius: '10px', padding: '16px 20px', color: '#fca5a5' }}>
            <strong>Error:</strong> {errorMsg}
            <div style={{ fontSize: '12px', marginTop: '8px', color: '#f87171' }}>
              Make sure the C++ server is running: <code>./build/file-crypto server</code>
            </div>
          </div>
        )}

        {/* Results */}
        {status === 'done' && result && <TestResults result={result} />}

      </div>
    </div>
  )
}
