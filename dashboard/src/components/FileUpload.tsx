import { useRef, useState } from 'react'

interface Props {
  file: File | null
  onChange: (f: File | null) => void
}

export function FileUpload({ file, onChange }: Props) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const dropped = e.dataTransfer.files[0]
    if (dropped) onChange(dropped)
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
  }

  return (
    <div
      onDragOver={e => { e.preventDefault(); setDragging(true) }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => inputRef.current?.click()}
      style={{
        border: `2px dashed ${dragging ? '#6366f1' : file ? '#22c55e' : '#4b5563'}`,
        borderRadius: '10px',
        padding: '28px',
        textAlign: 'center',
        cursor: 'pointer',
        background: dragging ? '#1e1b4b' : '#1f2937',
        transition: 'all 0.15s',
      }}
    >
      <input
        ref={inputRef}
        type="file"
        style={{ display: 'none' }}
        onChange={e => onChange(e.target.files?.[0] ?? null)}
      />
      {file ? (
        <div>
          <div style={{ fontSize: '28px', marginBottom: '6px' }}>📄</div>
          <div style={{ fontWeight: 700, color: '#f9fafb' }}>{file.name}</div>
          <div style={{ fontSize: '13px', color: '#9ca3af', marginTop: '4px' }}>{formatSize(file.size)}</div>
          <div style={{ fontSize: '12px', color: '#6b7280', marginTop: '8px' }}>Click or drag to replace</div>
        </div>
      ) : (
        <div>
          <div style={{ fontSize: '28px', marginBottom: '6px' }}>📂</div>
          <div style={{ color: '#d1d5db', fontWeight: 500 }}>Drop a file here, or click to select</div>
          <div style={{ fontSize: '12px', color: '#6b7280', marginTop: '6px' }}>
            Any file type · Results are most reliable on files ≥ 1 KB
          </div>
        </div>
      )}
    </div>
  )
}
