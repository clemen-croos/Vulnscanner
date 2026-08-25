import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { scansAPI } from '../utils/api'
import { Upload, FileIcon, X, Shield, Zap, AlertTriangle, CheckCircle, Info } from 'lucide-react'
import toast from 'react-hot-toast'

export default function NewScanPage() {
  const navigate = useNavigate()
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [scanType, setScanType] = useState('quick')
  const [staticEnabled, setStaticEnabled] = useState(true)
  const [dynamicEnabled, setDynamicEnabled] = useState(false)
  const [aiFilter, setAiFilter] = useState(true)

  const onDrop = useCallback((e) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f && f.name.endsWith('.apk')) {
      setFile(f)
    } else {
      toast.error('Only .apk files are supported')
    }
  }, [])

  const onFileSelect = (e) => {
    const f = e.target.files[0]
    if (f) setFile(f)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!file) return toast.error('Please select an APK file')
    if (!staticEnabled && !dynamicEnabled) return toast.error('Enable static analysis, dynamic analysis, or both')

    setUploading(true)
    setUploadProgress(0)

    const formData = new FormData()
    formData.append('file', file)
    formData.append('options', JSON.stringify({
      static: staticEnabled,
      dynamic: dynamicEnabled,
      ai_filter: aiFilter,
      scan_type: scanType
    }))

    try {
      const res = await scansAPI.upload(formData, (progressEvent) => {
        const pct = Math.round((progressEvent.loaded * 100) / progressEvent.total)
        setUploadProgress(pct)
      })
      toast.success('APK uploaded! Scan started.')
      navigate(`/scans/${res.data.scan_id}`)
    } catch (err) {
      toast.error(err.response?.data?.error || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const formatSize = (bytes) => {
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  }

  return (
    <div className="p-6 max-w-3xl mx-auto animate-fade-in">
      <div className="mb-6">
        <button onClick={() => navigate('/scans')} className="text-xs mb-3 flex items-center gap-1 hover:opacity-70 transition-opacity" style={{ color: '#6b7280', background: 'none', border: 'none', cursor: 'pointer' }}>
          ← Back to Scans
        </button>
        <h1 className="text-xl font-bold" style={{ color: '#e2e8f0' }}>New Scan</h1>
        <p className="text-sm mt-0.5" style={{ color: '#6b7280' }}>Upload an Android APK to begin security analysis</p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        <div
          onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
          className="rounded-xl border-2 border-dashed transition-all"
          style={{
            borderColor: dragging ? '#7c3aed' : file ? '#22c55e' : '#1e2d4a',
            background: dragging ? 'rgba(124,58,237,0.05)' : file ? 'rgba(34,197,94,0.03)' : '#0d1220',
            minHeight: 180,
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
            cursor: 'pointer', position: 'relative'
          }}
          onClick={() => !file && document.getElementById('apk-input').click()}
        >
          <input
            id="apk-input"
            type="file"
            accept=".apk"
            onChange={onFileSelect}
            style={{ display: 'none' }}
          />

          {file ? (
            <div className="text-center p-6">
              <div className="w-14 h-14 rounded-xl mx-auto mb-3 flex items-center justify-center" style={{ background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)' }}>
                <CheckCircle size={28} style={{ color: '#22c55e' }} />
              </div>
              <p className="font-semibold" style={{ color: '#e2e8f0' }}>{file.name}</p>
              <p className="text-sm mt-1" style={{ color: '#6b7280' }}>{formatSize(file.size)}</p>
              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); setFile(null) }}
                className="mt-3 flex items-center gap-1.5 mx-auto text-xs px-3 py-1.5 rounded-lg transition-all hover:bg-red-900/30"
                style={{ color: '#ef4444', background: 'none', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer' }}
              >
                <X size={12} /> Remove
              </button>
            </div>
          ) : (
            <div className="text-center p-8">
              <div className="w-14 h-14 rounded-xl mx-auto mb-4 flex items-center justify-center" style={{ background: 'rgba(124,58,237,0.1)', border: '1px solid rgba(124,58,237,0.2)' }}>
                <Upload size={26} style={{ color: '#7c3aed' }} />
              </div>
              <p className="font-semibold" style={{ color: '#e2e8f0' }}>Drag & Drop APK here</p>
              <p className="text-sm mt-1" style={{ color: '#4a5568' }}>or <span style={{ color: '#7c3aed', cursor: 'pointer' }}>browse files</span></p>
              <p className="text-xs mt-3" style={{ color: '#374151' }}>Max file size: 100MB &nbsp;·&nbsp; Only .apk files</p>
            </div>
          )}
        </div>

        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-4" style={{ color: '#94a3b8' }}>Scan Configuration</h3>

          <div className="grid grid-cols-2 gap-3 mb-4">
            {[
              { id: 'quick', icon: Zap, title: 'Quick Scan', desc: 'Static analysis only. Fast results in ~1-2 min.', color: '#3b82f6' },
              { id: 'deep', icon: Shield, title: 'Deep Scan', desc: 'Static analysis followed by dynamic emulator analysis.', color: '#7c3aed' }
            ].map(({ id, icon: Icon, title, desc, color }) => (
              <button
                key={id}
                type="button"
                onClick={() => { setScanType(id); setStaticEnabled(true); setDynamicEnabled(id === 'deep') }}
                className="p-4 rounded-xl text-left transition-all"
                style={{
                  border: `1px solid ${scanType === id ? color + '60' : '#1e2d4a'}`,
                  background: scanType === id ? `${color}10` : '#0d1220',
                  cursor: 'pointer'
                }}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Icon size={16} style={{ color: scanType === id ? color : '#4a5568' }} />
                  <span className="text-sm font-semibold" style={{ color: scanType === id ? '#e2e8f0' : '#6b7280' }}>{title}</span>
                  {id === 'quick' && <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: 'rgba(59,130,246,0.1)', color: '#3b82f6' }}>Recommended</span>}
                </div>
                <p className="text-xs" style={{ color: '#4a5568' }}>{desc}</p>
              </button>
            ))}
          </div>

          <div className="space-y-3">
            <Toggle
              label="Static Analysis"
              desc="Inspect manifest, code, secrets, cryptography, components, WebViews, storage, and native libraries"
              value={staticEnabled}
              onChange={setStaticEnabled}
              icon={<Shield size={15} style={{ color: '#3b82f6' }} />}
            />
            <Toggle
              label="AI/NLP False Positive Filter"
              desc={staticEnabled ? 'Reduces likely false positives in static secret detection' : 'Enable static analysis to use this filter'}
              value={aiFilter}
              onChange={staticEnabled ? setAiFilter : () => {}}
              icon={<Shield size={15} style={{ color: '#7c3aed' }} />}
            />
            <Toggle
              label="Dynamic Analysis (Emulator)"
              desc="Install and exercise the APK on the configured Android lab target, then collect runtime evidence"
              value={dynamicEnabled}
              onChange={setDynamicEnabled}
              icon={<AlertTriangle size={15} style={{ color: '#f97316' }} />}
            />
          </div>
        </div>

        {uploading && (
          <div className="card p-4">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-5 h-5 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
              <span className="text-sm" style={{ color: '#e2e8f0' }}>
                {uploadProgress < 100 ? `Uploading... ${uploadProgress}%` : 'Starting scan analysis...'}
              </span>
            </div>
            <div className="h-1.5 rounded-full overflow-hidden" style={{ background: '#1e2d4a' }}>
              <div className="h-full rounded-full transition-all duration-300" style={{ background: '#7c3aed', width: `${uploadProgress}%` }} />
            </div>
          </div>
        )}

        <div className="flex gap-3 p-3 rounded-lg text-xs" style={{ background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)' }}>
          <Info size={14} className="flex-shrink-0 mt-0.5" style={{ color: '#3b82f6' }} />
          <p style={{ color: '#6b7280' }}>
            Uploaded APKs are scanned in a secure, isolated environment. Files are stored temporarily and automatically deleted after 30 days.
          </p>
        </div>

        <button
          type="submit"
          disabled={uploading || !file}
          className="btn-primary w-full py-3 flex items-center justify-center gap-2 text-base"
          style={{ opacity: !file || uploading ? 0.5 : 1 }}
        >
          {uploading ? (
            <><div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" /> Scanning...</>
          ) : (
            <><Shield size={18} /> Start Scan</>
          )}
        </button>
      </form>
    </div>
  )
}

function Toggle({ label, desc, value, onChange, icon }) {
  return (
    <div className="flex items-start justify-between gap-4 p-3 rounded-lg" style={{ background: '#080c16', border: '1px solid #1e2d4a' }}>
      <div className="flex items-start gap-2">
        {icon}
        <div>
          <p className="text-sm font-medium" style={{ color: '#e2e8f0' }}>{label}</p>
          <p className="text-xs mt-0.5" style={{ color: '#4a5568' }}>{desc}</p>
        </div>
      </div>
      <button
        type="button"
        onClick={() => onChange(!value)}
        className="flex-shrink-0 w-10 h-5 rounded-full relative transition-all"
        style={{ background: value ? '#7c3aed' : '#1e2d4a', border: 'none', cursor: 'pointer' }}
      >
        <div className="absolute top-0.5 w-4 h-4 rounded-full transition-all" style={{
          background: 'white', left: value ? '22px' : '2px'
        }} />
      </button>
    </div>
  )
}
