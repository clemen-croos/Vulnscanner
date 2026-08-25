import { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { scansAPI, vulnsAPI, reportsAPI } from '../utils/api'
import { Shield, Smartphone, ChevronRight, Download, FileText, Loader, CheckCircle, XCircle, Clock, RefreshCw } from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge'
import RiskGauge from '../components/RiskGauge'
import toast from 'react-hot-toast'

const SCAN_STAGES = [
  { key: 'upload', label: 'APK Upload & Validation', threshold: 10 },
  { key: 'parse',  label: 'APK Parsing',             threshold: 30 },
  { key: 'static', label: 'Static Analysis',         threshold: 70 },
  { key: 'ai',     label: 'AI/NLP Filtering',        threshold: 85 },
  { key: 'score',  label: 'Risk Scoring',            threshold: 95 },
  { key: 'report', label: 'Finalizing Results',      threshold: 100 },
]

export default function ScanDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const [scan, setScan] = useState(null)
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [severityFilter, setSeverityFilter] = useState('all')
  const pollRef = useRef(null)

  useEffect(() => {
    loadScan()
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }
    }
  }, [id])

 const loadScan = async () => {
    try {
      const res = await scansAPI.get(id, true)
      const s = res.data.scan
      setScan(s)
      setVulns(s.vulnerabilities || [])
      setLoading(false)

      if (s.status === 'running' || s.status === 'pending') {
        clearInterval(pollRef.current)
        pollRef.current = setInterval(() => pollStatus(), 3000)
      }
    } catch (err) {
      toast.error('Scan not found')
      navigate('/scans')
    }
  }

  const pollStatus = async () => {
    try {
      const statusRes = await scansAPI.status(id)
      const { status, progress, analyses } = statusRes.data
      setScan(prev => prev ? { ...prev, status, progress, analyses } : prev)

      if (status === 'completed' || status === 'failed') {
        clearInterval(pollRef.current)
        pollRef.current = null
        if (status === 'completed') {
          const res = await scansAPI.get(id, true)
          setScan(res.data.scan)
          setVulns(res.data.scan.vulnerabilities || [])
          toast.success('Scan completed!')
        }
      }
    } catch {}
  }

  const generateReport = async (fmt) => {
    setGenerating(true)
    try {
      const res = await reportsAPI.generate({ scan_id: scan.id, format: fmt, report_type: 'full' })
      toast.success(`${fmt.toUpperCase()} report generated`)
      const blob = (await reportsAPI.download(res.data.report.id)).data
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `vulnscanner_${scan.apk_name}_report.${fmt}`
      a.click()
      URL.revokeObjectURL(url)
    } catch { toast.error('Report generation failed') }
    finally { setGenerating(false) }
  }

  const filteredVulns = vulns.filter(v =>
    !v.is_false_positive && (severityFilter === 'all' || v.severity === severityFilter)
  )

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
    </div>
  )

  const isScanning = scan.status === 'running' || scan.status === 'pending'

  return (
    <div className="p-6 max-w-6xl mx-auto animate-fade-in">
      <div className="flex items-start justify-between mb-6">
        <div>
          <button onClick={() => navigate('/scans')} className="text-xs mb-2 flex items-center gap-1 hover:opacity-70 transition-opacity" style={{ color: '#6b7280', background: 'none', border: 'none', cursor: 'pointer' }}>
            ← Back to Scans
          </button>
          <h1 className="text-xl font-bold" style={{ color: '#e2e8f0' }}>{scan.apk_name}</h1>
          <p className="text-sm mt-0.5" style={{ color: '#6b7280' }}>
            {scan.package_name} &nbsp;·&nbsp; v{scan.version_name}
            {scan.min_sdk && ` · API ${scan.min_sdk}+`}
          </p>
        </div>
        {scan.status === 'completed' && (
          <div className="flex gap-2">
            {['html','json'].map(fmt => (
              <button
                key={fmt}
                onClick={() => generateReport(fmt)}
                disabled={generating}
                className="btn-secondary flex items-center gap-1.5"
              >
                <Download size={14} />
                {fmt.toUpperCase()}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="grid md:grid-cols-2 gap-4 mb-5">
        {[
          { type: 'static', title: 'Static Scan Results', icon: Shield, color: '#3b82f6' },
          { type: 'dynamic', title: 'Dynamic Scan Results', icon: Smartphone, color: '#f97316' },
        ].map(({ type, title, icon: Icon, color }) => {
          const result = scan.analyses?.[type] || { status: 'not_requested', progress: 0, total_findings: 0 }
          return <button key={type} onClick={() => navigate(`/scans/${scan.id}/${type}-results`)} className="card p-4 text-left flex items-center gap-3" style={{ cursor: 'pointer', opacity: result.status === 'not_requested' ? .65 : 1 }}>
            <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: `${color}18` }}><Icon size={20} style={{ color }}/></div>
            <div className="flex-1"><div className="font-semibold" style={{ color: '#e2e8f0' }}>{title}</div><div className="text-xs mt-1 capitalize" style={{ color }}>{result.status.replace('_', ' ')}{result.status === 'running' ? ` · ${result.progress}%` : result.status === 'completed' ? ` · ${result.total_findings} findings` : ''}</div></div>
            <ChevronRight size={16} style={{ color: '#4a5568' }}/>
          </button>
        })}
      </div>

      {isScanning && (
        <div className="card p-6 mb-5 animate-pulse-subtle">
          <div className="flex items-center gap-3 mb-4">
            <Loader size={20} style={{ color: '#3b82f6' }} className="animate-spin" />
            <div>
              <p className="font-semibold" style={{ color: '#e2e8f0' }}>Scanning in progress...</p>
              <p className="text-xs" style={{ color: '#6b7280' }}>{scan.progress || 0}% complete</p>
            </div>
          </div>
          <div className="h-2 rounded-full overflow-hidden mb-5" style={{ background: '#1e2d4a' }}>
            <div className="h-full rounded-full transition-all duration-500" style={{ background: 'linear-gradient(90deg, #7c3aed, #3b82f6)', width: `${scan.progress || 0}%` }} />
          </div>
          <div className="grid grid-cols-6 gap-2">
            {SCAN_STAGES.map(({ key, label, threshold }) => {
              const done = (scan.progress || 0) >= threshold
              const active = !done && (scan.progress || 0) >= (threshold - 25)
              return (
                <div key={key} className="text-center">
                  <div className="w-7 h-7 rounded-full mx-auto mb-1 flex items-center justify-center text-xs"
                    style={{
                      background: done ? 'rgba(34,197,94,0.1)' : active ? 'rgba(59,130,246,0.1)' : '#1e2d4a',
                      border: `1px solid ${done ? '#22c55e' : active ? '#3b82f6' : '#2a3a5c'}`,
                      color: done ? '#22c55e' : active ? '#3b82f6' : '#4a5568'
                    }}>
                    {done ? '✓' : active ? '…' : '○'}
                  </div>
                  <p className="text-xs leading-tight" style={{ color: done ? '#22c55e' : active ? '#3b82f6' : '#374151', fontSize: '0.6rem' }}>{label}</p>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {scan.status === 'failed' && (
        <div className="card p-5 mb-5 flex items-start gap-3" style={{ borderColor: 'rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.05)' }}>
          <XCircle size={20} style={{ color: '#ef4444' }} />
          <div>
            <p className="font-semibold" style={{ color: '#ef4444' }}>Scan failed</p>
            <p className="text-sm mt-1" style={{ color: '#6b7280' }}>{scan.error_message || 'An unknown error occurred during scanning.'}</p>
          </div>
        </div>
      )}

      {scan.status === 'completed' && (
        <>
          <div className="grid grid-cols-5 gap-4 mb-5">
            <div className="card p-4 flex items-center justify-center">
              <RiskGauge score={scan.risk_score || 0} />
            </div>
            {[
              { label: 'Critical', count: scan.critical_count, color: '#ef4444' },
              { label: 'High',     count: scan.high_count,     color: '#f97316' },
              { label: 'Medium',   count: scan.medium_count,   color: '#eab308' },
              { label: 'Low',      count: scan.low_count,      color: '#22c55e' },
            ].map(({ label, count, color }) => (
              <div key={label} className="card p-4 text-center cursor-pointer hover:border-opacity-50 transition-all"
                style={{ borderColor: count > 0 ? `${color}30` : '#1e2d4a', background: count > 0 ? `${color}05` : '#111827' }}
                onClick={() => setSeverityFilter(label.toLowerCase())}>
                <div className="text-3xl font-black mb-1" style={{ color: count > 0 ? color : '#374151' }}>{count}</div>
                <div className="text-xs font-semibold uppercase tracking-wider" style={{ color: count > 0 ? color : '#4a5568' }}>{label}</div>
              </div>
            ))}
          </div>

          <div className="card">
            <div className="p-4 border-b flex items-center justify-between" style={{ borderColor: '#1e2d4a' }}>
              <h2 className="font-semibold" style={{ color: '#94a3b8' }}>
                Vulnerabilities <span style={{ color: '#4a5568' }}>({filteredVulns.length})</span>
              </h2>
              <div className="flex gap-1 p-1 rounded-lg" style={{ background: '#080c16', border: '1px solid #1e2d4a' }}>
                {['all','critical','high','medium','low'].map(f => (
                  <button key={f} onClick={() => setSeverityFilter(f)}
                    className="px-2.5 py-1 rounded text-xs font-medium capitalize transition-all"
                    style={severityFilter === f
                      ? { background: '#7c3aed', color: 'white', border: 'none', cursor: 'pointer' }
                      : { color: '#6b7280', background: 'none', border: 'none', cursor: 'pointer' }}>
                    {f}
                  </button>
                ))}
              </div>
            </div>
            <div className="divide-y" style={{ borderColor: '#1e2d4a' }}>
              {filteredVulns.length === 0 ? (
                <div className="p-8 text-center" style={{ color: '#4a5568' }}>No vulnerabilities in this category</div>
              ) : filteredVulns.map(v => (
                <div
                  key={v.id}
                  onClick={() => navigate(`/vulnerabilities/${v.id}`)}
                  className="flex items-center gap-3 p-4 cursor-pointer transition-all hover:bg-white/[0.02]"
                >
                  <SeverityBadge severity={v.severity} />
                  <div className="flex-1 min-w-0">
                    <p className="font-medium text-sm truncate" style={{ color: '#e2e8f0' }}>{v.title}</p>
                    <p className="text-xs mt-0.5 truncate" style={{ color: '#4a5568' }}>{v.location}</p>
                  </div>
                  <div className="flex items-center gap-3 text-xs" style={{ color: '#6b7280' }}>
                    <span>{v.category}</span>
                    {v.cvss_score && <span className="font-mono">CVSS {v.cvss_score}</span>}
                  </div>
                  <ChevronRight size={15} style={{ color: '#374151' }} />
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
