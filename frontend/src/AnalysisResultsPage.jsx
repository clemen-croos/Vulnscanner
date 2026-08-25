import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { ArrowLeft, ChevronRight, Download, Shield, Smartphone } from 'lucide-react'
import { scansAPI, reportsAPI } from '../utils/api'
import SeverityBadge from '../components/SeverityBadge'
import RiskGauge from '../components/RiskGauge'
import toast from 'react-hot-toast'

export default function AnalysisResultsPage({ analysisType }) {
  const { id } = useParams()
  const navigate = useNavigate()
  const [data, setData] = useState(null)
  const [filter, setFilter] = useState('all')
  const title = analysisType === 'dynamic' ? 'Dynamic Scan Results' : 'Static Scan Results'
  const Icon = analysisType === 'dynamic' ? Smartphone : Shield

  useEffect(() => {
    scansAPI.results(id, analysisType)
      .then(res => setData(res.data))
      .catch(() => { toast.error(`Unable to load ${analysisType} results`); navigate(`/scans/${id}`) })
  }, [id, analysisType])

  if (!data) return <div className="flex items-center justify-center h-full"><div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" /></div>

  const { scan, analysis, vulnerabilities } = data
  const visible = vulnerabilities.filter(v => filter === 'all' || v.severity === filter)
  const downloadReport = async (format) => {
    try {
      const res = await reportsAPI.generate({ scan_id: Number(id), format, report_type: 'full', analysis_type: analysisType })
      const blob = (await reportsAPI.download(res.data.report.id)).data
      const url = URL.createObjectURL(blob); const a = document.createElement('a')
      a.href = url; a.download = `${analysisType}_${scan.apk_name}_report.${format}`; a.click(); URL.revokeObjectURL(url)
    } catch { toast.error('Report generation failed') }
  }

  return (
    <div className="p-6 max-w-6xl mx-auto animate-fade-in">
      <button onClick={() => navigate(`/scans/${id}`)} className="text-xs mb-3 flex items-center gap-1" style={{ color: '#6b7280', background: 'none', border: 'none', cursor: 'pointer' }}><ArrowLeft size={13}/> Scan overview</button>
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-3"><div className="w-11 h-11 rounded-xl flex items-center justify-center" style={{ background: analysisType === 'dynamic' ? 'rgba(249,115,22,.12)' : 'rgba(59,130,246,.12)' }}><Icon size={22} style={{ color: analysisType === 'dynamic' ? '#f97316' : '#3b82f6' }}/></div><div><h1 className="text-xl font-bold" style={{ color: '#e2e8f0' }}>{title}</h1><p className="text-sm" style={{ color: '#6b7280' }}>{scan.apk_name}</p></div></div>
        {analysis.status === 'completed' && <div className="flex gap-2">{['html','json'].map(f => <button key={f} onClick={() => downloadReport(f)} className="btn-secondary flex items-center gap-1.5"><Download size={14}/>{f.toUpperCase()}</button>)}</div>}
      </div>

      {analysis.status !== 'completed' ? <div className="card p-5"><h2 className="font-semibold" style={{ color: analysis.status === 'failed' ? '#ef4444' : '#e2e8f0' }}>{analysis.status === 'failed' ? `${title} failed` : `${title} not available`}</h2><p className="text-sm mt-2" style={{ color: '#6b7280' }}>{analysis.error || `This ${analysisType} analysis was not requested or is still running.`}</p></div> : <>
        <div className="grid grid-cols-5 gap-4 mb-5"><div className="card p-4 flex items-center justify-center"><RiskGauge score={analysis.risk_score}/></div>{[['Critical',analysis.critical_count,'#ef4444'],['High',analysis.high_count,'#f97316'],['Medium',analysis.medium_count,'#eab308'],['Low',analysis.low_count,'#22c55e']].map(([label,count,color]) => <button key={label} onClick={() => setFilter(label.toLowerCase())} className="card p-4 text-center" style={{ color, cursor: 'pointer' }}><div className="text-3xl font-black">{count}</div><div className="text-xs uppercase">{label}</div></button>)}</div>
        {analysisType === 'dynamic' && analysis.metadata?.coverage && <div className="card p-4 mb-5"><h2 className="font-semibold mb-3" style={{ color: '#94a3b8' }}>Runtime coverage</h2><div className="grid md:grid-cols-2 gap-2">{analysis.metadata.coverage.map((item,i) => <div key={i} className="p-3 rounded-lg" style={{ background: '#080c16', border: '1px solid #1e2d4a' }}><div className="text-sm font-medium" style={{ color: '#e2e8f0' }}>{item.name} <span className="text-xs uppercase ml-1" style={{ color: item.status === 'completed' ? '#22c55e' : '#eab308' }}>{item.status}</span></div><p className="text-xs mt-1" style={{ color: '#6b7280' }}>{item.detail}</p></div>)}</div></div>}
        {analysisType === 'dynamic' && analysis.metadata?.limitations?.length > 0 && <div className="card p-4 mb-5"><h2 className="font-semibold mb-2" style={{ color: '#94a3b8' }}>Coverage limitations</h2><ul className="text-xs space-y-1 list-disc pl-5" style={{ color: '#6b7280' }}>{analysis.metadata.limitations.map((item,i) => <li key={i}>{item}</li>)}</ul></div>}
        <div className="card"><div className="p-4 border-b flex justify-between" style={{ borderColor: '#1e2d4a' }}><h2 className="font-semibold" style={{ color: '#94a3b8' }}>{title} ({visible.length})</h2><button onClick={() => setFilter('all')} className="text-xs" style={{ color: '#7c3aed', background: 'none', border: 'none' }}>Show all</button></div>{visible.length === 0 ? <div className="p-8 text-center" style={{ color: '#6b7280' }}>{analysisType === 'dynamic' && vulnerabilities.length === 0 ? 'No vulnerabilities were observed in the automated runtime path. This does not guarantee the APK is vulnerability-free. Run Static Scan for code and configuration risks; deeper authenticated workflows require test automation.' : 'No findings match this filter.'}</div> : visible.map(v => <div key={v.id} onClick={() => navigate(`/vulnerabilities/${v.id}`)} className="flex items-center gap-3 p-4 border-b cursor-pointer" style={{ borderColor: '#1e2d4a' }}><SeverityBadge severity={v.severity}/><div className="flex-1"><p className="text-sm font-medium" style={{ color: '#e2e8f0' }}>{v.title}</p><p className="text-xs" style={{ color: '#4a5568' }}>{v.location}</p></div><span className="text-xs" style={{ color: '#6b7280' }}>{v.category}</span><ChevronRight size={15} style={{ color: '#374151' }}/></div>)}</div>
      </>}
    </div>
  )
}
