import { useState, useEffect } from 'react'
import { reportsAPI, scansAPI } from '../utils/api'
import { FileText, Download, Trash2, Plus, X } from 'lucide-react'
import toast from 'react-hot-toast'

export default function ReportsPage() {
  const [reports, setReports] = useState([])
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [form, setForm] = useState({ scan_id: '', report_type: 'full', format: 'html' })

  useEffect(() => {
    Promise.all([
      reportsAPI.list().then(r => setReports(r.data.reports || [])),
      scansAPI.list({ status: 'completed', per_page: 50 }).then(r => setScans(r.data.scans || []))
    ]).finally(() => setLoading(false))
  }, [])

  const handleGenerate = async (e) => {
    e.preventDefault()
    if (!form.scan_id) return toast.error('Select a scan')
    setGenerating(true)
    try {
      const res = await reportsAPI.generate({ ...form, scan_id: parseInt(form.scan_id) })
      const newReport = res.data.report
      setReports(r => [newReport, ...r])
      setShowModal(false)
      toast.success('Report generated!')
      handleDownload(newReport.id, newReport.format)
    } catch (err) {
      toast.error(err.response?.data?.error || 'Generation failed')
    } finally { setGenerating(false) }
  }

  const handleDownload = async (id, fmt) => {
    try {
      const blob = (await reportsAPI.download(id)).data
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `vulnscanner_report_${id}.${fmt}`
      a.click()
      URL.revokeObjectURL(url)
      toast.success('Download started')
    } catch { toast.error('Download failed') }
  }

  const handleDelete = async (id) => {
    try {
      await reportsAPI.delete(id)
      setReports(r => r.filter(x => x.id !== id))
      toast.success('Report deleted')
    } catch { toast.error('Delete failed') }
  }

  const FORMAT_COLORS = { html: '#3b82f6', pdf: '#ef4444', json: '#22c55e' }

  return (
    <div className="p-6 max-w-5xl mx-auto animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold" style={{ color: '#e2e8f0' }}>Reports</h1>
          <p className="text-sm mt-0.5" style={{ color: '#6b7280' }}>{reports.length} generated reports</p>
        </div>
        <button onClick={() => setShowModal(true)} className="btn-primary flex items-center gap-2">
          <Plus size={16} /> Generate Report
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : reports.length === 0 ? (
        <div className="text-center py-20">
          <FileText size={40} className="mx-auto mb-4" style={{ color: '#2a3a5c' }} />
          <p style={{ color: '#4a5568' }}>No reports yet.</p>
          <button onClick={() => setShowModal(true)} className="btn-primary mt-4">Generate your first report</button>
        </div>
      ) : (
        <div className="space-y-3">
          {reports.map(r => (
            <div key={r.id} className="card p-4 flex items-center gap-4">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0"
                style={{ background: `${FORMAT_COLORS[r.format] || '#6b7280'}15`, border: `1px solid ${FORMAT_COLORS[r.format] || '#6b7280'}30` }}>
                <FileText size={18} style={{ color: FORMAT_COLORS[r.format] || '#6b7280' }} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm" style={{ color: '#e2e8f0' }}>{r.title}</p>
                <div className="flex items-center gap-3 mt-0.5 text-xs" style={{ color: '#4a5568' }}>
                  <span>{r.apk_name}</span>
                  {r.risk_score !== undefined && <span>Risk: {r.risk_score}</span>}
                  <span>{r.created_at ? new Date(r.created_at).toLocaleString() : ''}</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold px-2 py-0.5 rounded uppercase"
                  style={{ background: `${FORMAT_COLORS[r.format]}20`, color: FORMAT_COLORS[r.format], border: `1px solid ${FORMAT_COLORS[r.format]}40` }}>
                  {r.format}
                </span>
                <button onClick={() => handleDownload(r.id, r.format)}
                  className="w-8 h-8 rounded-lg flex items-center justify-center transition-all hover:bg-white/10"
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6b7280' }}>
                  <Download size={14} />
                </button>
                <button onClick={() => handleDelete(r.id)}
                  className="w-8 h-8 rounded-lg flex items-center justify-center transition-all hover:bg-red-900/30"
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4a5568' }}>
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" style={{ background: 'rgba(0,0,0,0.7)' }}>
          <div className="w-full max-w-md rounded-2xl p-6 animate-fade-in" style={{ background: '#0d1220', border: '1px solid #1e2d4a' }}>
            <div className="flex items-center justify-between mb-5">
              <h2 className="font-bold" style={{ color: '#e2e8f0' }}>Generate Report</h2>
              <button onClick={() => setShowModal(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6b7280' }}>
                <X size={18} />
              </button>
            </div>
            <form onSubmit={handleGenerate} className="space-y-4">
              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: '#8899aa' }}>Select Scan</label>
                <select value={form.scan_id} onChange={e => setForm(f => ({ ...f, scan_id: e.target.value }))} className="input-field" required>
                  <option value="">Choose a completed scan...</option>
                  {scans.map(s => <option key={s.id} value={s.id}>{s.apk_name} (Risk: {s.risk_score})</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: '#8899aa' }}>Report Type</label>
                <div className="grid grid-cols-3 gap-2">
                  {['full','executive','compliance'].map(t => (
                    <button key={t} type="button" onClick={() => setForm(f => ({ ...f, report_type: t }))}
                      className="py-2 rounded-lg text-xs font-medium capitalize transition-all"
                      style={form.report_type === t
                        ? { background: '#7c3aed', color: 'white', border: 'none', cursor: 'pointer' }
                        : { background: '#111827', color: '#6b7280', border: '1px solid #1e2d4a', cursor: 'pointer' }}>
                      {t}
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium mb-1.5" style={{ color: '#8899aa' }}>Format</label>
                <div className="grid grid-cols-3 gap-2">
                  {[['html','HTML'],['json','JSON']].map(([val, label]) => (
                    <button key={val} type="button" onClick={() => setForm(f => ({ ...f, format: val }))}
                      className="py-2 rounded-lg text-xs font-bold uppercase transition-all"
                      style={form.format === val
                        ? { background: `${FORMAT_COLORS[val]}20`, color: FORMAT_COLORS[val], border: `1px solid ${FORMAT_COLORS[val]}40`, cursor: 'pointer' }
                        : { background: '#111827', color: '#6b7280', border: '1px solid #1e2d4a', cursor: 'pointer' }}>
                      {label}
                    </button>
                  ))}
                </div>
              </div>
              <button type="submit" disabled={generating} className="btn-primary w-full py-2.5 flex items-center justify-center gap-2">
                {generating && <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
                {generating ? 'Generating...' : 'Generate & Download'}
              </button>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
