import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { scansAPI } from '../utils/api'
import { Plus, Trash2, ChevronRight, Clock, CheckCircle, XCircle, Loader, Search } from 'lucide-react'
import toast from 'react-hot-toast'

const STATUS_CONFIG = {
  completed: { icon: CheckCircle, color: '#22c55e', label: 'Completed' },
  running:   { icon: Loader,       color: '#3b82f6', label: 'Running',   anim: true },
  pending:   { icon: Clock,        color: '#eab308', label: 'Pending' },
  failed:    { icon: XCircle,      color: '#ef4444', label: 'Failed' }
}

export default function ScansPage() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('all')
  const navigate = useNavigate()

  useEffect(() => { load() }, [])

  const load = () => {
    setLoading(true)
    scansAPI.list({ per_page: 50 })
      .then(res => setScans(res.data.scans || []))
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  const handleDelete = async (e, id) => {
    e.stopPropagation()
    if (!confirm('Delete this scan and all its findings?')) return
    try {
      await scansAPI.delete(id)
      setScans(s => s.filter(x => x.id !== id))
      toast.success('Scan deleted')
    } catch { toast.error('Delete failed') }
  }

  const filtered = scans.filter(s => {
    const matchSearch = !search || s.apk_name?.toLowerCase().includes(search.toLowerCase()) || s.package_name?.toLowerCase().includes(search.toLowerCase())
    const matchFilter = filter === 'all' || s.status === filter
    return matchSearch && matchFilter
  })

  return (
    <div className="p-6 max-w-6xl mx-auto animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold" style={{ color: '#e2e8f0' }}>Scans</h1>
          <p className="text-sm mt-0.5" style={{ color: '#6b7280' }}>{scans.length} total scans</p>
        </div>
        <button onClick={() => navigate('/scans/new')} className="btn-primary flex items-center gap-2">
          <Plus size={16} /> New Scan
        </button>
      </div>

      <div className="flex items-center gap-3 mb-5">
        <div className="relative flex-1 max-w-xs">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#4a5568' }} />
          <input
            className="input-field pl-9"
            placeholder="Search scans..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-1 p-1 rounded-lg" style={{ background: '#0d1220', border: '1px solid #1e2d4a' }}>
          {['all','completed','running','failed'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className="px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-all"
              style={filter === f
                ? { background: '#7c3aed', color: 'white' }
                : { color: '#6b7280', background: 'none', border: 'none', cursor: 'pointer' }
              }
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-20">
          <p style={{ color: '#4a5568' }}>No scans found.</p>
          <button onClick={() => navigate('/scans/new')} className="btn-primary mt-4">Upload your first APK</button>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map(scan => <ScanRow key={scan.id} scan={scan} onDelete={handleDelete} onClick={() => navigate(`/scans/${scan.id}`)} />)}
        </div>
      )}
    </div>
  )
}

function ScanRow({ scan, onDelete, onClick }) {
  const cfg = STATUS_CONFIG[scan.status] || STATUS_CONFIG.pending
  const Icon = cfg.icon

  return (
    <div
      onClick={onClick}
      className="card p-4 flex items-center gap-4 cursor-pointer transition-all hover:border-purple-700/40 hover:bg-white/[0.02]"
    >
      <div className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0" style={{ background: `${cfg.color}15`, border: `1px solid ${cfg.color}30` }}>
        <Icon size={17} style={{ color: cfg.color }} className={cfg.anim ? 'animate-spin' : ''} />
      </div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="font-medium truncate" style={{ color: '#e2e8f0', fontSize: '0.9rem' }}>{scan.apk_name}</span>
          {scan.version_name && <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: '#1e2d4a', color: '#6b7280' }}>v{scan.version_name}</span>}
        </div>
        <div className="flex items-center gap-3 mt-0.5">
          <span className="text-xs" style={{ color: '#4a5568' }}>{scan.package_name || 'Unknown package'}</span>
          <span className="text-xs" style={{ color: '#374151' }}>
            {scan.created_at ? new Date(scan.created_at).toLocaleString() : ''}
          </span>
        </div>
      </div>

      {scan.status === 'completed' && (
        <div className="flex items-center gap-2">
          {[
            { count: scan.critical_count, color: '#ef4444' },
            { count: scan.high_count, color: '#f97316' },
            { count: scan.medium_count, color: '#eab308' },
            { count: scan.low_count, color: '#22c55e' }
          ].filter(x => x.count > 0).map(({ count, color }, i) => (
            <span key={i} className="text-xs font-semibold px-2 py-0.5 rounded" style={{ background: `${color}18`, color, border: `1px solid ${color}30` }}>
              {count}
            </span>
          ))}
        </div>
      )}

      {scan.status === 'completed' && (
        <div className="text-center w-14">
          <div className="text-lg font-bold" style={{ color: scan.risk_score >= 70 ? '#ef4444' : scan.risk_score >= 40 ? '#f97316' : '#eab308' }}>
            {scan.risk_score}
          </div>
          <div className="text-xs" style={{ color: '#4a5568' }}>risk</div>
        </div>
      )}

      {scan.status === 'running' && (
        <div className="w-28">
          <div className="h-1.5 rounded-full overflow-hidden" style={{ background: '#1e2d4a' }}>
            <div className="h-full rounded-full" style={{ background: '#3b82f6', width: `${scan.progress || 0}%`, transition: 'width 0.5s' }} />
          </div>
          <p className="text-xs mt-0.5 text-right" style={{ color: '#4a5568' }}>{scan.progress || 0}%</p>
        </div>
      )}

      <div className="flex items-center gap-2">
        <button
        onClick={e => onDelete(e, scan.id)}
        className="w-8 h-8 rounded-lg flex items-center justify-center transition-all hover:bg-red-900/30"
        style={{ color: '#4a5568', background: 'none', border: 'none', cursor: 'pointer' }}
      >
          <Trash2 size={14} />
        </button>
        <ChevronRight size={16} style={{ color: '#374151' }} />
      </div>
    </div>
  )
}
