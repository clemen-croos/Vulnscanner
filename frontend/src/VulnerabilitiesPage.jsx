import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { vulnsAPI } from '../utils/api'
import { Search, Filter, ChevronRight } from 'lucide-react'
import SeverityBadge from '../components/SeverityBadge'

export default function VulnerabilitiesPage() {
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('all')
  const [category, setCategory] = useState('all')
  const [categories, setCategories] = useState([])
  const navigate = useNavigate()

  useEffect(() => {
    vulnsAPI.categories().then(r => setCategories(r.data.categories || []))
    load()
  }, [])

  useEffect(() => { load() }, [severity, category, search])

  const load = () => {
    setLoading(true)
    const params = { per_page: 100 }
    if (severity !== 'all') params.severity = severity
    if (category !== 'all') params.category = category
    if (search) params.search = search
    vulnsAPI.list(params)
      .then(r => setVulns(r.data.vulnerabilities || []))
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  return (
    <div className="p-6 max-w-6xl mx-auto animate-fade-in">
      <div className="mb-6">
        <h1 className="text-xl font-bold" style={{ color: '#e2e8f0' }}>Vulnerabilities</h1>
        <p className="text-sm mt-0.5" style={{ color: '#6b7280' }}>{vulns.length} vulnerabilities across all scans</p>
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-5">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#4a5568' }} />
          <input
            className="input-field pl-9 w-56"
            placeholder="Search vulnerabilities..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        <div className="flex gap-1 p-1 rounded-lg" style={{ background: '#0d1220', border: '1px solid #1e2d4a' }}>
          {['all','critical','high','medium','low'].map(s => (
            <button key={s} onClick={() => setSeverity(s)}
              className="px-3 py-1.5 rounded-md text-xs font-medium capitalize transition-all"
              style={severity === s
                ? { background: '#7c3aed', color: 'white', border: 'none', cursor: 'pointer' }
                : { color: '#6b7280', background: 'none', border: 'none', cursor: 'pointer' }}>
              {s}
            </button>
          ))}
        </div>

        {categories.length > 0 && (
          <select
            value={category}
            onChange={e => setCategory(e.target.value)}
            className="input-field w-40"
            style={{ paddingTop: '8px', paddingBottom: '8px' }}
          >
            <option value="all">All categories</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        )}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-20">
          <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : vulns.length === 0 ? (
        <div className="text-center py-20" style={{ color: '#4a5568' }}>
          <p>No vulnerabilities found.</p>
          <p className="text-sm mt-2">Run a scan to start finding security issues.</p>
        </div>
      ) : (
        <div className="card divide-y" style={{ borderColor: '#1e2d4a' }}>
          {vulns.map(v => (
            <div
              key={v.id}
              onClick={() => navigate(`/vulnerabilities/${v.id}`)}
              className="flex items-center gap-3 p-4 cursor-pointer transition-all hover:bg-white/[0.02]"
            >
              <SeverityBadge severity={v.severity} />
              <div className="flex-1 min-w-0">
                <p className="font-medium text-sm" style={{ color: '#e2e8f0' }}>{v.title}</p>
                <p className="text-xs mt-0.5 truncate" style={{ color: '#4a5568' }}>{v.location}</p>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                <span className="text-xs px-2 py-0.5 rounded" style={{ background: '#1e2d4a', color: '#6b7280' }}>{v.category}</span>
                {v.cvss_score && <span className="text-xs font-mono" style={{ color: '#4a5568' }}>CVSS {v.cvss_score}</span>}
                {v.poc_command && <span className="text-xs px-2 py-0.5 rounded" style={{ background: 'rgba(59,130,246,0.1)', color: '#3b82f6', border: '1px solid rgba(59,130,246,0.2)' }}>PoC</span>}
              </div>
              <ChevronRight size={15} style={{ color: '#374151' }} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
