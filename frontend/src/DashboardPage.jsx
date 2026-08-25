import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { dashboardAPI } from '../utils/api'
import { Shield, TrendingUp, Scan, AlertTriangle, ChevronRight, Plus } from 'lucide-react'
import { AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import SeverityBadge from '../components/SeverityBadge'
import RiskGauge from '../components/RiskGauge'

const CATEGORY_COLORS = ['#7c3aed', '#3b82f6', '#06b6d4', '#10b981', '#eab308', '#f97316', '#ef4444']

export default function DashboardPage() {
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    dashboardAPI.stats()
      .then(res => setStats(res.data))
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return (
    <div className="flex items-center justify-center h-full">
      <div className="w-8 h-8 border-2 border-purple-500 border-t-transparent rounded-full animate-spin" />
    </div>
  )

  const { severity_breakdown, category_breakdown, trend_data, recent_scans, overall_risk_score, total_scans } = stats || {}

  const pieData = severity_breakdown ? [
    { name: 'Critical', value: severity_breakdown.critical, color: '#ef4444' },
    { name: 'High', value: severity_breakdown.high, color: '#f97316' },
    { name: 'Medium', value: severity_breakdown.medium, color: '#eab308' },
    { name: 'Low', value: severity_breakdown.low, color: '#22c55e' }
  ].filter(d => d.value > 0) : []

  const totalVulns = pieData.reduce((s, d) => s + d.value, 0)

  return (
    <div className="p-6 max-w-7xl mx-auto animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-bold" style={{ color: '#e2e8f0' }}>Security Dashboard</h1>
          <p className="text-sm mt-0.5" style={{ color: '#6b7280' }}>Overview of your Android app security posture</p>
        </div>
        <button onClick={() => navigate('/scans/new')} className="btn-primary flex items-center gap-2">
          <Plus size={16} /> New Scan
        </button>
      </div>

      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'Total Scans', value: total_scans || 0, icon: Scan, color: '#7c3aed', bg: 'rgba(124,58,237,0.1)' },
          { label: 'Critical Issues', value: severity_breakdown?.critical || 0, icon: AlertTriangle, color: '#ef4444', bg: 'rgba(239,68,68,0.1)' },
          { label: 'High Issues', value: severity_breakdown?.high || 0, icon: Shield, color: '#f97316', bg: 'rgba(249,115,22,0.1)' },
          { label: 'Risk Score', value: `${overall_risk_score || 0}/100`, icon: TrendingUp, color: '#3b82f6', bg: 'rgba(59,130,246,0.1)' }
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="card p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: bg }}>
                <Icon size={20} style={{ color }} />
              </div>
              <div>
                <p className="text-xs" style={{ color: '#6b7280' }}>{label}</p>
                <p className="text-xl font-bold" style={{ color: '#e2e8f0' }}>{value}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-4" style={{ color: '#94a3b8' }}>Overall Risk Score</h3>
          <RiskGauge score={overall_risk_score || 0} />
          <div className="grid grid-cols-2 gap-2 mt-4">
            {pieData.map(({ name, value, color }) => (
              <div key={name} className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color }} />
                <span className="text-xs" style={{ color: '#8899aa' }}>{name}:</span>
                <span className="text-xs font-semibold" style={{ color }}>{value}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-1" style={{ color: '#94a3b8' }}>Severity Distribution</h3>
          <p className="text-xs mb-3" style={{ color: '#4a5568' }}>{totalVulns} total vulnerabilities</p>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <PieChart>
                <Pie data={pieData} dataKey="value" innerRadius={50} outerRadius={70} paddingAngle={3}>
                  {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip formatter={(v, n) => [v, n]} contentStyle={{ background: '#0d1220', border: '1px solid #1e2d4a', borderRadius: '8px', color: '#e2e8f0', fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-40 flex items-center justify-center" style={{ color: '#4a5568' }}>
              <p className="text-sm">No vulnerabilities found</p>
            </div>
          )}
        </div>

        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-3" style={{ color: '#94a3b8' }}>Top Categories</h3>
          <div className="space-y-2">
            {(category_breakdown || []).slice(0, 6).map(({ category, count }, i) => (
              <div key={category} className="flex items-center gap-2">
                <span className="text-xs w-24 truncate" style={{ color: '#8899aa' }}>{category}</span>
                <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: '#1e2d4a' }}>
                  <div className="h-full rounded-full" style={{
                    background: CATEGORY_COLORS[i % CATEGORY_COLORS.length],
                    width: `${Math.min(100, (count / (category_breakdown[0]?.count || 1)) * 100)}%`
                  }} />
                </div>
                <span className="text-xs font-semibold w-4 text-right" style={{ color: '#e2e8f0' }}>{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="card p-5">
          <h3 className="text-sm font-semibold mb-4" style={{ color: '#94a3b8' }}>Risk Score Trend</h3>
          {(trend_data || []).length > 0 ? (
            <ResponsiveContainer width="100%" height={160}>
              <AreaChart data={trend_data}>
                <defs>
                  <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#7c3aed" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#7c3aed" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" tick={{ fill: '#4a5568', fontSize: 11 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: '#4a5568', fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: '#0d1220', border: '1px solid #1e2d4a', borderRadius: '8px', color: '#e2e8f0', fontSize: '12px' }} />
                <Area type="monotone" dataKey="risk_score" stroke="#7c3aed" fill="url(#riskGrad)" strokeWidth={2} dot={{ fill: '#7c3aed', r: 3 }} />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-40 flex items-center justify-center" style={{ color: '#4a5568' }}>
              <p className="text-sm">Run scans to see trend data</p>
            </div>
          )}
        </div>

        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold" style={{ color: '#94a3b8' }}>Recent Scans</h3>
            <button onClick={() => navigate('/scans')} className="text-xs flex items-center gap-1 hover:opacity-80" style={{ color: '#7c3aed' }}>
              View all <ChevronRight size={13} />
            </button>
          </div>
          <div className="space-y-2">
            {(recent_scans || []).map(scan => (
              <button
                key={scan.id}
                onClick={() => navigate(`/scans/${scan.id}`)}
                className="w-full text-left p-3 rounded-lg transition-all hover:bg-white/5"
                style={{ border: '1px solid #1e2d4a' }}
              >
                <div className="flex items-center justify-between">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate" style={{ color: '#e2e8f0' }}>{scan.apk_name}</p>
                    <div className="flex items-center gap-2 mt-0.5">
                      <span className="text-xs" style={{ color: '#4a5568' }}>
                        {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : ''}
                      </span>
                      {scan.total_findings > 0 && (
                        <span className="text-xs" style={{ color: '#6b7280' }}>
                          {scan.total_findings} findings
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <RiskPill score={scan.risk_score} />
                    <ChevronRight size={14} style={{ color: '#4a5568' }} />
                  </div>
                </div>
                <div className="flex gap-1.5 mt-2">
                  {scan.critical_count > 0 && <SeverityDot count={scan.critical_count} color="#ef4444" />}
                  {scan.high_count > 0 && <SeverityDot count={scan.high_count} color="#f97316" />}
                  {scan.medium_count > 0 && <SeverityDot count={scan.medium_count} color="#eab308" />}
                  {scan.low_count > 0 && <SeverityDot count={scan.low_count} color="#22c55e" />}
                </div>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function RiskPill({ score }) {
  const color = score >= 70 ? '#ef4444' : score >= 40 ? '#f97316' : score >= 20 ? '#eab308' : '#22c55e'
  return (
    <span className="text-xs font-bold px-2 py-0.5 rounded" style={{ background: `${color}20`, color, border: `1px solid ${color}40` }}>
      {score}
    </span>
  )
}

function SeverityDot({ count, color }) {
  return (
    <span className="flex items-center gap-1 text-xs px-1.5 py-0.5 rounded" style={{ background: `${color}15`, color }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: color }} />
      {count}
    </span>
  )
}
