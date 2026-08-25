import { useState } from 'react'
import { useAuth } from '../utils/AuthContext'
import { User, Bell, Shield, Key, Moon, Save } from 'lucide-react'
import toast from 'react-hot-toast'

export default function SettingsPage() {
  const { user } = useAuth()
  const [prefs, setPrefs] = useState({
    darkMode: true,
    emailReports: false,
    autoScan: false,
    notifyCritical: true,
    notifyHigh: true,
    notifyMedium: false,
    notifyLow: false,
    reportFrequency: 'weekly'
  })

  const save = () => toast.success('Settings saved')

  return (
    <div className="p-6 max-w-3xl mx-auto animate-fade-in">
      <div className="mb-6">
        <h1 className="text-xl font-bold" style={{ color: '#e2e8f0' }}>Settings</h1>
        <p className="text-sm mt-0.5" style={{ color: '#6b7280' }}>Manage your account and preferences</p>
      </div>

      <div className="space-y-4">
        <Section icon={<User size={16} />} title="Profile">
          <div className="flex items-center gap-4 mb-4">
            <div className="w-14 h-14 rounded-full flex items-center justify-center text-xl font-bold"
              style={{ background: 'rgba(124,58,237,0.2)', color: '#a78bfa', border: '1px solid rgba(124,58,237,0.3)' }}>
              {user?.username?.[0]?.toUpperCase()}
            </div>
            <div>
              <p className="font-semibold" style={{ color: '#e2e8f0' }}>{user?.username}</p>
              <p className="text-sm" style={{ color: '#6b7280' }}>{user?.email}</p>
              <span className="text-xs px-2 py-0.5 rounded mt-1 inline-block" style={{ background: 'rgba(124,58,237,0.1)', color: '#a78bfa' }}>{user?.role}</span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: '#8899aa' }}>Display Name</label>
              <input className="input-field" defaultValue={user?.username} />
            </div>
            <div>
              <label className="block text-xs font-medium mb-1.5" style={{ color: '#8899aa' }}>Email</label>
              <input className="input-field" defaultValue={user?.email} type="email" />
            </div>
          </div>
        </Section>

        <Section icon={<Moon size={16} />} title="Preferences">
          <div className="space-y-3">
            <Toggle label="Dark Mode" desc="Use dark theme (recommended for security professionals)" value={prefs.darkMode} onChange={v => setPrefs(p => ({ ...p, darkMode: v }))} />
            <Toggle label="Email Reports" desc="Receive scan reports via email" value={prefs.emailReports} onChange={v => setPrefs(p => ({ ...p, emailReports: v }))} />
            <Toggle label="Auto-scan on Upload" desc="Automatically start scan when APK is uploaded" value={prefs.autoScan} onChange={v => setPrefs(p => ({ ...p, autoScan: v }))} />
          </div>
        </Section>

        <Section icon={<Bell size={16} />} title="Alert Thresholds">
          <p className="text-xs mb-3" style={{ color: '#4a5568' }}>Get notified when vulnerabilities of selected severity are found</p>
          <div className="space-y-2">
            {[
              { key: 'notifyCritical', label: 'Critical vulnerabilities', color: '#ef4444' },
              { key: 'notifyHigh',     label: 'High vulnerabilities',     color: '#f97316' },
              { key: 'notifyMedium',   label: 'Medium vulnerabilities',   color: '#eab308' },
              { key: 'notifyLow',      label: 'Low vulnerabilities',      color: '#22c55e' },
            ].map(({ key, label, color }) => (
              <div key={key} className="flex items-center justify-between p-2.5 rounded-lg" style={{ background: '#080c16', border: '1px solid #1e2d4a' }}>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full" style={{ background: color }} />
                  <span className="text-sm" style={{ color: '#94a3b8' }}>{label}</span>
                </div>
                <ToggleSwitch value={prefs[key]} onChange={v => setPrefs(p => ({ ...p, [key]: v }))} />
              </div>
            ))}
          </div>
        </Section>

        <Section icon={<Key size={16} />} title="API Access">
          <p className="text-xs mb-3" style={{ color: '#4a5568' }}>Use the API key to integrate VulnScanner with CI/CD pipelines</p>
          <div className="flex gap-2">
            <input
              className="input-field font-mono text-xs"
              value="vs_live_••••••••••••••••••••••••••••••••"
              readOnly
            />
            <button onClick={() => toast.success('API key copied')} className="btn-secondary flex-shrink-0 text-xs px-4">Copy</button>
            <button onClick={() => toast.success('API key regenerated')} className="btn-secondary flex-shrink-0 text-xs px-4" style={{ borderColor: 'rgba(239,68,68,0.3)', color: '#ef4444' }}>Regenerate</button>
          </div>
        </Section>

        <Section icon={<Shield size={16} />} title="Danger Zone">
          <div className="p-4 rounded-lg" style={{ border: '1px solid rgba(239,68,68,0.2)', background: 'rgba(239,68,68,0.03)' }}>
            <p className="text-sm font-medium mb-1" style={{ color: '#ef4444' }}>Delete Account</p>
            <p className="text-xs mb-3" style={{ color: '#4a5568' }}>This will permanently delete your account and all scan data. This action cannot be undone.</p>
            <button
              onClick={() => toast.error('Account deletion requires email confirmation')}
              className="text-xs px-4 py-2 rounded-lg transition-all hover:bg-red-900/30"
              style={{ background: 'transparent', color: '#ef4444', border: '1px solid rgba(239,68,68,0.3)', cursor: 'pointer' }}>
              Delete Account
            </button>
          </div>
        </Section>

        <button onClick={save} className="btn-primary flex items-center gap-2 px-6">
          <Save size={15} /> Save Changes
        </button>
      </div>
    </div>
  )
}

function Section({ icon, title, children }) {
  return (
    <div className="card p-5">
      <div className="flex items-center gap-2 mb-4 pb-3" style={{ borderBottom: '1px solid #1e2d4a' }}>
        <span style={{ color: '#7c3aed' }}>{icon}</span>
        <h2 className="font-semibold text-sm" style={{ color: '#94a3b8' }}>{title}</h2>
      </div>
      {children}
    </div>
  )
}

function Toggle({ label, desc, value, onChange }) {
  return (
    <div className="flex items-start justify-between gap-4 p-3 rounded-lg" style={{ background: '#080c16', border: '1px solid #1e2d4a' }}>
      <div>
        <p className="text-sm font-medium" style={{ color: '#e2e8f0' }}>{label}</p>
        {desc && <p className="text-xs mt-0.5" style={{ color: '#4a5568' }}>{desc}</p>}
      </div>
      <ToggleSwitch value={value} onChange={onChange} />
    </div>
  )
}

function ToggleSwitch({ value, onChange }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!value)}
      className="flex-shrink-0 w-10 h-5 rounded-full relative transition-all"
      style={{ background: value ? '#7c3aed' : '#1e2d4a', border: 'none', cursor: 'pointer' }}>
      <div className="absolute top-0.5 w-4 h-4 rounded-full transition-all" style={{ background: 'white', left: value ? '22px' : '2px' }} />
    </button>
  )
}
