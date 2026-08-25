import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import { AuthProvider, useAuth } from './utils/AuthContext'
import Layout from './components/Layout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import ScansPage from './pages/ScansPage'
import ScanDetailPage from './pages/ScanDetailPage'
import VulnerabilitiesPage from './pages/VulnerabilitiesPage'
import VulnerabilityDetailPage from './pages/VulnerabilityDetailPage'
import NewScanPage from './pages/NewScanPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'
import AnalysisResultsPage from './pages/AnalysisResultsPage'

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return (
    <div className="flex items-center justify-center h-screen" style={{ background: '#080c16' }}>
      <div className="text-center">
        <div className="w-12 h-12 border-2 border-purple-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
        <p style={{ color: '#8899aa' }}>Loading VulnScanner...</p>
      </div>
    </div>
  )
  return user ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster
          position="top-right"
          toastOptions={{
            style: { background: '#161d30', color: '#e2e8f0', border: '1px solid #1e2d4a' },
            success: { iconTheme: { primary: '#22c55e', secondary: '#0d1220' } },
            error: { iconTheme: { primary: '#ef4444', secondary: '#0d1220' } }
          }}
        />
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<DashboardPage />} />
            <Route path="scans" element={<ScansPage />} />
            <Route path="scans/new" element={<NewScanPage />} />
            <Route path="scans/:id" element={<ScanDetailPage />} />
            <Route path="scans/:id/static-results" element={<AnalysisResultsPage analysisType="static" />} />
            <Route path="scans/:id/dynamic-results" element={<AnalysisResultsPage analysisType="dynamic" />} />
            <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="vulnerabilities/:id" element={<VulnerabilityDetailPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}
