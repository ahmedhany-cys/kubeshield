import type { ReactNode } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Loading } from './components/Loading'
import { AuthProvider, useAuth } from './hooks/useAuth'
import ClusterPage from './pages/Cluster'
import IncidentDetailPage from './pages/IncidentDetail'
import IncidentsPage from './pages/Incidents'
import LoginPage from './pages/Login'
import MitrePage from './pages/Mitre'
import NetworkPage from './pages/Network'
import NotFoundPage from './pages/NotFound'
import OverviewPage from './pages/Overview'
import PoliciesPage from './pages/Policies'
import ResponsesPage from './pages/Responses'
import SettingsPage from './pages/Settings'
import SimulationsPage from './pages/Simulations'
import ThreatsPage from './pages/Threats'
import VulnerabilitiesPage from './pages/Vulnerabilities'

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, checking } = useAuth()
  const location = useLocation()
  if (checking) return <Loading label="Checking session…" className="h-full" />
  if (!user) {
    const next = location.pathname + location.search
    return <Navigate to={`/login${next && next !== '/' ? `?next=${encodeURIComponent(next)}` : ''}`} replace />
  }
  return <>{children}</>
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<OverviewPage />} />
          <Route path="threats" element={<ThreatsPage />} />
          <Route path="cluster" element={<ClusterPage />} />
          <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="network" element={<NetworkPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="incidents/:id" element={<IncidentDetailPage />} />
          <Route path="simulations" element={<SimulationsPage />} />
          <Route path="mitre" element={<MitrePage />} />
          <Route path="responses" element={<ResponsesPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </AuthProvider>
  )
}
