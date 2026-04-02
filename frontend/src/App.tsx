import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { ThemeProvider } from './contexts/ThemeContext'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import AlertDetail from './pages/AlertDetail'
import Incidents from './pages/Incidents'
import IncidentDetail from './pages/IncidentDetail'
import IOCs from './pages/IOCs'
import Users from './pages/Users'
import Playbooks from './pages/Playbooks'
import Assets from './pages/Assets'
import Settings from './pages/Settings'
import AuditLogs from './pages/AuditLogs'
import Profile from './pages/Profile'
import Reports from './pages/Reports'
import ApiKeys from './pages/ApiKeys'
import Analytics from './pages/Analytics'
import Organizations from './pages/Organizations'
import ThreatIntel from './pages/ThreatIntel'
import SIEMDashboard from './pages/SIEMDashboard'
import ThreatHunting from './pages/ThreatHunting'
import ExposureManagement from './pages/ExposureManagement'
import AIEngine from './pages/AIEngine'
import UEBADashboard from './pages/UEBADashboard'
import AttackSimulation from './pages/AttackSimulation'
import DeceptionTech from './pages/DeceptionTech'
import Remediation from './pages/Remediation'
import ComplianceDashboard from './pages/ComplianceDashboard'
import ZeroTrustDashboard from './pages/ZeroTrustDashboard'
import STIGCompliance from './pages/STIGCompliance'
import AuditEvidence from './pages/AuditEvidence'
import DFIRDashboard from './pages/DFIRDashboard'
import ITDRDashboard from './pages/ITDRDashboard'
import VulnManagement from './pages/VulnManagement'
import SupplyChainDashboard from './pages/SupplyChainDashboard'
import DarkWebMonitor from './pages/DarkWebMonitor'
import IntegrationMarketplace from './pages/IntegrationMarketplace'
import AgenticSOC from './pages/AgenticSOC'
import PlaybookBuilder from './pages/PlaybookBuilder'
import DLPDashboard from './pages/DLPDashboard'
import RiskQuantification from './pages/RiskQuantification'
import OTSecurityDashboard from './pages/OTSecurityDashboard'
import ContainerSecurity from './pages/ContainerSecurity'
import PrivacyDashboard from './pages/PrivacyDashboard'
import ThreatModeling from './pages/ThreatModeling'
import APISecurityDashboard from './pages/APISecurityDashboard'
import DataLakeDashboard from './pages/DataLakeDashboard'
import WarRoom from './pages/WarRoom'
import PhishingSimulation from './pages/PhishingSimulation'
import TicketHub from './pages/TicketHub'
import FedRAMP from './pages/FedRAMP'
import NotFound from './pages/NotFound'

import React from 'react'

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props)
    this.state = { hasError: false, error: null }
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error }
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 40, fontFamily: 'monospace', color: '#c00' }}>
          <h1>Application Error</h1>
          <pre>{this.state.error?.message}</pre>
          <pre>{this.state.error?.stack}</pre>
        </div>
      )
    }
    return this.props.children
  }
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
    },
  },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  if (isAuthenticated) {
    return <Navigate to="/" replace />
  }

  return <>{children}</>
}

function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <PublicRoute>
            <Login />
          </PublicRoute>
        }
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="alerts/:id" element={<AlertDetail />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="incidents/:id" element={<IncidentDetail />} />
        <Route path="iocs" element={<IOCs />} />
        <Route path="playbooks" element={<Playbooks />} />
        <Route path="assets" element={<Assets />} />
        <Route path="users" element={<Users />} />
        <Route path="settings" element={<Settings />} />
        <Route path="audit" element={<AuditLogs />} />
        <Route path="profile" element={<Profile />} />
        <Route path="reports" element={<Reports />} />
        <Route path="api-keys" element={<ApiKeys />} />
        <Route path="analytics" element={<Analytics />} />
        <Route path="organizations" element={<Organizations />} />
        <Route path="threat-intel" element={<ThreatIntel />} />
        <Route path="siem" element={<SIEMDashboard />} />
        <Route path="hunting" element={<ThreatHunting />} />
        <Route path="exposure" element={<ExposureManagement />} />
        <Route path="ai" element={<AIEngine />} />
        <Route path="ueba" element={<UEBADashboard />} />
        <Route path="simulation" element={<AttackSimulation />} />
        <Route path="deception" element={<DeceptionTech />} />
        <Route path="remediation" element={<Remediation />} />
        <Route path="compliance" element={<ComplianceDashboard />} />
        <Route path="zerotrust" element={<ZeroTrustDashboard />} />
        <Route path="stig" element={<STIGCompliance />} />
        <Route path="audit-evidence" element={<AuditEvidence />} />
        <Route path="dfir" element={<DFIRDashboard />} />
        <Route path="itdr" element={<ITDRDashboard />} />
        <Route path="vulnmgmt" element={<VulnManagement />} />
        <Route path="supplychain" element={<SupplyChainDashboard />} />
        <Route path="darkweb" element={<DarkWebMonitor />} />
        <Route path="integrations" element={<IntegrationMarketplace />} />
        <Route path="agentic" element={<AgenticSOC />} />
        <Route path="playbook-builder" element={<PlaybookBuilder />} />
        <Route path="dlp" element={<DLPDashboard />} />
        <Route path="risk" element={<RiskQuantification />} />
        <Route path="ot-security" element={<OTSecurityDashboard />} />
        <Route path="container-security" element={<ContainerSecurity />} />
        <Route path="privacy" element={<PrivacyDashboard />} />
        <Route path="threat-modeling" element={<ThreatModeling />} />
        <Route path="api-security" element={<APISecurityDashboard />} />
        <Route path="data-lake" element={<DataLakeDashboard />} />
        <Route path="warroom" element={<WarRoom />} />
        <Route path="phishing" element={<PhishingSimulation />} />
        <Route path="ticket-hub" element={<TicketHub />} />
        <Route path="fedramp" element={<FedRAMP />} />
      </Route>
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <BrowserRouter>
            <AuthProvider>
              <AppRoutes />
            </AuthProvider>
          </BrowserRouter>
        </ThemeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}

export default App
