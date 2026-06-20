import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React, { Suspense } from 'react'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { ThemeProvider } from './contexts/ThemeContext'
import Layout from './components/Layout'

const Login = React.lazy(() => import('./pages/Login'))
const Dashboard = React.lazy(() => import('./pages/Dashboard'))
const Alerts = React.lazy(() => import('./pages/Alerts'))
const AlertDetail = React.lazy(() => import('./pages/AlertDetail'))
const Incidents = React.lazy(() => import('./pages/Incidents'))
const IncidentDetail = React.lazy(() => import('./pages/IncidentDetail'))
const Users = React.lazy(() => import('./pages/Users'))
const Playbooks = React.lazy(() => import('./pages/Playbooks'))
const Assets = React.lazy(() => import('./pages/Assets'))
const Settings = React.lazy(() => import('./pages/Settings'))
const AuditLogs = React.lazy(() => import('./pages/AuditLogs'))
const Profile = React.lazy(() => import('./pages/Profile'))
const Reports = React.lazy(() => import('./pages/Reports'))
const ApiKeys = React.lazy(() => import('./pages/ApiKeys'))
const Analytics = React.lazy(() => import('./pages/Analytics'))
const Organizations = React.lazy(() => import('./pages/Organizations'))
const ThreatIntel = React.lazy(() => import('./pages/ThreatIntel'))
const SIEMDashboard = React.lazy(() => import('./pages/SIEMDashboard'))
const ThreatHunting = React.lazy(() => import('./pages/ThreatHunting'))
const ExposureManagement = React.lazy(() => import('./pages/ExposureManagement'))
const UEBADashboard = React.lazy(() => import('./pages/UEBADashboard'))
const AttackSimulation = React.lazy(() => import('./pages/AttackSimulation'))
const DeceptionTech = React.lazy(() => import('./pages/DeceptionTech'))
const Remediation = React.lazy(() => import('./pages/Remediation'))
const ComplianceDashboard = React.lazy(() => import('./pages/ComplianceDashboard'))
const ZeroTrustDashboard = React.lazy(() => import('./pages/ZeroTrustDashboard'))
const STIGCompliance = React.lazy(() => import('./pages/STIGCompliance'))
const AuditEvidence = React.lazy(() => import('./pages/AuditEvidence'))
const DFIRDashboard = React.lazy(() => import('./pages/DFIRDashboard'))
const ITDRDashboard = React.lazy(() => import('./pages/ITDRDashboard'))
const VulnManagement = React.lazy(() => import('./pages/VulnManagement'))
const SupplyChainDashboard = React.lazy(() => import('./pages/SupplyChainDashboard'))
const DarkWebMonitor = React.lazy(() => import('./pages/DarkWebMonitor'))
const IntegrationMarketplace = React.lazy(() => import('./pages/IntegrationMarketplace'))
const AgenticSOC = React.lazy(() => import('./pages/AgenticSOC'))
const PlaybookBuilder = React.lazy(() => import('./pages/PlaybookBuilder'))
const DLPDashboard = React.lazy(() => import('./pages/DLPDashboard'))
const RiskQuantification = React.lazy(() => import('./pages/RiskQuantification'))
const OTSecurityDashboard = React.lazy(() => import('./pages/OTSecurityDashboard'))
const ContainerSecurity = React.lazy(() => import('./pages/ContainerSecurity'))
const PrivacyDashboard = React.lazy(() => import('./pages/PrivacyDashboard'))
const ThreatModeling = React.lazy(() => import('./pages/ThreatModeling'))
const APISecurityDashboard = React.lazy(() => import('./pages/APISecurityDashboard'))
const DataLakeDashboard = React.lazy(() => import('./pages/DataLakeDashboard'))
const WarRoom = React.lazy(() => import('./pages/WarRoom'))
const PhishingSimulation = React.lazy(() => import('./pages/PhishingSimulation'))
const TicketHub = React.lazy(() => import('./pages/TicketHub'))
const FedRAMP = React.lazy(() => import('./pages/FedRAMP'))
const AgentManagement = React.lazy(() => import('./pages/AgentManagement'))
const LiveResponse = React.lazy(() => import('./pages/LiveResponse'))
const PurpleTeam = React.lazy(() => import('./pages/PurpleTeam'))
const NotFound = React.lazy(() => import('./pages/NotFound'))

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

function PageFallback() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-primary-600"></div>
    </div>
  )
}

function AppRoutes() {
  return (
    <Suspense fallback={<PageFallback />}>
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
          <Route path="iocs" element={<Navigate to="/threat-intel" replace />} />
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
          {/* Legacy path kept as a redirect so old bookmarks still work —
              the two pages were consolidated into /agentic's Chat tab. */}
          <Route path="agent-console" element={<Navigate to="/agentic?tab=chat" replace />} />
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
          <Route path="agents" element={<AgentManagement />} />
          <Route path="live-response" element={<LiveResponse />} />
          <Route path="purple-team" element={<PurpleTeam />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Suspense>
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
