import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Box,
  Shield,
  AlertTriangle,
  CheckCircle,
  Search,
  Plus,
  Eye,
  RefreshCw,
  Activity,
  Server,
  X,
  ShieldAlert,
  AlertCircle,
  FileWarning,
  Key,
  Trash2,
  ListChecks,
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../lib/api';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';

const NA = 'not available';

const inputCls = 'w-full px-3 py-2 text-sm border border-gray-300 rounded-lg bg-white';

const checkStatusColor = (status: string) => {
  switch (status) {
    case 'pass': return 'bg-green-100 text-green-800';
    case 'fail': return 'bg-red-100 text-red-800';
    default: return 'bg-gray-100 text-gray-600';
  }
};

const scanStatusColor = (status: string | null | undefined) => {
  switch (status) {
    case 'completed': return 'bg-green-100 text-green-800';
    case 'pending':
    case 'awaiting_approval': return 'bg-blue-100 text-blue-800';
    case 'failed': return 'bg-red-100 text-red-800';
    case 'awaiting_integration': return 'bg-yellow-100 text-yellow-800';
    default: return 'bg-gray-100 text-gray-600';
  }
};

const severityColor = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'bg-red-100 text-red-800';
    case 'high': return 'bg-orange-100 text-orange-800';
    case 'medium': return 'bg-yellow-100 text-yellow-800';
    case 'low': return 'bg-green-100 text-green-800';
    default: return 'bg-gray-100 text-gray-800';
  }
};

const complianceColor = (status: string) => {
  switch (status) {
    case 'compliant': return 'bg-green-100 text-green-800';
    case 'partial': return 'bg-yellow-100 text-yellow-800';
    case 'non_compliant': return 'bg-red-100 text-red-800';
    case 'not_scanned': return 'bg-gray-100 text-gray-600';
    case 'exception': return 'bg-yellow-100 text-yellow-800';
    default: return 'bg-gray-100 text-gray-600';
  }
};

const alertStatusColor = (status: string) => {
  switch (status) {
    case 'new': return 'bg-blue-100 text-blue-800';
    case 'investigating': return 'bg-yellow-100 text-yellow-800';
    case 'confirmed': return 'bg-orange-100 text-orange-800';
    case 'contained': return 'bg-purple-100 text-purple-800';
    case 'resolved': return 'bg-green-100 text-green-800';
    default: return 'bg-gray-100 text-gray-600';
  }
};

const findingStatusColor = (status: string) => {
  switch (status) {
    case 'open': return 'bg-red-100 text-red-800';
    case 'remediated': return 'bg-green-100 text-green-800';
    case 'accepted': return 'bg-blue-100 text-blue-800';
    case 'false_positive': return 'bg-gray-100 text-gray-600';
    default: return 'bg-gray-100 text-gray-600';
  }
};

type TabType = 'overview' | 'images' | 'clusters' | 'findings' | 'runtime';

export default function ContainerSecurity() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedImage, setSelectedImage] = useState<Row | null>(null);
  const [selectedCluster, setSelectedCluster] = useState<Row | null>(null);
  // Outcome of the last rescan / audit / remediate action, shown once.
  const [actionMessage, setActionMessage] = useState<{ kind: 'error' | 'info'; text: string } | null>(null);
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [scanTarget, setScanTarget] = useState<Row | null>(null);
  const [scanScanner, setScanScanner] = useState<'trivy' | 'grype'>('trivy');
  const [scanAgent, setScanAgent] = useState('');
  const [credentialCluster, setCredentialCluster] = useState<Row | null>(null);
  const [credentialMode, setCredentialMode] = useState<'kubeconfig' | 'token'>('kubeconfig');
  const [showRegisterImage, setShowRegisterImage] = useState(false);
  const [showRegisterCluster, setShowRegisterCluster] = useState(false);
  const [lastAudit, setLastAudit] = useState<Row | null>(null);
  const [remediation, setRemediation] = useState<Row | null>(null);

  const { data: scanners, error: scannersError } = useQuery<Row>({
    queryKey: ['container-security', 'scanners'],
    queryFn: async () => (await api.get('/container-security/scanners')).data,
  });

  const { data: imageScans, error: imageScansError } = useQuery<Row[]>({
    queryKey: ['container-security', 'image-scans', selectedImage?.id],
    queryFn: async () => (await api.get(`/container-security/images/${selectedImage?.id}/scans`)).data,
    enabled: Boolean(selectedImage?.id),
  });

  const { data: imageVulns, error: imageVulnsError } = useQuery<Row[]>({
    queryKey: ['container-security', 'image-vulns', selectedImage?.id],
    queryFn: async () => (await api.get(`/container-security/images/${selectedImage?.id}/vulnerabilities`)).data,
    enabled: Boolean(selectedImage?.id),
  });

  const { data: clusterChecks, error: clusterChecksError, isLoading: clusterChecksLoading } = useQuery<Row[]>({
    queryKey: ['container-security', 'cluster-checks', selectedCluster?.id],
    queryFn: async () => (await api.get(`/container-security/clusters/${selectedCluster?.id}/checks`)).data,
    enabled: Boolean(selectedCluster?.id),
  });

  const runAction = async (what: string, fn: () => Promise<void>) => {
    setActionError(null);
    setActionMessage(null);
    try {
      await fn();
      queryClient.invalidateQueries({ queryKey: ['container-security'] });
    } catch (error) {
      setActionError({ what, error });
    }
  };

  // ─── Queries ──────────────────────────────────────────────────────
  const { data: dashboardData, isLoading: dashLoading, error: dashError } = useQuery({
    queryKey: ['container-security', 'dashboard'],
    queryFn: async () => {
      const res = await api.get('/container-security/dashboard/overview');
      return res.data;
    },
  });

  const { data: imagesRaw, isLoading: imagesLoading, error: imagesError } = useQuery({
    queryKey: ['container-security', 'images'],
    queryFn: async () => {
      const res = await api.get('/container-security/images');
      return res.data;
    },
    enabled: activeTab === 'images' || activeTab === 'overview',
  });

  const { data: clustersRaw, isLoading: clustersLoading, error: clustersError } = useQuery({
    queryKey: ['container-security', 'clusters'],
    queryFn: async () => {
      const res = await api.get('/container-security/clusters');
      return res.data;
    },
    enabled: activeTab === 'clusters' || activeTab === 'overview',
  });

  const { data: findingsRaw, isLoading: findingsLoading, error: findingsError } = useQuery({
    queryKey: ['container-security', 'findings'],
    queryFn: async () => {
      const res = await api.get('/container-security/findings');
      return res.data;
    },
    enabled: activeTab === 'findings' || activeTab === 'overview',
  });

  const { data: alertsRaw, isLoading: alertsLoading, error: alertsError } = useQuery({
    queryKey: ['container-security', 'runtime-alerts'],
    queryFn: async () => {
      const res = await api.get('/container-security/runtime-alerts');
      return res.data;
    },
    enabled: activeTab === 'runtime' || activeTab === 'overview',
  });

  // Normalize data (handle both array and paginated responses)
  const images: Row[] = Array.isArray(imagesRaw) ? imagesRaw : (imagesRaw?.items || []);
  const clusters: Row[] = Array.isArray(clustersRaw) ? clustersRaw : (clustersRaw?.items || []);
  const findings: Row[] = Array.isArray(findingsRaw) ? findingsRaw : (findingsRaw?.items || []);
  const alerts: Row[] = Array.isArray(alertsRaw) ? alertsRaw : (alertsRaw?.items || []);
  const scanAgents: Row[] = Array.isArray(scanners?.agents) ? scanners.agents : [];

  // ─── Mutations ────────────────────────────────────────────────────
  // Scan through an installed scanner integration, else an endpoint agent
  // with the container_scan capability; otherwise awaiting_integration.
  const scanImageMutation = useMutation({
    mutationFn: async ({ imageId, scanner, agentId }: { imageId: string; scanner: string; agentId?: string }) => {
      const res = await api.post(`/container-security/images/${imageId}/scan`, null, {
        params: { scanner, agent_id: agentId || undefined },
      });
      return res.data;
    },
    onSuccess: (data: Row) => {
      setActionError(null);
      setScanTarget(null);
      setActionMessage({
        kind: data?.status === 'failed' ? 'error' : 'info',
        text: `Image scan ${String(data?.status ?? '').replace(/_/g, ' ')}${data?.method ? ` (${data.method})` : ''}: ${data?.detail || 'no detail returned'}`
          + (data?.status === 'completed' ? ` ${data?.vulnerabilities ?? 0} vulnerability record(s).` : ''),
      });
      queryClient.invalidateQueries({ queryKey: ['container-security'] });
    },
    onError: (err) => setActionError({ what: 'scan the image', error: err }),
  });

  const auditClusterMutation = useMutation({
    // CIS checks run against the Kubernetes API when a credential is
    // installed; otherwise every check is not_assessed.
    mutationFn: async (clusterId: string) => {
      const res = await api.post(`/container-security/clusters/${clusterId}/audit`, {
        audit_type: 'full',
      });
      return res.data;
    },
    onSuccess: (data: Row) => {
      setActionError(null);
      setLastAudit(data);
      queryClient.invalidateQueries({ queryKey: ['container-security'] });
    },
    onError: (err) => setActionError({ what: 'audit the cluster', error: err }),
  });

  const remediateFindingMutation = useMutation({
    // Endpoint requires a JSON body even when empty — sending no body causes a 422.
    mutationFn: async (findingId: string) => {
      const res = await api.post(`/container-security/findings/${findingId}/remediate`, {});
      return res.data;
    },
    onSuccess: (data: Row) => {
      setActionError(null);
      setRemediation(data);
      queryClient.invalidateQueries({ queryKey: ['container-security', 'findings'] });
    },
    onError: (err) => setActionError({ what: 'generate the remediation', error: err }),
  });

  // ─── Dashboard stats ──────────────────────────────────────────────
  // Counts come only from the org-scoped dashboard aggregate. When it
  // fails they read "not available" rather than a count of page 1.
  const dash = dashboardData ?? null;
  const totalImages: number | null = dash?.total_images ?? null;
  const totalClusters: number | null = dash?.total_clusters ?? null;
  const totalFindings: number | null = dash?.open_findings ?? null;
  const totalAlerts: number | null = dash?.active_alerts ?? null;
  const criticalVulns: number | null = dash?.critical_vulnerabilities ?? null;
  const highVulns: number | null = dash?.high_vulnerabilities ?? null;

  // Filtered data
  const q = searchQuery.toLowerCase();
  const filteredImages = images.filter((i: Row) =>
    (i.repository || '').toLowerCase().includes(q) ||
    (i.tag || '').toLowerCase().includes(q) ||
    (i.registry || '').toLowerCase().includes(q)
  );
  const filteredClusters = clusters.filter((c: Row) =>
    (c.name || '').toLowerCase().includes(q) ||
    (c.provider || '').toLowerCase().includes(q)
  );
  const filteredFindings = findings.filter((f: Row) =>
    (f.finding_type || '').toLowerCase().includes(q) ||
    (f.namespace || '').toLowerCase().includes(q) ||
    (f.resource_name || '').toLowerCase().includes(q)
  );
  const filteredAlerts = alerts.filter((a: Row) =>
    (a.alert_type || '').toLowerCase().includes(q) ||
    (a.pod_name || '').toLowerCase().includes(q) ||
    (a.namespace || '').toLowerCase().includes(q)
  );

  const tabs: { id: TabType; label: string; icon: typeof Activity; count?: number }[] = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'images', label: 'Images', icon: Box, count: totalImages ?? undefined },
    { id: 'clusters', label: 'K8s Clusters', icon: Server, count: totalClusters ?? undefined },
    { id: 'findings', label: 'Findings', icon: FileWarning, count: totalFindings ?? undefined },
    { id: 'runtime', label: 'Runtime Alerts', icon: ShieldAlert, count: totalAlerts ?? undefined },
  ];

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-cyan-100 rounded-lg">
              <Shield className="w-7 h-7 text-cyan-600" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">Container Security</h1>
              <p className="text-sm text-gray-500">Image scanning, K8s hardening, runtime protection</p>
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={() => setShowRegisterImage(true)} className="flex items-center gap-1.5 px-3 py-2 text-sm bg-cyan-600 text-white rounded-lg hover:bg-cyan-700">
              <Plus className="w-4 h-4" /> Register Image
            </button>
            <button onClick={() => setShowRegisterCluster(true)} className="flex items-center gap-1.5 px-3 py-2 text-sm border border-gray-300 rounded-lg hover:bg-gray-100">
              <Plus className="w-4 h-4" /> Register Cluster
            </button>
          </div>
        </div>

        {/* Scanner availability (GET /scanners) */}
        <LoadErrorBanner what="image scanner availability" error={scannersError} />
        {scanners && (
          <div className={clsx('text-sm rounded p-3 border', scanners.status === 'available' ? 'bg-green-50 border-green-200 text-green-800' : 'bg-yellow-50 border-yellow-200 text-yellow-800')}>
            {scanners.status === 'available' ? (
              <span>
                Image scanning available through{' '}
                {[
                  ...(scanners.integrations ?? []).map((i: Row) => `${i.display_name || i.connector || 'integration'} (integration)`),
                  ...scanAgents.map((a: Row) => `${a.hostname || a.id} (agent)`),
                ].join(', ')}.
              </span>
            ) : (
              <span>Image scans: awaiting integration. {scanners.reason}</span>
            )}
          </div>
        )}

        {/* Summary Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
          {[
            { label: 'Images', value: totalImages, color: 'text-cyan-600', bg: 'bg-cyan-50' },
            { label: 'Clusters', value: totalClusters, color: 'text-blue-600', bg: 'bg-blue-50' },
            { label: 'Open Findings', value: totalFindings, color: 'text-orange-600', bg: 'bg-orange-50' },
            { label: 'Runtime Alerts', value: totalAlerts, color: 'text-red-600', bg: 'bg-red-50' },
            { label: 'Critical Vulns', value: criticalVulns, color: 'text-red-700', bg: 'bg-red-50' },
            { label: 'High Vulns', value: highVulns, color: 'text-orange-700', bg: 'bg-orange-50' },
          ].map((c) => (
            <div key={c.label} className={clsx('rounded-lg p-4 text-center', c.bg)}>
              <p className={clsx(c.value === null ? 'text-sm text-gray-400 py-1.5' : ['text-2xl font-bold', c.color])}>
                {c.value ?? 'not available'}
              </p>
              <p className="text-xs text-gray-500 mt-1">{c.label}</p>
            </div>
          ))}
        </div>

        <LoadErrorBanner what="container security summary" error={dashError} />
        {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
        {lastAudit && (
          <div className="text-sm rounded p-3 border bg-blue-50 border-blue-200 text-blue-900 flex justify-between gap-4">
            <span>
              Cluster audit {String(lastAudit.status).replace(/_/g, ' ')}
              {lastAudit.benchmark ? ` (${lastAudit.benchmark})` : ''}:{' '}
              {lastAudit.status === 'assessed'
                ? `CIS ${lastAudit.cis_compliance == null ? NA : `${lastAudit.cis_compliance}%`}, ${lastAudit.checks?.pass ?? 0} pass / ${lastAudit.checks?.fail ?? 0} fail / ${lastAudit.checks?.not_assessed ?? 0} not assessed; findings ${lastAudit.findings_new} new, ${lastAudit.findings_updated} updated, ${lastAudit.findings_resolved} resolved.`
                : lastAudit.reason || 'no reason returned'}
            </span>
            <button onClick={() => setLastAudit(null)} className="text-xs underline">dismiss</button>
          </div>
        )}
        {remediation && (
          <div className="text-sm rounded p-3 border bg-gray-50 border-gray-200 space-y-2">
            <div className="flex justify-between">
              <span className="font-medium">Remediation manifest generated (not applied to the cluster): {remediation.description}</span>
              <button onClick={() => setRemediation(null)} className="text-xs underline">dismiss</button>
            </div>
            {remediation.manifest && <pre className="text-xs bg-white border rounded p-2 overflow-x-auto">{remediation.manifest}</pre>}
          </div>
        )}
        {actionMessage && (
          <div
            role={actionMessage.kind === 'error' ? 'alert' : 'status'}
            className={clsx(
              'text-sm rounded p-3 border',
              actionMessage.kind === 'error'
                ? 'text-red-700 bg-red-50 border-red-200'
                : 'text-gray-700 bg-gray-50 border-gray-200',
            )}
          >
            {actionMessage.text}
          </div>
        )}

        {/* Tabs */}
        <div className="bg-white rounded-lg border border-gray-200">
          <nav className="flex overflow-x-auto" role="tablist">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  role="tab"
                  aria-selected={activeTab === tab.id}
                  onClick={() => { setActiveTab(tab.id); setSearchQuery(''); }}
                  className={clsx(
                    'flex items-center gap-2 px-5 py-3 text-sm font-medium whitespace-nowrap border-b-2 transition-colors',
                    activeTab === tab.id
                      ? 'border-cyan-600 text-cyan-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                  )}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                  {tab.count !== undefined && (
                    <span className="ml-1 px-1.5 py-0.5 text-xs rounded-full bg-gray-100 text-gray-600">{tab.count}</span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Search (shown on list tabs) */}
        {activeTab !== 'overview' && (
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder={`Search ${activeTab}...`}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2 text-sm border border-gray-300 rounded-lg bg-white focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
            />
          </div>
        )}

        {/* ─── Overview Tab ──────────────────────────────────────────── */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {dashLoading ? (
              <div className="flex items-center justify-center h-40"><RefreshCw className="w-6 h-6 text-cyan-600 animate-spin" /></div>
            ) : (
              <>
                <LoadErrorBanner what="images" error={imagesError} />
                <LoadErrorBanner what="security findings" error={findingsError} />
                <LoadErrorBanner what="runtime alerts" error={alertsError} />
                {/* Recent Vulnerable Images */}
                <div className="bg-white rounded-lg border border-gray-200 p-6">
                  <h3 className="text-sm font-semibold text-gray-700 mb-4">High-Risk Images <span className="font-normal text-gray-400">(scanned images only)</span></h3>
                  {images.filter((i: Row) => i.scanned_at && (i.risk_score || 0) > 50).length === 0 ? (
                    <p className="text-sm text-gray-400">No scanned image has a risk score above 50.</p>
                  ) : (
                    <div className="space-y-2">
                      {images
                        .filter((i: Row) => i.scanned_at && (i.risk_score || 0) > 50)
                        .sort((a: Row, b: Row) => (b.risk_score || 0) - (a.risk_score || 0))
                        .slice(0, 5)
                        .map((img: Row) => (
                          <div key={img.id} className="flex items-center justify-between p-3 rounded-lg bg-red-50">
                            <div>
                              <span className="font-mono text-sm font-medium text-gray-900">{img.repository || 'unknown'}:{img.tag || 'latest'}</span>
                              <span className="ml-2 text-xs text-gray-500">{img.registry}</span>
                            </div>
                            <div className="flex items-center gap-3">
                              <span className="text-xs text-red-600 font-semibold">Risk: {img.risk_score}</span>
                              <span className="text-xs">{img.vulnerability_count_critical}C / {img.vulnerability_count_high}H</span>
                              <button
                                onClick={() => setSelectedImage(img)}
                                className="text-blue-600 hover:text-blue-800"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                            </div>
                          </div>
                        ))}
                    </div>
                  )}
                </div>

                {/* Recent Findings & Alerts side by side */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="bg-white rounded-lg border border-gray-200 p-6">
                    <h3 className="text-sm font-semibold text-gray-700 mb-4">Recent Security Findings</h3>
                    {findings.length === 0 ? (
                      <p className="text-sm text-gray-400">No findings.</p>
                    ) : (
                      <div className="space-y-2">
                        {findings.slice(0, 5).map((f: Row) => (
                          <div key={f.id} className="flex items-center justify-between p-2 rounded bg-gray-50">
                            <div className="flex items-center gap-2">
                              <span className={clsx('px-1.5 py-0.5 text-xs rounded font-medium', severityColor(f.severity))}>{f.severity}</span>
                              <span className="text-sm text-gray-800">{(f.finding_type || '').replace(/_/g, ' ')}</span>
                            </div>
                            <span className="text-xs text-gray-500">{f.namespace || '-'}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="bg-white rounded-lg border border-gray-200 p-6">
                    <h3 className="text-sm font-semibold text-gray-700 mb-4">Recent Runtime Alerts</h3>
                    {alerts.length === 0 ? (
                      <p className="text-sm text-gray-400">No runtime alerts.</p>
                    ) : (
                      <div className="space-y-2">
                        {alerts.slice(0, 5).map((a: Row) => (
                          <div key={a.id} className="flex items-center justify-between p-2 rounded bg-gray-50">
                            <div className="flex items-center gap-2">
                              <span className={clsx('px-1.5 py-0.5 text-xs rounded font-medium', severityColor(a.severity))}>{a.severity}</span>
                              <span className="text-sm text-gray-800">{(a.alert_type || '').replace(/_/g, ' ')}</span>
                            </div>
                            <span className="text-xs text-gray-500">{a.pod_name || '-'}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* ─── Images Tab ────────────────────────────────────────────── */}
        {activeTab === 'images' && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {imagesLoading ? (
              <div className="flex items-center justify-center h-40"><RefreshCw className="w-6 h-6 text-cyan-600 animate-spin" /></div>
            ) : imagesError ? (
              <div className="p-4"><LoadErrorBanner what="images" error={imagesError} /></div>
            ) : filteredImages.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                <Box className="w-10 h-10 mb-3" />
                <p className="text-sm">{searchQuery ? 'No images match your search.' : 'No container image registered. Use Register Image.'}</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 text-left">
                      <th className="px-4 py-3 font-semibold text-gray-600">Image</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Tag</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Registry</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Vulnerabilities</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Risk</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Compliance</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Signed</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Scan</th>
                      <th className="px-4 py-3 font-semibold text-gray-600 w-20">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {filteredImages.map((img: Row) => {
                      const totalVulns = img.vulnerability_count_critical + img.vulnerability_count_high + img.vulnerability_count_medium + img.vulnerability_count_low;
                      return (
                        <tr key={img.id} className="hover:bg-gray-50">
                          <td className="px-4 py-3 font-mono font-medium text-gray-900">{img.repository || 'unknown'}</td>
                          <td className="px-4 py-3"><span className="px-2 py-0.5 bg-gray-100 rounded text-xs font-mono">{img.tag || 'latest'}</span></td>
                          <td className="px-4 py-3 text-gray-500">{img.registry || 'docker.io'}</td>
                          <td className="px-4 py-3">
                            {totalVulns > 0 ? (
                              <div className="flex items-center gap-1">
                                <AlertTriangle className="w-3.5 h-3.5 text-red-500" />
                                <span className="text-xs">
                                  <span className="text-red-600 font-semibold">{img.vulnerability_count_critical}</span>C{' '}
                                  <span className="text-orange-600 font-semibold">{img.vulnerability_count_high}</span>H{' '}
                                  <span className="text-yellow-600">{img.vulnerability_count_medium}</span>M{' '}
                                  <span className="text-gray-500">{img.vulnerability_count_low}</span>L
                                </span>
                              </div>
                            ) : (
                              <span className="text-xs text-gray-400">{img.scanned_at ? 'None found' : 'Not scanned'}</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            {img.scanned_at ? (
                              <span className={clsx(
                                'px-2 py-0.5 rounded text-xs font-semibold',
                                (img.risk_score || 0) >= 70 ? 'bg-red-100 text-red-800' :
                                (img.risk_score || 0) >= 40 ? 'bg-yellow-100 text-yellow-800' :
                                'bg-green-100 text-green-800'
                              )}>
                                {img.risk_score ?? 0}
                              </span>
                            ) : (
                              <span className="text-xs text-gray-400">{NA}</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', complianceColor(img.compliance_status || 'not_scanned'))}>
                              {(img.compliance_status || 'not_scanned').replace(/_/g, ' ')}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            {img.is_signed ? (
                              <CheckCircle className={clsx('w-4 h-4', img.signature_verified ? 'text-green-500' : 'text-yellow-500')} />
                            ) : (
                              <span className="text-xs text-gray-400">No</span>
                            )}
                          </td>
                          <td className="px-4 py-3 text-xs text-gray-500">
                            <span className={clsx('px-1.5 py-0.5 rounded', scanStatusColor(img.scan_status))}>{String(img.scan_status || 'not_scanned').replace(/_/g, ' ')}</span>
                            <div className="mt-0.5">{img.scanned_at ? new Date(img.scanned_at).toLocaleDateString() : 'never'}</div>
                            {img.scan_error && <div className="text-red-600 mt-0.5" title={img.scan_error}>{String(img.scan_error).slice(0, 60)}</div>}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex gap-1.5">
                              <button onClick={() => setSelectedImage(img)} className="text-blue-600 hover:text-blue-800" title="Details and scan history">
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => { setActionError(null); setScanTarget(img); }}
                                disabled={scanImageMutation.isPending}
                                className="text-cyan-600 hover:text-cyan-800 disabled:opacity-50"
                                title="Scan"
                              >
                                <RefreshCw className={clsx('w-4 h-4', scanImageMutation.isPending && 'animate-spin')} />
                              </button>
                              <button
                                onClick={() => {
                                  if (!window.confirm(`Delete image ${img.repository}:${img.tag}?`)) return;
                                  runAction('delete the image', async () => { await api.delete(`/container-security/images/${img.id}`); });
                                }}
                                className="text-red-500 hover:text-red-700"
                                title="Delete (admin)"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ─── Clusters Tab ──────────────────────────────────────────── */}
        {activeTab === 'clusters' && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {clustersLoading ? (
              <div className="flex items-center justify-center h-40"><RefreshCw className="w-6 h-6 text-cyan-600 animate-spin" /></div>
            ) : clustersError ? (
              <div className="p-4"><LoadErrorBanner what="clusters" error={clustersError} /></div>
            ) : filteredClusters.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                <Server className="w-10 h-10 mb-3" />
                <p className="text-sm">{searchQuery ? 'No clusters match your search.' : 'No Kubernetes clusters registered. Use Register Cluster.'}</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 text-left">
                      <th className="px-4 py-3 font-semibold text-gray-600">Cluster</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Provider</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Version</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Nodes</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Security Features <span className="font-normal text-gray-400">(self-attested)</span></th>
                      <th className="px-4 py-3 font-semibold text-gray-600">API Credential</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">CIS Compliance</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Last Audit</th>
                      <th className="px-4 py-3 font-semibold text-gray-600 w-28">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {filteredClusters.map((c: Row) => (
                      <tr key={c.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 font-medium text-gray-900">{c.name}</td>
                        <td className="px-4 py-3"><span className="px-2 py-0.5 bg-blue-50 text-blue-700 rounded text-xs font-medium uppercase">{c.provider || 'unknown'}</span></td>
                        <td className="px-4 py-3 font-mono text-xs">{c.version || '-'}</td>
                        <td className="px-4 py-3">{c.node_count ?? '-'}</td>
                        <td className="px-4 py-3">
                          <div className="flex gap-1">
                            {c.rbac_enabled && <span className="px-1.5 py-0.5 bg-green-50 text-green-700 rounded text-xs">RBAC</span>}
                            {c.network_policy_enabled && <span className="px-1.5 py-0.5 bg-green-50 text-green-700 rounded text-xs">NetPol</span>}
                            {c.audit_logging_enabled && <span className="px-1.5 py-0.5 bg-green-50 text-green-700 rounded text-xs">Audit</span>}
                            {c.encryption_at_rest && <span className="px-1.5 py-0.5 bg-green-50 text-green-700 rounded text-xs">Encrypt</span>}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs">
                          {c.has_credential ? (
                            <span className="text-green-700">{c.credential_type || 'installed'}{c.credential_set_at ? ` · ${new Date(c.credential_set_at).toLocaleDateString()}` : ''}</span>
                          ) : (
                            <span className="text-gray-400">none (checks not assessed)</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className={clsx('px-2 py-0.5 rounded text-xs font-semibold', complianceColor(c.compliance_status || 'not_assessed'))}>
                            {String(c.compliance_status || 'not_assessed').replace(/_/g, ' ')}
                            {c.compliance_status && c.compliance_status !== 'not_assessed' ? ` · ${c.compliance_score}%` : ''}
                          </span>
                          {c.assessment_error && <div className="text-xs text-red-600 mt-1" title={c.assessment_error}>{String(c.assessment_error).slice(0, 60)}</div>}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-500">
                          {c.last_audit ? new Date(c.last_audit).toLocaleDateString() : 'Never'}
                          <div>{String(c.assessment_status || 'not_assessed').replace(/_/g, ' ')}</div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex gap-1.5">
                            <button onClick={() => setSelectedCluster(c)} className="text-blue-600 hover:text-blue-800" title="Details and CIS checks">
                              <ListChecks className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => auditClusterMutation.mutate(c.id)}
                              disabled={auditClusterMutation.isPending}
                              className="text-cyan-600 hover:text-cyan-800 disabled:opacity-50"
                              title="Run CIS audit through the Kubernetes API"
                            >
                              <RefreshCw className={clsx('w-4 h-4', auditClusterMutation.isPending && 'animate-spin')} />
                            </button>
                            <button onClick={() => { setActionError(null); setCredentialCluster(c); }} className="text-gray-600 hover:text-gray-900" title="Set API credential (admin)">
                              <Key className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => {
                                if (!window.confirm(`Delete cluster ${c.name}?`)) return;
                                runAction('delete the cluster', async () => { await api.delete(`/container-security/clusters/${c.id}`); });
                              }}
                              className="text-red-500 hover:text-red-700"
                              title="Delete (admin)"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ─── Findings Tab ──────────────────────────────────────────── */}
        {activeTab === 'findings' && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {findingsLoading ? (
              <div className="flex items-center justify-center h-40"><RefreshCw className="w-6 h-6 text-cyan-600 animate-spin" /></div>
            ) : findingsError ? (
              <div className="p-4"><LoadErrorBanner what="security findings" error={findingsError} /></div>
            ) : filteredFindings.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                <FileWarning className="w-10 h-10 mb-3" />
                <p className="text-sm">{searchQuery ? 'No findings match.' : 'No security findings.'}</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 text-left">
                      <th className="px-4 py-3 font-semibold text-gray-600">Type</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Severity</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Namespace</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Resource / Image</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Check</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Status</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Detected / Last seen</th>
                      <th className="px-4 py-3 font-semibold text-gray-600 w-24">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {filteredFindings.map((f: Row) => (
                      <tr key={f.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 text-gray-900">{(f.finding_type || '').replace(/_/g, ' ')}</td>
                        <td className="px-4 py-3"><span className={clsx('px-2 py-0.5 rounded text-xs font-medium', severityColor(f.severity))}>{f.severity}</span></td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-600">{f.namespace || '-'}</td>
                        <td className="px-4 py-3 text-xs">
                          {f.image_ref ? (
                            <span className="font-mono text-gray-800">{f.image_ref}</span>
                          ) : (
                            <>
                              <span className="text-gray-500">{f.resource_type}/</span>
                              <span className="font-medium text-gray-800">{f.resource_name || '-'}</span>
                            </>
                          )}
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-500">{f.check_id || f.cis_benchmark_id || '-'}</td>
                        <td className="px-4 py-3"><span className={clsx('px-2 py-0.5 rounded text-xs font-medium', findingStatusColor(f.status))}>{(f.status || '').replace(/_/g, ' ')}</span></td>
                        <td className="px-4 py-3 text-xs text-gray-500">
                          {f.detected_at ? new Date(f.detected_at).toLocaleDateString() : f.created_at ? new Date(f.created_at).toLocaleDateString() : '-'}
                          {f.last_seen_at && <div>seen {new Date(f.last_seen_at).toLocaleDateString()}</div>}
                        </td>
                        <td className="px-4 py-3">
                          {f.status === 'open' && (
                            <button
                              onClick={() => remediateFindingMutation.mutate(f.id)}
                              disabled={remediateFindingMutation.isPending}
                              title="Generates a remediation manifest; nothing is applied to the cluster"
                              className="text-xs px-2 py-1 bg-cyan-600 text-white rounded hover:bg-cyan-700 disabled:opacity-50"
                            >
                              Generate Fix
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ─── Runtime Alerts Tab ────────────────────────────────────── */}
        {activeTab === 'runtime' && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {alertsLoading ? (
              <div className="flex items-center justify-center h-40"><RefreshCw className="w-6 h-6 text-cyan-600 animate-spin" /></div>
            ) : alertsError ? (
              <div className="p-4"><LoadErrorBanner what="runtime alerts" error={alertsError} /></div>
            ) : filteredAlerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                <ShieldAlert className="w-10 h-10 mb-3" />
                <p className="text-sm">{searchQuery ? 'No alerts match.' : 'No runtime alerts. Runtime alerts need a runtime sensor (e.g. Falco) forwarding events; none is built in.'}</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="bg-gray-50 text-left">
                      <th className="px-4 py-3 font-semibold text-gray-600">Alert Type</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Severity</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Namespace</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Pod</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Process</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">MITRE</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Status</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Time</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {filteredAlerts.map((a: Row) => (
                      <tr key={a.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 text-gray-900 capitalize">{(a.alert_type || '').replace(/_/g, ' ')}</td>
                        <td className="px-4 py-3"><span className={clsx('px-2 py-0.5 rounded text-xs font-medium', severityColor(a.severity))}>{a.severity}</span></td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-600">{a.namespace || '-'}</td>
                        <td className="px-4 py-3 text-xs font-mono text-gray-700">{a.pod_name || '-'}</td>
                        <td className="px-4 py-3 text-xs font-mono text-gray-500">{a.process_name || '-'}</td>
                        <td className="px-4 py-3 text-xs text-gray-500">{a.mitre_technique || '-'}</td>
                        <td className="px-4 py-3"><span className={clsx('px-2 py-0.5 rounded text-xs font-medium', alertStatusColor(a.status))}>{(a.status || '').replace(/_/g, ' ')}</span></td>
                        <td className="px-4 py-3 text-xs text-gray-500">{a.created_at ? new Date(a.created_at || "").toLocaleString() : '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ─── Image Detail Modal ──────────────────────────────────────── */}
      {selectedImage && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setSelectedImage(null)}>
          <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
              <h2 className="text-lg font-semibold">Image Details</h2>
              <button onClick={() => setSelectedImage(null)} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-3">
                <div><span className="text-gray-500">Repository:</span><p className="font-mono font-medium">{selectedImage.repository || '-'}</p></div>
                <div><span className="text-gray-500">Tag:</span><p className="font-mono">{selectedImage.tag || 'latest'}</p></div>
                <div><span className="text-gray-500">Registry:</span><p>{selectedImage.registry || 'docker.io'}</p></div>
                <div><span className="text-gray-500">OS / Arch:</span><p>{selectedImage.os || '-'} / {selectedImage.architecture || '-'}</p></div>
                <div><span className="text-gray-500">Size:</span><p>{selectedImage.image_size_mb ? `${selectedImage.image_size_mb} MB` : 'N/A'}</p></div>
                <div><span className="text-gray-500">Risk Score:</span><p className="font-semibold">{selectedImage.scanned_at ? (selectedImage.risk_score ?? 0) : NA}</p></div>
                <div><span className="text-gray-500">Compliance:</span><p className={clsx('inline-block px-2 py-0.5 rounded text-xs font-medium', complianceColor(selectedImage.compliance_status || 'not_scanned'))}>{(selectedImage.compliance_status || 'not_scanned').replace(/_/g, ' ')}</p></div>
                <div><span className="text-gray-500">Signed:</span><p>{selectedImage.is_signed ? (selectedImage.signature_verified ? 'Verified' : 'Signed (unverified; no verifier backend)') : 'No'}</p></div>
                <div><span className="text-gray-500">Scan status:</span><p><span className={clsx('px-1.5 py-0.5 rounded text-xs', scanStatusColor(selectedImage.scan_status))}>{String(selectedImage.scan_status || 'not_scanned').replace(/_/g, ' ')}</span></p></div>
                {selectedImage.scan_error && <div className="col-span-2"><span className="text-gray-500">Scan error:</span><p className="text-red-600">{selectedImage.scan_error}</p></div>}
              </div>
              <div className="border-t pt-3 mt-3">
                <h4 className="font-semibold text-gray-700 mb-2">Vulnerabilities</h4>
                <div className="grid grid-cols-4 gap-2 text-center">
                  <div className="bg-red-50 rounded p-2"><p className="text-lg font-bold text-red-600">{selectedImage.vulnerability_count_critical}</p><p className="text-xs text-gray-500">Critical</p></div>
                  <div className="bg-orange-50 rounded p-2"><p className="text-lg font-bold text-orange-600">{selectedImage.vulnerability_count_high}</p><p className="text-xs text-gray-500">High</p></div>
                  <div className="bg-yellow-50 rounded p-2"><p className="text-lg font-bold text-yellow-600">{selectedImage.vulnerability_count_medium}</p><p className="text-xs text-gray-500">Medium</p></div>
                  <div className="bg-green-50 rounded p-2"><p className="text-lg font-bold text-green-600">{selectedImage.vulnerability_count_low}</p><p className="text-xs text-gray-500">Low</p></div>
                </div>
              </div>
              {selectedImage.digest_sha256 && (
                <div><span className="text-gray-500">Digest:</span><p className="font-mono text-xs break-all">{selectedImage.digest_sha256}</p></div>
              )}
              <div><span className="text-gray-500">Last Scanned:</span><p>{selectedImage.scanned_at ? new Date(selectedImage.scanned_at).toLocaleString() : 'Never'}</p></div>
              <div className="border-t pt-3">
                <h4 className="font-semibold text-gray-700 mb-2">Scan history</h4>
                <LoadErrorBanner what="scan history" error={imageScansError} />
                {imageScans && imageScans.length === 0 && <p className="text-xs text-gray-400">No scan requested yet.</p>}
                <div className="space-y-1">
                  {(imageScans ?? []).map((s: Row) => (
                    <div key={s.id} className="text-xs flex flex-wrap gap-2 items-center bg-gray-50 rounded p-1.5">
                      <span className={clsx('px-1.5 py-0.5 rounded', scanStatusColor(s.status))}>{String(s.status).replace(/_/g, ' ')}</span>
                      <span>{s.method}{s.scanner ? ` / ${s.scanner}` : ''}</span>
                      <span className="text-gray-500">{s.created_at ? new Date(s.created_at).toLocaleString() : ''}</span>
                      {s.status === 'completed' && <span>{s.vulnerabilities_total} vuln(s), {s.vulnerabilities_new} new</span>}
                      {s.error && <span className="text-red-600">{s.error}</span>}
                    </div>
                  ))}
                </div>
              </div>
              <div className="border-t pt-3">
                <h4 className="font-semibold text-gray-700 mb-2">Recorded vulnerabilities</h4>
                <LoadErrorBanner what="image vulnerabilities" error={imageVulnsError} />
                {imageVulns && imageVulns.length === 0 && <p className="text-xs text-gray-400">None recorded.</p>}
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {(imageVulns ?? []).slice(0, 100).map((v: Row) => (
                    <div key={v.id} className="text-xs flex flex-wrap gap-2">
                      <span className={clsx('px-1.5 py-0.5 rounded', severityColor(v.severity))}>{v.severity}</span>
                      <span className="font-mono">{v.cve_id}</span>
                      <span>{v.package_name} {v.package_version}</span>
                      <span className="text-gray-500">fix: {v.fixed_version || 'none'}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ─── Cluster Detail Modal ────────────────────────────────────── */}
      {selectedCluster && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setSelectedCluster(null)}>
          <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
              <h2 className="text-lg font-semibold">Cluster: {selectedCluster.name}</h2>
              <button onClick={() => setSelectedCluster(null)} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-3 text-sm">
              <div className="grid grid-cols-2 gap-3">
                <div><span className="text-gray-500">Provider:</span><p className="uppercase font-medium">{selectedCluster.provider || '-'}</p></div>
                <div><span className="text-gray-500">Version:</span><p className="font-mono">{selectedCluster.version || '-'}</p></div>
                <div><span className="text-gray-500">Nodes:</span><p>{selectedCluster.node_count ?? '-'}</p></div>
                <div><span className="text-gray-500">Namespaces:</span><p>{selectedCluster.namespace_count ?? '-'}</p></div>
                <div><span className="text-gray-500">Pods:</span><p>{selectedCluster.pod_count ?? '-'}</p></div>
                <div><span className="text-gray-500">Pod Security:</span><p className="capitalize">{selectedCluster.pod_security_standards || '-'}</p></div>
                <div><span className="text-gray-500">CIS Compliance:</span><p className="font-semibold">{selectedCluster.compliance_status && selectedCluster.compliance_status !== 'not_assessed' ? `${selectedCluster.compliance_score}% (${String(selectedCluster.compliance_status).replace(/_/g, ' ')})` : 'not assessed'}</p></div>
                <div><span className="text-gray-500">API Credential:</span><p>{selectedCluster.has_credential ? selectedCluster.credential_type || 'installed' : 'none'}</p></div>
              </div>
              {selectedCluster.has_credential && (
                <button
                  onClick={() => runAction('remove the cluster credential', async () => {
                    const res = await api.delete(`/container-security/clusters/${selectedCluster.id}/credential`);
                    setSelectedCluster(res.data);
                  })}
                  className="text-xs px-2 py-1 border border-red-300 text-red-700 rounded hover:bg-red-50"
                >
                  Remove API credential (admin)
                </button>
              )}
              <div className="border-t pt-3">
                <h4 className="font-semibold text-gray-700 mb-2">CIS checks (from the last API assessment)</h4>
                <LoadErrorBanner what="CIS checks" error={clusterChecksError} />
                {clusterChecksLoading && <p className="text-xs text-gray-400">Loading...</p>}
                {clusterChecks && clusterChecks.length === 0 && <p className="text-xs text-gray-400">No check has been evaluated. Run an audit.</p>}
                <div className="space-y-1 max-h-60 overflow-y-auto">
                  {(clusterChecks ?? []).map((chk: Row) => (
                    <div key={chk.check_id} className="text-xs border-b border-gray-100 pb-1">
                      <div className="flex gap-2 items-center">
                        <span className={clsx('px-1.5 py-0.5 rounded', checkStatusColor(chk.status))}>{String(chk.status).replace(/_/g, ' ')}</span>
                        <span className="font-mono">{chk.check_id}</span>
                        <span>{chk.title}</span>
                      </div>
                      {chk.reason && <p className="text-gray-500 ml-1 mt-0.5">{chk.reason}</p>}
                    </div>
                  ))}
                </div>
              </div>
              <div className="border-t pt-3">
                <h4 className="font-semibold text-gray-700 mb-2">Security Features <span className="font-normal text-xs text-gray-400">(self-attested at registration; not verified)</span></h4>
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { label: 'RBAC', enabled: selectedCluster.rbac_enabled },
                    { label: 'Network Policies', enabled: selectedCluster.network_policy_enabled },
                    { label: 'Audit Logging', enabled: selectedCluster.audit_logging_enabled },
                    { label: 'Encryption at Rest', enabled: selectedCluster.encryption_at_rest },
                    { label: 'Secrets Encrypted', enabled: selectedCluster.secrets_encrypted },
                  ].map((feat) => (
                    <div key={feat.label} className="flex items-center gap-2">
                      {feat.enabled ? <CheckCircle className="w-4 h-4 text-green-500" /> : <AlertCircle className="w-4 h-4 text-red-400" />}
                      <span className={feat.enabled ? 'text-gray-800' : 'text-gray-400'}>{feat.label}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div><span className="text-gray-500">Last Audit:</span><p>{selectedCluster.last_audit ? new Date(selectedCluster.last_audit).toLocaleString() : 'Never'}</p></div>
            </div>
          </div>
        </div>
      )}

      {/* ─── Scan Image Modal ────────────────────────────────────────── */}
      {scanTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setScanTarget(null)}>
          <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4 p-6 space-y-3" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold">Scan {scanTarget.repository}:{scanTarget.tag}</h2>
            <p className="text-xs text-gray-500">
              An installed scanner integration answers at once; otherwise the scan is queued on a container_scan agent
              (it may need approval). Without either, nothing is scanned and the status is awaiting integration.
            </p>
            {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
            <label className="block text-sm">Scanner the agent runs
              <select value={scanScanner} onChange={(e) => setScanScanner(e.target.value as 'trivy' | 'grype')} className={inputCls}>
                <option value="trivy">Trivy</option>
                <option value="grype">Grype</option>
              </select>
            </label>
            <label className="block text-sm">Agent
              <select value={scanAgent} onChange={(e) => setScanAgent(e.target.value)} className={inputCls}>
                <option value="">Automatic (integration first, then any capable agent)</option>
                {scanAgents.map((a: Row) => <option key={a.id} value={a.id}>{a.hostname || a.id}</option>)}
              </select>
            </label>
            {scanAgents.length === 0 && <p className="text-xs text-gray-500">No agent with the container_scan capability is enrolled.</p>}
            <div className="flex gap-2 pt-2">
              <button
                onClick={() => scanImageMutation.mutate({ imageId: scanTarget.id, scanner: scanScanner, agentId: scanAgent })}
                disabled={scanImageMutation.isPending}
                className="flex-1 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 disabled:opacity-50"
              >
                {scanImageMutation.isPending ? 'Requesting...' : 'Scan'}
              </button>
              <button onClick={() => setScanTarget(null)} className="flex-1 px-4 py-2 border border-gray-300 rounded-lg">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* ─── Cluster Credential Modal ────────────────────────────────── */}
      {credentialCluster && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setCredentialCluster(null)}>
          <form
            className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4 p-6 space-y-3"
            onClick={(e) => e.stopPropagation()}
            onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              const body = credentialMode === 'kubeconfig'
                ? { kubeconfig: String(fd.get('kubeconfig') || ''), context: String(fd.get('context') || '') || undefined }
                : { token: String(fd.get('token') || ''), ca_data: String(fd.get('ca_data') || '') || undefined };
              await runAction('install the cluster credential', async () => {
                await api.put(`/container-security/clusters/${credentialCluster.id}/credential`, body);
                setCredentialCluster(null);
                setActionMessage({ kind: 'info', text: `Credential installed for ${credentialCluster.name}. Run an audit to evaluate the CIS checks.` });
              });
            }}
          >
            <h2 className="text-lg font-semibold">API credential for {credentialCluster.name}</h2>
            <p className="text-xs text-gray-500">
              Stored encrypted and used read-only for CIS checks against {credentialCluster.endpoint}. Private API addresses are refused by the outbound guard.
              {credentialCluster.has_credential ? ' Saving replaces the installed credential.' : ''}
            </p>
            {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
            <div className="flex gap-4 text-sm">
              <label className="flex items-center gap-1"><input type="radio" checked={credentialMode === 'kubeconfig'} onChange={() => setCredentialMode('kubeconfig')} /> kubeconfig</label>
              <label className="flex items-center gap-1"><input type="radio" checked={credentialMode === 'token'} onChange={() => setCredentialMode('token')} /> bearer token</label>
            </div>
            {credentialMode === 'kubeconfig' ? (
              <>
                <textarea name="kubeconfig" required rows={8} className={clsx(inputCls, 'font-mono text-xs')} placeholder="apiVersion: v1&#10;kind: Config&#10;..." />
                <input name="context" className={inputCls} placeholder="context (optional; current-context otherwise)" />
              </>
            ) : (
              <>
                <input name="token" required className={clsx(inputCls, 'font-mono text-xs')} placeholder="service account bearer token" />
                <textarea name="ca_data" rows={4} className={clsx(inputCls, 'font-mono text-xs')} placeholder="base64-encoded PEM CA bundle (optional)" />
              </>
            )}
            <div className="flex gap-2">
              <button type="submit" className="flex-1 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700">Save credential</button>
              <button type="button" onClick={() => setCredentialCluster(null)} className="flex-1 px-4 py-2 border border-gray-300 rounded-lg">Cancel</button>
            </div>
          </form>
        </div>
      )}

      {/* ─── Register Image Modal ────────────────────────────────────── */}
      {showRegisterImage && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setShowRegisterImage(false)}>
          <form
            className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4 p-6 space-y-3"
            onClick={(e) => e.stopPropagation()}
            onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              await runAction('register the image', async () => {
                await api.post('/container-security/images', {
                  registry: fd.get('registry'),
                  repository: fd.get('repository'),
                  tag: fd.get('tag'),
                  digest_sha256: String(fd.get('digest') || '') || undefined,
                });
                setShowRegisterImage(false);
              });
            }}
          >
            <h2 className="text-lg font-semibold">Register container image</h2>
            {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
            <input name="registry" required className={inputCls} placeholder="registry (e.g. ghcr.io)" />
            <input name="repository" required className={inputCls} placeholder="repository (e.g. org/app)" />
            <input name="tag" required className={inputCls} placeholder="tag" />
            <input name="digest" className={clsx(inputCls, 'font-mono text-xs')} placeholder="sha256:<64 hex> (optional)" />
            <div className="flex gap-2">
              <button type="submit" className="flex-1 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700">Register</button>
              <button type="button" onClick={() => setShowRegisterImage(false)} className="flex-1 px-4 py-2 border border-gray-300 rounded-lg">Cancel</button>
            </div>
          </form>
        </div>
      )}

      {/* ─── Register Cluster Modal ──────────────────────────────────── */}
      {showRegisterCluster && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setShowRegisterCluster(false)}>
          <form
            className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4 p-6 space-y-3"
            onClick={(e) => e.stopPropagation()}
            onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              await runAction('register the cluster', async () => {
                await api.post('/container-security/clusters', {
                  name: fd.get('name'),
                  version: fd.get('version'),
                  provider: fd.get('provider') || '',
                  endpoint: fd.get('endpoint'),
                  pod_security_standards: fd.get('pss') || 'baseline',
                });
                setShowRegisterCluster(false);
              });
            }}
          >
            <h2 className="text-lg font-semibold">Register Kubernetes cluster</h2>
            {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
            <input name="name" required className={inputCls} placeholder="name" />
            <input name="version" required className={inputCls} placeholder="Kubernetes version (e.g. 1.30)" />
            <input name="provider" className={inputCls} placeholder="provider (eks, aks, gke, on-prem...)" />
            <input name="endpoint" required type="url" pattern="https://.*" className={inputCls} placeholder="https://api-server.example.com:6443" />
            <label className="block text-sm">Pod Security Standard (self-attested)
              <select name="pss" defaultValue="baseline" className={inputCls}>
                <option value="privileged">privileged</option>
                <option value="baseline">baseline</option>
                <option value="restricted">restricted</option>
              </select>
            </label>
            <div className="flex gap-2">
              <button type="submit" className="flex-1 px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700">Register</button>
              <button type="button" onClick={() => setShowRegisterCluster(false)} className="flex-1 px-4 py-2 border border-gray-300 rounded-lg">Cancel</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
