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
  Cpu,
  AlertCircle,
  FileWarning,
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../lib/api';

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
  const [selectedImage, setSelectedImage] = useState<any>(null);
  const [selectedCluster, setSelectedCluster] = useState<any>(null);

  // ─── Queries ──────────────────────────────────────────────────────
  const { data: dashboardData, isLoading: dashLoading } = useQuery({
    queryKey: ['container-security', 'dashboard'],
    queryFn: async () => {
      const res = await api.get('/container-security/dashboard/overview');
      return res.data;
    },
  });

  const { data: imagesRaw, isLoading: imagesLoading } = useQuery({
    queryKey: ['container-security', 'images'],
    queryFn: async () => {
      const res = await api.get('/container-security/images');
      return res.data;
    },
    enabled: activeTab === 'images' || activeTab === 'overview',
  });

  const { data: clustersRaw, isLoading: clustersLoading } = useQuery({
    queryKey: ['container-security', 'clusters'],
    queryFn: async () => {
      const res = await api.get('/container-security/clusters');
      return res.data;
    },
    enabled: activeTab === 'clusters' || activeTab === 'overview',
  });

  const { data: findingsRaw, isLoading: findingsLoading } = useQuery({
    queryKey: ['container-security', 'findings'],
    queryFn: async () => {
      const res = await api.get('/container-security/findings');
      return res.data;
    },
    enabled: activeTab === 'findings' || activeTab === 'overview',
  });

  const { data: alertsRaw, isLoading: alertsLoading } = useQuery({
    queryKey: ['container-security', 'runtime-alerts'],
    queryFn: async () => {
      const res = await api.get('/container-security/runtime-alerts');
      return res.data;
    },
    enabled: activeTab === 'runtime' || activeTab === 'overview',
  });

  // Normalize data (handle both array and paginated responses)
  const images: any[] = Array.isArray(imagesRaw) ? imagesRaw : (imagesRaw?.items || []);
  const clusters: any[] = Array.isArray(clustersRaw) ? clustersRaw : (clustersRaw?.items || []);
  const findings: any[] = Array.isArray(findingsRaw) ? findingsRaw : (findingsRaw?.items || []);
  const alerts: any[] = Array.isArray(alertsRaw) ? alertsRaw : (alertsRaw?.items || []);

  // ─── Mutations ────────────────────────────────────────────────────
  const scanImageMutation = useMutation({
    mutationFn: async (imageId: string) => {
      const res = await api.post(`/container-security/images/${imageId}/scan`);
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['container-security'] });
    },
  });

  const auditClusterMutation = useMutation({
    // Backend audit_cluster expects a ClusterAuditRequest body. Send the minimal
    // valid payload so the request validates and the audit kicks off.
    mutationFn: async (clusterId: string) => {
      const res = await api.post(`/container-security/clusters/${clusterId}/audit`, {
        audit_type: 'full',
      });
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['container-security'] });
    },
  });

  const remediateFindingMutation = useMutation({
    // Endpoint requires a JSON body even when empty — sending no body causes a 422.
    mutationFn: async (findingId: string) => {
      const res = await api.post(`/container-security/findings/${findingId}/remediate`, {});
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['container-security', 'findings'] });
    },
  });

  // ─── Dashboard stats ──────────────────────────────────────────────
  const dash = dashboardData || {};
  const totalImages = dash.total_images ?? images.length;
  const totalClusters = dash.total_clusters ?? clusters.length;
  const totalFindings = dash.open_findings ?? findings.filter((f: any) => f.status === 'open').length;
  const totalAlerts = dash.active_alerts ?? alerts.filter((a: any) => a.status !== 'resolved').length;
  const criticalVulns = dash.critical_vulnerabilities ?? images.reduce((s: number, i: any) => s + (i.critical_count || 0), 0);
  const highVulns = dash.high_vulnerabilities ?? images.reduce((s: number, i: any) => s + (i.high_count || 0), 0);

  // Filtered data
  const q = searchQuery.toLowerCase();
  const filteredImages = images.filter((i: any) =>
    (i.repository || '').toLowerCase().includes(q) ||
    (i.tag || '').toLowerCase().includes(q) ||
    (i.registry || '').toLowerCase().includes(q)
  );
  const filteredClusters = clusters.filter((c: any) =>
    (c.name || '').toLowerCase().includes(q) ||
    (c.provider || '').toLowerCase().includes(q)
  );
  const filteredFindings = findings.filter((f: any) =>
    (f.finding_type || '').toLowerCase().includes(q) ||
    (f.namespace || '').toLowerCase().includes(q) ||
    (f.resource_name || '').toLowerCase().includes(q)
  );
  const filteredAlerts = alerts.filter((a: any) =>
    (a.alert_type || '').toLowerCase().includes(q) ||
    (a.pod_name || '').toLowerCase().includes(q) ||
    (a.namespace || '').toLowerCase().includes(q)
  );

  const tabs: { id: TabType; label: string; icon: any; count?: number }[] = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'images', label: 'Images', icon: Box, count: totalImages },
    { id: 'clusters', label: 'K8s Clusters', icon: Server, count: totalClusters },
    { id: 'findings', label: 'Findings', icon: FileWarning, count: totalFindings },
    { id: 'runtime', label: 'Runtime Alerts', icon: ShieldAlert, count: totalAlerts },
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
        </div>

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
              <p className={clsx('text-2xl font-bold', c.color)}>{c.value}</p>
              <p className="text-xs text-gray-500 mt-1">{c.label}</p>
            </div>
          ))}
        </div>

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
                {/* Recent Vulnerable Images */}
                <div className="bg-white rounded-lg border border-gray-200 p-6">
                  <h3 className="text-sm font-semibold text-gray-700 mb-4">High-Risk Images</h3>
                  {images.filter((i: any) => (i.risk_score || 0) > 50).length === 0 ? (
                    <p className="text-sm text-gray-400">No high-risk images found.</p>
                  ) : (
                    <div className="space-y-2">
                      {images
                        .filter((i: any) => (i.risk_score || 0) > 50)
                        .sort((a: any, b: any) => (b.risk_score || 0) - (a.risk_score || 0))
                        .slice(0, 5)
                        .map((img: any) => (
                          <div key={img.id} className="flex items-center justify-between p-3 rounded-lg bg-red-50">
                            <div>
                              <span className="font-mono text-sm font-medium text-gray-900">{img.repository || 'unknown'}:{img.tag || 'latest'}</span>
                              <span className="ml-2 text-xs text-gray-500">{img.registry}</span>
                            </div>
                            <div className="flex items-center gap-3">
                              <span className="text-xs text-red-600 font-semibold">Risk: {img.risk_score}</span>
                              <span className="text-xs">{img.critical_count || 0}C / {img.high_count || 0}H</span>
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
                        {findings.slice(0, 5).map((f: any) => (
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
                        {alerts.slice(0, 5).map((a: any) => (
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
            ) : filteredImages.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                <Box className="w-10 h-10 mb-3" />
                <p className="text-sm">{searchQuery ? 'No images match your search.' : 'No container images scanned yet.'}</p>
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
                      <th className="px-4 py-3 font-semibold text-gray-600">Scanned</th>
                      <th className="px-4 py-3 font-semibold text-gray-600 w-20">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {filteredImages.map((img: any) => {
                      const totalVulns = (img.critical_count || 0) + (img.high_count || 0) + (img.medium_count || 0) + (img.low_count || 0);
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
                                  <span className="text-red-600 font-semibold">{img.critical_count || 0}</span>C{' '}
                                  <span className="text-orange-600 font-semibold">{img.high_count || 0}</span>H{' '}
                                  <span className="text-yellow-600">{img.medium_count || 0}</span>M{' '}
                                  <span className="text-gray-500">{img.low_count || 0}</span>L
                                </span>
                              </div>
                            ) : (
                              <span className="flex items-center gap-1 text-green-600 text-xs"><CheckCircle className="w-3.5 h-3.5" /> Clean</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span className={clsx(
                              'px-2 py-0.5 rounded text-xs font-semibold',
                              (img.risk_score || 0) >= 70 ? 'bg-red-100 text-red-800' :
                              (img.risk_score || 0) >= 40 ? 'bg-yellow-100 text-yellow-800' :
                              'bg-green-100 text-green-800'
                            )}>
                              {img.risk_score ?? 0}
                            </span>
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
                            {img.scanned_at ? new Date(img.scanned_at || "").toLocaleDateString() : 'Never'}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex gap-1.5">
                              <button onClick={() => setSelectedImage(img)} className="text-blue-600 hover:text-blue-800" title="Details">
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => scanImageMutation.mutate(img.id)}
                                disabled={scanImageMutation.isPending}
                                className="text-cyan-600 hover:text-cyan-800 disabled:opacity-50"
                                title="Re-scan"
                              >
                                <RefreshCw className={clsx('w-4 h-4', scanImageMutation.isPending && 'animate-spin')} />
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
            ) : filteredClusters.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                <Server className="w-10 h-10 mb-3" />
                <p className="text-sm">{searchQuery ? 'No clusters match your search.' : 'No Kubernetes clusters registered.'}</p>
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
                      <th className="px-4 py-3 font-semibold text-gray-600">Security Features</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Compliance</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Risk</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Last Audit</th>
                      <th className="px-4 py-3 font-semibold text-gray-600 w-20">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {filteredClusters.map((c: any) => (
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
                        <td className="px-4 py-3">
                          <span className={clsx(
                            'px-2 py-0.5 rounded text-xs font-semibold',
                            (c.compliance_score || 0) >= 80 ? 'bg-green-100 text-green-800' :
                            (c.compliance_score || 0) >= 50 ? 'bg-yellow-100 text-yellow-800' :
                            'bg-red-100 text-red-800'
                          )}>
                            {c.compliance_score ?? 0}%
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={clsx(
                            'px-2 py-0.5 rounded text-xs font-semibold',
                            (c.risk_score || 0) >= 70 ? 'bg-red-100 text-red-800' :
                            (c.risk_score || 0) >= 40 ? 'bg-yellow-100 text-yellow-800' :
                            'bg-green-100 text-green-800'
                          )}>
                            {c.risk_score ?? 0}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-500">
                          {c.last_audit ? new Date(c.last_audit || "").toLocaleDateString() : 'Never'}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex gap-1.5">
                            <button onClick={() => setSelectedCluster(c)} className="text-blue-600 hover:text-blue-800" title="Details">
                              <Eye className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => auditClusterMutation.mutate(c.id)}
                              disabled={auditClusterMutation.isPending}
                              className="text-cyan-600 hover:text-cyan-800 disabled:opacity-50"
                              title="Run Audit"
                            >
                              <RefreshCw className={clsx('w-4 h-4', auditClusterMutation.isPending && 'animate-spin')} />
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
                      <th className="px-4 py-3 font-semibold text-gray-600">Resource</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">CIS Benchmark</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Status</th>
                      <th className="px-4 py-3 font-semibold text-gray-600">Detected</th>
                      <th className="px-4 py-3 font-semibold text-gray-600 w-24">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {filteredFindings.map((f: any) => (
                      <tr key={f.id} className="hover:bg-gray-50">
                        <td className="px-4 py-3 text-gray-900 capitalize">{(f.finding_type || '').replace(/_/g, ' ')}</td>
                        <td className="px-4 py-3"><span className={clsx('px-2 py-0.5 rounded text-xs font-medium', severityColor(f.severity))}>{f.severity}</span></td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-600">{f.namespace || '-'}</td>
                        <td className="px-4 py-3 text-xs">
                          <span className="text-gray-500">{f.resource_type}/</span>
                          <span className="font-medium text-gray-800">{f.resource_name || '-'}</span>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-500">{f.cis_benchmark_id || '-'}</td>
                        <td className="px-4 py-3"><span className={clsx('px-2 py-0.5 rounded text-xs font-medium', findingStatusColor(f.status))}>{(f.status || '').replace(/_/g, ' ')}</span></td>
                        <td className="px-4 py-3 text-xs text-gray-500">{f.detected_at ? new Date(f.detected_at || "").toLocaleDateString() : f.created_at ? new Date(f.created_at || "").toLocaleDateString() : '-'}</td>
                        <td className="px-4 py-3">
                          {f.status === 'open' && (
                            <button
                              onClick={() => remediateFindingMutation.mutate(f.id)}
                              disabled={remediateFindingMutation.isPending}
                              className="text-xs px-2 py-1 bg-cyan-600 text-white rounded hover:bg-cyan-700 disabled:opacity-50"
                            >
                              Remediate
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
            ) : filteredAlerts.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-48 text-gray-400">
                <ShieldAlert className="w-10 h-10 mb-3" />
                <p className="text-sm">{searchQuery ? 'No alerts match.' : 'No runtime alerts.'}</p>
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
                    {filteredAlerts.map((a: any) => (
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
                <div><span className="text-gray-500">Risk Score:</span><p className="font-semibold">{selectedImage.risk_score ?? 0}</p></div>
                <div><span className="text-gray-500">Compliance:</span><p className={clsx('inline-block px-2 py-0.5 rounded text-xs font-medium', complianceColor(selectedImage.compliance_status || 'not_scanned'))}>{(selectedImage.compliance_status || 'not_scanned').replace(/_/g, ' ')}</p></div>
                <div><span className="text-gray-500">Signed:</span><p>{selectedImage.is_signed ? (selectedImage.signature_verified ? 'Verified' : 'Signed (unverified)') : 'No'}</p></div>
              </div>
              <div className="border-t pt-3 mt-3">
                <h4 className="font-semibold text-gray-700 mb-2">Vulnerabilities</h4>
                <div className="grid grid-cols-4 gap-2 text-center">
                  <div className="bg-red-50 rounded p-2"><p className="text-lg font-bold text-red-600">{selectedImage.critical_count || 0}</p><p className="text-xs text-gray-500">Critical</p></div>
                  <div className="bg-orange-50 rounded p-2"><p className="text-lg font-bold text-orange-600">{selectedImage.high_count || 0}</p><p className="text-xs text-gray-500">High</p></div>
                  <div className="bg-yellow-50 rounded p-2"><p className="text-lg font-bold text-yellow-600">{selectedImage.medium_count || 0}</p><p className="text-xs text-gray-500">Medium</p></div>
                  <div className="bg-green-50 rounded p-2"><p className="text-lg font-bold text-green-600">{selectedImage.low_count || 0}</p><p className="text-xs text-gray-500">Low</p></div>
                </div>
              </div>
              {selectedImage.digest_sha256 && (
                <div><span className="text-gray-500">Digest:</span><p className="font-mono text-xs break-all">{selectedImage.digest_sha256}</p></div>
              )}
              <div><span className="text-gray-500">Last Scanned:</span><p>{selectedImage.scanned_at ? new Date(selectedImage.scanned_at || "").toLocaleString() : 'Never'}</p></div>
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
                <div><span className="text-gray-500">Compliance Score:</span><p className="font-semibold">{selectedCluster.compliance_score ?? 0}%</p></div>
                <div><span className="text-gray-500">Risk Score:</span><p className="font-semibold">{selectedCluster.risk_score ?? 0}</p></div>
              </div>
              <div className="border-t pt-3">
                <h4 className="font-semibold text-gray-700 mb-2">Security Features</h4>
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
              <div><span className="text-gray-500">Last Audit:</span><p>{selectedCluster.last_audit ? new Date(selectedCluster.last_audit || "").toLocaleString() : 'Never'}</p></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
