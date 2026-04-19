import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ChevronDown,
  ChevronRight,
  Plus,
  Filter,
  Download,
  Upload,
  Loader2,
  FileText,
  Image,
  Square,
  Settings,
  Eye,
  Trash2,
  Calendar,
  CheckCircle,
  AlertCircle,
  Clock,
  Search,
  Shield,
  Play,
  Zap,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';
import FormModal from '../components/FormModal';

type TabType = 'dashboard' | 'audit-trail' | 'evidence' | 'packages' | 'conmon';

// ---- Module-scope helpers (shared by all tab sub-components) ----
// These used to live inside the main AuditEvidence component which meant
// the sub-component functions (EvidenceTab, AuditTrailTab, etc.) tried to
// reference them from a closure they never captured → ReferenceError at
// render time. Lifting them to module scope fixes that.

const statusColorMap: Record<string, string> = {
  success: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  failure: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  pending: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  reviewed: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  approved: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  draft: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400',
  'in-review': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  submitted: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
};

const riskColorMap: Record<string, string> = {
  low: 'text-green-600 dark:text-green-400',
  medium: 'text-yellow-600 dark:text-yellow-400',
  high: 'text-red-600 dark:text-red-400',
};

function getStatusColor(status: string): string {
  return statusColorMap[status] || 'bg-gray-100 text-gray-800';
}

function getRiskColor(risk: string): string {
  return riskColorMap[risk] || 'text-gray-600';
}

interface DashboardData {
  auditEventsCount: number;
  evidenceItemsCount: number;
  activePackagesCount: number;
  readinessScore: number;
  evidenceCoverage: {
    withEvidence: number;
    withoutEvidence: number;
  };
  recentAuditEvents: AuditEvent[];
}

interface AuditEvent {
  id: string;
  time: string;
  type: string;
  action: string;
  actor: string;
  resource: string;
  result: 'success' | 'failure';
  riskLevel: 'low' | 'medium' | 'high';
}

interface EvidenceItem {
  id: string;
  title: string;
  type: 'document' | 'screenshot' | 'log' | 'config' | 'scan' | string;
  control: string;
  source: string;
  collected?: string;
  status: 'pending' | 'reviewed' | 'approved' | string;
  contentUrl?: string | null;
  created_at?: string;
}

interface Package {
  id: string;
  name: string;
  framework: string;
  status: 'draft' | 'in-review' | 'submitted' | 'approved';
  evidenceCount: number;
  dueDate: string;
  assessor: string;
}

interface ConMonStatus {
  id: string;
  name: string;
  active: boolean;
  lastRun: string;
  status?: string;
  compliance_percentage?: number;
  last_run?: string; // back-compat alias
}

export default function AuditEvidence() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [expandedEvent, setExpandedEvent] = useState<string | null>(null);
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('all');
  const [resultFilter, setResultFilter] = useState<string>('all');
  const [dateRangeFilter, setDateRangeFilter] = useState<string>('7d');
  const [evidenceStatusFilter, setEvidenceStatusFilter] = useState<string>('all');
  const [evidenceTypeFilter, setEvidenceTypeFilter] = useState<string>('all');
  const [actionError, setActionError] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: dashboardData, isLoading: dashboardLoading } = useQuery<DashboardData>({
    queryKey: ['audit-evidence-dashboard'],
    queryFn: async () => {
      try {
        const pkgRes = await api.get('/audit-evidence/packages');
        const pkgs = Array.isArray(pkgRes.data) ? pkgRes.data : (pkgRes.data?.items || []);
        const active = pkgs.filter((p: any) => p.status !== 'approved' && p.status !== 'archived').length;
        const withEv = pkgs.filter((p: any) => (p.evidenceCount ?? p.evidence_count ?? 0) > 0).length;
        return {
          auditEventsCount: 0,
          evidenceItemsCount: pkgs.reduce((s: number, p: any) => s + (p.evidenceCount ?? p.evidence_count ?? 0), 0),
          activePackagesCount: active,
          readinessScore: pkgs.length > 0 ? Math.round((withEv / pkgs.length) * 100) : 0,
          evidenceCoverage: {
            withEvidence: withEv,
            withoutEvidence: pkgs.length - withEv,
          },
          recentAuditEvents: [],
        } as DashboardData;
      } catch {
        return {
          auditEventsCount: 0,
          evidenceItemsCount: 0,
          activePackagesCount: 0,
          readinessScore: 0,
          evidenceCoverage: { withEvidence: 0, withoutEvidence: 0 },
          recentAuditEvents: [],
        } as DashboardData;
      }
    },
  });

  const { data: auditTrail, isLoading: auditLoading } = useQuery<AuditEvent[]>({
    queryKey: [
      'audit-trail',
      eventTypeFilter,
      resultFilter,
      dateRangeFilter,
    ],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (eventTypeFilter !== 'all') params.append('type', eventTypeFilter);
      if (resultFilter !== 'all') params.append('result', resultFilter);
      if (dateRangeFilter !== '7d') params.append('range', dateRangeFilter);
      try {
      const response = await api.post('/audit-evidence/audit/search', { type: eventTypeFilter !== 'all' ? eventTypeFilter : undefined });
      const d = response.data;
      return Array.isArray(d) ? d : (d?.items || []);
      } catch { return []; }
    },
  });

  const { data: evidenceItems, isLoading: evidenceLoading } = useQuery<EvidenceItem[]>({
    queryKey: ['evidence-items', evidenceStatusFilter, evidenceTypeFilter],
    queryFn: async () => {
      try {
        const params: Record<string, string> = {};
        if (evidenceStatusFilter !== 'all') params.status = evidenceStatusFilter;
        if (evidenceTypeFilter !== 'all') params.evidence_type = evidenceTypeFilter;
        const response = await api.get('/audit-evidence/evidence/list', { params });
        const d = response.data;
        if (Array.isArray(d)) return d;
        if (d && Array.isArray(d.items)) return d.items;
        return [];
      } catch { return []; }
    },
  });

  const { data: packages, isLoading: packagesLoading } = useQuery<Package[]>({
    queryKey: ['audit-packages'],
    queryFn: async () => {
      try {
      const response = await api.get('/audit-evidence/packages');
      return response.data;
      } catch { return null; }
    },
  });

  const { data: conmonStatuses, isLoading: conmonLoading } = useQuery<ConMonStatus[]>({
    queryKey: ['conmon-status'],
    queryFn: async () => {
      try {
        const response = await api.get('/audit-evidence/conmon/status');
        const d = response.data;
        if (Array.isArray(d)) return d;
        // Back-compat: older /conmon/status returned an object {status, checks, last_run}
        if (d && typeof d === 'object' && d.checks && typeof d.checks === 'object') {
          const now = d.last_run || new Date().toISOString();
          return Object.entries(d.checks).map(([key, val]: [string, any]) => ({
            id: key,
            name: key.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
            active: val?.status === 'compliant' || val?.status === 'on_track',
            lastRun: now,
          }));
        }
        return [];
      } catch { return []; }
    },
  });

  const runConMonMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/audit-evidence/conmon/run');
      return response.data;
    },
    onSuccess: () => {
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['conmon-status'] });
      queryClient.invalidateQueries({ queryKey: ['audit-evidence-dashboard'] });
    },
    onError: (err: any) => {
      console.error('ConMon run failed:', err);
      setActionError(
        err?.response?.data?.detail || err?.message || 'Failed to run continuous monitoring'
      );
    },
  });

  const deleteEvidenceMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/audit-evidence/evidence/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence-items'] });
    },
  });

  const approveEvidenceMutation = useMutation({
    mutationFn: async (id: string) => {
      try {
      const response = await api.post(`/audit-evidence/evidence/${id}/approve`);
      return response.data;
      } catch { return null; }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence-items'] });
    },
  });

  // Helpers now live at module scope (statusColorMap/riskColorMap + getStatusColor/getRiskColor)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Audit & Evidence</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Compliance evidence management and continuous monitoring
        </p>
      </div>

      {actionError && (
        <div className="flex items-start gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
          <div className="flex-1">{actionError}</div>
          <button
            onClick={() => setActionError(null)}
            className="text-red-700 hover:text-red-900 text-sm"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-8 -mb-px" aria-label="Tabs">
          {(['dashboard', 'audit-trail', 'evidence', 'packages', 'conmon'] as const).map(
            (tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={clsx(
                  'py-2 px-1 border-b-2 font-medium text-sm transition-colors',
                  activeTab === tab
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300'
                )}
              >
                {tab === 'dashboard' && 'Dashboard'}
                {tab === 'audit-trail' && 'Audit Trail'}
                {tab === 'evidence' && 'Evidence'}
                {tab === 'packages' && 'Packages'}
                {tab === 'conmon' && 'ConMon'}
              </button>
            )
          )}
        </nav>
      </div>

      {/* Dashboard Tab */}
      {activeTab === 'dashboard' && (
        <DashboardTab data={dashboardData} loading={dashboardLoading} />
      )}

      {/* Audit Trail Tab */}
      {activeTab === 'audit-trail' && (
        <AuditTrailTab
          events={auditTrail || []}
          loading={auditLoading}
          expandedEvent={expandedEvent}
          setExpandedEvent={setExpandedEvent}
          eventTypeFilter={eventTypeFilter}
          setEventTypeFilter={setEventTypeFilter}
          resultFilter={resultFilter}
          setResultFilter={setResultFilter}
          dateRangeFilter={dateRangeFilter}
          setDateRangeFilter={setDateRangeFilter}
        />
      )}

      {/* Evidence Tab */}
      {activeTab === 'evidence' && (
        <EvidenceTab
          items={evidenceItems || []}
          loading={evidenceLoading}
          statusFilter={evidenceStatusFilter}
          setStatusFilter={setEvidenceStatusFilter}
          typeFilter={evidenceTypeFilter}
          setTypeFilter={setEvidenceTypeFilter}
          onDeleteEvidence={(id) => deleteEvidenceMutation.mutate(id)}
          onApproveEvidence={(id) => approveEvidenceMutation.mutate(id)}
        />
      )}

      {/* Packages Tab */}
      {activeTab === 'packages' && (
        <PackagesTab packages={packages || []} loading={packagesLoading} />
      )}

      {/* ConMon Tab */}
      {activeTab === 'conmon' && (
        <ConMonTab
          statuses={conmonStatuses || []}
          loading={conmonLoading}
          onRunConMon={() => runConMonMutation.mutate()}
        />
      )}
    </div>
  );
}

function DashboardTab({
  data,
  loading,
}: {
  data?: DashboardData;
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KPICard
          label="Audit Events (24h)"
          value={data?.auditEventsCount || 0}
          icon={Square}
          color="blue"
        />
        <KPICard
          label="Evidence Items"
          value={data?.evidenceItemsCount || 0}
          icon={FileText}
          color="green"
        />
        <KPICard
          label="Active Packages"
          value={data?.activePackagesCount || 0}
          icon={Calendar}
          color="orange"
        />
        <KPICard
          label="Readiness Score"
          value={`${data?.readinessScore || 0}%`}
          icon={CheckCircle}
          color="purple"
        />
      </div>

      {/* Evidence Coverage Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Evidence Coverage by Control
        </h2>
        <div className="flex items-center gap-8">
          <div className="relative w-40 h-40">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 120 120">
              <circle
                cx="60"
                cy="60"
                r="54"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                className="text-gray-200 dark:text-gray-700"
              />
              <circle
                cx="60"
                cy="60"
                r="54"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                strokeDasharray={`${
                  (data?.evidenceCoverage?.withEvidence || 0) * 3.4
                } 340`}
                className="text-green-500 transition-all duration-500"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {data?.evidenceCoverage?.withEvidence || 0}
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400">
                  with evidence
                </div>
              </div>
            </div>
          </div>
          <div className="flex-1">
            <div className="space-y-3">
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    Controls with Evidence
                  </span>
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">
                    {data?.evidenceCoverage?.withEvidence || 0}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div className="h-full bg-green-500 rounded-full" style={{ width: '75%' }} />
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    Controls without Evidence
                  </span>
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">
                    {data?.evidenceCoverage?.withoutEvidence || 0}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div className="h-full bg-orange-500 rounded-full" style={{ width: '25%' }} />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Audit Events */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Recent Audit Events
        </h2>
        <div className="space-y-2">
          {(data?.recentAuditEvents || []).map((event) => (
            <div
              key={event.id}
              className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
            >
              <div className="flex-1">
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {event.action}
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                  {event.actor} on {event.resource}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={clsx('text-xs font-medium', getRiskColor(event.riskLevel))}>
                  {event.riskLevel}
                </span>
                <span
                  className={clsx(
                    'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                    getStatusColor(event.result)
                  )}
                >
                  {event.result}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AuditTrailTab({
  events,
  loading,
  expandedEvent,
  setExpandedEvent,
  eventTypeFilter,
  setEventTypeFilter,
  resultFilter,
  setResultFilter,
  dateRangeFilter,
  setDateRangeFilter,
}: {
  events: AuditEvent[];
  loading: boolean;
  expandedEvent: string | null;
  setExpandedEvent: (id: string | null) => void;
  eventTypeFilter: string;
  setEventTypeFilter: (value: string) => void;
  resultFilter: string;
  setResultFilter: (value: string) => void;
  dateRangeFilter: string;
  setDateRangeFilter: (value: string) => void;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const eventTypes = ['all', 'login', 'access', 'change', 'delete'];
  const dateRanges = ['1d', '7d', '30d', '90d'];

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center gap-2 mb-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">Filters</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Event Type
            </label>
            <select
              value={eventTypeFilter}
              onChange={(e) => setEventTypeFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              {eventTypes.map((type) => (
                <option key={type} value={type}>
                  {type.charAt(0).toUpperCase() + type.slice(1)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Result
            </label>
            <select
              value={resultFilter}
              onChange={(e) => setResultFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Results</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Date Range
            </label>
            <select
              value={dateRangeFilter}
              onChange={(e) => setDateRangeFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              {dateRanges.map((range) => (
                <option key={range} value={range}>
                  Last {range.replace('d', ' days')}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Time
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Action
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Actor
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Resource
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Result
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Risk Level
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {events.map((event) => (
              <tr
                key={event.id}
                className="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                onClick={() =>
                  setExpandedEvent(expandedEvent === event.id ? null : event.id)
                }
              >
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {new Date(event.time || event.timestamp || "").toLocaleTimeString()}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {event.type}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white font-medium">
                  {event.action}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">
                  {event.actor}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {event.resource}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      getStatusColor(event.result)
                    )}
                  >
                    {event.result}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'font-medium text-xs uppercase',
                      getRiskColor(event.riskLevel)
                    )}
                  >
                    {event.riskLevel}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Export Button — streams real CSV from /audit/export */}
      <button
        onClick={async () => {
          try {
            const response = await api.get('/audit/export?format=csv&days=90', {
              responseType: 'blob',
            });
            const blob = response.data as Blob;
            const cd = response.headers?.['content-disposition'];
            let filename = `pysoar_audit_${new Date().toISOString().slice(0, 10)}.csv`;
            if (cd && typeof cd === 'string') {
              const m = cd.match(/filename="?([^"]+)"?/);
              if (m) filename = m[1];
            }
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
          } catch (err) {
            console.error('Audit log export failed:', err);
          }
        }}
        className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
      >
        <Download className="w-5 h-5" />
        Export Audit Log
      </button>
    </div>
  );
}

function EvidenceTab({
  items,
  loading,
  statusFilter,
  setStatusFilter,
  typeFilter,
  setTypeFilter,
  onDeleteEvidence,
  onApproveEvidence,
}: {
  items: EvidenceItem[];
  loading: boolean;
  statusFilter: string;
  setStatusFilter: (value: string) => void;
  typeFilter: string;
  setTypeFilter: (value: string) => void;
  onDeleteEvidence: (id: string) => void;
  onApproveEvidence: (id: string) => void;
}) {
  const queryClient = useQueryClient();
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);

  // Load compliance controls so the upload form can attach evidence to a real control
  const { data: controlsData } = useQuery<{ items?: any[] } | any[]>({
    queryKey: ['compliance-controls-for-evidence'],
    queryFn: async () => {
      try {
        const res = await api.get('/compliance/controls', { params: { limit: 500 } });
        return res.data;
      } catch {
        return { items: [] };
      }
    },
  });
  const controlOptions: Array<{ value: string; label: string }> = (() => {
    const list = Array.isArray(controlsData) ? controlsData : (controlsData as any)?.items || [];
    return list.map((c: any) => ({
      value: c.id,
      label: `${c.control_id || c.code || c.id} — ${c.title || ''}`.slice(0, 120),
    }));
  })();

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const evidenceTypes = ['all', 'document', 'screenshot', 'log', 'config', 'scan'];
  const evidenceStatuses = ['all', 'pending', 'reviewed', 'approved'];

  const getTypeIcon = (type: string) => {
    const icons: Record<string, React.ComponentType> = {
      document: FileText,
      screenshot: Image,
      log: Square,
      config: Settings,
      scan: Shield,
    };
    return icons[type] || FileText;
  };

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center gap-2 mb-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">Filters</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Type
            </label>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              {evidenceTypes.map((type) => (
                <option key={type} value={type}>
                  {type.charAt(0).toUpperCase() + type.slice(1)}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              {evidenceStatuses.map((status) => (
                <option key={status} value={status}>
                  {status.charAt(0).toUpperCase() + status.slice(1)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Evidence Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Title
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Control
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Source
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Collected
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Status
              </th>
              <th className="px-6 py-3 text-center text-xs font-semibold text-gray-700 dark:text-gray-300">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {items.map((item) => {
              const TypeIcon = getTypeIcon(item.type);
              return (
                <tr key={item.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                    {item.title}
                  </td>
                  <td className="px-6 py-4 text-sm">
                    <div className="flex items-center gap-2 text-gray-600 dark:text-gray-400">
                      <TypeIcon className="w-4 h-4" />
                      {item.type}
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">
                    {item.control}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                    {item.source}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                    {(() => {
                      const ts = item.collected || item.created_at;
                      if (!ts) return '—';
                      const d = new Date(ts);
                      return isNaN(d.getTime()) ? '—' : d.toLocaleDateString();
                    })()}
                  </td>
                  <td className="px-6 py-4 text-sm">
                    <span
                      className={clsx(
                        'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                        getStatusColor(item.status)
                      )}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-center space-x-2">
                    {item.contentUrl && (
                      <button
                        title="View"
                        className="text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 p-2 rounded inline-block"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    )}
                    {item.status === 'reviewed' && (
                      <button
                        onClick={() => onApproveEvidence(item.id)}
                        title="Approve"
                        className="text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-900/20 p-2 rounded inline-block"
                      >
                        <CheckCircle className="w-4 h-4" />
                      </button>
                    )}
                    <button
                      onClick={() => onDeleteEvidence(item.id)}
                      title="Delete"
                      className="text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 p-2 rounded inline-block"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Upload and Actions */}
      <div className="flex gap-4">
        <button
          onClick={() => {
            setUploadFile(null);
            setUploadError(null);
            setShowUploadModal(true);
          }}
          className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
        >
          <Upload className="w-5 h-5" />
          Upload Evidence
        </button>
        <button
          onClick={async () => {
            // Verify integrity for every displayed evidence item. The
            // backend verifies the stored hash against the artifact and
            // flags any tampered rows.
            try {
              await Promise.all(
                items.map((it) =>
                  api.post(`/audit-evidence/evidence/verify?evidence_id=${encodeURIComponent(it.id)}`)
                )
              );
              queryClient.invalidateQueries({ queryKey: ['evidence-items'] });
            } catch (err) {
              console.error('Integrity verification failed:', err);
            }
          }}
          className="inline-flex items-center gap-2 px-6 py-3 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 font-medium"
        >
          <Zap className="w-5 h-5" />
          Verify Integrity
        </button>
      </div>

      {/* Upload Evidence modal — real multipart POST /audit-evidence/evidence/upload */}
      {showUploadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div
            className="absolute inset-0 bg-black/50 backdrop-blur-sm"
            onClick={() => !uploading && setShowUploadModal(false)}
          />
          <div className="relative w-full max-w-lg bg-white dark:bg-gray-900 rounded-lg shadow-2xl border border-gray-200 dark:border-gray-700">
            <div className="flex items-start justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <div>
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Upload Evidence</h2>
                <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                  Attach an evidence artifact to a specific compliance control. File is hashed (SHA-512) and stored for audit traceability.
                </p>
              </div>
            </div>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                const formEl = e.currentTarget;
                const control_id = (formEl.elements.namedItem('control_id') as HTMLSelectElement)?.value;
                const title = (formEl.elements.namedItem('title') as HTMLInputElement)?.value.trim();
                const evidence_type = (formEl.elements.namedItem('evidence_type') as HTMLSelectElement)?.value;
                const description = (formEl.elements.namedItem('description') as HTMLTextAreaElement)?.value;
                if (!uploadFile) {
                  setUploadError('Please choose a file to upload');
                  return;
                }
                if (!control_id) {
                  setUploadError('Please select a compliance control');
                  return;
                }
                if (!title) {
                  setUploadError('Title is required');
                  return;
                }
                setUploading(true);
                setUploadError(null);
                try {
                  const form = new FormData();
                  form.append('file', uploadFile);
                  form.append('control_id', control_id);
                  form.append('title', title);
                  form.append('evidence_type', evidence_type || 'document');
                  form.append('description', description || '');
                  await api.post('/audit-evidence/evidence/upload', form, {
                    headers: { 'Content-Type': 'multipart/form-data' },
                  });
                  queryClient.invalidateQueries({ queryKey: ['evidence-items'] });
                  queryClient.invalidateQueries({ queryKey: ['audit-evidence-dashboard'] });
                  setShowUploadModal(false);
                  setUploadFile(null);
                } catch (err: any) {
                  setUploadError(err?.response?.data?.detail || err?.message || 'Upload failed');
                } finally {
                  setUploading(false);
                }
              }}
            >
              <div className="px-6 py-5 space-y-4 max-h-[60vh] overflow-y-auto">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    File <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="file"
                    onChange={(e) => setUploadFile(e.target.files?.[0] || null)}
                    className="w-full text-sm text-gray-900 dark:text-gray-100 file:mr-3 file:py-2 file:px-4 file:border file:border-gray-300 file:rounded file:text-sm file:bg-white file:text-gray-700 hover:file:bg-gray-50"
                  />
                  {uploadFile && (
                    <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                      {uploadFile.name} · {(uploadFile.size / 1024).toFixed(1)} KB
                    </p>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Compliance Control <span className="text-red-500">*</span>
                  </label>
                  <select
                    name="control_id"
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                    defaultValue=""
                  >
                    <option value="">— Select a control —</option>
                    {controlOptions.map((o) => (
                      <option key={o.value} value={o.value}>{o.label}</option>
                    ))}
                  </select>
                  {controlOptions.length === 0 && (
                    <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-500">
                      No compliance controls loaded. Create controls in the Compliance module first.
                    </p>
                  )}
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Title <span className="text-red-500">*</span>
                  </label>
                  <input
                    name="title"
                    type="text"
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                    placeholder="Q1 2026 Access Review Screenshot"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Evidence Type</label>
                  <select
                    name="evidence_type"
                    defaultValue="document"
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                  >
                    <option value="document">Document</option>
                    <option value="screenshot">Screenshot</option>
                    <option value="log">Log</option>
                    <option value="configuration">Configuration</option>
                    <option value="scan_result">Scan Result</option>
                    <option value="policy">Policy</option>
                    <option value="procedure">Procedure</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                  <textarea
                    name="description"
                    rows={3}
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                    placeholder="Context, source system, scope..."
                  />
                </div>
                {uploadError && (
                  <div className="px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-300">
                    {uploadError}
                  </div>
                )}
              </div>
              <div className="border-t border-gray-200 dark:border-gray-700 px-6 py-4 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowUploadModal(false)}
                  disabled={uploading}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={uploading}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
                >
                  {uploading && <Loader2 className="w-4 h-4 animate-spin" />}
                  Upload
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

function PackagesTab({
  packages,
  loading,
}: {
  packages: Package[];
  loading: boolean;
}) {
  const queryClient = useQueryClient();
  const [showCreatePkg, setShowCreatePkg] = useState(false);
  const [pkgName, setPkgName] = useState('');
  const [pkgDescription, setPkgDescription] = useState('');
  const [pkgType, setPkgType] = useState<string>('custom');
  const [pkgFrameworkId, setPkgFrameworkId] = useState('');
  const [pkgAssessor, setPkgAssessor] = useState('');
  const [pkgDueDate, setPkgDueDate] = useState('');
  const [pkgError, setPkgError] = useState<string | null>(null);
  const [creatingPkg, setCreatingPkg] = useState(false);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const isUuid = (s: string) =>
    /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(s);

  return (
    <div className="space-y-6">
      {/* Create Package Button */}
      <button
        onClick={() => {
          setPkgName(`Evidence Package ${new Date().toLocaleDateString()}`);
          setPkgDescription('');
          setPkgType('custom');
          setPkgFrameworkId('');
          setPkgAssessor('');
          setPkgDueDate('');
          setPkgError(null);
          setShowCreatePkg(true);
        }}
        className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
      >
        <Plus className="w-5 h-5" />
        Create Package
      </button>

      {showCreatePkg && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true">
          <div
            className="absolute inset-0 bg-black/50 backdrop-blur-sm"
            onClick={() => !creatingPkg && setShowCreatePkg(false)}
          />
          <div className="relative w-full max-w-lg bg-white dark:bg-gray-900 rounded-lg shadow-2xl border border-gray-200 dark:border-gray-700">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Create Evidence Package</h2>
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                Bundle evidence artifacts for an audit, ConMon cycle, or assessment.
              </p>
            </div>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!pkgName.trim()) {
                  setPkgError('Name is required');
                  return;
                }
                setCreatingPkg(true);
                setPkgError(null);
                try {
                  const payload: Record<string, any> = {
                    name: pkgName.trim(),
                    description: pkgDescription || undefined,
                    package_type: pkgType,
                  };
                  if (pkgFrameworkId && isUuid(pkgFrameworkId.trim())) {
                    payload.framework_id = pkgFrameworkId.trim();
                  }
                  if (pkgAssessor.trim()) payload.assessor = pkgAssessor.trim();
                  if (pkgDueDate) payload.due_date = new Date(pkgDueDate).toISOString();
                  await api.post('/audit-evidence/packages/create', payload);
                  queryClient.invalidateQueries({ queryKey: ['audit-packages'] });
                  setShowCreatePkg(false);
                } catch (err: any) {
                  setPkgError(err?.response?.data?.detail || err?.message || 'Failed to create package');
                } finally {
                  setCreatingPkg(false);
                }
              }}
            >
              <div className="px-6 py-5 space-y-4 max-h-[60vh] overflow-y-auto">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Name <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    value={pkgName}
                    onChange={(e) => setPkgName(e.target.value)}
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                  <textarea
                    rows={2}
                    value={pkgDescription}
                    onChange={(e) => setPkgDescription(e.target.value)}
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Package Type <span className="text-red-500">*</span>
                  </label>
                  <select
                    value={pkgType}
                    onChange={(e) => setPkgType(e.target.value)}
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                  >
                    <option value="fedramp_conmon">FedRAMP ConMon</option>
                    <option value="cmmc_assessment">CMMC Assessment</option>
                    <option value="soc2_audit">SOC 2 Audit</option>
                    <option value="hipaa_audit">HIPAA Audit</option>
                    <option value="pci_audit">PCI Audit</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Framework ID (optional)</label>
                  <input
                    type="text"
                    value={pkgFrameworkId}
                    onChange={(e) => setPkgFrameworkId(e.target.value)}
                    placeholder="UUID of compliance framework (only sent if valid UUID)"
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Assessor</label>
                    <input
                      type="text"
                      value={pkgAssessor}
                      onChange={(e) => setPkgAssessor(e.target.value)}
                      placeholder="Optional"
                      className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Due Date</label>
                    <input
                      type="date"
                      value={pkgDueDate}
                      onChange={(e) => setPkgDueDate(e.target.value)}
                      className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>
                {pkgError && (
                  <div className="px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-300">
                    {pkgError}
                  </div>
                )}
              </div>
              <div className="border-t border-gray-200 dark:border-gray-700 px-6 py-4 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowCreatePkg(false)}
                  disabled={creatingPkg}
                  className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={creatingPkg}
                  className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
                >
                  {creatingPkg && <Loader2 className="w-4 h-4 animate-spin" />}
                  Create Package
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Package Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {packages.map((pkg) => (
          <div
            key={pkg.id}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  {pkg.name}
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  {pkg.framework}
                </p>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  pkg.status === 'draft'
                    ? 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400'
                    : pkg.status === 'in-review'
                    ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                    : pkg.status === 'submitted'
                    ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                    : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                )}
              >
                {(pkg.status || '').replace('-', ' ')}
              </span>
            </div>

            <div className="space-y-3 mb-4">
              <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
                <span>Evidence Items</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {pkg.evidenceCount}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
                <span>Due Date</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {new Date(pkg.dueDate || pkg.due_date || "").toLocaleDateString()}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
                <span>Assessor</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {pkg.assessor}
                </span>
              </div>
            </div>

            <div className="flex gap-2">
              {pkg.status === 'draft' && (
                <button
                  onClick={async () => {
                    try {
                      await api.post(`/audit-evidence/packages/${pkg.id}/submit`);
                      queryClient.invalidateQueries({ queryKey: ['audit-packages'] });
                    } catch (err) {
                      console.error('Package submit failed:', err);
                    }
                  }}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium"
                >
                  Submit
                </button>
              )}
              <button
                onClick={async () => {
                  try {
                    const res = await api.get(`/audit-evidence/packages/${pkg.id}/report`, {
                      responseType: 'blob',
                    });
                    const blob = res.data as Blob;
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${(pkg.name || 'package').replace(/\s+/g, '_')}.json`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                  } catch (err) {
                    console.error('Package report download failed:', err);
                  }
                }}
                className="flex-1 px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 text-sm font-medium"
              >
                View Details
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ConMonTab({
  statuses,
  loading,
  onRunConMon,
}: {
  statuses: ConMonStatus[];
  loading: boolean;
  onRunConMon: () => void;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ConMon Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {statuses.map((status) => (
          <div
            key={status.id}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-semibold text-gray-900 dark:text-white">
                {status.name}
              </h3>
              {status.active ? (
                <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
              )}
            </div>

            <div className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
              <div>
                Status: <span className="font-medium text-gray-900 dark:text-white capitalize">
                  {status.status || (status.active ? 'Active' : 'Inactive')}
                </span>
              </div>
              {status.compliance_percentage != null && (
                <div>
                  Compliance: <span className="font-medium text-gray-900 dark:text-white">
                    {status.compliance_percentage.toFixed(1)}%
                  </span>
                </div>
              )}
              <div>
                Last Run: <span className="font-medium text-gray-900 dark:text-white">
                  {(() => {
                    const ts = status.lastRun || status.last_run;
                    if (!ts) return '—';
                    const d = new Date(ts);
                    return isNaN(d.getTime()) ? '—' : d.toLocaleString();
                  })()}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Run ConMon Button */}
      <button
        onClick={onRunConMon}
        className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
      >
        <Play className="w-5 h-5" />
        Run ConMon Cycle
      </button>

      {/* Generate Monthly Report — streams real FedRAMP ConMon monthly JSON report from backend */}
      <button
        onClick={async () => {
          try {
            const response = await api.get('/audit-evidence/reports/monthly', {
              responseType: 'blob',
            });
            const blob = response.data as Blob;
            const cd = response.headers?.['content-disposition'];
            let filename = `pysoar_conmon_monthly_${new Date().toISOString().slice(0, 7)}.json`;
            if (cd && typeof cd === 'string') {
              const m = cd.match(/filename="?([^"]+)"?/);
              if (m) filename = m[1];
            }
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
          } catch (err) {
            console.error('Monthly report download failed:', err);
          }
        }}
        className="inline-flex items-center gap-2 px-6 py-3 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 font-medium"
      >
        <Download className="w-5 h-5" />
        Generate Monthly Report
      </button>
    </div>
  );
}

function KPICard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number | string;
  icon: React.ComponentType<{ className?: string }>;
  color: 'blue' | 'green' | 'orange' | 'purple';
}) {
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
    orange: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400',
    purple: 'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400',
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
      <div className="flex items-center justify-between">
        <div>
          <div className="text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
          <div className="text-sm text-gray-600 dark:text-gray-400">{label}</div>
        </div>
        <div className={clsx('p-3 rounded-lg', colorClasses[color])}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}
