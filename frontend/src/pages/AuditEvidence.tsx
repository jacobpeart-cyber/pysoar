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
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';
import { filenameFromDisposition, parseBlobError, saveBlob } from '../lib/download';

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
  collecting: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400',
  packaged: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  compliant: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  non_compliant: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
  not_assessed: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
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

// Every number is either a field GET /audit-evidence/dashboard/stats
// (AuditDashboardStats) or GET /audit-evidence/packages actually returns,
// or null when there is no such field; null renders "not available".
interface DashboardData {
  auditEventsThisMonth: number | null;
  auditEventsLast24h: number | null;
  evidenceItemsCount: number | null;
  approvedEvidenceCount: number | null;
  activePackagesCount: number | null;
  // FedRAMP Moderate readiness from control records; null without controls.
  readinessScore: number | null;
  readinessFramework: string | null;
  conmonStatus: string | null;
  lastConmonRun: string | null;
  recentEvents: AuditEvent[];
  // Packages whose evidence_items map is non-empty, out of all packages.
  packageCoverage: {
    withEvidence: number;
    withoutEvidence: number;
  } | null;
}

// AuditTrailResponse (src/schemas/audit_evidence.py)
interface AuditEvent {
  id: string;
  created_at?: string | null;
  event_type: string;
  action: string;
  actor_id: string;
  resource_type: string;
  resource_id?: string;
  result: string;
  risk_level: string;
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

// EvidencePackageResponse (src/schemas/audit_evidence.py).
interface Package {
  id: string;
  name: string;
  description?: string | null;
  package_type: string;
  framework_id?: string | null;
  status: string;
  evidence_items: Record<string, unknown>;
  control_mappings?: Record<string, unknown>;
  due_date?: string | null;
  assessor?: string | null;
  submitted_at?: string | null;
  package_hash?: string | null;
}

// GET /audit-evidence/conmon/status rows.
interface ConMonStatus {
  id: string;
  name: string;
  active: boolean;
  lastRun: string | null;
  status?: string;
  reason?: string | null;
  compliance_percentage?: number | null;
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
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [conmonReport, setConmonReport] = useState<Row | null>(null);
  const queryClient = useQueryClient();

  const { data: dashboardData, isLoading: dashboardLoading, error: dashboardError } = useQuery<DashboardData>({
    queryKey: ['audit-evidence-dashboard'],
    queryFn: async () => {
      // Previously this derived everything from /packages and
      // hardcoded auditEventsCount=0 + recentAuditEvents=[] — the
      // backend /dashboard/stats endpoint exists and returns real
      // counts + recent activity but was never called from the UI.
      // A failure of either request fails the query, so the tab shows the
      // server's error instead of a row of zeros.
      const [pkgRes, statsRes] = await Promise.all([
        api.get('/audit-evidence/packages'),
        api.get('/audit-evidence/dashboard/stats'),
      ]);
      const pkgs: Row[] = Array.isArray(pkgRes.data) ? pkgRes.data : (pkgRes.data?.items || []);
      const active = pkgs.filter((p) => p.status !== 'approved' && p.status !== 'archived').length;
      const hasEvidence = (p: Row) =>
        p?.evidence_items && typeof p.evidence_items === 'object' && Object.keys(p.evidence_items).length > 0;
      const withEv = pkgs.filter(hasEvidence).length;
      const stats = statsRes.data ?? {};
      const num = (v: unknown) => (typeof v === 'number' ? v : null);
      return {
        auditEventsThisMonth: num(stats.audit_entries_this_month),
        auditEventsLast24h: num(stats.audit_events_last_24h),
        evidenceItemsCount: num(stats.total_evidence_items),
        approvedEvidenceCount: num(stats.approved_evidence_items),
        activePackagesCount: active,
        readinessScore: num(stats.readiness_score),
        readinessFramework: stats.readiness_framework ?? null,
        conmonStatus: stats.conmon_status ?? null,
        lastConmonRun: stats.last_conmon_run ?? null,
        recentEvents: Array.isArray(stats.recent_audit_events) ? stats.recent_audit_events : [],
        packageCoverage: pkgs.length > 0
          ? { withEvidence: withEv, withoutEvidence: pkgs.length - withEv }
          : null,
      } as DashboardData;
    },
  });

  const { data: auditTrail, isLoading: auditLoading, error: auditError } = useQuery<AuditEvent[]>({
    queryKey: [
      'audit-trail',
      eventTypeFilter,
      resultFilter,
      dateRangeFilter,
    ],
    queryFn: async () => {
      // Map UI filters into the POST body the search endpoint actually
      // reads. Previously only `type` was passed, so resultFilter and
      // dateRangeFilter were silently ignored — user changed filters
      // and saw no change in results.
      const body: Record<string, string> = {};
      if (eventTypeFilter !== 'all') body.event_type = eventTypeFilter;
      if (resultFilter !== 'all') body.result = resultFilter;
      const rangeDays: Record<string, number> = {
        '1d': 1, '7d': 7, '30d': 30, '90d': 90,
      };
      const daysBack = rangeDays[dateRangeFilter] ?? 7;
      body.date_from = new Date(Date.now() - daysBack * 86_400_000).toISOString();
      const response = await api.post('/audit-evidence/audit/search', body);
      const d = response.data;
      return Array.isArray(d) ? d : (d?.items || []);
    },
  });

  const { data: evidenceItems, isLoading: evidenceLoading, error: evidenceError } = useQuery<EvidenceItem[]>({
    queryKey: ['evidence-items', evidenceStatusFilter, evidenceTypeFilter],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (evidenceStatusFilter !== 'all') params.status = evidenceStatusFilter;
      if (evidenceTypeFilter !== 'all') params.evidence_type = evidenceTypeFilter;
      const response = await api.get('/audit-evidence/evidence/list', { params });
      const d = response.data;
      if (Array.isArray(d)) return d;
      if (d && Array.isArray(d.items)) return d.items;
      return [];
    },
  });

  const { data: packages, isLoading: packagesLoading, error: packagesError } = useQuery<Package[]>({
    queryKey: ['audit-packages'],
    queryFn: async () => {
      const response = await api.get('/audit-evidence/packages');
      return response.data;
    },
  });

  const { data: conmonStatuses, isLoading: conmonLoading, error: conmonError } = useQuery<ConMonStatus[]>({
    queryKey: ['conmon-status'],
    queryFn: async () => {
      const response = await api.get('/audit-evidence/conmon/status');
      const d = response.data;
      if (Array.isArray(d)) return d;
      // An object without rows is not a status list; show nothing rather
      // than inventing a run time.
      return [];
    },
  });

  // Runs and stores a ConMon cycle (its time becomes lastRun).
  const runConMonMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/audit-evidence/conmon/run');
      return response.data;
    },
    onSuccess: (data: Row) => {
      setActionError(null);
      setConmonReport(data);
      queryClient.invalidateQueries({ queryKey: ['conmon-status'] });
      queryClient.invalidateQueries({ queryKey: ['audit-evidence-dashboard'] });
    },
    onError: (err: unknown) => setActionError({ what: 'run the ConMon cycle', error: err }),
  });

  const deleteEvidenceMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/audit-evidence/evidence/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence-items'] });
    },
    onError: (err: unknown) => setActionError({ what: 'delete the evidence item', error: err }),
  });

  const approveEvidenceMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await api.post(`/audit-evidence/evidence/${id}/approve`);
      return response.data;
    },
    onSuccess: () => {
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['evidence-items'] });
    },
    onError: (err: unknown) => setActionError({ what: 'approve the evidence', error: err }),
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
        <div className="flex items-start gap-2">
          <div className="flex-1"><ActionErrorBanner what={actionError.what} error={actionError.error} /></div>
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
        <>
          <LoadErrorBanner what="the audit dashboard" error={dashboardError} />
          {!dashboardError && (
            <DashboardTab
              data={dashboardData}
              loading={dashboardLoading}
              recentEvents={(dashboardData?.recentEvents ?? []).slice(0, 5)}
              recentEventsError={null}
            />
          )}
        </>
      )}

      {/* Audit Trail Tab */}
      {activeTab === 'audit-trail' && <LoadErrorBanner what="the audit trail" error={auditError} />}
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
      {activeTab === 'evidence' && <LoadErrorBanner what="evidence items" error={evidenceError} />}
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
        <>
          <LoadErrorBanner what="evidence packages" error={packagesError} />
          <PackagesTab packages={packages || []} loading={packagesLoading} evidence={evidenceItems || []} />
        </>
      )}

      {/* ConMon Tab */}
      {activeTab === 'conmon' && <LoadErrorBanner what="continuous monitoring status" error={conmonError} />}
      {activeTab === 'conmon' && conmonReport && (
        <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 flex justify-between gap-4">
          <span>
            ConMon cycle {conmonReport.persisted ? 'stored' : 'computed (not stored)'}: overall{' '}
            <span className="font-medium">{String(conmonReport.overall_status ?? 'not_assessed').replace(/_/g, ' ')}</span>
            {conmonReport.assessment_id ? ` · assessment ${conmonReport.assessment_id}` : ''}.
          </span>
          <button onClick={() => setConmonReport(null)} className="text-xs underline">dismiss</button>
        </div>
      )}
      {activeTab === 'conmon' && (
        <ConMonTab
          statuses={conmonStatuses || []}
          loading={conmonLoading}
          running={runConMonMutation.isPending}
          onRunConMon={() => runConMonMutation.mutate()}
        />
      )}
    </div>
  );
}

function DashboardTab({
  data,
  loading,
  recentEvents,
  recentEventsError,
}: {
  data?: DashboardData;
  loading: boolean;
  recentEvents: AuditEvent[];
  recentEventsError: unknown;
}) {
  const fmt = (v: number | null | undefined) => (typeof v === 'number' ? v : 'not available');
  const cov = data?.packageCoverage ?? null;
  const covTotal = cov ? cov.withEvidence + cov.withoutEvidence : 0;
  const covPct = cov && covTotal > 0 ? (cov.withEvidence / covTotal) * 100 : 0;
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
          label={`Audit Events (this month)${typeof data?.auditEventsLast24h === 'number' ? ` · ${data.auditEventsLast24h} in 24 h` : ''}`}
          value={fmt(data?.auditEventsThisMonth)}
          icon={Square}
          color="blue"
        />
        <KPICard
          label={`Evidence Items${typeof data?.approvedEvidenceCount === 'number' ? ` · ${data.approvedEvidenceCount} approved` : ''}`}
          value={fmt(data?.evidenceItemsCount)}
          icon={FileText}
          color="green"
        />
        <KPICard
          label="Active Packages"
          value={fmt(data?.activePackagesCount)}
          icon={Calendar}
          color="orange"
        />
        <KPICard
          label={`Readiness (${data?.readinessFramework || 'FedRAMP Moderate'})`}
          value={typeof data?.readinessScore === 'number' ? `${data.readinessScore}%` : 'not available'}
          icon={CheckCircle}
          color="purple"
        />
      </div>
      <p className="text-xs text-gray-500 dark:text-gray-400">
        ConMon: {String(data?.conmonStatus ?? 'not_run').replace(/_/g, ' ')}
        {data?.lastConmonRun ? ` · last cycle ${new Date(data.lastConmonRun).toLocaleString()}` : ' · no cycle stored yet'}
        {typeof data?.readinessScore !== 'number' && ' · readiness is not available until FedRAMP control records exist'}
      </p>

      {/* Evidence Coverage Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Evidence Coverage by Package
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
                strokeDasharray={`${covPct * 3.4} 340`}
                className="text-green-500 transition-all duration-500"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <div className="text-2xl font-bold text-gray-900 dark:text-white">
                  {cov ? cov.withEvidence : 'not available'}
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
                    Packages with Evidence
                  </span>
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">
                    {cov ? cov.withEvidence : 'not available'}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div className="h-full bg-green-500 rounded-full" style={{ width: `${covPct}%` }} />
                </div>
              </div>
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    Packages without Evidence
                  </span>
                  <span className="text-sm font-semibold text-gray-900 dark:text-white">
                    {cov ? cov.withoutEvidence : 'not available'}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div className="h-full bg-orange-500 rounded-full" style={{ width: `${cov && covTotal > 0 ? 100 - covPct : 0}%` }} />
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
          <LoadErrorBanner what="recent audit events" error={recentEventsError} />
          {!recentEventsError && recentEvents.length === 0 && (
            <p className="text-sm text-gray-500 dark:text-gray-400">No audit events in the selected range.</p>
          )}
          {recentEvents.map((event) => (
            <div
              key={event.id}
              className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
            >
              <div className="flex-1">
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {event.action}
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                  {event.actor_id} on {event.resource_type}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={clsx('text-xs font-medium', getRiskColor(event.risk_level))}>
                  {event.risk_level}
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

  // EventTypeEnum values the search endpoint filters on.
  const eventTypes = ['all', 'access', 'change', 'admin', 'policy', 'compliance', 'security', 'data'];
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
                  {event.created_at ? new Date(event.created_at).toLocaleString() : '—'}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {event.event_type}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white font-medium">
                  {event.action}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">
                  {event.actor_id}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {event.resource_type}{event.resource_id ? ` ${event.resource_id}` : ''}
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
                      getRiskColor(event.risk_level)
                    )}
                  >
                    {event.risk_level}
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
  const [collectResult, setCollectResult] = useState<Row | null>(null);
  const [collectError, setCollectError] = useState<unknown>(null);
  const [downloadError, setDownloadError] = useState<unknown>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  // Stream the stored artifact back (tenant-scoped on the server; a path
  // outside the organisation's evidence root answers 403, a missing file 404).
  const downloadEvidence = async (item: EvidenceItem) => {
    setDownloadError(null);
    setDownloadingId(item.id);
    try {
      const res = await api.get(`/audit-evidence/evidence/${item.id}/download`, { responseType: 'blob' });
      const fallback = (item.title || `evidence-${item.id}`).replace(/[^\w.-]+/g, '_');
      saveBlob(res.data as Blob, filenameFromDisposition(res.headers?.['content-disposition'], fallback));
    } catch (err) {
      setDownloadError(await parseBlobError(err));
    } finally {
      setDownloadingId(null);
    }
  };
  const [collecting, setCollecting] = useState(false);

  // Run every enabled automated evidence rule: each one collects, reports
  // awaiting_integration, finds no matching controls, or fails.
  const collectAll = async () => {
    setCollecting(true);
    setCollectError(null);
    setCollectResult(null);
    try {
      const res = await api.post('/audit-evidence/evidence/collect-all', {});
      setCollectResult(res.data);
      queryClient.invalidateQueries({ queryKey: ['evidence-items'] });
    } catch (err) {
      setCollectError(err);
    } finally {
      setCollecting(false);
    }
  };

  // Load compliance controls so the upload form can attach evidence to a real control
  const { data: controlsData, error: controlsError } = useQuery<{ items?: Row[] } | Row[]>({
    queryKey: ['compliance-controls-for-evidence'],
    queryFn: async () => {
      const res = await api.get('/compliance/controls', { params: { limit: 500 } });
      return res.data;
    },
  });
  const controlOptions: Array<{ value: string; label: string }> = (() => {
    const list: Row[] = Array.isArray(controlsData) ? controlsData : controlsData?.items || [];
    return list.map((c: Row) => ({
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
    const icons: Record<string, React.ComponentType<{ className?: string }>> = {
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
      <div className="flex flex-wrap items-center gap-3">
        <button
          onClick={collectAll}
          disabled={collecting}
          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium disabled:opacity-50"
        >
          {collecting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
          Run Automated Evidence Rules
        </button>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          Rules that need an integration that is not installed report &quot;awaiting integration&quot; and write nothing.
        </span>
      </div>
      <ActionErrorBanner what="run the automated evidence rules" error={collectError} />
      <ActionErrorBanner what="download the evidence file" error={downloadError} />
      {collectResult && (
        <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 space-y-1">
          <p>
            {String(collectResult.status ?? '').replace(/_/g, ' ')}: {collectResult.rules_run ?? 0} rule(s) run, {collectResult.collected ?? 0} collected,{' '}
            {collectResult.evidence_written ?? 0} evidence row(s) written, {collectResult.awaiting_integration ?? 0} awaiting an integration,{' '}
            {collectResult.no_matching_controls ?? 0} without matching controls, {collectResult.failed ?? 0} failed.
            {collectResult.reason ? ` ${collectResult.reason}` : ''}
          </p>
          {collectResult.results && typeof collectResult.results === 'object' && Object.keys(collectResult.results).length > 0 && (
            <ul className="text-xs list-disc ml-5 max-h-40 overflow-y-auto">
              {(Object.values(collectResult.results) as Row[]).map((r: Row, i: number) => (
                <li key={i}>
                  {r.rule_name ?? r.rule_id ?? `rule ${i + 1}`}: {String(r.status ?? '').replace(/_/g, ' ')}
                  {r.evidence?.reason ? ` (${r.evidence.reason})` : r.reason ? ` (${r.reason})` : ''}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
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
                    {item.contentUrl ? (
                      <button
                        onClick={() => downloadEvidence(item)}
                        disabled={downloadingId === item.id}
                        title="Download the evidence file"
                        className="text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 p-2 rounded inline-block disabled:opacity-50"
                      >
                        {downloadingId === item.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
                      </button>
                    ) : (
                      <span className="text-xs text-gray-400" title="This evidence row was recorded without an uploaded file">
                        no file
                      </span>
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
                  {controlsError ? (
                    <div className="mt-1"><LoadErrorBanner what="compliance controls" error={controlsError} /></div>
                  ) : controlOptions.length === 0 && (
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
  evidence,
}: {
  packages: Package[];
  loading: boolean;
  evidence: EvidenceItem[];
}) {
  const queryClient = useQueryClient();
  const [pkgActionError, setPkgActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [pkgNotice, setPkgNotice] = useState<string | null>(null);
  const [addingTo, setAddingTo] = useState<Package | null>(null);
  const [detailId, setDetailId] = useState<string | null>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<string[]>([]);
  const pkgAction = async (what: string, fn: () => Promise<string | void>) => {
    setPkgActionError(null);
    setPkgNotice(null);
    try {
      const msg = await fn();
      if (msg) setPkgNotice(msg);
      queryClient.invalidateQueries({ queryKey: ['audit-packages'] });
      queryClient.invalidateQueries({ queryKey: ['audit-evidence-dashboard'] });
    } catch (error) {
      setPkgActionError({ what, error });
    }
  };
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
      {pkgActionError && <ActionErrorBanner what={pkgActionError.what} error={pkgActionError.error} />}
      {pkgNotice && (
        <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 flex justify-between gap-4">
          <span>{pkgNotice}</span>
          <button onClick={() => setPkgNotice(null)} className="text-xs underline">dismiss</button>
        </div>
      )}
      {addingTo && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setAddingTo(null)}>
          <div className="bg-white dark:bg-gray-900 rounded-lg shadow-xl w-full max-w-lg mx-4 p-6 space-y-3" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Add evidence to {addingTo.name}</h2>
            {evidence.length === 0 ? (
              <p className="text-sm text-gray-500">No evidence item is stored. Upload or collect evidence first.</p>
            ) : (
              <div className="max-h-72 overflow-y-auto space-y-1 text-sm">
                {evidence.map((ev) => (
                  <label key={ev.id} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={selectedEvidence.includes(ev.id)}
                      onChange={(e) => setSelectedEvidence((prev) => (e.target.checked ? [...prev, ev.id] : prev.filter((x) => x !== ev.id)))}
                    />
                    <span className="truncate">{ev.title}</span>
                    <span className="text-xs text-gray-500">{ev.control} · {ev.status}</span>
                  </label>
                ))}
              </div>
            )}
            <div className="flex gap-2">
              <button
                disabled={selectedEvidence.length === 0}
                onClick={() => {
                  const target = addingTo;
                  pkgAction('add evidence to the package', async () => {
                    const res = await api.post(`/audit-evidence/packages/${target.id}/evidence`, { evidence_ids: selectedEvidence });
                    setAddingTo(null);
                    return `${res.data?.added ?? 0} item(s) added to ${target.name}${res.data?.not_found?.length ? `, ${res.data.not_found.length} not found` : ''}; the package now holds ${res.data?.evidence_count ?? 0}.`;
                  });
                }}
                className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg disabled:opacity-50"
              >
                Add {selectedEvidence.length || ''} item(s)
              </button>
              <button onClick={() => setAddingTo(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
            </div>
          </div>
        </div>
      )}
      {packages.length === 0 && (
        <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
          No evidence package yet.
        </p>
      )}
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
                  {String(pkg.package_type || '').replace(/_/g, ' ')}
                </p>
              </div>
              <span className={clsx('inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium', getStatusColor(pkg.status))}>
                {(pkg.status || '').replace(/[-_]/g, ' ')}
              </span>
            </div>

            <div className="space-y-3 mb-4">
              <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
                <span>Evidence Items</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {Object.keys(pkg.evidence_items || {}).length}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
                <span>Due Date</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {pkg.due_date ? new Date(pkg.due_date).toLocaleDateString() : 'no due date'}
                </span>
              </div>
              <div className="flex items-center justify-between text-sm text-gray-600 dark:text-gray-400">
                <span>Assessor</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {pkg.assessor || '—'}
                </span>
              </div>
              {pkg.package_hash && (
                <div className="text-xs text-gray-500 font-mono truncate" title={pkg.package_hash}>sha256 {pkg.package_hash}</div>
              )}
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setDetailId(pkg.id)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm font-medium"
              >
                Details
              </button>
              {!pkg.submitted_at && (
                <button
                  onClick={() => { setSelectedEvidence([]); setAddingTo(pkg); }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm font-medium"
                >
                  Add Evidence
                </button>
              )}
              {!pkg.submitted_at && (
                <button
                  onClick={() => pkgAction(`build ${pkg.name}`, async () => {
                    const res = await api.post(`/audit-evidence/packages/${pkg.id}/package`);
                    return `${pkg.name} built${res.data?.package_hash ? ` (sha256 ${String(res.data.package_hash).slice(0, 16)}…)` : ''}.`;
                  })}
                  title="Assemble and hash the package (refused while it holds no evidence)"
                  className="flex-1 px-4 py-2 border border-blue-600 text-blue-700 dark:text-blue-300 rounded-lg text-sm font-medium"
                >
                  Build Package
                </button>
              )}
              {!pkg.submitted_at && (
                <button
                  onClick={() => pkgAction(`submit ${pkg.name}`, async () => {
                    await api.post(`/audit-evidence/packages/${pkg.id}/submit`);
                    return `${pkg.name} submitted.`;
                  })}
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
                    setPkgActionError({ what: 'download the package report', error: err });
                  }
                }}
                className="flex-1 px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 text-sm font-medium"
              >
                Download Report
              </button>
            </div>
          </div>
        ))}
      </div>
      {detailId && <PackageDetail packageId={detailId} evidence={evidence} onClose={() => setDetailId(null)} />}
    </div>
  );
}

// GET /audit-evidence/packages/{id}: the package as stored, re-read from the
// server so the contents reflect the last Add Evidence / Build call.
function PackageDetail({
  packageId,
  evidence,
  onClose,
}: {
  packageId: string;
  evidence: EvidenceItem[];
  onClose: () => void;
}) {
  const { data: pkg, isLoading, error } = useQuery<Package & Row>({
    queryKey: ['audit-package', packageId],
    queryFn: async () => (await api.get(`/audit-evidence/packages/${packageId}`)).data,
    staleTime: 0,
  });
  const titles = new Map(evidence.map((e) => [e.id, e.title]));
  const items = Object.entries(pkg?.evidence_items || {});
  const mappings = Object.entries((pkg?.control_mappings as Record<string, unknown> | undefined) || {});
  const show = (v: unknown) => (typeof v === 'string' ? v : JSON.stringify(v));
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40" onClick={onClose}>
      <div
        role="dialog"
        aria-label="Evidence package"
        className="w-full max-w-2xl h-full overflow-y-auto bg-white dark:bg-gray-800 p-6 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{pkg?.name ?? 'Evidence package'}</h2>
            <p className="text-xs font-mono text-gray-500">{packageId}</p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-800 dark:hover:text-gray-200">Close</button>
        </div>
        <LoadErrorBanner what="the evidence package" error={error} />
        {isLoading && <Loader2 className="w-5 h-5 animate-spin text-gray-400" />}
        {pkg && (
          <div className="space-y-4 text-sm">
            <dl className="grid grid-cols-2 gap-2">
              {[
                ['Status', pkg.status],
                ['Type', pkg.package_type],
                ['Framework', pkg.framework_id],
                ['Assessor', pkg.assessor],
                ['Due', pkg.due_date ? new Date(pkg.due_date).toLocaleDateString() : null],
                ['Submitted', pkg.submitted_at ? new Date(pkg.submitted_at).toLocaleString() : null],
              ].map(([k, v]) => (
                <div key={String(k)}>
                  <dt className="text-xs text-gray-500">{k}</dt>
                  <dd className="text-gray-900 dark:text-white">{v || 'not set'}</dd>
                </div>
              ))}
            </dl>
            {pkg.description && <p className="text-gray-700 dark:text-gray-300">{pkg.description}</p>}
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Package hash</h3>
              <p className="font-mono text-xs break-all text-gray-700 dark:text-gray-300">
                {pkg.package_hash || 'not built yet: Build Package hashes the evidence it holds'}
              </p>
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Evidence items ({items.length})</h3>
              {items.length === 0 ? (
                <p className="text-xs text-gray-500">No evidence attached. Build and Submit are refused (409 package_empty) until some is.</p>
              ) : (
                <ul className="space-y-1 text-xs">
                  {items.map(([id, v]) => (
                    <li key={id} className="border border-gray-200 dark:border-gray-700 rounded p-2">
                      <span className="font-medium">{titles.get(id) ?? id}</span>
                      <span className="block font-mono text-gray-500 break-all">{show(v)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <div>
              <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Control mappings ({mappings.length})</h3>
              {mappings.length === 0 ? (
                <p className="text-xs text-gray-500">No control mappings recorded on this package.</p>
              ) : (
                <ul className="space-y-1 text-xs font-mono">
                  {mappings.map(([k, v]) => (
                    <li key={k}>{k}: {show(v)}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ConMonTab({
  statuses,
  loading,
  running,
  onRunConMon,
}: {
  statuses: ConMonStatus[];
  loading: boolean;
  running: boolean;
  onRunConMon: () => void;
}) {
  const [reportError, setReportError] = useState<unknown>(null);
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
              {status.status === 'not_assessed' ? (
                <Clock className="w-5 h-5 text-gray-400" />
              ) : status.active ? (
                <CheckCircle className="w-5 h-5 text-green-600 dark:text-green-400" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
              )}
            </div>

            <div className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
              <div>
                Status: <span className="font-medium text-gray-900 dark:text-white">
                  {String(status.status || (status.active ? 'passing' : 'failing')).replace(/_/g, ' ')}
                </span>
              </div>
              <div>
                Compliance: <span className="font-medium text-gray-900 dark:text-white">
                  {status.compliance_percentage != null ? `${status.compliance_percentage.toFixed(1)}%` : 'not available'}
                </span>
              </div>
              {status.reason && <div className="text-xs">{status.reason}</div>}
              <div>
                Last Run: <span className="font-medium text-gray-900 dark:text-white">
                  {(() => {
                    const ts = status.lastRun || status.last_run;
                    if (!ts) return 'no cycle stored';
                    const d = new Date(ts);
                    return isNaN(d.getTime()) ? '—' : d.toLocaleString();
                  })()}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {statuses.length === 0 && (
        <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
          No ConMon check is reported.
        </p>
      )}
      <ActionErrorBanner what="download the monthly report" error={reportError} />

      {/* Run ConMon Button */}
      <button
        onClick={onRunConMon}
        disabled={running}
        className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium disabled:opacity-50"
      >
        {running ? <Loader2 className="w-5 h-5 animate-spin" /> : <Play className="w-5 h-5" />}
        Run and Store ConMon Cycle
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
            setReportError(err);
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
