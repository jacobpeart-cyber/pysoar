import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ChevronDown,
  ChevronRight,
  Plus,
  Filter,
  Play,
  Loader2,
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  Clock,
  Zap,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';

const NA = 'not available';
// Only agents enrolled with this capability run whole-benchmark scans.
const STIG_SCAN_CAPABILITY = 'stig_scan';

type TabType = 'dashboard' | 'benchmarks' | 'results' | 'remediation';

type Severity = 'CAT I' | 'CAT II' | 'CAT III';
type RuleStatus = 'Open' | 'Not a Finding' | 'N/A' | 'Not Reviewed';

// Field names match the backend snake_case STIGDashboardStats schema.
// Historical note: the interface used camelCase (benchmarksLoaded, etc.)
// and the dashboard silently showed zeros forever because none of the
// fields existed on the backend response.
interface DashboardData {
  total_benchmarks: number;
  total_scans: number;
  average_compliance: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  compliance_by_benchmark: Array<{ name: string; percentage: number }>;
  findings_by_severity: { [key: string]: number };
  recent_scans: Scan[];
  top_failing_rules: Array<{ rule_id: string; title: string; failures: number }>;
  last_scan_date: string | null;
  compliance_trend: string;
  scans_not_run?: number;
  scans_pending?: number;
}

interface Benchmark {
  id: string;
  name: string;
  platform: string;
  version: string;
  totalRules: number;
  findings: { [key in Severity]: number };
  lastScanDate: string;
}

// Scan statuses: completed, failed, pending_results (awaiting an ARF
// upload), dispatched / awaiting_approval (agent command), not_run /
// no_agent / no_automatable_rules (nothing was evaluated; see status_reason).
interface Scan {
  id: string;
  host: string;
  benchmark: string;
  status: string;
  status_reason?: string | null;
  agent_id?: string | null;
  command_id?: string | null;
  // Null unless the scan completed with results.
  compliance: number | null;
  findings: {
    open: number;
    naf: number;
    na: number;
    nr: number;
  };
  cat?: { i: number; ii: number; iii: number };
  date: string;
}

interface ScanResult {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  status: RuleStatus;
  description?: string;
}


interface ComplianceAgent {
  id: string;
  hostname: string;
  capabilities?: string[];
  status?: string;
}

// STIGRule.severity → DISA category label.
const SEVERITY_TO_CAT: Record<string, Severity> = {
  high: 'CAT I',
  medium: 'CAT II',
  low: 'CAT III',
};

// Per-rule status values the engine/ARF ingest store → UI labels.
const RULE_STATUS_LABEL: Record<string, RuleStatus> = {
  open: 'Open',
  not_a_finding: 'Not a Finding',
  not_applicable: 'N/A',
  not_reviewed: 'Not Reviewed',
};

// STIGScanResultResponse → the Scan row shape the tables render.
function scanFromApi(s: Row): Scan {
  return {
    id: s.id,
    host: s.target_host,
    benchmark: s.benchmark_id_ref,
    status: s.status,
    status_reason: s.status_reason ?? null,
    agent_id: s.agent_id ?? null,
    command_id: s.command_id ?? null,
    compliance: s.status === 'completed' && s.compliance_percentage != null ? Number(s.compliance_percentage) : null,
    findings: {
      open: s.open_findings ?? 0,
      naf: s.not_a_finding ?? 0,
      na: s.not_applicable ?? 0,
      nr: s.not_reviewed ?? 0,
    },
    cat: { i: s.cat1_open ?? 0, ii: s.cat2_open ?? 0, iii: s.cat3_open ?? 0 },
    date: s.completed_at ?? s.started_at ?? s.created_at ?? '',
  };
}

function ComplianceCell({ scan }: { scan: Scan }) {
  if (scan.compliance === null) {
    return (
      <span className="text-xs text-gray-500 dark:text-gray-400" title={scan.status_reason ?? undefined}>
        {NA}{scan.status_reason ? ` (${scan.status_reason})` : ` (${String(scan.status).replace(/_/g, ' ')})`}
      </span>
    );
  }
  return (
    <>
      <div className="w-16 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden inline-block align-middle">
        <div
          className={clsx('h-full rounded-full', scan.compliance >= 80 ? 'bg-green-500' : scan.compliance >= 60 ? 'bg-yellow-500' : 'bg-red-500')}
          style={{ width: `${scan.compliance}%` }}
        />
      </div>
      <span className="text-xs text-gray-600 dark:text-gray-400 ml-2">{scan.compliance.toFixed(1)}%</span>
    </>
  );
}

export default function STIGCompliance() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [platformFilter, setPlatformFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [launchScanFor, setLaunchScanFor] = useState<string | null>(null);
  const [launchResult, setLaunchResult] = useState<Row | null>(null);
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [remediationResult, setRemediationResult] = useState<Row | null>(null);
  const queryClient = useQueryClient();

  const { data: dashboardData, isLoading: dashboardLoading, error: dashboardError } = useQuery<DashboardData>({
    queryKey: ['stig-dashboard'],
    queryFn: async () => {
      const response = await api.get('/stig/dashboard/stats');
      return response.data;
    },
  });

  const { data: benchmarks, isLoading: benchmarksLoading, error: benchmarksError } = useQuery<Benchmark[]>({
    queryKey: ['stig-benchmarks', platformFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (platformFilter !== 'all') params.append('platform', platformFilter);
      const response = await api.get(`/stig/benchmarks?${params}`);
      // Normalize STIGBenchmarkResponse (snake_case: `title`,
      // `total_rules`, `category_N_count`, `last_scan_at`) into the
      // camelCase card shape.
      const raw = response.data;
      const list = Array.isArray(raw) ? raw : (raw?.items ?? raw?.benchmarks ?? []);
      return list.map((b: Row) => ({
        id: b.id ?? '',
        name: b.title || b.benchmark_id || 'Untitled benchmark',
        platform: b.platform ?? '',
        version: b.version ?? '',
        totalRules: b.total_rules,
        findings: {
          'CAT I': b.category_1_count,
          'CAT II': b.category_2_count,
          'CAT III': b.category_3_count,
        },
        lastScanDate: b.last_scan_at ?? '',
      }));
    },
  });

  const { data: scans, isLoading: scansLoading, error: scansError } = useQuery<Scan[]>({
    queryKey: ['stig-scans'],
    queryFn: async () => {
      const response = await api.get('/stig/scans');
      return (Array.isArray(response.data) ? response.data : []).map(scanFromApi);
    },
    // Poll every 10s when the user is on the Scan Results tab so
    // a newly-launched scan transitions through queued → running →
    // completed live, and an ARF upload's effect is visible without
    // a manual reload.
    refetchInterval: activeTab === 'results' ? 10000 : false,
  });

  const { data: expandedScanResults, isLoading: scanResultsLoading, error: scanResultsError } = useQuery<
    ScanResult[]
  >({
    queryKey: ['stig-scan-results', expandedScan],
    queryFn: async () => {
      if (!expandedScan) return [];
      const response = await api.get(`/stig/scans/${expandedScan}`);
      // STIGScanResultResponse.findings is {rule_id: {status, severity, title?}}.
      const findings = response.data?.findings;
      if (!findings || typeof findings !== 'object') return [];
      return Object.entries(findings as Record<string, Row>).map(([ruleId, f]) => ({
        id: ruleId,
        ruleId,
        title: f?.title ?? '',
        severity: (SEVERITY_TO_CAT[f?.severity] ?? f?.severity ?? '') as Severity,
        status: (RULE_STATUS_LABEL[f?.status] ?? f?.status ?? '') as RuleStatus,
        description: f?.finding_details ?? f?.comments ?? undefined,
      }));
    },
    enabled: !!expandedScan,
  });

  // Remediation works per completed scan with open findings.
  const remediations: Scan[] = (scans ?? []).filter((s) => s.status === 'completed' && s.findings.open > 0);

  const runScanMutation = useMutation({
    mutationFn: async (params: { host: string; benchmark_id: string; scan_type: string }) => {
      const response = await api.post('/stig/scans/launch', params);
      return response.data;
    },
    onSuccess: (data: Row) => {
      setActionError(null);
      setLaunchResult(data);
      queryClient.invalidateQueries({ queryKey: ['stig-scans'] });
      queryClient.invalidateQueries({ queryKey: ['stig-dashboard'] });
    },
    onError: (err: unknown) => setActionError({ what: 'launch the STIG scan', error: err }),
  });

  const autoRemediateMutation = useMutation({
    mutationFn: async (params: { scan_result_id: string; categories: string[] }) => {
      // Backend remediator matches on severity = high/medium/low (or
      // critical). Frontend uses STIG CAT I/II/III labels. Translate
      // before dispatch — previously we sent "CAT I" and matched zero
      // rules, so Auto-Remediate always reported "remediated: 0".
      const catMap: Record<string, string> = {
        'CAT I': 'high',
        'CAT II': 'medium',
        'CAT III': 'low',
      };
      const severities = (params.categories || [])
        .map((c) => catMap[c] ?? c.toLowerCase())
        .filter(Boolean);
      const response = await api.post('/stig/remediate/auto', {
        scan_result_id: params.scan_result_id,
        categories: severities,
      });
      return response.data;
    },
    onError: (err: unknown) => setActionError({ what: 'auto-remediate', error: err }),
    onSuccess: (data: Row) => {
      setActionError(null);
      setRemediationResult(data);
      queryClient.invalidateQueries({ queryKey: ['stig-scans'] });
      queryClient.invalidateQueries({ queryKey: ['stig-dashboard'] });
    },
  });

  const getSeverityColor = (severity: Severity | string) => {
    const colors: Record<string, string> = {
      'CAT I': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      'CAT II': 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
      'CAT III': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
    };
    return colors[severity] || 'bg-gray-100 text-gray-800';
  };

  const getStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      'completed': 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      'in-progress': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
      'failed': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      'Open': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      'Not a Finding': 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      'N/A': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400',
      'Not Reviewed': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">STIG/SCAP Compliance</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Security Technical Implementation Guide scan results and remediation tracking
        </p>
      </div>

      {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
      {launchResult && (
        <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 flex justify-between gap-4">
          <span>
            Scan on <span className="font-mono">{launchResult.host}</span> ({launchResult.benchmark}):{' '}
            <span className="font-medium">{String(launchResult.status).replace(/_/g, ' ')}</span>
            {launchResult.status_reason ? `. ${launchResult.status_reason}` : ''}
            {launchResult.command_id ? ` · agent command ${launchResult.command_id}` : ''}
            {launchResult.total_checks != null ? ` · ${launchResult.total_checks} rule(s) in the benchmark` : ''}
            {launchResult.note ? ` · ${launchResult.note}` : ''}
            {' '}No compliance figure is recorded until results arrive.
          </span>
          <button onClick={() => setLaunchResult(null)} className="text-xs underline">dismiss</button>
        </div>
      )}
      {remediationResult && (
        <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 flex justify-between gap-4">
          <span>
            Auto-remediate on {remediationResult.host}: {remediationResult.attempted ?? 0} fix(es) attempted,{' '}
            {remediationResult.awaiting_integration ?? 0} awaiting an integration, {remediationResult.failed ?? 0} failed.
            {remediationResult.note ? ` ${remediationResult.note}` : ''}
          </span>
          <button onClick={() => setRemediationResult(null)} className="text-xs underline">dismiss</button>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-8 -mb-px" aria-label="Tabs">
          {(['dashboard', 'benchmarks', 'results', 'remediation'] as const).map((tab) => (
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
              {tab === 'benchmarks' && 'Benchmarks'}
              {tab === 'results' && 'Scan Results'}
              {tab === 'remediation' && 'Remediation'}
            </button>
          ))}
        </nav>
      </div>

      {/* Dashboard Tab */}
      {activeTab === 'dashboard' && (
        <>
          <LoadErrorBanner what="STIG dashboard stats" error={dashboardError} />
          <DashboardTab data={dashboardData} loading={dashboardLoading} />
        </>
      )}

      {/* Benchmarks Tab */}
      {activeTab === 'benchmarks' && <LoadErrorBanner what="STIG benchmarks" error={benchmarksError} />}
      {activeTab === 'benchmarks' && (
        <BenchmarksTab
          benchmarks={benchmarks || []}
          loading={benchmarksLoading}
          platformFilter={platformFilter}
          setPlatformFilter={setPlatformFilter}
          onRunScan={(id) => setLaunchScanFor(id)}
        />
      )}

      {/* Launch Scan Modal */}
      {launchScanFor && (
        <LaunchScanModal
          benchmarkId={launchScanFor}
          onClose={() => setLaunchScanFor(null)}
          onSubmit={(host, scanType) => {
            runScanMutation.mutate({ host, benchmark_id: launchScanFor, scan_type: scanType });
            setLaunchScanFor(null);
          }}
          submitting={runScanMutation.isPending}
        />
      )}

      {/* Scan Results Tab */}
      {activeTab === 'results' && <LoadErrorBanner what="STIG scans" error={scansError} />}
      {activeTab === 'results' && (
        <ScanResultsTab
          scans={scans || []}
          loading={scansLoading}
          expandedScan={expandedScan}
          setExpandedScan={setExpandedScan}
          expandedScanResults={expandedScanResults || []}
          scanResultsLoading={scanResultsLoading}
          scanResultsError={scanResultsError}
        />
      )}

      {/* Remediation Tab */}
      {activeTab === 'remediation' && <LoadErrorBanner what="STIG scans" error={scansError} />}
      {activeTab === 'remediation' && (
        <RemediationTab
          remediations={remediations}
          loading={scansLoading}
          severityFilter={severityFilter}
          setSeverityFilter={setSeverityFilter}
          onAutoRemediate={(scanId, categories) =>
            autoRemediateMutation.mutate({ scan_result_id: scanId, categories })
          }
          autoRemediatePending={autoRemediateMutation.isPending}
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
          label="Benchmarks Loaded"
          value={data?.total_benchmarks || 0}
          icon={CheckCircle}
          color="blue"
        />
        <KPICard
          label="Total Scans"
          value={data?.total_scans || 0}
          icon={Zap}
          color="green"
        />
        <KPICard
          label="Avg Compliance (completed scans)"
          value={(data?.recent_scans || []).some((s) => s.status === 'completed') || (data?.average_compliance ?? 0) > 0 ? `${Math.round(data?.average_compliance || 0)}%` : NA}
          icon={AlertTriangle}
          color="yellow"
        />
        <KPICard
          label="Scans Not Run"
          value={data?.scans_not_run ?? NA}
          icon={AlertCircle}
          color="yellow"
        />
        <KPICard
          label="Scans Awaiting Results"
          value={data?.scans_pending ?? NA}
          icon={Clock}
          color="blue"
        />
        <KPICard
          label="CAT I Findings"
          value={data?.critical_findings || 0}
          icon={AlertCircle}
          color="red"
        />
      </div>

      {/* Compliance by Benchmark */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Compliance by Benchmark
        </h2>
        <div className="space-y-4">
          {(data?.compliance_by_benchmark || []).map((item: { name: string; percentage: number }) => (
            <div key={item.name}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  {item.name}
                </span>
                <span className="text-sm font-semibold text-gray-900 dark:text-white">
                  {item.percentage}%
                </span>
              </div>
              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div
                  className={clsx(
                    'h-full rounded-full transition-all duration-300',
                    item.percentage >= 80
                      ? 'bg-green-500'
                      : item.percentage >= 60
                      ? 'bg-yellow-500'
                      : 'bg-red-500'
                  )}
                  style={{ width: `${item.percentage}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* CAT I/II/III Findings Distribution */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Findings by Severity
        </h2>
        <div className="grid grid-cols-3 gap-4">
          {Object.entries(data?.findings_by_severity || {}).map(([severity, count]) => (
            <div
              key={severity}
              className={clsx(
                'p-4 rounded-lg text-center',
                severity === 'CAT I'
                  ? 'bg-red-100 dark:bg-red-900/20'
                  : severity === 'CAT II'
                  ? 'bg-orange-100 dark:bg-orange-900/20'
                  : 'bg-yellow-100 dark:bg-yellow-900/20'
              )}
            >
              <div
                className={clsx(
                  'text-3xl font-bold',
                  severity === 'CAT I'
                    ? 'text-red-600 dark:text-red-400'
                    : severity === 'CAT II'
                    ? 'text-orange-600 dark:text-orange-400'
                    : 'text-yellow-600 dark:text-yellow-400'
                )}
              >
                {count as number}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">{severity}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Recent Scans
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700">
                <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">
                  Host
                </th>
                <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">
                  Benchmark
                </th>
                <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">
                  Status
                </th>
                <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">
                  Compliance
                </th>
                <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">
                  Open / NaF / N/A
                </th>
                <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">
                  Date
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {(data?.recent_scans || []).slice(0, 5).map((scan: Scan) => (
                <tr key={scan.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-4 py-3 text-gray-900 dark:text-white font-mono">
                    {scan.host}
                  </td>
                  <td className="px-4 py-3 text-gray-600 dark:text-gray-400">
                    {scan.benchmark}
                  </td>
                  <td className="px-4 py-3 text-xs">
                    <span className={clsx('px-2 py-0.5 rounded-full', getStatusColor(scan.status))}>{String(scan.status).replace(/_/g, ' ')}</span>
                  </td>
                  <td className="px-4 py-3">
                    <ComplianceCell scan={scan} />
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                    <span className="font-mono">
                      {scan.findings.open}/{scan.findings.naf}/{scan.findings.na}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-600 dark:text-gray-400">
                    {scan.date ? new Date(scan.date).toLocaleDateString() : '—'}
                  </td>
                </tr>
              ))}
              {(data?.recent_scans || []).length === 0 && (
                <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500">No STIG scan recorded.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function XCCDFUploader() {
  const queryClient = useQueryClient();
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [status, setStatus] = useState<{ kind: 'ok' | 'err'; msg: string } | null>(null);

  const handleFile = async (file: File) => {
    setUploading(true);
    setStatus(null);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await api.post('/stig/scap/upload', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      const parsed = res.data?.check_count ?? 0;
      const name = res.data?.benchmark_title || res.data?.name || file.name;
      setStatus({
        kind: 'ok',
        msg: `Imported "${name}" — ${parsed} rule${parsed === 1 ? '' : 's'} parsed.`,
      });
      // Refresh the benchmarks list so the new one appears immediately.
      queryClient.invalidateQueries({ queryKey: ['stig-benchmarks'] });
    } catch (err: any) {
      setStatus({
        kind: 'err',
        msg: err?.response?.data?.detail || err?.message || 'Upload failed',
      });
    } finally {
      setUploading(false);
    }
  };

  const onDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    const file = e.dataTransfer.files?.[0];
    if (file) await handleFile(file);
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      <div className="flex items-center gap-2 mb-3">
        <Plus className="w-5 h-5 text-blue-600 dark:text-blue-400" />
        <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">
          Upload STIG / SCAP Benchmark
        </span>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          (XCCDF .xml from <span className="underline">public.cyber.mil/stigs</span>)
        </span>
      </div>
      <label
        onDragOver={(e) => { e.preventDefault(); setDragActive(true); }}
        onDragLeave={() => setDragActive(false)}
        onDrop={onDrop}
        className={clsx(
          'flex flex-col items-center justify-center gap-1 py-6 px-4 border-2 border-dashed rounded-lg cursor-pointer transition',
          dragActive
            ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
            : 'border-gray-300 dark:border-gray-600 hover:border-blue-400 dark:hover:border-blue-500',
          uploading && 'opacity-60 pointer-events-none',
        )}
      >
        <input
          type="file"
          accept=".xml,.xccdf,application/xml"
          className="hidden"
          disabled={uploading}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
            e.target.value = '';
          }}
        />
        {uploading ? (
          <>
            <Loader2 className="w-6 h-6 animate-spin text-blue-600" />
            <span className="text-sm text-gray-600 dark:text-gray-300">Parsing XCCDF…</span>
          </>
        ) : (
          <>
            <Plus className="w-6 h-6 text-gray-400" />
            <span className="text-sm text-gray-700 dark:text-gray-300">
              Drop an XCCDF file here or click to choose
            </span>
            <span className="text-xs text-gray-500 dark:text-gray-400">
              Parsed rules land in the benchmark list immediately.
            </span>
          </>
        )}
      </label>
      {status && (
        <div className={clsx(
          'mt-3 text-sm px-3 py-2 rounded border',
          status.kind === 'ok'
            ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-800 dark:text-green-200'
            : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-800 dark:text-red-200',
        )}>
          {status.msg}
        </div>
      )}
    </div>
  );
}

function BenchmarksTab({
  benchmarks,
  loading,
  platformFilter,
  setPlatformFilter,
  onRunScan,
}: {
  benchmarks: Benchmark[];
  loading: boolean;
  platformFilter: string;
  setPlatformFilter: (value: string) => void;
  onRunScan: (id: string) => void;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const platforms = Array.from(new Set(benchmarks.map((b) => b.platform)));

  return (
    <div className="space-y-6">
      {/* XCCDF upload — the operator path to load DISA STIG content */}
      <XCCDFUploader />

      {/* Filter */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Filter className="w-5 h-5 text-gray-400" />
          <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">Filter</span>
        </div>
        <select
          value={platformFilter}
          onChange={(e) => setPlatformFilter(e.target.value)}
          className="w-full md:w-64 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
        >
          <option value="all">All Platforms</option>
          {platforms.map((platform) => (
            <option key={platform} value={platform}>
              {platform}
            </option>
          ))}
        </select>
      </div>

      {/* Benchmark Cards */}
      {benchmarks.length === 0 ? (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8 text-center">
          <AlertCircle className="w-10 h-10 text-gray-400 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-gray-900 dark:text-white mb-1">
            No benchmarks loaded yet
          </h3>
          <p className="text-sm text-gray-600 dark:text-gray-400 max-w-lg mx-auto">
            Upload an XCCDF benchmark above to get started. Download current
            DISA STIGs from{' '}
            <a
              href="https://public.cyber.mil/stigs/downloads/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-600 dark:text-blue-400 underline"
            >
              public.cyber.mil/stigs/downloads
            </a>
            . After upload, each benchmark's rules are ingested into the
            platform and available for scans.
          </p>
        </div>
      ) : null}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {benchmarks.map((benchmark) => (
          <div
            key={benchmark.id}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
          >
            <div className="mb-4">
              <h3 className="font-semibold text-gray-900 dark:text-white">
                {benchmark.name}
              </h3>
              <div className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                <div>{benchmark.platform}</div>
                <div className="text-xs text-gray-500 dark:text-gray-500">
                  v{benchmark.version}
                </div>
              </div>
            </div>

            <div className="space-y-3 mb-4">
              <div className="text-sm">
                <div className="text-gray-600 dark:text-gray-400">
                  Total Rules: <span className="font-medium text-gray-900 dark:text-white">
                    {benchmark.totalRules}
                  </span>
                </div>
              </div>

              <div className="flex gap-2">
                <FindingSummary severity="CAT I" count={benchmark.findings['CAT I']} color="red" />
                <FindingSummary severity="CAT II" count={benchmark.findings['CAT II']} color="orange" />
                <FindingSummary severity="CAT III" count={benchmark.findings['CAT III']} color="yellow" />
              </div>

              <div className="text-xs text-gray-500 dark:text-gray-400">
                Last scanned: {benchmark.lastScanDate ? new Date(benchmark.lastScanDate).toLocaleDateString() : 'never'}
              </div>
            </div>

            <button
              onClick={() => onRunScan(benchmark.id)}
              className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium flex items-center justify-center gap-2"
            >
              <Play className="w-4 h-4" />
              Scan
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function ARFUploader({ scanId }: { scanId: string }) {
  const queryClient = useQueryClient();
  const [uploading, setUploading] = useState(false);
  const [status, setStatus] = useState<{ kind: 'ok' | 'err'; msg: string } | null>(null);

  const handleFile = async (file: File) => {
    setUploading(true);
    setStatus(null);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const res = await api.post(`/stig/scans/${scanId}/arf`, fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setStatus({
        kind: 'ok',
        msg: `Ingested — ${res.data?.checks_evaluated ?? 0} checks, ${res.data?.open_findings ?? 0} open, ${(res.data?.compliance_percentage ?? 0).toFixed(1)}% compliant.`,
      });
      queryClient.invalidateQueries({ queryKey: ['stig-scans'] });
      queryClient.invalidateQueries({ queryKey: ['stig-scan-results', scanId] });
    } catch (err: any) {
      setStatus({
        kind: 'err',
        msg: err?.response?.data?.detail || err?.message || 'Upload failed',
      });
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-blue-300 dark:border-blue-700 p-4">
      <div className="flex items-center gap-2 mb-2">
        <Plus className="w-4 h-4 text-blue-600 dark:text-blue-400" />
        <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">
          Upload ARF report for this scan
        </span>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          (oscap --results-arf output)
        </span>
      </div>
      <label className={clsx(
        "flex items-center gap-2 text-sm cursor-pointer",
        uploading && 'opacity-60 pointer-events-none'
      )}>
        <input
          type="file"
          accept=".xml,application/xml"
          className="hidden"
          disabled={uploading}
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFile(file);
            e.target.value = '';
          }}
        />
        <span className="px-3 py-1.5 bg-blue-600 text-white rounded hover:bg-blue-700 text-xs font-medium inline-flex items-center gap-1">
          {uploading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Plus className="w-3 h-3" />}
          {uploading ? 'Ingesting…' : 'Choose ARF file'}
        </span>
        <span className="text-xs text-gray-500 dark:text-gray-400">
          Parses {`<rule-result>`} elements per NIST SP 800-126 §5.5, updates findings + compliance %.
        </span>
      </label>
      {status && (
        <div className={clsx(
          'mt-2 text-xs px-2 py-1 rounded',
          status.kind === 'ok'
            ? 'bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-200'
            : 'bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-200',
        )}>
          {status.msg}
        </div>
      )}
    </div>
  );
}

function ScanResultsTab({
  scans,
  loading,
  expandedScan,
  setExpandedScan,
  expandedScanResults,
  scanResultsLoading,
  scanResultsError,
}: {
  scans: Scan[];
  loading: boolean;
  expandedScan: string | null;
  setExpandedScan: (id: string | null) => void;
  expandedScanResults: ScanResult[];
  scanResultsLoading: boolean;
  scanResultsError: unknown;
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
      {/* Scans Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Host
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Benchmark
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Compliance
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                O/NAF/NA/NR
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Date
              </th>
              <th className="px-6 py-3 text-center text-xs font-semibold text-gray-700 dark:text-gray-300">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {scans.map((scan) => (
              <tr
                key={scan.id}
                className="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                onClick={() => setExpandedScan(expandedScan === scan.id ? null : scan.id)}
              >
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {expandedScan === scan.id ? (
                    <ChevronDown className="w-4 h-4 inline mr-2" />
                  ) : (
                    <ChevronRight className="w-4 h-4 inline mr-2" />
                  )}
                  {scan.host}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {scan.benchmark}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      getStatusColor(scan.status)
                    )}
                  >
                    {String(scan.status).replace(/_/g, ' ')}
                  </span>
                  {scan.status_reason && (
                    <div className="text-xs text-gray-500 mt-1 max-w-xs">{scan.status_reason}</div>
                  )}
                </td>
                <td className="px-6 py-4 text-sm">
                  <ComplianceCell scan={scan} />
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">
                  {scan.findings.open}/{scan.findings.naf}/{scan.findings.na}/{scan.findings.nr}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {scan.date ? new Date(scan.date).toLocaleDateString() : '—'}
                </td>
                <td className="px-6 py-4 text-center">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setExpandedScan(scan.id);
                    }}
                    className="text-blue-600 dark:text-blue-400 hover:underline text-sm"
                  >
                    View Details
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {scans.length === 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-8 text-center">
          <AlertCircle className="w-10 h-10 text-gray-400 mx-auto mb-3" />
          <h3 className="text-base font-semibold text-gray-900 dark:text-white mb-1">
            No scans yet
          </h3>
          <p className="text-sm text-gray-600 dark:text-gray-400 max-w-lg mx-auto">
            Run a scan from the Benchmarks tab to populate this view. Scans run
            through an endpoint agent enrolled with the {STIG_SCAN_CAPABILITY} capability
            (approved in the agent queue); without one a scan is recorded as not run with the
            reason. A manual scan waits for an ARF results upload.
          </p>
        </div>
      )}

      {/* Expanded Scan Results */}
      {expandedScan && (
        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
          <ARFUploader scanId={expandedScan} />
          <h3 className="font-semibold text-gray-900 dark:text-white mb-4 mt-6">
            Per-Rule Results
          </h3>
          <LoadErrorBanner what="per-rule results" error={scanResultsError} />
          {scanResultsLoading ? (
            <div className="flex items-center justify-center h-32">
              <Loader2 className="w-6 h-6 animate-spin text-blue-500" />
            </div>
          ) : (
            <div className="space-y-2">
              {expandedScanResults.map((result) => (
                <div
                  key={result.id}
                  className="flex items-center justify-between p-3 bg-white dark:bg-gray-800 rounded-lg"
                >
                  <div className="flex-1">
                    <div className="text-sm font-medium text-gray-900 dark:text-white">
                      {result.ruleId}: {result.title}
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                      {result.description}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      getSeverityColor(result.severity)
                    )}>
                      {result.severity}
                    </span>
                    <span
                      className={clsx(
                        'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                        getStatusColor(result.status)
                      )}
                    >
                      {result.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function RemediationTab({
  remediations,
  loading,
  severityFilter,
  setSeverityFilter,
  onAutoRemediate,
  autoRemediatePending,
}: {
  remediations: Scan[];
  loading: boolean;
  severityFilter: string;
  setSeverityFilter: (value: string) => void;
  onAutoRemediate: (scanId: string, categories: string[]) => void;
  autoRemediatePending: boolean;
}) {
  const [selectedRemediation, setSelectedRemediation] = useState<Scan | null>(null);
  const catCount = (s: Scan, cat: string) => (cat === 'CAT I' ? s.cat?.i ?? 0 : cat === 'CAT II' ? s.cat?.ii ?? 0 : s.cat?.iii ?? 0);
  const visible = severityFilter === 'all' ? remediations : remediations.filter((s) => catCount(s, severityFilter) > 0);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Remediation Detail Modal */}
      {selectedRemediation && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-md p-6">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">Remediation Details</h2>
            <div className="space-y-3 text-sm">
              <div><span className="text-gray-500">Host:</span> <span className="font-mono text-gray-900 dark:text-white">{selectedRemediation.host}</span></div>
              <div><span className="text-gray-500">Benchmark:</span> {selectedRemediation.benchmark}</div>
              <div><span className="text-gray-500">Open findings:</span> {selectedRemediation.findings.open} (CAT I {selectedRemediation.cat?.i ?? 0}, CAT II {selectedRemediation.cat?.ii ?? 0}, CAT III {selectedRemediation.cat?.iii ?? 0})</div>
              <div><span className="text-gray-500">Compliance:</span> <ComplianceCell scan={selectedRemediation} /></div>
              <div><span className="text-gray-500">Scanned:</span> {selectedRemediation.date ? new Date(selectedRemediation.date).toLocaleString() : '—'}</div>
            </div>
            <button onClick={() => setSelectedRemediation(null)} className="mt-6 w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Close</button>
          </div>
        </div>
      )}

      {/* Filter */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Severities</option>
              <option value="CAT I">CAT I</option>
              <option value="CAT II">CAT II</option>
              <option value="CAT III">CAT III</option>
            </select>
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            Completed scans with open findings. <span className="font-medium">Auto-Remediate</span> queues the rules&apos; fixes for that host; rules without an automated fix are skipped.
          </div>
        </div>
      </div>

      {/* Remediations Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Finding
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Severity
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Host
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Open CAT I/II/III
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Scanned
              </th>
              <th className="px-6 py-3 text-center text-xs font-semibold text-gray-700 dark:text-gray-300">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {visible.length === 0 && (
              <tr><td colSpan={7} className="px-6 py-8 text-center text-sm text-gray-500">No completed scan has open findings{severityFilter !== 'all' ? ` at ${severityFilter}` : ''}.</td></tr>
            )}
            {visible.map((remediation) => {
              const topCat = (remediation.cat?.i ?? 0) > 0 ? 'CAT I' : (remediation.cat?.ii ?? 0) > 0 ? 'CAT II' : 'CAT III';
              const cats = severityFilter === 'all' ? ['CAT I', 'CAT II', 'CAT III'].filter((c) => catCount(remediation, c) > 0) : [severityFilter];
              return (
              <tr key={remediation.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  {remediation.findings.open} open finding(s) · {remediation.benchmark}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      getSeverityColor(topCat)
                    )}
                  >
                    {topCat}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">
                  {remediation.host}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span className={clsx('inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium', getStatusColor(remediation.status))}>
                    {String(remediation.status).replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">
                  {remediation.cat?.i ?? 0}/{remediation.cat?.ii ?? 0}/{remediation.cat?.iii ?? 0}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {remediation.date ? new Date(remediation.date).toLocaleDateString() : '—'}
                </td>
                <td className="px-6 py-4 text-center">
                  <div className="flex items-center justify-center gap-3">
                    <button
                      onClick={() => setSelectedRemediation(remediation)}
                      className="text-blue-600 dark:text-blue-400 hover:underline text-sm"
                    >
                      Details
                    </button>
                    <button
                      onClick={() => onAutoRemediate(remediation.id, cats)}
                      disabled={autoRemediatePending}
                      title={`Auto-remediate ${cats.join(', ')} findings for this scan`}
                      className="inline-flex items-center gap-1 px-3 py-1 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:bg-gray-400 text-xs font-medium"
                    >
                      <Zap className="w-3 h-3" />
                      Auto-Remediate
                    </button>
                  </div>
                </td>
              </tr>
              );
            })}
          </tbody>
        </table>
      </div>
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
  color: 'blue' | 'green' | 'yellow' | 'red';
}) {
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
    yellow: 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900/30 dark:text-yellow-400',
    red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
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

function FindingSummary({
  severity,
  count,
  color,
}: {
  severity: string;
  count: number;
  color: 'red' | 'orange' | 'yellow';
}) {
  const colorClasses: Record<string, string> = {
    red: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400',
    orange: 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400',
    yellow: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400',
  };

  return (
    <div className={clsx('px-3 py-1 rounded-lg text-sm font-medium', colorClasses[color])}>
      {severity}: {count}
    </div>
  );
}

function getSeverityColor(severity: string) {
  const colors: Record<string, string> = {
    'CAT I': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    'CAT II': 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400',
    'CAT III': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  };
  return colors[severity] || 'bg-gray-100 text-gray-800';
}

function getStatusColor(status: string) {
  const colors: Record<string, string> = {
    'completed': 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    'in-progress': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
    'failed': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    'dispatched': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
    'awaiting_approval': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
    'pending_results': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
    'not_run': 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
    'no_agent': 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
    'no_automatable_rules': 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
    'Open': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    'Not a Finding': 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    'N/A': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400',
    'Not Reviewed': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  };
  return colors[status] || 'bg-gray-100 text-gray-800';
}

function LaunchScanModal({
  benchmarkId,
  onClose,
  onSubmit,
  submitting,
}: {
  benchmarkId: string;
  onClose: () => void;
  onSubmit: (host: string, scanType: string) => void;
  submitting: boolean;
}) {
  const [selectedHost, setSelectedHost] = useState<string>('');
  const [manualHost, setManualHost] = useState<string>('');
  const [useManual, setUseManual] = useState<boolean>(false);
  const [scanType, setScanType] = useState<string>('agent');

  const { data: agentsData, isLoading: agentsLoading, error: agentsError } = useQuery<{
    total: number;
    agents: ComplianceAgent[];
  }>({
    queryKey: ['stig-scan-agents'],
    queryFn: async () => {
      // Only agents enrolled with stig_scan run whole-benchmark scans.
      const response = await api.get('/agents', {
        params: { capability: STIG_SCAN_CAPABILITY },
      });
      const data = response.data;
      // Defensive parse for either {agents:[]} or array
      if (Array.isArray(data)) {
        return { total: data.length, agents: data };
      }
      return {
        total: data?.total ?? (data?.agents?.length || 0),
        agents: data?.agents || [],
      };
    },
  });

  const agents = agentsData?.agents || [];
  const hasAgents = agents.length > 0;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const host = useManual || !hasAgents ? manualHost.trim() : selectedHost.trim();
    if (!host) return;
    onSubmit(host, scanType);
  };

  return (
    <div
      className="fixed inset-0 bg-black/50 flex items-center justify-center z-50"
      onClick={onClose}
    >
      <div
        className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-md p-6"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
            Launch STIG Scan
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600"
            aria-label="Close"
          >
            ✕
          </button>
        </div>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
          Benchmark: <span className="font-mono">{benchmarkId}</span>
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <LoadErrorBanner what="stig_scan agents" error={agentsError} />
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Scan type</label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="agent">Agent (oscap on the host's stig_scan agent, after approval)</option>
              <option value="manual">Manual (register the scan and upload the ARF results)</option>
            </select>
          </div>
          {agentsLoading ? (
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading agents...
            </div>
          ) : hasAgents && !useManual ? (
            <div>
              <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">
                Target Host
              </label>
              <select
                value={selectedHost}
                onChange={(e) => setSelectedHost(e.target.value)}
                required
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="">Select a stig_scan-capable host</option>
                {agents.map((a) => (
                  <option key={a.id} value={a.hostname}>
                    {a.hostname}
                    {a.status ? ` (${a.status})` : ''}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={() => setUseManual(true)}
                className="mt-2 text-xs text-blue-600 dark:text-blue-400 hover:underline"
              >
                Enter hostname manually
              </button>
            </div>
          ) : (
            <div>
              {!hasAgents && (
                <div className="mb-3 p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 text-yellow-800 dark:text-yellow-300 text-xs">
                  No agent with the <code className="font-mono">{STIG_SCAN_CAPABILITY}</code> capability is enrolled; an agent scan
                  will be recorded as not run with the reason. Choose a manual scan to upload ARF results instead.
                </div>
              )}
              <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">
                Target Hostname
              </label>
              <input
                type="text"
                value={manualHost}
                onChange={(e) => setManualHost(e.target.value)}
                placeholder="host.example.com"
                required
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm"
              />
              {hasAgents && (
                <button
                  type="button"
                  onClick={() => setUseManual(false)}
                  className="mt-2 text-xs text-blue-600 dark:text-blue-400 hover:underline"
                >
                  Pick from enrolled agents instead
                </button>
              )}
            </div>
          )}

          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={
                submitting ||
                (useManual || !hasAgents
                  ? !manualHost.trim()
                  : !selectedHost.trim())
              }
              className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400"
            >
              {submitting ? 'Launching...' : 'Launch Scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
