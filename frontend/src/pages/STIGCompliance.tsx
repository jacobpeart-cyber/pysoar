import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ChevronDown,
  ChevronRight,
  Plus,
  Filter,
  Download,
  Play,
  Loader2,
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  Clock,
  Copy,
  Eye,
  Zap,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';

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

interface Scan {
  id: string;
  host: string;
  benchmark: string;
  status: 'completed' | 'in-progress' | 'failed';
  compliance: number;
  findings: {
    open: number;
    naf: number;
    na: number;
    nr: number;
  };
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

interface Remediation {
  id: string;
  finding: string;
  severity: Severity;
  host: string;
  status: 'open' | 'in-progress' | 'remediated';
  assignedTo: string;
  dueDate: string;
}

interface ComplianceAgent {
  id: string;
  hostname: string;
  capabilities?: string[];
  status?: string;
}

export default function STIGCompliance() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [platformFilter, setPlatformFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [launchScanFor, setLaunchScanFor] = useState<string | null>(null);
  const queryClient = useQueryClient();

  const { data: dashboardData, isLoading: dashboardLoading } = useQuery<DashboardData>({
    queryKey: ['stig-dashboard'],
    queryFn: async () => {
      try {
      const response = await api.get('/stig/dashboard/stats');
      return response.data;
      } catch { return null; }
    },
  });

  const { data: benchmarks, isLoading: benchmarksLoading } = useQuery<Benchmark[]>({
    queryKey: ['stig-benchmarks', platformFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (platformFilter !== 'all') params.append('platform', platformFilter);
      try {
      const response = await api.get(`/stig/benchmarks?${params}`);
      return response.data;
      } catch { return null; }
    },
  });

  const { data: scans, isLoading: scansLoading } = useQuery<Scan[]>({
    queryKey: ['stig-scans'],
    queryFn: async () => {
      try {
      const response = await api.get('/stig/scans');
      return response.data;
      } catch { return null; }
    },
  });

  const { data: expandedScanResults, isLoading: scanResultsLoading } = useQuery<
    ScanResult[]
  >({
    queryKey: ['stig-scan-results', expandedScan],
    queryFn: async () => {
      if (!expandedScan) return [];
      try {
      const response = await api.get(`/stig/scans/${expandedScan}`);
      return response.data.results;
      } catch { return null; }
    },
    enabled: !!expandedScan,
  });

  const { data: remediations, isLoading: remediationsLoading } = useQuery<Remediation[]>({
    queryKey: ['stig-remediations', severityFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (severityFilter !== 'all') params.append('severity', severityFilter);
      try {
      const response = await api.get(`/stig/scans?${params}`);
      return response.data;
      } catch { return null; }
    },
  });

  const runScanMutation = useMutation({
    mutationFn: async (params: { host: string; benchmark_id: string }) => {
      try {
      const response = await api.post('/stig/scans/launch', params);
      return response.data;
      } catch { return null; }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['stig-scans'] });
      queryClient.invalidateQueries({ queryKey: ['stig-dashboard'] });
    },
  });

  const autoRemediateMutation = useMutation({
    mutationFn: async (params: { scan_result_id: string; categories: string[] }) => {
      try {
      const response = await api.post('/stig/remediate/auto', params);
      return response.data;
      } catch { return null; }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['stig-remediations'] });
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
        <DashboardTab data={dashboardData} loading={dashboardLoading} />
      )}

      {/* Benchmarks Tab */}
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
          onSubmit={(host) => {
            runScanMutation.mutate({ host, benchmark_id: launchScanFor });
            setLaunchScanFor(null);
          }}
          submitting={runScanMutation.isPending}
        />
      )}

      {/* Scan Results Tab */}
      {activeTab === 'results' && (
        <ScanResultsTab
          scans={scans || []}
          loading={scansLoading}
          expandedScan={expandedScan}
          setExpandedScan={setExpandedScan}
          expandedScanResults={expandedScanResults || []}
          scanResultsLoading={scanResultsLoading}
        />
      )}

      {/* Remediation Tab */}
      {activeTab === 'remediation' && (
        <RemediationTab
          remediations={remediations || []}
          loading={remediationsLoading}
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
          label="Avg Compliance"
          value={`${Math.round(data?.average_compliance || 0)}%`}
          icon={AlertTriangle}
          color="yellow"
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
                  Compliance
                </th>
                <th className="px-4 py-3 text-left font-semibold text-gray-700 dark:text-gray-300">
                  CAT I/II/III
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
                  <td className="px-4 py-3">
                    <div className="w-16 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                      <div
                        className={clsx(
                          'h-full rounded-full',
                          scan.compliance >= 80
                            ? 'bg-green-500'
                            : scan.compliance >= 60
                            ? 'bg-yellow-500'
                            : 'bg-red-500'
                        )}
                        style={{ width: `${scan.compliance}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-600 dark:text-gray-400 ml-2">
                      {scan.compliance}%
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-400">
                    <span className="font-mono">
                      {scan.findings.open}/{scan.findings.naf}/{scan.findings.na}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-600 dark:text-gray-400">
                    {new Date(scan.date || "").toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
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
                Last scanned: {new Date(benchmark.lastScanDate || "").toLocaleDateString()}
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

function ScanResultsTab({
  scans,
  loading,
  expandedScan,
  setExpandedScan,
  expandedScanResults,
  scanResultsLoading,
}: {
  scans: Scan[];
  loading: boolean;
  expandedScan: string | null;
  setExpandedScan: (id: string | null) => void;
  expandedScanResults: ScanResult[];
  scanResultsLoading: boolean;
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
                    {scan.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm">
                  <div className="w-16 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className={clsx(
                        'h-full rounded-full',
                        scan.compliance >= 80
                          ? 'bg-green-500'
                          : scan.compliance >= 60
                          ? 'bg-yellow-500'
                          : 'bg-red-500'
                      )}
                      style={{ width: `${scan.compliance}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-600 dark:text-gray-400 ml-2">
                    {scan.compliance}%
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">
                  {scan.findings.open}/{scan.findings.naf}/{scan.findings.na}/{scan.findings.nr}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {new Date(scan.date || "").toLocaleDateString()}
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

      {/* Expanded Scan Results */}
      {expandedScan && (
        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
          <h3 className="font-semibold text-gray-900 dark:text-white mb-4">
            Per-Rule Results
          </h3>
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
  remediations: Remediation[];
  loading: boolean;
  severityFilter: string;
  setSeverityFilter: (value: string) => void;
  onAutoRemediate: (scanId: string, categories: string[]) => void;
  autoRemediatePending: boolean;
}) {
  const [selectedRemediation, setSelectedRemediation] = useState<Remediation | null>(null);

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
              <div><span className="text-gray-500">Finding:</span> <span className="text-gray-900 dark:text-white font-medium">{selectedRemediation.finding}</span></div>
              <div><span className="text-gray-500">Severity:</span> <span className={clsx('px-2 py-1 rounded text-xs font-medium', getSeverityColor(selectedRemediation.severity))}>{selectedRemediation.severity}</span></div>
              <div><span className="text-gray-500">Host:</span> <span className="font-mono text-gray-900 dark:text-white">{selectedRemediation.host}</span></div>
              <div><span className="text-gray-500">Status:</span> {selectedRemediation.status}</div>
              <div><span className="text-gray-500">Assigned To:</span> {selectedRemediation.assignedTo}</div>
              <div><span className="text-gray-500">Due Date:</span> {new Date(selectedRemediation.dueDate || "").toLocaleDateString()}</div>
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
            Use <span className="font-medium">Auto-Remediate</span> per scan result to queue automatic fixes.
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
                Assigned To
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Due Date
              </th>
              <th className="px-6 py-3 text-center text-xs font-semibold text-gray-700 dark:text-gray-300">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {remediations.map((remediation) => (
              <tr key={remediation.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  {remediation.finding}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      getSeverityColor(remediation.severity)
                    )}
                  >
                    {remediation.severity}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">
                  {remediation.host}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      remediation.status === 'open'
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        : remediation.status === 'in-progress'
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                        : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    )}
                  >
                    {remediation.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {remediation.assignedTo}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {new Date(remediation.dueDate || "").toLocaleDateString()}
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
                      onClick={() => onAutoRemediate(remediation.id, [remediation.severity])}
                      disabled={autoRemediatePending}
                      title={`Auto-remediate ${remediation.severity} findings for this scan`}
                      className="inline-flex items-center gap-1 px-3 py-1 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:bg-gray-400 text-xs font-medium"
                    >
                      <Zap className="w-3 h-3" />
                      Auto-Remediate
                    </button>
                  </div>
                </td>
              </tr>
            ))}
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
  onSubmit: (host: string) => void;
  submitting: boolean;
}) {
  const [selectedHost, setSelectedHost] = useState<string>('');
  const [manualHost, setManualHost] = useState<string>('');
  const [useManual, setUseManual] = useState<boolean>(false);

  const { data: agentsData, isLoading: agentsLoading } = useQuery<{
    total: number;
    agents: ComplianceAgent[];
  }>({
    queryKey: ['compliance-agents'],
    queryFn: async () => {
      try {
        // Backend supports `capability` filter (singular).
        const response = await api.get('/agents', {
          params: { capability: 'compliance' },
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
      } catch {
        return { total: 0, agents: [] };
      }
    },
  });

  const agents = agentsData?.agents || [];
  const hasAgents = agents.length > 0;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const host = useManual || !hasAgents ? manualHost.trim() : selectedHost.trim();
    if (!host) return;
    onSubmit(host);
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
                <option value="">Select a compliance-capable host</option>
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
                  No compliance-capable agent enrolled; scan will record{' '}
                  <code className="font-mono">status='no_agent'</code>.
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
