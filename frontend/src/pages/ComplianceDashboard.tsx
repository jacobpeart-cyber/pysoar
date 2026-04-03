import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Plus,
  Filter,
  Download,
  Calendar,
  CheckCircle,
  Clock,
  AlertCircle,
  Loader2,
  X,
  Edit2,
  Trash2,
  Eye,
  FileText,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';

type TabType = 'overview' | 'controls' | 'poams' | 'cui' | 'cisa';

interface DashboardData {
  overall_compliance_score: number;
  frameworks_total: number;
  frameworks_compliant: number;
  framework_scores: Array<{ name: string; score: number }>;
  overdue_poams: number;
  upcoming_poams?: number;
  upcoming_assessments: number;
  control_status_breakdown: { total: number; implemented: number };
  active_cisa_directives: number;
  cui_assets_total: number;
  cui_assets_active?: number;
  trends: Array<{ date: string; score: number }>;
  last_updated?: string;
}

interface Control {
  id: string;
  title: string;
  control_family: string;
  status: 'implemented' | 'partially' | 'planned' | 'not_implemented';
  implementation_status: string;
  baseline: 'L' | 'M' | 'H';
  last_assessed_at: string;
  evidence_ids: string[];
  description?: string;
  relatedControls?: string[];
}

interface POAM {
  id: string;
  weakness_name: string;
  risk_level: 'high' | 'medium' | 'low';
  status: 'open' | 'in_progress' | 'completed';
  scheduled_completion_date: string;
  assigned_to: string;
}

interface CUIAsset {
  id: string;
  asset_id: string;
  asset_type: string;
  cui_category: string;
  cui_designation: string;
  dissemination_controls: string[];
  classification_authority: string;
}

interface CISADirective {
  id: string;
  title: string;
  compliance_deadline: string;
  status: 'open' | 'in_progress' | 'completed';
  actions_taken: string[];
}

export default function ComplianceDashboard() {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [frameworkFilter, setFrameworkFilter] = useState<string>('all');
  const [familyFilter, setFamilyFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [poamStatusFilter, setPOAMStatusFilter] = useState<string>('all');
  const [riskLevelFilter, setRiskLevelFilter] = useState<string>('all');
  const queryClient = useQueryClient();

  const { data: dashboardData, isLoading: dashboardLoading } = useQuery<DashboardData>({
    queryKey: ['compliance-dashboard'],
    queryFn: async () => {
      try {
      const response = await api.get('/compliance/dashboard');
      return response.data;
      } catch { return null; }
    },
  });

  const { data: controls, isLoading: controlsLoading } = useQuery<Control[]>({
    queryKey: ['compliance-controls', frameworkFilter, familyFilter, statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (frameworkFilter !== 'all') params.append('framework_id', frameworkFilter);
      if (familyFilter !== 'all') params.append('family', familyFilter);
      if (statusFilter !== 'all') params.append('status', statusFilter);
      try {
      const response = await api.get(`/compliance/controls?${params}`);
      return response.data;
      } catch { return null; }
    },
  });

  const { data: poams, isLoading: poamsLoading } = useQuery<POAM[]>({
    queryKey: ['compliance-poams', poamStatusFilter, riskLevelFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (poamStatusFilter !== 'all') params.append('status', poamStatusFilter);
      if (riskLevelFilter !== 'all') params.append('risk_level', riskLevelFilter);
      try {
      const response = await api.get(`/compliance/poams?${params}`);
      return response.data;
      } catch { return null; }
    },
  });

  const { data: cuiAssets, isLoading: cuiLoading } = useQuery<CUIAsset[]>({
    queryKey: ['compliance-cui'],
    queryFn: async () => {
      try {
      const response = await api.get('/compliance/cui');
      return response.data;
      } catch { return null; }
    },
  });

  const { data: cisaDirectives, isLoading: cisaLoading } = useQuery<CISADirective[]>({
    queryKey: ['compliance-cisa'],
    queryFn: async () => {
      try {
      const response = await api.get('/compliance/cisa/directives');
      return response.data;
      } catch { return null; }
    },
  });

  const createPOAMMutation = useMutation({
    mutationFn: async (data: Partial<POAM>) => {
      try {
      const response = await api.post('/compliance/poams', data);
      return response.data;
      } catch { return null; }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-poams'] });
    },
  });

  const deletePOAMMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/compliance/poams/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-poams'] });
    },
  });

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-green-600 dark:text-green-400';
    if (score >= 60) return 'text-yellow-600 dark:text-yellow-400';
    return 'text-red-600 dark:text-red-400';
  };

  const getStatusBadgeColor = (status: string) => {
    const colors: Record<string, string> = {
      compliant: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      partially: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
      'non-compliant': 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      open: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      in_progress: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
      completed: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      'implemented': 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      'partially_implemented': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
      'planned': 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
      'not_implemented': 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400',
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Compliance Dashboard</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Federal compliance framework tracking and management
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-8 -mb-px" aria-label="Tabs">
          {(['overview', 'controls', 'poams', 'cui', 'cisa'] as const).map((tab) => (
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
              {tab === 'overview' && 'Overview'}
              {tab === 'controls' && 'Controls'}
              {tab === 'poams' && 'POA&Ms'}
              {tab === 'cui' && 'CUI Management'}
              {tab === 'cisa' && 'CISA Directives'}
            </button>
          ))}
        </nav>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <OverviewTab
          data={dashboardData}
          loading={dashboardLoading}
        />
      )}

      {/* Controls Tab */}
      {activeTab === 'controls' && (
        <ControlsTab
          controls={controls || []}
          loading={controlsLoading}
          expandedControl={expandedControl}
          setExpandedControl={setExpandedControl}
          frameworkFilter={frameworkFilter}
          setFrameworkFilter={setFrameworkFilter}
          familyFilter={familyFilter}
          setFamilyFilter={setFamilyFilter}
          statusFilter={statusFilter}
          setStatusFilter={setStatusFilter}
          frameworkScores={dashboardData?.framework_scores || []}
        />
      )}

      {/* POA&Ms Tab */}
      {activeTab === 'poams' && (
        <POAMsTab
          poams={poams || []}
          loading={poamsLoading}
          statusFilter={poamStatusFilter}
          setStatusFilter={setPOAMStatusFilter}
          riskLevelFilter={riskLevelFilter}
          setRiskLevelFilter={setRiskLevelFilter}
          onDeletePOAM={(id) => deletePOAMMutation.mutate(id)}
          overduePOAMs={dashboardData?.overdue_poams || 0}
        />
      )}

      {/* CUI Management Tab */}
      {activeTab === 'cui' && (
        <CUITab
          assets={cuiAssets || []}
          loading={cuiLoading}
        />
      )}

      {/* CISA Directives Tab */}
      {activeTab === 'cisa' && (
        <CISATab
          directives={cisaDirectives || []}
          loading={cisaLoading}
        />
      )}
    </div>
  );
}

function OverviewTab({
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
      {/* Overall Compliance Gauge */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Overall Compliance Score
        </h2>
        <div className="flex items-center gap-8">
          <div className="flex-shrink-0">
            <div className="relative w-32 h-32">
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
                  strokeDasharray={`${(data?.overall_compliance_score || 0) * 3.4} 340`}
                  className={clsx(
                    'transition-all duration-500',
                    (data?.overall_compliance_score || 0) >= 80
                      ? 'text-green-500'
                      : (data?.overall_compliance_score || 0) >= 60
                      ? 'text-yellow-500'
                      : 'text-red-500'
                  )}
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <div className="text-3xl font-bold text-gray-900 dark:text-white">
                    {data?.overall_compliance_score || 0}
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400">%</div>
                </div>
              </div>
            </div>
          </div>
          <div className="flex-1">
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              Your organization's overall compliance posture across all federal frameworks.
            </p>
            <a
              href="#"
              className="inline-flex items-center text-blue-600 dark:text-blue-400 hover:underline"
            >
              View detailed breakdown
              <ChevronRight className="w-4 h-4 ml-1" />
            </a>
          </div>
        </div>
      </div>

      {/* Overdue POA&Ms Alert */}
      {data && data.overdue_poams > 0 && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-semibold text-red-800 dark:text-red-400">Overdue POA&Ms</h3>
            <p className="text-sm text-red-700 dark:text-red-300">
              {data.overdue_poams} Plan of Action and Milestones are overdue. Review and update schedules immediately.
            </p>
          </div>
        </div>
      )}

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Frameworks" value={data?.frameworks_total ?? 0} icon={FileText} color="blue" />
        <StatCard label="Compliant" value={data?.frameworks_compliant ?? 0} icon={CheckCircle} color="green" />
        <StatCard label="Overdue POA&Ms" value={data?.overdue_poams ?? 0} icon={AlertTriangle} color="red" />
        <StatCard label="CISA Directives" value={data?.active_cisa_directives ?? 0} icon={AlertCircle} color="orange" />
      </div>

      {/* Framework Score Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {(data?.framework_scores ?? []).map((fw) => (
          <div
            key={fw.name}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-5"
          >
            <div className="flex items-start justify-between mb-4">
              <h3 className="font-semibold text-gray-900 dark:text-white">
                {fw.name}
              </h3>
            </div>

            <div className="space-y-3">
              {/* Score Gauge */}
              <div>
                <div className="flex items-end justify-between mb-1">
                  <span className="text-xs text-gray-600 dark:text-gray-400">Score</span>
                  <span className={clsx('text-lg font-bold', getScoreColor(fw.score ?? 0))}>
                    {fw.score ?? 0}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={clsx(
                      'h-full rounded-full transition-all duration-300',
                      (fw.score ?? 0) >= 80
                        ? 'bg-green-500'
                        : (fw.score ?? 0) >= 60
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                    )}
                    style={{ width: `${fw.score ?? 0}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Compliance Trend Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Compliance Trend (90 Days)
        </h2>
        <div className="h-64 flex items-end justify-between gap-1">
          {(data?.trends || []).map((point, idx) => {
            const height = Math.max(point.score * 1.25, 10);
            return (
              <div key={idx} className="flex-1 flex flex-col items-center">
                <div
                  className="w-full bg-blue-500 dark:bg-blue-600 rounded-t"
                  style={{ height: `${height}%`, minHeight: '4px' }}
                  title={`${point.score}% on ${point.date}`}
                />
              </div>
            );
          })}
        </div>
      </div>

      {/* Upcoming Assessments */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Upcoming Assessments
        </h2>
        <div className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
          <Calendar className="w-5 h-5 text-blue-600 dark:text-blue-400" />
          <div>
            <div className="font-medium text-gray-900 dark:text-white">
              {data?.upcoming_assessments ?? 0} planned assessments
            </div>
            <div className="text-sm text-gray-500 dark:text-gray-400">
              Controls: {data?.control_status_breakdown?.implemented ?? 0}/{data?.control_status_breakdown?.total ?? 0} implemented
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function ControlsTab({
  controls,
  loading,
  expandedControl,
  setExpandedControl,
  frameworkFilter,
  setFrameworkFilter,
  familyFilter,
  setFamilyFilter,
  statusFilter,
  setStatusFilter,
  frameworkScores,
}: {
  controls: Control[];
  loading: boolean;
  expandedControl: string | null;
  setExpandedControl: (id: string | null) => void;
  frameworkFilter: string;
  setFrameworkFilter: (value: string) => void;
  familyFilter: string;
  setFamilyFilter: (value: string) => void;
  statusFilter: string;
  setStatusFilter: (value: string) => void;
  frameworkScores: Array<{ name: string; score: number }>;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const controlFamilies = ['AC', 'AU', 'CM', 'CP', 'IA', 'SC', 'SI'];
  const controlStatuses = ['implemented', 'partially', 'planned', 'not_implemented'];

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center gap-2 mb-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">Filters</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Framework Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Framework
            </label>
            <select
              value={frameworkFilter}
              onChange={(e) => setFrameworkFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Frameworks</option>
              {frameworkScores.map((fw) => (
                <option key={fw.name} value={fw.name}>
                  {fw.name}
                </option>
              ))}
            </select>
          </div>

          {/* Family Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Family
            </label>
            <select
              value={familyFilter}
              onChange={(e) => setFamilyFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Families</option>
              {controlFamilies.map((family) => (
                <option key={family} value={family}>
                  {family}
                </option>
              ))}
            </select>
          </div>

          {/* Status Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Statuses</option>
              {controlStatuses.map((status) => (
                <option key={status} value={status}>
                  {status.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Controls Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Control ID
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Title
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Family
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Implementation
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Baseline
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Evidence
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {controls.map((control) => (
              <tr
                key={control.id}
                className="hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer transition-colors"
                onClick={() =>
                  setExpandedControl(expandedControl === control.id ? null : control.id)
                }
              >
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {expandedControl === control.id ? (
                    <ChevronDown className="w-4 h-4 inline mr-2" />
                  ) : (
                    <ChevronRight className="w-4 h-4 inline mr-2" />
                  )}
                  {control.id}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  {control.title}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {control.control_family ?? ''}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      control.status === 'implemented'
                        ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                        : control.status === 'partially'
                        ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                        : control.status === 'planned'
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                        : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400'
                    )}
                  >
                    {control.status}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {control.implementation_status ?? 'N/A'}
                </td>
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {control.baseline}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {control.evidence_ids?.length ?? 0}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Expanded Control Details */}
      {expandedControl && (
        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-6">
          {controls.find((c) => c.id === expandedControl) && (
            <ControlExpandedDetails
              control={controls.find((c) => c.id === expandedControl)!}
            />
          )}
        </div>
      )}
    </div>
  );
}

function ControlExpandedDetails({ control }: { control: Control }) {
  return (
    <div className="space-y-4">
      <div>
        <h3 className="font-semibold text-gray-900 dark:text-white">Description</h3>
        <p className="text-sm text-gray-700 dark:text-gray-300 mt-1">
          {control.description || 'No description available'}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Last Assessed</h4>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            {control.last_assessed_at ? new Date(control.last_assessed_at || "").toLocaleDateString() : 'Never'}
          </p>
        </div>
        <div>
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Evidence Items</h4>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            {control.evidence_ids?.length ?? 0} files
          </p>
        </div>
      </div>

      {control.relatedControls && control.relatedControls.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Related Controls</h4>
          <div className="flex flex-wrap gap-2 mt-2">
            {(control.relatedControls ?? control.related_controls ?? []).map((relatedId) => (
              <span
                key={relatedId}
                className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-white dark:bg-gray-700 border border-gray-200 dark:border-gray-600 text-gray-700 dark:text-gray-300"
              >
                {relatedId}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="pt-4 border-t border-blue-200 dark:border-blue-800 flex gap-2">
        <button
          onClick={() => setExpandedControl(null)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium"
        >
          <FileText className="w-4 h-4" />
          View Evidence
        </button>
        <button
          onClick={() => setExpandedControl(null)}
          className="inline-flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-600 text-sm font-medium"
        >
          <Edit2 className="w-4 h-4" />
          Edit
        </button>
      </div>
    </div>
  );
}

function POAMsTab({
  poams,
  loading,
  statusFilter,
  setStatusFilter,
  riskLevelFilter,
  setRiskLevelFilter,
  onDeletePOAM,
  overduePOAMs,
}: {
  poams: POAM[];
  loading: boolean;
  statusFilter: string;
  setStatusFilter: (value: string) => void;
  riskLevelFilter: string;
  setRiskLevelFilter: (value: string) => void;
  onDeletePOAM: (id: string) => void;
  overduePOAMs: number;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const poamStatuses = ['open', 'in_progress', 'completed'];
  const riskLevels = ['high', 'medium', 'low'];

  // Calculate stats
  const stats = {
    open: poams.filter((p) => p.status === 'open').length,
    overdue: overduePOAMs,
    high_risk: poams.filter((p) => p.risk_level === 'high').length,
    completed: poams.filter((p) => p.status === 'completed').length,
  };

  return (
    <div className="space-y-6">
      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Open POA&Ms"
          value={stats.open}
          icon={AlertCircle}
          color="red"
        />
        <StatCard
          label="Overdue"
          value={stats.overdue}
          icon={Clock}
          color="orange"
        />
        <StatCard
          label="High Risk"
          value={stats.high_risk}
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          label="Completed This Quarter"
          value={stats.completed}
          icon={CheckCircle}
          color="green"
        />
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center gap-2 mb-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">Filters</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Status
            </label>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Statuses</option>
              {poamStatuses.map((status) => (
                <option key={status} value={status}>
                  {status.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Risk Level
            </label>
            <select
              value={riskLevelFilter}
              onChange={(e) => setRiskLevelFilter(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="all">All Risk Levels</option>
              {riskLevels.map((level) => (
                <option key={level} value={level}>
                  {level.charAt(0).toUpperCase() + level.slice(1)}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* POA&Ms Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                ID
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Weakness
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Risk Level
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Scheduled Date
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Assigned To
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Days Remaining
              </th>
              <th className="px-6 py-3 text-center text-xs font-semibold text-gray-700 dark:text-gray-300">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {poams.map((poam) => (
              <tr key={poam.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {poam.id}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  {poam.weakness_name ?? ''}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      poam.risk_level === 'high'
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        : poam.risk_level === 'medium'
                        ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                        : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    )}
                  >
                    {poam.risk_level}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      poam.status === 'open'
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        : poam.status === 'in_progress'
                        ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                        : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    )}
                  >
                    {(poam.status || '').replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {poam.scheduled_completion_date ? new Date(poam.scheduled_completion_date || "").toLocaleDateString() : 'N/A'}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {poam.assigned_to ?? ''}
                </td>
                <td className="px-6 py-4 text-sm">
                  {(() => {
                    if (!poam.scheduled_completion_date) return <span className="text-gray-400">N/A</span>;
                    const daysRemaining = Math.ceil(
                      (new Date(poam.scheduled_completion_date || "").getTime() - Date.now()) / (1000 * 60 * 60 * 24)
                    );
                    return (
                      <span
                        className={clsx(
                          'font-medium',
                          daysRemaining < 0
                            ? 'text-red-600 dark:text-red-400'
                            : daysRemaining < 7
                            ? 'text-orange-600 dark:text-orange-400'
                            : 'text-gray-600 dark:text-gray-400'
                        )}
                      >
                        {daysRemaining < 0
                          ? `${Math.abs(daysRemaining)} days overdue`
                          : `${daysRemaining} days`}
                      </span>
                    );
                  })()}
                </td>
                <td className="px-6 py-4 text-center">
                  <button
                    onClick={() => onDeletePOAM(poam.id)}
                    className="text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 p-2 rounded"
                    title="Delete"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Create POA&M Button */}
      <button className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium">
        <Plus className="w-5 h-5" />
        Create POA&M
      </button>
    </div>
  );
}

function CUITab({
  assets,
  loading,
}: {
  assets: CUIAsset[];
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
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard label="CUI Assets" value={assets.length} icon={FileText} color="blue" />
        <StatCard
          label="Active Markings"
          value={assets.filter((a) => a.cui_designation).length}
          icon={CheckCircle}
          color="green"
        />
        <StatCard
          label="Categories Tracked"
          value={new Set(assets.map((a) => a.cui_category)).size}
          icon={AlertTriangle}
          color="orange"
        />
      </div>

      {/* CUI Assets Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Asset
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                CUI Category
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Designation
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Dissemination Controls
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Classification Authority
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {assets.map((asset) => (
              <tr key={asset.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {asset.asset_id ?? ''}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {asset.asset_type ?? ''}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {asset.cui_category ?? ''}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {asset.cui_designation ?? ''}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {Array.isArray(asset.dissemination_controls) ? asset.dissemination_controls.join(', ') : ''}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {asset.classification_authority ?? ''}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Mark as CUI Button */}
      <button
        onClick={() => { setActiveTab('controls'); }}
        className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
      >
        <Plus className="w-5 h-5" />
        Mark as CUI
      </button>
    </div>
  );
}

function CISATab({
  directives,
  loading,
}: {
  directives: CISADirective[];
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
      {/* Active Directives Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {directives.map((directive) => (
          <div
            key={directive.id}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  {directive.id}
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  {directive.title}
                </p>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  directive.status === 'open'
                    ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                    : directive.status === 'in_progress'
                    ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400'
                    : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                )}
              >
                {(directive.status ?? '').replace(/_/g, ' ')}
              </span>
            </div>

            <div className="space-y-2 mb-4">
              <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                <Calendar className="w-4 h-4" />
                Deadline: {directive.compliance_deadline ? new Date(directive.compliance_deadline || "").toLocaleDateString() : 'N/A'}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                {Array.isArray(directive.actions_taken) ? directive.actions_taken.length : 0} actions taken
              </div>
            </div>

            <button
              onClick={() => api.post(`/compliance/cisa/directives/${directive.id}/check`)}
              className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium"
            >
              Check Compliance
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  color: 'red' | 'orange' | 'green' | 'blue';
}) {
  const colorClasses: Record<string, string> = {
    red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
    orange: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
    blue: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
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
