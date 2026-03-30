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

interface Framework {
  id: string;
  name: string;
  score: number;
  status: 'compliant' | 'partially' | 'non-compliant';
  controlsImplemented: number;
  controlsTotal: number;
  lastAssessment: string;
}

interface DashboardData {
  overallScore: number;
  frameworks: Framework[];
  overduePOAMs: number;
  trends: Array<{ date: string; score: number }>;
  upcomingAssessments: Array<{ framework: string; date: string }>;
}

interface Control {
  id: string;
  title: string;
  family: string;
  status: 'implemented' | 'partially' | 'planned' | 'not_implemented';
  implementationPercentage: number;
  baseline: 'L' | 'M' | 'H';
  lastAssessed: string;
  evidenceCount: number;
  description?: string;
  relatedControls?: string[];
}

interface POAM {
  id: string;
  weakness: string;
  riskLevel: 'high' | 'medium' | 'low';
  status: 'open' | 'in_progress' | 'completed';
  scheduledDate: string;
  assignedTo: string;
  daysRemaining: number;
}

interface CUIAsset {
  id: string;
  asset: string;
  type: string;
  cuiCategory: string;
  designation: string;
  disseminationControls: string;
  classificationAuthority: string;
}

interface CISADirective {
  id: string;
  title: string;
  deadline: string;
  status: 'open' | 'in_progress' | 'completed';
  actionsTaken: number;
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
      const response = await api.get('/compliance/dashboard');
      return response.data;
    },
  });

  const { data: controls, isLoading: controlsLoading } = useQuery<Control[]>({
    queryKey: ['compliance-controls', frameworkFilter, familyFilter, statusFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (frameworkFilter !== 'all') params.append('framework', frameworkFilter);
      if (familyFilter !== 'all') params.append('family', familyFilter);
      if (statusFilter !== 'all') params.append('status', statusFilter);
      const response = await api.get(`/compliance/controls?${params}`);
      return response.data;
    },
  });

  const { data: poams, isLoading: poamsLoading } = useQuery<POAM[]>({
    queryKey: ['compliance-poams', poamStatusFilter, riskLevelFilter],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (poamStatusFilter !== 'all') params.append('status', poamStatusFilter);
      if (riskLevelFilter !== 'all') params.append('riskLevel', riskLevelFilter);
      const response = await api.get(`/compliance/poams?${params}`);
      return response.data;
    },
  });

  const { data: cuiAssets, isLoading: cuiLoading } = useQuery<CUIAsset[]>({
    queryKey: ['compliance-cui'],
    queryFn: async () => {
      const response = await api.get('/compliance/cui');
      return response.data;
    },
  });

  const { data: cisaDirectives, isLoading: cisaLoading } = useQuery<CISADirective[]>({
    queryKey: ['compliance-cisa'],
    queryFn: async () => {
      const response = await api.get('/compliance/cisa/directives');
      return response.data;
    },
  });

  const createPOAMMutation = useMutation({
    mutationFn: async (data: Partial<POAM>) => {
      const response = await api.post('/compliance/poams', data);
      return response.data;
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
          frameworks={dashboardData?.frameworks || []}
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
          frameworks={dashboardData?.frameworks || []}
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
          overduePOAMs={dashboardData?.overduePOAMs || 0}
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
  frameworks,
}: {
  data?: DashboardData;
  loading: boolean;
  frameworks: Framework[];
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
                  strokeDasharray={`${(data?.overallScore || 0) * 3.4} 340`}
                  className={clsx(
                    'transition-all duration-500',
                    (data?.overallScore || 0) >= 80
                      ? 'text-green-500'
                      : (data?.overallScore || 0) >= 60
                      ? 'text-yellow-500'
                      : 'text-red-500'
                  )}
                />
              </svg>
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="text-center">
                  <div className="text-3xl font-bold text-gray-900 dark:text-white">
                    {data?.overallScore || 0}
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
      {data && data.overduePOAMs > 0 && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-semibold text-red-800 dark:text-red-400">Overdue POA&Ms</h3>
            <p className="text-sm text-red-700 dark:text-red-300">
              {data.overduePOAMs} Plan of Action and Milestones are overdue. Review and update schedules immediately.
            </p>
          </div>
        </div>
      )}

      {/* Framework Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {frameworks.map((framework) => (
          <div
            key={framework.id}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-5"
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  {framework.name}
                </h3>
              </div>
              <span className={clsx('text-xs font-semibold px-2.5 py-1 rounded-full', getStatusBadgeColor(framework.status))}>
                {framework.status.replace(/-/g, ' ').replace('non compliant', 'Non-Compliant')}
              </span>
            </div>

            <div className="space-y-3">
              {/* Score Gauge */}
              <div>
                <div className="flex items-end justify-between mb-1">
                  <span className="text-xs text-gray-600 dark:text-gray-400">Score</span>
                  <span className={clsx('text-lg font-bold', getScoreColor(framework.score))}>
                    {framework.score}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={clsx(
                      'h-full rounded-full transition-all duration-300',
                      framework.score >= 80
                        ? 'bg-green-500'
                        : framework.score >= 60
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                    )}
                    style={{ width: `${framework.score}%` }}
                  />
                </div>
              </div>

              {/* Control Counts */}
              <div className="text-sm">
                <div className="text-gray-600 dark:text-gray-400">
                  Controls: <span className="font-semibold text-gray-900 dark:text-white">
                    {framework.controlsImplemented}/{framework.controlsTotal}
                  </span>
                </div>
              </div>

              {/* Last Assessment */}
              <div className="text-xs text-gray-500 dark:text-gray-400">
                Last assessed: {new Date(framework.lastAssessment).toLocaleDateString()}
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
        <div className="space-y-3">
          {(data?.upcomingAssessments || []).map((assessment, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
            >
              <div className="flex items-center gap-3">
                <Calendar className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                <div>
                  <div className="font-medium text-gray-900 dark:text-white">
                    {assessment.framework}
                  </div>
                  <div className="text-sm text-gray-500 dark:text-gray-400">
                    {new Date(assessment.date).toLocaleDateString()}
                  </div>
                </div>
              </div>
              <button className="text-blue-600 dark:text-blue-400 hover:underline text-sm font-medium">
                Schedule
              </button>
            </div>
          ))}
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
  frameworks,
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
  frameworks: Framework[];
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
              {frameworks.map((fw) => (
                <option key={fw.id} value={fw.id}>
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
                  {control.family}
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
                <td className="px-6 py-4 text-sm">
                  <div className="w-16 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-blue-500 dark:bg-blue-600"
                      style={{ width: `${control.implementationPercentage}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-500 dark:text-gray-400 ml-2">
                    {control.implementationPercentage}%
                  </span>
                </td>
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {control.baseline}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {control.evidenceCount}
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
            {new Date(control.lastAssessed).toLocaleDateString()}
          </p>
        </div>
        <div>
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Evidence Items</h4>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
            {control.evidenceCount} files
          </p>
        </div>
      </div>

      {control.relatedControls && control.relatedControls.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300">Related Controls</h4>
          <div className="flex flex-wrap gap-2 mt-2">
            {control.relatedControls.map((relatedId) => (
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
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium">
          <FileText className="w-4 h-4" />
          View Evidence
        </button>
        <button className="inline-flex items-center gap-2 px-4 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-white border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-600 text-sm font-medium">
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
    high_risk: poams.filter((p) => p.riskLevel === 'high').length,
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
                  {poam.weakness}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      poam.riskLevel === 'high'
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        : poam.riskLevel === 'medium'
                        ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                        : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    )}
                  >
                    {poam.riskLevel}
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
                    {poam.status.replace(/_/g, ' ')}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {new Date(poam.scheduledDate).toLocaleDateString()}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {poam.assignedTo}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'font-medium',
                      poam.daysRemaining < 0
                        ? 'text-red-600 dark:text-red-400'
                        : poam.daysRemaining < 7
                        ? 'text-orange-600 dark:text-orange-400'
                        : 'text-gray-600 dark:text-gray-400'
                    )}
                  >
                    {poam.daysRemaining < 0
                      ? `${Math.abs(poam.daysRemaining)} days overdue`
                      : `${poam.daysRemaining} days`}
                  </span>
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
          value={assets.filter((a) => a.designation).length}
          icon={CheckCircle}
          color="green"
        />
        <StatCard
          label="Categories Tracked"
          value={new Set(assets.map((a) => a.cuiCategory)).size}
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
                  {asset.asset}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {asset.type}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {asset.cuiCategory}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {asset.designation}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {asset.disseminationControls}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {asset.classificationAuthority}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Mark as CUI Button */}
      <button className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium">
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
                {directive.status.replace(/_/g, ' ')}
              </span>
            </div>

            <div className="space-y-2 mb-4">
              <div className="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400">
                <Calendar className="w-4 h-4" />
                Deadline: {new Date(directive.deadline).toLocaleDateString()}
              </div>
              <div className="text-sm text-gray-600 dark:text-gray-400">
                {directive.actionsTaken} actions taken
              </div>
            </div>

            <button className="w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium">
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
