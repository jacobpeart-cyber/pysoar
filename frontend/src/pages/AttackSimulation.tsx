import { useState, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import {
  Target,
  AlertTriangle,
  Zap,
  Shield,
  Activity,
  TrendingUp,
  Play,
  Pause,
  CheckCircle,
  XCircle,
  Search,
  Filter,
  Gauge,
} from 'lucide-react';
import { LineChart, Line, BarChart, Bar, RadarChart, Radar, PolarAngleAxis, PolarRadiusAxis, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import clsx from 'clsx';

interface SimulationDashboard {
  total_simulations: number;
  completed_simulations: number;
  running_simulations: number;
  average_detection_rate: number;
  average_posture_score: number;
  techniques_in_library: number;
  adversary_profiles: number;
  top_tactics: TacticData[];
  recent_simulations: Simulation[];
  security_trends: { scores: number[]; detection_rates: number[] };
}

interface Simulation {
  id: string;
  name: string;
  simulation_type: 'atomic' | 'chain' | 'adversary' | 'purple';
  status: 'draft' | 'running' | 'completed' | 'failed';
  tests_passed: number;
  tests_failed: number;
  tests_blocked: number;
  detection_rate: number;
  score: number;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  progress?: number;
}

interface PaginatedSimulations {
  total: number;
  page: number;
  page_size: number;
  simulations: Simulation[];
}

interface PaginatedTechniques {
  total: number;
  techniques: MITRETechnique[];
  facets: Record<string, any>;
}

interface PaginatedAdversaries {
  total: number;
  adversaries: AdversaryProfile[];
}

interface MITRETechnique {
  id: string;
  mitre_id: string;
  name: string;
  tactic: string;
  platforms: string[];
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  is_safe: boolean;
  description: string;
  test_command: string;
  expected_detection: string;
}

interface AdversaryProfile {
  id: string;
  name: string;
  sophistication: 'low' | 'medium' | 'high' | 'expert';
  target_sectors: string[];
  tools_used: string[];
  attack_chain: AttackStep[];
  is_builtin: boolean;
}

interface AttackStep {
  step: number;
  technique_id: string;
  technique_name: string;
  description: string;
}

interface PostureData {
  tactic: string;
  score: number;
}

interface PostureResponse {
  simulation_id: string;
  score_type: string;
  score: number;
  max_score: number;
  breakdown: PostureData[];
  assessed_at: string;
  recommendations?: GapAnalysis[];
}

interface GapAnalysis {
  technique: string;
  tactic: string;
  detection_status: 'detected' | 'missed';
  recommendation: string;
}

interface TrendPoint {
  date: string;
  score: number;
}

interface TacticData {
  tactic: string;
  detection_rate: number;
}

const statusColors = {
  draft: 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300',
  running: 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300',
  completed: 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-300',
  failed: 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-300',
};

const riskLevelColors = {
  critical: 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20',
  high: 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20',
  medium: 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20',
  low: 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20',
};

const sophisticationColors = {
  low: 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400',
  medium: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600 dark:text-yellow-400',
  high: 'bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400',
  expert: 'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400',
};

function formatDuration(startedAt: string | null, completedAt: string | null, durationSeconds: number | null): string {
  if (durationSeconds != null) {
    const h = Math.floor(durationSeconds / 3600);
    const m = Math.floor((durationSeconds % 3600) / 60);
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }
  if (startedAt && completedAt) {
    const diff = Math.floor((new Date(completedAt || "").getTime() - new Date(startedAt || "").getTime()) / 1000);
    const h = Math.floor(diff / 3600);
    const m = Math.floor((diff % 3600) / 60);
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  }
  return '--';
}

function showNotification(message: string, type: 'success' | 'error' = 'success') {
  if (type === 'error') {
    console.error(message);
  } else {
    console.log(message);
  }
}

export default function AttackSimulation() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'simulations' | 'techniques' | 'adversaries' | 'posture'>('dashboard');
  const [tacticFilter, setTacticFilter] = useState('all');
  const [platformFilter, setPlatformFilter] = useState('all');
  const [safeOnly, setSafeOnly] = useState(false);
  const [expandedTechnique, setExpandedTechnique] = useState<string | null>(null);
  const [showNewSimulationModal, setShowNewSimulationModal] = useState(false);

  // Form state for new simulation modal
  const [newSimName, setNewSimName] = useState('');
  const [newSimType, setNewSimType] = useState<string>('atomic');
  const [newSimDescription, setNewSimDescription] = useState('');
  const [newSimEnvironment, setNewSimEnvironment] = useState('lab');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [runningTests, setRunningTests] = useState<Set<string>>(new Set());

  // Fetch simulation dashboard
  const { data: dashboard, isLoading: dashboardLoading, error: dashboardError } = useQuery({
    queryKey: ['simulationDashboard'],
    queryFn: async () => {
      const response = await api.get<SimulationDashboard>('/simulation/dashboard');
      return response.data;
    },
  });

  // Fetch simulations
  const { data: simulations, isLoading: simulationsLoading } = useQuery({
    queryKey: ['simulations'],
    queryFn: async () => {
      const response = await api.get<PaginatedSimulations | Simulation[]>('/simulation/simulations');
      const data = response.data;
      if (Array.isArray(data)) return data;
      return data.simulations ?? [];
    },
  });

  // Fetch MITRE techniques
  const { data: techniques, isLoading: techniquesLoading } = useQuery({
    queryKey: ['techniques', tacticFilter, platformFilter, safeOnly],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (tacticFilter !== 'all') params.tactic = tacticFilter;
      if (platformFilter !== 'all') params.platform = platformFilter;
      if (safeOnly) params.safe_only = true;

      const response = await api.get<PaginatedTechniques | MITRETechnique[]>('/simulation/techniques', { params });
      const data = response.data;
      if (Array.isArray(data)) return data;
      return data.techniques ?? [];
    },
  });

  // Fetch adversary profiles
  const { data: adversaries, isLoading: adversariesLoading } = useQuery({
    queryKey: ['adversaries'],
    queryFn: async () => {
      const response = await api.get<PaginatedAdversaries | AdversaryProfile[]>('/simulation/adversaries');
      const data = response.data;
      if (Array.isArray(data)) return data;
      return data.adversaries ?? [];
    },
  });

  // Fetch posture analysis
  const { data: posture, isLoading: postureLoading } = useQuery({
    queryKey: ['postureAnalysis'],
    queryFn: async () => {
      const response = await api.get<PostureResponse>('/simulation/posture');
      return response.data;
    },
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Breach & Attack Simulation</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">Test security controls and measure detection capabilities</p>
        </div>
        <Target className="w-10 h-10 text-red-600 dark:text-red-400" />
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <div className="flex space-x-8 overflow-x-auto">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: Activity },
            { id: 'simulations', label: 'Simulations', icon: Zap },
            { id: 'techniques', label: 'Technique Library', icon: Shield },
            { id: 'adversaries', label: 'Adversary Profiles', icon: AlertTriangle },
            { id: 'posture', label: 'Security Posture', icon: TrendingUp },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={clsx(
                  'px-4 py-3 border-b-2 font-medium text-sm transition-colors flex items-center gap-2 whitespace-nowrap',
                  activeTab === tab.id
                    ? 'border-red-600 text-red-600 dark:text-red-400'
                    : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200'
                )}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Content */}

      {/* Dashboard Tab */}
      {activeTab === 'dashboard' && (
        <div className="space-y-6">
          {dashboardLoading && (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading dashboard...</div>
          )}
          {dashboardError && (
            <div className="text-center py-8 text-red-500 dark:text-red-400">Failed to load dashboard data. Please try again.</div>
          )}
          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Simulations Run</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">{dashboard?.total_simulations ?? 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Detection Rate</p>
              <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-2">{dashboard?.average_detection_rate?.toFixed(1) ?? 0}%</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Security Posture</p>
              <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-2">{dashboard?.average_posture_score ?? 0}/100</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Techniques in Library</p>
              <p className="text-3xl font-bold text-purple-600 dark:text-purple-400 mt-2">{dashboard?.techniques_in_library ?? 0}</p>
            </div>
          </div>

          {/* Charts */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Posture Trend */}
            {dashboard?.posture_trend && dashboard.posture_trend.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Posture Score Trend</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <LineChart data={dashboard.posture_trend}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                    <XAxis dataKey="date" stroke="#6b7280" />
                    <YAxis stroke="#6b7280" domain={[0, 100]} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: 'none',
                        borderRadius: '0.5rem',
                        color: '#fff',
                      }}
                    />
                    <Line
                      type="monotone"
                      dataKey="score"
                      stroke="#3b82f6"
                      strokeWidth={2}
                      dot={{ fill: '#3b82f6', r: 4 }}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            )}

            {/* Detection by Tactic */}
            {dashboard?.detection_by_tactic && dashboard.detection_by_tactic.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Detection Rate by Tactic</h3>
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={dashboard.detection_by_tactic}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                    <XAxis dataKey="tactic" stroke="#6b7280" angle={-45} textAnchor="end" height={80} />
                    <YAxis stroke="#6b7280" />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#1f2937',
                        border: 'none',
                        borderRadius: '0.5rem',
                        color: '#fff',
                      }}
                    />
                    <Bar dataKey="detection_rate" fill="#10b981" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          {/* Recent Simulations */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Simulations</h3>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Detection Rate</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Score</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {dashboard?.recent_simulations && dashboard.recent_simulations.length > 0 ? (
                  dashboard.recent_simulations.slice(0, 10).map((sim) => (
                    <tr key={sim.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                      <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{sim.name}</td>
                      <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 capitalize">{sim.simulation_type}</td>
                      <td className="px-6 py-4">
                        <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', statusColors[sim.status] ?? '')}>
                          {sim.status ? (sim.status || "").charAt(0).toUpperCase() + sim.status.slice(1) : '--'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <div className="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div
                              className="bg-green-500 h-2 rounded-full"
                              style={{ width: `${sim.detection_rate ?? 0}%` }}
                            />
                          </div>
                          <span className="text-sm font-medium text-gray-900 dark:text-white">{(sim.detection_rate ?? 0).toFixed(0)}%</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{sim.score ?? '--'}</td>
                      <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{sim.completed_at ? new Date(sim.completed_at || "").toLocaleDateString() : '--'}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No recent simulations found.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Simulations Tab */}
      {activeTab === 'simulations' && (
        <div className="space-y-6">
          <button
            onClick={() => setShowNewSimulationModal(true)}
            className="px-4 py-2 rounded-lg bg-red-600 dark:bg-red-700 text-white hover:bg-red-700 dark:hover:bg-red-600 font-medium transition-colors"
          >
            New Simulation
          </button>

          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Tests</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Detection Rate</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Duration</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {simulationsLoading && (
                  <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">Loading simulations...</td>
                  </tr>
                )}
                {!simulationsLoading && (!simulations || simulations.length === 0) && (
                  <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No simulations found. Create one to get started.</td>
                  </tr>
                )}
                {simulations?.map((sim) => (
                  <tr key={sim.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{sim.name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 capitalize">{sim.simulation_type}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', statusColors[sim.status] ?? '')}>
                          {sim.status ? (sim.status || "").charAt(0).toUpperCase() + sim.status.slice(1) : '--'}
                        </span>
                        {sim.status === 'running' && sim.progress != null && (
                          <div className="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div
                              className="bg-blue-500 h-2 rounded-full transition-all"
                              style={{ width: `${sim.progress}%` }}
                            />
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      <div className="flex gap-2">
                        <span className="text-green-600 dark:text-green-400 font-medium">{sim.tests_passed ?? 0}</span>
                        <span className="text-gray-400 dark:text-gray-500">/</span>
                        <span className="text-red-600 dark:text-red-400 font-medium">{sim.tests_failed ?? 0}</span>
                        <span className="text-gray-400 dark:text-gray-500">/</span>
                        <span className="text-orange-600 dark:text-orange-400 font-medium">{sim.tests_blocked ?? 0}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className="bg-green-500 h-2 rounded-full"
                            style={{ width: `${sim.detection_rate ?? 0}%` }}
                          />
                        </div>
                        <span className="text-sm font-medium text-gray-900 dark:text-white">{(sim.detection_rate ?? 0).toFixed(0)}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{formatDuration(sim.started_at, sim.completed_at, sim.duration_seconds)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Technique Library Tab */}
      {activeTab === 'techniques' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="flex flex-wrap gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-white mb-2">Tactic</label>
              <select
                value={tacticFilter}
                onChange={(e) => setTacticFilter(e.target.value)}
                className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-red-500"
              >
                <option value="all">All Tactics</option>
                <option value="reconnaissance">Reconnaissance</option>
                <option value="resource_development">Resource Development</option>
                <option value="initial_access">Initial Access</option>
                <option value="execution">Execution</option>
                <option value="persistence">Persistence</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-900 dark:text-white mb-2">Platform</label>
              <select
                value={platformFilter}
                onChange={(e) => setPlatformFilter(e.target.value)}
                className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-red-500"
              >
                <option value="all">All Platforms</option>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
                <option value="macos">macOS</option>
              </select>
            </div>
            <div className="flex items-end">
              <label className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gray-100 dark:bg-gray-700 cursor-pointer">
                <input
                  type="checkbox"
                  checked={safeOnly}
                  onChange={(e) => setSafeOnly(e.target.checked)}
                  className="w-4 h-4"
                />
                <span className="text-sm font-medium text-gray-900 dark:text-white">Safe only</span>
              </label>
            </div>
          </div>

          {/* Techniques Grid */}
          {techniquesLoading && (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading techniques...</div>
          )}
          {!techniquesLoading && (!techniques || techniques.length === 0) && (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">No techniques found matching the current filters.</div>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {techniques?.slice(0, 15).map((technique) => (
              <div
                key={technique.mitre_id ?? technique.id}
                onClick={() => setExpandedTechnique(expandedTechnique === (technique.mitre_id ?? technique.id) ? null : (technique.mitre_id ?? technique.id))}
                className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4 cursor-pointer hover:border-gray-300 dark:hover:border-gray-600 transition-colors"
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1">
                      <p className="text-sm text-gray-600 dark:text-gray-400 font-medium">{technique.mitre_id ?? technique.id}</p>
                      <h3 className="font-semibold text-gray-900 dark:text-white mt-1">{technique.name}</h3>
                    </div>
                    {technique.is_safe && (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400 whitespace-nowrap">
                        Safe
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-500 mt-2">{technique.tactic}</p>
                </div>

                <div className="flex flex-wrap gap-1">
                  {technique.platforms?.map((platform) => (
                    <span key={platform} className="px-2 py-1 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                      {platform}
                    </span>
                  ))}
                </div>

                <div>
                  <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', riskLevelColors[technique.risk_level] ?? '')}>
                    {technique.risk_level ? (technique.risk_level || "").charAt(0).toUpperCase() + technique.risk_level.slice(1) : '--'}
                  </span>
                </div>

                {expandedTechnique === (technique.mitre_id ?? technique.id) && (
                  <div className="pt-4 border-t border-gray-200 dark:border-gray-700 space-y-3">
                    <div>
                      <p className="text-xs font-semibold text-gray-900 dark:text-white mb-1">Description</p>
                      <p className="text-xs text-gray-600 dark:text-gray-400">{technique.description}</p>
                    </div>
                    {technique.test_command && (
                      <div>
                        <p className="text-xs font-semibold text-gray-900 dark:text-white mb-1">Test Command</p>
                        <p className="text-xs text-gray-600 dark:text-gray-400 font-mono bg-gray-50 dark:bg-gray-700 p-2 rounded truncate">{technique.test_command}</p>
                      </div>
                    )}
                    <button
                      disabled={runningTests.has(technique.mitre_id ?? technique.id)}
                      onClick={async (e) => {
                        e.stopPropagation();
                        const techId = technique.mitre_id ?? technique.id;
                        setRunningTests((prev) => new Set(prev).add(techId));
                        try {
                          await api.post(`/simulation/techniques/${technique.mitre_id}/test`);
                          showNotification('Test started for technique: ' + technique.name);
                        } catch (error: any) {
                          showNotification(error?.response?.data?.detail ?? 'Failed to start test.', 'error');
                        } finally {
                          setRunningTests((prev) => {
                            const next = new Set(prev);
                            next.delete(techId);
                            return next;
                          });
                        }
                      }}
                      className={clsx(
                        'w-full px-3 py-2 rounded-lg text-white text-xs font-medium transition-colors',
                        runningTests.has(technique.mitre_id ?? technique.id)
                          ? 'bg-gray-400 cursor-not-allowed'
                          : 'bg-red-600 dark:bg-red-700 hover:bg-red-700 dark:hover:bg-red-600'
                      )}
                    >
                      {runningTests.has(technique.mitre_id ?? technique.id) ? 'Running...' : 'Run Test'}
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Adversary Profiles Tab */}
      {activeTab === 'adversaries' && (
        <div className="space-y-6">
          {adversariesLoading && (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading adversary profiles...</div>
          )}
          {!adversariesLoading && (!adversaries || adversaries.length === 0) && (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">No adversary profiles found.</div>
          )}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {adversaries?.map((adversary) => (
            <div key={adversary.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="font-semibold text-gray-900 dark:text-white">{adversary.name}</h3>
                  {adversary.is_builtin && (
                    <span className="text-xs text-blue-600 dark:text-blue-400 font-medium mt-1">Built-in</span>
                  )}
                </div>
                <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', sophisticationColors[adversary.sophistication])}>
                  {(adversary.sophistication || "").charAt(0).toUpperCase() + adversary.sophistication.slice(1)}
                </span>
              </div>

              <div>
                <p className="text-xs font-semibold text-gray-900 dark:text-white mb-2">Target Sectors</p>
                <div className="flex flex-wrap gap-1">
                  {(adversary.target_sectors ?? []).map((sector) => (
                    <span key={sector} className="px-2 py-1 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                      {sector}
                    </span>
                  ))}
                </div>
              </div>

              <div>
                <p className="text-xs font-semibold text-gray-900 dark:text-white mb-2">Tools</p>
                <div className="flex flex-wrap gap-1">
                  {adversary.tools_used.slice(0, 3).map((tool) => (
                    <span key={tool} className="px-2 py-1 rounded text-xs bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300">
                      {tool}
                    </span>
                  ))}
                  {adversary.tools_used.length > 3 && (
                    <span className="px-2 py-1 rounded text-xs text-gray-600 dark:text-gray-400">
                      +{adversary.tools_used.length - 3} more
                    </span>
                  )}
                </div>
              </div>

              <div>
                <p className="text-xs font-semibold text-gray-900 dark:text-white mb-2">Attack Chain</p>
                <div className="space-y-2">
                  {adversary.attack_chain.slice(0, 3).map((step) => (
                    <div key={step.step} className="flex gap-2 text-xs">
                      <span className="text-gray-500 dark:text-gray-500 font-medium">{step.step}.</span>
                      <span className="text-gray-600 dark:text-gray-400">{step.technique_name}</span>
                    </div>
                  ))}
                  {adversary.attack_chain.length > 3 && (
                    <p className="text-xs text-gray-500 dark:text-gray-500">+{adversary.attack_chain.length - 3} more steps</p>
                  )}
                </div>
              </div>

              <button
                onClick={async () => {
                  try {
                    await api.post(`/simulation/adversaries/${adversary.id}/emulate`);
                    showNotification('Simulation started for adversary: ' + adversary.name);
                    queryClient.invalidateQueries({ queryKey: ['simulations'] });
                  } catch (error: any) {
                    showNotification(error?.response?.data?.detail ?? 'Failed to start adversary emulation.', 'error');
                  }
                }}
                className="w-full px-4 py-2 rounded-lg bg-red-600 dark:bg-red-700 text-white hover:bg-red-700 dark:hover:bg-red-600 font-medium text-sm transition-colors"
              >
                Emulate
              </button>
            </div>
          ))}
        </div>
        </div>
      )}

      {/* Security Posture Tab */}
      {activeTab === 'posture' && (
        <div className="space-y-6">
          {postureLoading && (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading security posture...</div>
          )}
          {/* Posture Gauge */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">Overall Security Posture</h3>
            <div className="flex items-center justify-center">
              <div className="relative w-40 h-40">
                <svg viewBox="0 0 100 100" className="w-full h-full transform -rotate-90">
                  <circle cx="50" cy="50" r="45" fill="none" stroke="#e5e7eb" strokeWidth="8" />
                  <circle
                    cx="50"
                    cy="50"
                    r="45"
                    fill="none"
                    stroke={
                      (posture?.score || 0) > 70
                        ? '#10b981'
                        : (posture?.score || 0) > 50
                        ? '#f59e0b'
                        : '#ef4444'
                    }
                    strokeWidth="8"
                    strokeDasharray={`${((posture?.score || 0) / 100) * 282.7} 282.7`}
                    strokeLinecap="round"
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center">
                    <p className="text-4xl font-bold text-gray-900 dark:text-white">{posture?.score || 0}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">/ 100</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Score by Tactic */}
          {posture?.breakdown && posture.breakdown.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Coverage by Tactic</h3>
              <ResponsiveContainer width="100%" height={300}>
                <RadarChart data={posture.breakdown}>
                  <PolarAngleAxis dataKey="tactic" stroke="#6b7280" />
                  <PolarRadiusAxis stroke="#6b7280" />
                  <Radar name="Score" dataKey="score" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.6} />
                </RadarChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Gap Analysis */}
          {posture?.recommendations && posture.recommendations.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
              <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Gap Analysis</h3>
              </div>
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Technique</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Tactic</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Recommendation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {posture.recommendations.slice(0, 10).map((gap, idx) => (
                    <tr key={idx} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                      <td className="px-6 py-4 font-medium text-gray-900 dark:text-white text-sm">{gap.technique}</td>
                      <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{gap.tactic}</td>
                      <td className="px-6 py-4">
                        <span
                          className={clsx(
                            'px-3 py-1 rounded-full text-xs font-medium',
                            gap.detection_status === 'detected'
                              ? 'bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400'
                              : 'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400'
                          )}
                        >
                          {(gap.detection_status || "").charAt(0).toUpperCase() + gap.detection_status.slice(1)}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{gap.recommendation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Score Summary */}
          {posture && (
            <div className={clsx(
              'p-4 rounded-lg border',
              (posture.score / (posture.max_score || 100)) > 0.7
                ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-700'
                : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-700'
            )}>
              <p className={clsx(
                'text-sm font-medium',
                (posture.score / (posture.max_score || 100)) > 0.7
                  ? 'text-green-800 dark:text-green-200'
                  : 'text-red-800 dark:text-red-200'
              )}>
                Security posture score: {posture.score} / {posture.max_score || 100} ({posture.score_type})
              </p>
            </div>
          )}
        </div>
      )}
      {/* New Simulation Modal */}
      {showNewSimulationModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Launch New Simulation</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Simulation Name</label>
                <input
                  type="text"
                  value={newSimName}
                  onChange={(e) => setNewSimName(e.target.value)}
                  placeholder="e.g., Ransomware Attack Chain"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Type</label>
                <select
                  value={newSimType}
                  onChange={(e) => setNewSimType(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="atomic">Atomic</option>
                  <option value="chain">Attack Chain</option>
                  <option value="adversary">Adversary Emulation</option>
                  <option value="purple">Purple Team</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Description</label>
                <textarea
                  value={newSimDescription}
                  onChange={(e) => setNewSimDescription(e.target.value)}
                  placeholder="Describe the simulation objective..."
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Target Environment</label>
                <select
                  value={newSimEnvironment}
                  onChange={(e) => setNewSimEnvironment(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="lab">Lab</option>
                  <option value="staging">Staging</option>
                  <option value="production">Production</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => {
                    setShowNewSimulationModal(false);
                    setNewSimName('');
                    setNewSimType('atomic');
                    setNewSimDescription('');
                    setNewSimEnvironment('lab');
                  }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-900 dark:text-white transition"
                >
                  Cancel
                </button>
                <button
                  disabled={isSubmitting || !newSimName.trim()}
                  onClick={async () => {
                    setIsSubmitting(true);
                    try {
                      await api.post('/simulation/simulations', {
                        simulation_type: newSimType,
                        name: newSimName.trim(),
                        description: newSimDescription.trim(),
                        techniques: [],
                        target_environment: newSimEnvironment,
                      });
                      showNotification('Simulation created successfully.');
                      setShowNewSimulationModal(false);
                      setNewSimName('');
                      setNewSimType('atomic');
                      setNewSimDescription('');
                      setNewSimEnvironment('lab');
                      queryClient.invalidateQueries({ queryKey: ['simulations'] });
                      queryClient.invalidateQueries({ queryKey: ['simulationDashboard'] });
                    } catch (error: any) {
                      showNotification(error?.response?.data?.detail ?? 'Failed to create simulation.', 'error');
                    } finally {
                      setIsSubmitting(false);
                    }
                  }}
                  className={clsx(
                    'flex-1 px-4 py-2 text-white rounded-lg transition',
                    isSubmitting || !newSimName.trim()
                      ? 'bg-gray-400 cursor-not-allowed'
                      : 'bg-red-600 hover:bg-red-700'
                  )}
                >
                  {isSubmitting ? 'Creating...' : 'Launch'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
