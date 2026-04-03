import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  BarChart3,
  ChevronDown,
  ChevronRight,
  Plus,
  Filter,
  Shield,
  ShieldAlert,
  Loader2,
  Zap,
  Lock,
  Server,
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  Clock,
  TrendingUp,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';

type TabType = 'overview' | 'access-control' | 'devices' | 'segmentation' | 'policies';

type MaturityLevel = 'traditional' | 'initial' | 'advanced' | 'optimal';

interface Pillar {
  name: string;
  score: number;
  status: 'healthy' | 'at-risk' | 'critical';
}

interface DashboardData {
  total_policies: number;
  enabled_policies: number;
  total_devices: number;
  compliant_devices: number;
  non_compliant_devices: number;
  average_device_trust_score: number;
  total_access_decisions: number;
  allowed_decisions: number;
  denied_decisions: number;
  challenged_decisions: number;
  total_segments: number;
  active_segments: number;
  violation_count: number;
  maturity_score: number;
  maturity_level: string;
  last_updated: string;
}

interface AccessDecision {
  id: string;
  created_at: string;
  decision: string;
  risk_score: number;
  risk_factors: string[];
  reason: string;
}

interface Device {
  id: string;
  hostname: string;
  device_type: string;
  os_type: string;
  trust_score: number;
  is_compliant: boolean;
  compliance_checks: Record<string, boolean>;
  last_seen: string;
  status: string;
}

interface Segment {
  id: string;
  name: string;
  segment_type: string;
  member_count: number;
  allowed_protocols: string[];
  violation_count: number;
  status: string;
}

interface Policy {
  id: string;
  name: string;
  policy_type: string;
  risk_threshold: number;
  mfa_required: boolean;
  device_trust_required: boolean;
  decision_count: number;
  is_enabled: boolean;
}

interface DeviceStats {
  total: number;
  trusted: number;
  conditional: number;
  untrusted: number;
  blocked: number;
}

export default function ZeroTrustDashboard() {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [expandedDevice, setExpandedDevice] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<string>('all');
  const queryClient = useQueryClient();

  const { data: dashboardData, isLoading: dashboardLoading } = useQuery<DashboardData>({
    queryKey: ['zerotrust-dashboard'],
    queryFn: async () => {
      try {
      const response = await api.get('/zerotrust/dashboard');
      return response.data;
      } catch { return null; }
    },
  });

  const { data: deviceStats, isLoading: statsLoading } = useQuery<DeviceStats>({
    queryKey: ['zerotrust-device-stats'],
    queryFn: async () => {
      try {
      const response = await api.get('/zerotrust/device-stats');
      return response.data;
      } catch { return null; }
    },
  });

  const { data: devicesRaw, isLoading: devicesLoading } = useQuery<any>({
    queryKey: ['zerotrust-devices'],
    queryFn: async () => {
      try {
      const response = await api.get('/zerotrust/devices');
      return response.data;
      } catch { return null; }
    },
  });
  const devices: Device[] = Array.isArray(devicesRaw) ? devicesRaw : (devicesRaw?.devices || devicesRaw?.items || []);

  const { data: segmentsRaw, isLoading: segmentsLoading } = useQuery<any>({
    queryKey: ['zerotrust-segments'],
    queryFn: async () => {
      try {
      const response = await api.get('/zerotrust/segments');
      return response.data;
      } catch { return null; }
    },
  });
  const segments: Segment[] = Array.isArray(segmentsRaw) ? segmentsRaw : (segmentsRaw?.segments || segmentsRaw?.items || []);

  const { data: policiesRaw, isLoading: policiesLoading } = useQuery<any>({
    queryKey: ['zerotrust-policies'],
    queryFn: async () => {
      try {
      const response = await api.get('/zerotrust/policies');
      return response.data;
      } catch { return null; }
    },
  });
  const policies: Policy[] = Array.isArray(policiesRaw) ? policiesRaw : (policiesRaw?.policies || policiesRaw?.items || []);

  const assessDevicesMutation = useMutation({
    mutationFn: async () => {
      try {
      const response = await api.post('/zerotrust/assess-devices');
      return response.data;
      } catch { return null; }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['zerotrust-devices'] });
    },
  });

  const evaluateAccessMutation = useMutation({
    mutationFn: async (data: {
      subject: string;
      resource: string;
      context?: string;
    }) => {
      try {
      const response = await api.post('/zerotrust/evaluate-access', data);
      return response.data;
      } catch { return null; }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['zerotrust-dashboard'] });
    },
  });

  const getMaturityColor = (level: MaturityLevel) => {
    const colors: Record<MaturityLevel, string> = {
      traditional: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      initial: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
      advanced: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
      optimal: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    };
    return colors[level];
  };

  const getStatusColor = (status: string) => {
    const colors: Record<string, string> = {
      healthy: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      'at-risk': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
      critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
      active: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
      inactive: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400',
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Zero Trust Dashboard</h1>
        <p className="text-gray-500 dark:text-gray-400">
          Real-time access evaluation and trust posture assessment
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-8 -mb-px" aria-label="Tabs">
          {(['overview', 'access-control', 'devices', 'segmentation', 'policies'] as const).map((tab) => (
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
              {tab === 'access-control' && 'Access Control'}
              {tab === 'devices' && 'Device Trust'}
              {tab === 'segmentation' && 'Micro-Segmentation'}
              {tab === 'policies' && 'Policies'}
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

      {/* Access Control Tab */}
      {activeTab === 'access-control' && (
        <AccessControlTab
          recentDecisions={[]}
          accessDecisions24h={{ allowed: dashboardData?.allowed_decisions || 0, denied: dashboardData?.denied_decisions || 0, challenged: dashboardData?.challenged_decisions || 0 }}
          loading={dashboardLoading}
          decisionFilter={decisionFilter}
          setDecisionFilter={setDecisionFilter}
          onEvaluateAccess={(data) => evaluateAccessMutation.mutate(data)}
        />
      )}

      {/* Device Trust Tab */}
      {activeTab === 'devices' && (
        <DeviceTrustTab
          devices={devices || []}
          stats={deviceStats}
          loading={devicesLoading || statsLoading}
          expandedDevice={expandedDevice}
          setExpandedDevice={setExpandedDevice}
          onAssessDevices={() => assessDevicesMutation.mutate()}
        />
      )}

      {/* Micro-Segmentation Tab */}
      {activeTab === 'segmentation' && (
        <SegmentationTab
          segments={segments || []}
          loading={segmentsLoading}
        />
      )}

      {/* Policies Tab */}
      {activeTab === 'policies' && (
        <PoliciesTab
          policies={policies || []}
          loading={policiesLoading}
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

  const pillarArray = Array.isArray(data?.pillars) ? data.pillars : Object.entries(data?.pillars || {}).map(([k, v]: [string, any]) => ({ name: k, score: v?.score || 0, status: (v?.score || 0) >= 70 ? 'healthy' : 'at-risk' }));

  const maturityLevels = (() => {
    const levels: { level: MaturityLevel; label: string; pillarCount: number }[] = [
      { level: 'traditional', label: 'Traditional', pillarCount: 0 },
      { level: 'initial', label: 'Initial', pillarCount: 0 },
      { level: 'advanced', label: 'Advanced', pillarCount: 0 },
      { level: 'optimal', label: 'Optimal', pillarCount: 0 },
    ];
    const pillarArray = Array.isArray(data?.pillars) ? data.pillars : Object.entries(data?.pillars || {}).map(([k, v]: [string, any]) => ({ name: k, score: v?.score || 0, status: (v?.score || 0) >= 70 ? 'healthy' : 'at-risk' }));
    if (pillarArray.length > 0) {
      pillarArray.forEach((pillar: any) => {
        if (pillar.score >= 90) levels[3].pillarCount += 1;
        else if (pillar.score >= 70) levels[2].pillarCount += 1;
        else if (pillar.score >= 40) levels[1].pillarCount += 1;
        else levels[0].pillarCount += 1;
      });
    }
    return levels;
  })();

  return (
    <div className="space-y-6">
      {/* Maturity Level Banner */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Zero Trust Maturity
        </h2>
        <div className="flex items-center gap-3">
          {maturityLevels.map((item) => (
            <div
              key={item.level}
              className={clsx(
                'flex-1 px-4 py-3 rounded-lg border-2 text-center font-medium transition-all',
                (data?.maturity_level || "traditional") as MaturityLevel === item.level
                  ? `${getMaturityColor(item.level)} border-current`
                  : 'bg-gray-50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 text-gray-600 dark:text-gray-400'
              )}
            >
              <div>{item.label}</div>
              {item.pillarCount > 0 && (
                <div className="text-xs opacity-75 mt-1">{item.pillarCount} pillar{item.pillarCount !== 1 ? 's' : ''}</div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Pillar Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {pillarArray.map((pillar: any) => (
          <div
            key={pillar.name}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-5"
          >
            <h3 className="font-semibold text-gray-900 dark:text-white mb-3">
              {pillar.name}
            </h3>

            <div className="space-y-3">
              {/* Score Gauge */}
              <div>
                <div className="flex items-end justify-between mb-1">
                  <span className="text-xs text-gray-600 dark:text-gray-400">Score</span>
                  <span className="text-lg font-bold text-gray-900 dark:text-white">
                    {pillar.score}
                  </span>
                </div>
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                  <div
                    className={clsx(
                      'h-full rounded-full transition-all duration-300',
                      pillar.status === 'healthy'
                        ? 'bg-green-500'
                        : pillar.status === 'at-risk'
                        ? 'bg-yellow-500'
                        : 'bg-red-500'
                    )}
                    style={{ width: `${pillar.score}%` }}
                  />
                </div>
              </div>

              {/* Status */}
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  getStatusColor(pillar.status)
                )}
              >
                {(pillar.status || '').replace('-', ' ')}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Access Decisions Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Access Decisions (24h)
        </h2>
        <div className="grid grid-cols-3 gap-4">
          <DecisionChart
            label="Allowed"
            value={data?.allowed_decisions || 0}
            icon={CheckCircle}
            color="green"
          />
          <DecisionChart
            label="Denied"
            value={data?.denied_decisions || 0}
            icon={AlertTriangle}
            color="red"
          />
          <DecisionChart
            label="Challenged"
            value={data?.challenged_decisions || 0}
            icon={Clock}
            color="yellow"
          />
        </div>
      </div>

      {/* Recent Access Decisions */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Recent Access Decisions
        </h2>
        <div className="space-y-2">
          {(([] as AccessDecision[]) || []).slice(0, 5).map((decision) => (
            <div
              key={decision.id}
              className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
            >
              <div className="flex-1">
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {(decision as any).subject_id || "user"} → {(decision as any).resource_id || "resource"}
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                  {new Date(decision.created_at || "").toLocaleTimeString()} • Risk: {decision.risk_score}%
                </div>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  decision.decision === 'allow'
                    ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    : decision.decision === 'deny'
                    ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                    : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                )}
              >
                {decision.decision}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AccessControlTab({
  recentDecisions,
  accessDecisions24h,
  loading,
  decisionFilter,
  setDecisionFilter,
  onEvaluateAccess,
}: {
  recentDecisions: AccessDecision[];
  accessDecisions24h?: { allowed: number; denied: number; challenged: number };
  loading: boolean;
  decisionFilter: string;
  setDecisionFilter: (value: string) => void;
  onEvaluateAccess: (data: {
    subject: string;
    resource: string;
    context?: string;
  }) => void;
}) {
  const [evalSubject, setEvalSubject] = useState('');
  const [evalResource, setEvalResource] = useState('');
  const [evalContext, setEvalContext] = useState('');

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Evaluation Form */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
          Real-Time Access Evaluation
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Subject (User/Service)
            </label>
            <input
              type="text"
              value={evalSubject}
              onChange={(e) => setEvalSubject(e.target.value)}
              placeholder="user@domain.com"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Resource
            </label>
            <input
              type="text"
              value={evalResource}
              onChange={(e) => setEvalResource(e.target.value)}
              placeholder="api/secrets"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Context (Optional)
            </label>
            <input
              type="text"
              value={evalContext}
              onChange={(e) => setEvalContext(e.target.value)}
              placeholder="remote, high-risk-ip"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            />
          </div>
        </div>
        <button
          onClick={() =>
            onEvaluateAccess({
              subject: evalSubject,
              resource: evalResource,
              context: evalContext,
            })
          }
          className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium text-sm"
        >
          Evaluate Access
        </button>
      </div>

      {/* Decisions Statistics */}
      <div className="grid grid-cols-3 gap-4">
        <DecisionChart
          label="Allowed"
          value={accessDecisions24h?.allowed || 0}
          icon={CheckCircle}
          color="green"
        />
        <DecisionChart
          label="Denied"
          value={accessDecisions24h?.denied || 0}
          icon={AlertTriangle}
          color="red"
        />
        <DecisionChart
          label="Challenged"
          value={accessDecisions24h?.challenged || 0}
          icon={Clock}
          color="yellow"
        />
      </div>

      {/* Filter */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Filter className="w-5 h-5 text-gray-400" />
          <span className="text-sm font-semibold text-gray-700 dark:text-gray-300">Filter</span>
        </div>
        <div className="flex gap-2">
          {['all', 'allow', 'deny', 'challenge'].map((filter) => (
            <button
              key={filter}
              onClick={() => setDecisionFilter(filter)}
              className={clsx(
                'px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                decisionFilter === filter
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600'
              )}
            >
              {filter.charAt(0).toUpperCase() + filter.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Recent Decisions Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Time
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Subject
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Resource
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Decision
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Risk Score
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Reason
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {recentDecisions.map((decision) => (
              <tr key={decision.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {new Date(decision.created_at || "").toLocaleTimeString()}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white font-mono">
                  {(decision as any).subject_id || "user"}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  {(decision as any).resource_id || "resource"}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      decision.decision === 'allow'
                        ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                        : decision.decision === 'deny'
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                    )}
                  >
                    {decision.decision}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm">
                  <div className="flex items-center gap-2">
                    <div className="w-12 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                      <div
                        className={clsx(
                          'h-full',
                          decision.risk_score >= 70
                            ? 'bg-red-500'
                            : decision.risk_score >= 40
                            ? 'bg-yellow-500'
                            : 'bg-green-500'
                        )}
                        style={{ width: `${decision.risk_score}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-600 dark:text-gray-400">
                      {decision.risk_score}%
                    </span>
                  </div>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {decision.reason}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DeviceTrustTab({
  devices,
  stats,
  loading,
  expandedDevice,
  setExpandedDevice,
  onAssessDevices,
}: {
  devices: Device[];
  stats?: DeviceStats;
  loading: boolean;
  expandedDevice: string | null;
  setExpandedDevice: (id: string | null) => void;
  onAssessDevices: () => void;
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
      {/* Device Stats */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        <StatCard label="Total Devices" value={stats?.total || 0} color="blue" />
        <StatCard label="Trusted" value={stats?.trusted || 0} color="green" />
        <StatCard label="Conditional" value={stats?.conditional || 0} color="yellow" />
        <StatCard label="Untrusted" value={stats?.untrusted || 0} color="orange" />
        <StatCard label="Blocked" value={stats?.blocked || 0} color="red" />
      </div>

      {/* Assess Devices Button */}
      <button
        onClick={onAssessDevices}
        className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
      >
        <Zap className="w-5 h-5" />
        Assess All Devices
      </button>

      {/* Devices Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {devices.map((device) => (
          <div
            key={device.id}
            className={clsx(
              'rounded-lg border p-5 cursor-pointer transition-all',
              device.is_compliant
                ? 'bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 hover:border-blue-400 dark:hover:border-blue-600'
                : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
            )}
            onClick={() => setExpandedDevice(expandedDevice === device.id ? null : device.id)}
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  {device.hostname}
                </h3>
                <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                  {device.device_type.charAt(0).toUpperCase() + device.device_type.slice(1)} • {device.os_type}
                </p>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  device.is_compliant
                    ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                )}
              >
                {device.is_compliant ? 'Compliant' : 'Non-Compliant'}
              </span>
            </div>

            {/* Trust Score Gauge */}
            <div className="mb-3">
              <div className="flex items-end justify-between mb-1">
                <span className="text-xs text-gray-600 dark:text-gray-400">Trust Score</span>
                <span className="text-sm font-bold text-gray-900 dark:text-white">
                  {device.trust_score}%
                </span>
              </div>
              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div
                  className={clsx(
                    'h-full rounded-full',
                    device.trust_score >= 80
                      ? 'bg-green-500'
                      : device.trust_score >= 60
                      ? 'bg-yellow-500'
                      : 'bg-red-500'
                  )}
                  style={{ width: `${device.trust_score}%` }}
                />
              </div>
            </div>

            {/* Compliance Checks */}
            <div className="space-y-1 text-xs">
              <CheckItem label="Patch" status={device.checks.patch} />
              <CheckItem label="Antivirus" status={device.checks.av} />
              <CheckItem label="Encryption" status={device.checks.encryption} />
              <CheckItem label="Firewall" status={device.checks.firewall} />
            </div>

            {/* Last Seen */}
            <div className="text-xs text-gray-500 dark:text-gray-400 mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
              Last seen: {new Date(device.last_seen || "").toLocaleTimeString()}
            </div>

            {/* Expanded Details */}
            {expandedDevice === device.id && (
              <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 space-y-2">
                <button className="w-full px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-xs font-medium">
                  View Details
                </button>
                <button className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 text-xs font-medium">
                  Re-assess
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function SegmentationTab({
  segments,
  loading,
}: {
  segments: Segment[];
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
      {/* Create Segment Button */}
      <button className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium">
        <Plus className="w-5 h-5" />
        Create Segment
      </button>

      {/* Segment Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {segments.map((segment) => (
          <div
            key={segment.id}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
          >
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  {segment.name}
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Type: {segment.type}
                </p>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  segment.status === 'healthy'
                    ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400'
                )}
              >
                {segment.status}
              </span>
            </div>

            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between text-gray-600 dark:text-gray-400">
                <span>Members</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {segment.member_count}
                </span>
              </div>
              <div>
                <span className="text-gray-600 dark:text-gray-400">Allowed Protocols</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {(segment.allowed_protocols || []).map((protocol) => (
                    <span
                      key={protocol}
                      className="inline-flex items-center px-2 py-1 rounded text-xs bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 font-mono"
                    >
                      {protocol}
                    </span>
                  ))}
                </div>
              </div>
              {segment.violation_count > 0 && (
                <div className="text-sm text-red-600 dark:text-red-400 font-medium">
                  {segment.violation_count} policy violations
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function PoliciesTab({
  policies,
  loading,
}: {
  policies: Policy[];
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
      {/* Create Policy Button */}
      <button className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium">
        <Plus className="w-5 h-5" />
        Create Policy
      </button>

      {/* Policies Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700/50">
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Name
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Risk Threshold
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                MFA Required
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Device Trust
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Hit Count
              </th>
              <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700 dark:text-gray-300">
                Status
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {policies.map((policy) => (
              <tr key={policy.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-6 py-4 text-sm font-medium text-gray-900 dark:text-white">
                  {policy.name}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {policy.type}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {policy.risk_threshold}%
                </td>
                <td className="px-6 py-4 text-sm">
                  {policy.mfa_required ? (
                    <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-gray-400" />
                  )}
                </td>
                <td className="px-6 py-4 text-sm">
                  {policy.device_trust_required ? (
                    <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-gray-400" />
                  )}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {policy.decision_count}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      policy.is_enabled
                        ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                        : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400'
                    )}
                  >
                    {policy.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function DecisionChart({
  label,
  value,
  icon: Icon,
  color,
}: {
  label: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  color: 'green' | 'red' | 'yellow';
}) {
  const colorClasses: Record<string, string> = {
    green: 'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/30',
    red: 'text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/30',
    yellow: 'text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900/30',
  };

  return (
    <div className="text-center p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
      <div className={clsx('p-3 rounded-lg inline-block mb-2', colorClasses[color])}>
        <Icon className="w-6 h-6" />
      </div>
      <div className="text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
      <div className="text-sm text-gray-600 dark:text-gray-400">{label}</div>
    </div>
  );
}

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: 'blue' | 'green' | 'yellow' | 'orange' | 'red';
}) {
  const colorClasses: Record<string, string> = {
    blue: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
    green: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
    yellow: 'bg-yellow-100 text-yellow-600 dark:bg-yellow-900/30 dark:text-yellow-400',
    orange: 'bg-orange-100 text-orange-600 dark:bg-orange-900/30 dark:text-orange-400',
    red: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      <div className={clsx('p-3 rounded-lg inline-block mb-2', colorClasses[color])}>
        <BarChart3 className="w-5 h-5" />
      </div>
      <div className="text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
      <div className="text-sm text-gray-600 dark:text-gray-400">{label}</div>
    </div>
  );
}

function CheckItem({ label, status }: { label: string; status: boolean }) {
  return (
    <div className="flex items-center justify-between text-gray-600 dark:text-gray-400">
      <span>{label}</span>
      {status ? (
        <CheckCircle className="w-4 h-4 text-green-500" />
      ) : (
        <AlertCircle className="w-4 h-4 text-red-500" />
      )}
    </div>
  );
}
