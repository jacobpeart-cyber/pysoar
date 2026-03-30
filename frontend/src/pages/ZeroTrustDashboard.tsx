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
  maturityLevel: MaturityLevel;
  pillars: Pillar[];
  accessDecisions24h: {
    allowed: number;
    denied: number;
    challenged: number;
  };
  recentDecisions: AccessDecision[];
}

interface AccessDecision {
  id: string;
  time: string;
  subject: string;
  resource: string;
  decision: 'allow' | 'deny' | 'challenge';
  riskScore: number;
  reason: string;
}

interface Device {
  id: string;
  hostname: string;
  type: 'laptop' | 'desktop' | 'mobile' | 'server';
  os: string;
  trustScore: number;
  compliant: boolean;
  checks: {
    patch: boolean;
    av: boolean;
    encryption: boolean;
    firewall: boolean;
  };
  lastSeen: string;
}

interface Segment {
  id: string;
  name: string;
  type: 'network' | 'application' | 'data';
  memberCount: number;
  allowedProtocols: string[];
  violationCount: number;
  status: 'healthy' | 'at-risk';
}

interface Policy {
  id: string;
  name: string;
  type: string;
  riskThreshold: number;
  mfaRequired: boolean;
  deviceTrustRequired: boolean;
  hitCount: number;
  status: 'active' | 'inactive';
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
      const response = await api.get('/zerotrust/dashboard');
      return response.data;
    },
  });

  const { data: deviceStats, isLoading: statsLoading } = useQuery<DeviceStats>({
    queryKey: ['zerotrust-device-stats'],
    queryFn: async () => {
      const response = await api.get('/zerotrust/device-stats');
      return response.data;
    },
  });

  const { data: devices, isLoading: devicesLoading } = useQuery<Device[]>({
    queryKey: ['zerotrust-devices'],
    queryFn: async () => {
      const response = await api.get('/zerotrust/devices');
      return response.data;
    },
  });

  const { data: segments, isLoading: segmentsLoading } = useQuery<Segment[]>({
    queryKey: ['zerotrust-segments'],
    queryFn: async () => {
      const response = await api.get('/zerotrust/segments');
      return response.data;
    },
  });

  const { data: policies, isLoading: policiesLoading } = useQuery<Policy[]>({
    queryKey: ['zerotrust-policies'],
    queryFn: async () => {
      const response = await api.get('/zerotrust/policies');
      return response.data;
    },
  });

  const assessDevicesMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/zerotrust/assess-devices');
      return response.data;
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
      const response = await api.post('/zerotrust/evaluate-access', data);
      return response.data;
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
          recentDecisions={dashboardData?.recentDecisions || []}
          accessDecisions24h={dashboardData?.accessDecisions24h}
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

  const maturityLevels = [
    { level: 'traditional' as const, label: 'Traditional' },
    { level: 'initial' as const, label: 'Initial' },
    { level: 'advanced' as const, label: 'Advanced' },
    { level: 'optimal' as const, label: 'Optimal' },
  ];

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
                data?.maturityLevel === item.level
                  ? `${getMaturityColor(item.level)} border-current`
                  : 'bg-gray-50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 text-gray-600 dark:text-gray-400'
              )}
            >
              {item.label}
            </div>
          ))}
        </div>
      </div>

      {/* Pillar Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        {data?.pillars.map((pillar) => (
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
                {pillar.status.replace('-', ' ')}
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
            value={data?.accessDecisions24h.allowed || 0}
            icon={CheckCircle}
            color="green"
          />
          <DecisionChart
            label="Denied"
            value={data?.accessDecisions24h.denied || 0}
            icon={AlertTriangle}
            color="red"
          />
          <DecisionChart
            label="Challenged"
            value={data?.accessDecisions24h.challenged || 0}
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
          {(data?.recentDecisions || []).slice(0, 5).map((decision) => (
            <div
              key={decision.id}
              className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
            >
              <div className="flex-1">
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {decision.subject} → {decision.resource}
                </div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
                  {new Date(decision.time).toLocaleTimeString()} • Risk: {decision.riskScore}%
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
                  {new Date(decision.time).toLocaleTimeString()}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white font-mono">
                  {decision.subject}
                </td>
                <td className="px-6 py-4 text-sm text-gray-900 dark:text-white">
                  {decision.resource}
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
                          decision.riskScore >= 70
                            ? 'bg-red-500'
                            : decision.riskScore >= 40
                            ? 'bg-yellow-500'
                            : 'bg-green-500'
                        )}
                        style={{ width: `${decision.riskScore}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-600 dark:text-gray-400">
                      {decision.riskScore}%
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
              device.compliant
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
                  {device.type.charAt(0).toUpperCase() + device.type.slice(1)} • {device.os}
                </p>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  device.compliant
                    ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    : 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                )}
              >
                {device.compliant ? 'Compliant' : 'Non-Compliant'}
              </span>
            </div>

            {/* Trust Score Gauge */}
            <div className="mb-3">
              <div className="flex items-end justify-between mb-1">
                <span className="text-xs text-gray-600 dark:text-gray-400">Trust Score</span>
                <span className="text-sm font-bold text-gray-900 dark:text-white">
                  {device.trustScore}%
                </span>
              </div>
              <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                <div
                  className={clsx(
                    'h-full rounded-full',
                    device.trustScore >= 80
                      ? 'bg-green-500'
                      : device.trustScore >= 60
                      ? 'bg-yellow-500'
                      : 'bg-red-500'
                  )}
                  style={{ width: `${device.trustScore}%` }}
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
              Last seen: {new Date(device.lastSeen).toLocaleTimeString()}
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
                  {segment.memberCount}
                </span>
              </div>
              <div>
                <span className="text-gray-600 dark:text-gray-400">Allowed Protocols</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {segment.allowedProtocols.map((protocol) => (
                    <span
                      key={protocol}
                      className="inline-flex items-center px-2 py-1 rounded text-xs bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 font-mono"
                    >
                      {protocol}
                    </span>
                  ))}
                </div>
              </div>
              {segment.violationCount > 0 && (
                <div className="text-sm text-red-600 dark:text-red-400 font-medium">
                  {segment.violationCount} policy violations
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
                  {policy.riskThreshold}%
                </td>
                <td className="px-6 py-4 text-sm">
                  {policy.mfaRequired ? (
                    <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-gray-400" />
                  )}
                </td>
                <td className="px-6 py-4 text-sm">
                  {policy.deviceTrustRequired ? (
                    <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-gray-400" />
                  )}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {policy.hitCount}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                      policy.status === 'active'
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
