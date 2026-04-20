import React, { useState, useEffect, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import {
  Wrench,
  AlertCircle,
  CheckCircle2,
  Clock,
  Activity,
  Plus,
  Filter,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  Search,
  ToggleLeft,
  ToggleRight,
  AlertTriangle,
  Server,
  Lock,
  User,
  FileText,
  Zap,
  CheckSquare,
  XSquare,
  Loader,
  Shield,
  Network,
  Smartphone,
  Mail,
  Ticket,
  Cloud,
  Globe,
  Wifi,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';
import { remediationApi } from '../api/endpoints';
import FormModal from '../components/FormModal';

interface Tab {
  id: string;
  label: string;
}

interface StatCard {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: string;
  badge?: string | number;
}

interface Policy {
  id: string;
  name: string;
  policy_type: string;
  trigger_type: string;
  is_enabled: boolean;
  requires_approval: boolean;
  execution_count: number;
  success_rate: number | null;
  last_executed_at: string | null;
}

interface Execution {
  id: string;
  created_at: string;
  trigger_source: string;
  target_entity: string;
  target_type: string;
  policy_id: string | null;
  status: string;
  overall_result: string | null;
  actions_completed: any[];
  actions_planned: any[];
  created_by: string | null;
  started_at: string | null;
  completed_at: string | null;
}

interface QuickAction {
  id: string;
  trigger_source: string;
  target_entity: string;
  created_at: string;
  status: string;
}

interface Integration {
  id: string;
  name: string;
  integration_type: string;
  vendor: string | null;
  is_connected: boolean;
  health_status: string;
  capabilities: string[];
  last_health_check: string | null;
}

const tabs: Tab[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'policies', label: 'Policies' },
  { id: 'executions', label: 'Executions' },
  { id: 'quick-actions', label: 'Quick Actions' },
  { id: 'integrations', label: 'Integrations' },
];

const policyTypeColors: Record<string, string> = {
  auto_block: 'bg-red-100 text-red-700 border-red-200',
  auto_isolate: 'bg-orange-100 text-orange-700 border-orange-200',
  auto_patch: 'bg-blue-100 text-blue-700 border-blue-200',
  auto_disable: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  notification: 'bg-gray-100 text-gray-700 border-gray-200',
  custom: 'bg-purple-100 text-purple-700 border-purple-200',
};

const statusColors: Record<string, string> = {
  completed: 'bg-green-100 text-green-700',
  running: 'bg-blue-100 text-blue-700',
  awaiting_approval: 'bg-yellow-100 text-yellow-700',
  awaiting_manual: 'bg-amber-100 text-amber-700',
  awaiting_integration: 'bg-amber-100 text-amber-700',
  failed: 'bg-red-100 text-red-700',
  rolled_back: 'bg-purple-100 text-purple-700',
};

const triggerIcons: Record<string, React.ReactNode> = {
  alert: <AlertCircle className="w-4 h-4" />,
  anomaly: <Activity className="w-4 h-4" />,
  ueba: <User className="w-4 h-4" />,
  deception: <Zap className="w-4 h-4" />,
};

const integrationTypeColors: Record<string, string> = {
  firewall: 'bg-red-100 text-red-700',
  edr: 'bg-blue-100 text-blue-700',
  'active-directory': 'bg-purple-100 text-purple-700',
  'email-gateway': 'bg-orange-100 text-orange-700',
  ticketing: 'bg-green-100 text-green-700',
  'cloud-provider': 'bg-indigo-100 text-indigo-700',
  dns: 'bg-pink-100 text-pink-700',
  waf: 'bg-yellow-100 text-yellow-700',
  proxy: 'bg-cyan-100 text-cyan-700',
};

export default function Remediation() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [expandedExecution, setExpandedExecution] = useState<string | null>(null);
  const [policyTypeFilter, setPolicyTypeFilter] = useState('');
  const [policyEnabledFilter, setPolicyEnabledFilter] = useState('');
  const [showCreatePolicyModal, setShowCreatePolicyModal] = useState(false);
  const [showAddIntegrationModal, setShowAddIntegrationModal] = useState(false);
  const [rejectTarget, setRejectTarget] = useState<{ id: string; policy?: string } | null>(null);
  const [markCompleteTarget, setMarkCompleteTarget] = useState<{ id: string; target?: string } | null>(null);
  const [markFailedTarget, setMarkFailedTarget] = useState<{ id: string; target?: string } | null>(null);
  const [integrationTestResults, setIntegrationTestResults] = useState<Record<string, { ok: boolean; message: string }>>({});
  const [executionStatusFilter, setExecutionStatusFilter] = useState('');
  const [executionTriggerFilter, setExecutionTriggerFilter] = useState('');
  const [blockIPValue, setBlockIPValue] = useState('');
  const [blockDuration, setBlockDuration] = useState('24h');
  const [isolateHostValue, setIsolateHostValue] = useState('');
  const [isolateReason, setIsolateReason] = useState('');
  const [disableUsername, setDisableUsername] = useState('');
  const [forcePasswordReset, setForcePasswordReset] = useState(false);
  const [quarantineHost, setQuarantineHost] = useState('');
  const [quarantineFilePath, setQuarantineFilePath] = useState('');

  // Fetch dashboard stats
  const { data: dashboardData, isLoading: dashboardLoading } = useQuery({
    queryKey: ['remediation-dashboard'],
    queryFn: async () => {
      try {
      const response = await api.get('/remediation/dashboard');
      return response.data;
      } catch { return null; }
    },
    enabled: activeTab === 'dashboard',
  });

  // Fetch policies
  const { data: policiesData, isLoading: policiesLoading } = useQuery({
    queryKey: ['remediation-policies', policyTypeFilter, policyEnabledFilter],
    queryFn: async () => {
      const response = await api.get('/remediation/policies', {
        params: {
          type: policyTypeFilter,
          enabled: policyEnabledFilter,
        },
      });
      return response.data;
    },
    enabled: activeTab === 'policies',
  });

  // Fetch executions
  const { data: executionsData, isLoading: executionsLoading } = useQuery({
    queryKey: ['remediation-executions', executionStatusFilter, executionTriggerFilter],
    queryFn: async () => {
      const response = await api.get('/remediation/executions', {
        params: {
          status: executionStatusFilter,
          trigger: executionTriggerFilter,
        },
      });
      return response.data;
    },
    enabled: activeTab === 'executions',
  });

  // Fetch pending approvals
  const { data: pendingApprovalsData, isLoading: pendingApprovalsLoading } = useQuery({
    queryKey: ['remediation-pending-approvals'],
    queryFn: async () => {
      try {
      const response = await api.get('/remediation/executions/pending');
      return response.data;
      } catch { return null; }
    },
    enabled: activeTab === 'executions',
  });

  // Fetch quick actions
  const { data: quickActionsData, isLoading: quickActionsLoading } = useQuery({
    queryKey: ['remediation-quick-actions'],
    queryFn: async () => {
      try {
      const response = await api.get('/remediation/quick-actions');
      return response.data;
      } catch { return null; }
    },
    enabled: activeTab === 'quick-actions',
  });

  // Fetch integrations
  const { data: integrationsData, isLoading: integrationsLoading } = useQuery({
    queryKey: ['remediation-integrations'],
    queryFn: async () => {
      try {
      const response = await api.get('/remediation/integrations');
      return response.data;
      } catch { return null; }
    },
    enabled: activeTab === 'integrations',
  });

  // Fetch available connectors from marketplace (for Add Integration modal)
  const { data: connectorsData } = useQuery({
    queryKey: ['integrations-connectors'],
    queryFn: async () => {
      try {
        const response = await api.get('/integrations/connectors', {
          params: { size: 100 },
        });
        return response.data;
      } catch {
        return null;
      }
    },
    enabled: showAddIntegrationModal,
  });

  // Mutations
  const blockIPMutation = useMutation({
    mutationFn: async (data: { ip: string; duration: string }) => {
      try {
      const response = await api.post('/remediation/block-ip', data);
      return response.data;
      } catch { return null; }
    },
  });

  const isolateHostMutation = useMutation({
    mutationFn: async (data: { hostname: string; reason: string }) => {
      try {
      const response = await api.post('/remediation/isolate-host', data);
      return response.data;
      } catch { return null; }
    },
  });

  const disableAccountMutation = useMutation({
    mutationFn: async (data: { username: string; force_password_reset: boolean }) => {
      try {
      const response = await api.post('/remediation/disable-account', data);
      return response.data;
      } catch { return null; }
    },
  });

  const quarantineFileMutation = useMutation({
    mutationFn: async (data: { host: string; file_path: string }) => {
      try {
      const response = await api.post('/remediation/quarantine-file', data);
      return response.data;
      } catch { return null; }
    },
  });

  const handleBlockIP = () => {
    if (blockIPValue.trim()) {
      blockIPMutation.mutate({ ip: blockIPValue, duration: blockDuration });
      setBlockIPValue('');
    }
  };

  const handleIsolateHost = () => {
    if (isolateHostValue.trim()) {
      isolateHostMutation.mutate({ hostname: isolateHostValue, reason: isolateReason });
      setIsolateHostValue('');
      setIsolateReason('');
    }
  };

  const handleDisableAccount = () => {
    if (disableUsername.trim()) {
      disableAccountMutation.mutate({ username: disableUsername, force_password_reset: forcePasswordReset });
      setDisableUsername('');
      setForcePasswordReset(false);
    }
  };

  const handleQuarantineFile = () => {
    if (quarantineHost.trim() && quarantineFilePath.trim()) {
      quarantineFileMutation.mutate({ host: quarantineHost, file_path: quarantineFilePath });
      setQuarantineHost('');
      setQuarantineFilePath('');
    }
  };

  // Derive chart data from executions API response
  const executionTimelineData = useMemo(() => {
    const rawData = Array.isArray(executionsData) ? executionsData : (executionsData?.items || executionsData?.executions || []);
    const executions: Execution[] = rawData;
    if (executions.length === 0) return [];
    const grouped: Record<string, { successful: number; failed: number }> = {};
    executions.forEach((exec) => {
      const day = new Date(exec.created_at || "").toLocaleDateString('en-US', { weekday: 'short' });
      if (!grouped[day]) grouped[day] = { successful: 0, failed: 0 };
      if (exec.overall_result === 'success' || exec.status === 'completed') grouped[day].successful += 1;
      else if (exec.overall_result === 'failure' || exec.status === 'failed') grouped[day].failed += 1;
    });
    return Object.entries(grouped).map(([date, counts]) => ({ date, ...counts }));
  }, [executionsData]);

  const actionTypeData = useMemo(() => {
    const rawData = Array.isArray(executionsData) ? executionsData : (executionsData?.items || executionsData?.executions || []);
    const executions: Execution[] = rawData;
    if (executions.length === 0) return [];
    const counts: Record<string, number> = {};
    executions.forEach((exec) => {
      const type = exec.trigger_source || 'unknown';
      counts[type] = (counts[type] || 0) + 1;
    });
    return Object.entries(counts).map(([type, count]) => ({ type, count }));
  }, [executionsData]);

  // Render Dashboard Tab
  const renderDashboard = () => {
    if (dashboardLoading) {
      return <LoadingState />;
    }

    // All values come from the backend aggregate query. Previously the
    // `||` fallbacks substituted fabricated numbers like '1,247' / '94.2'
    // on a cold system — customers saw fake operational metrics before
    // any real remediation had ever run. Show honest zeros or '—'.
    const fmt = (v: unknown, fallback: string = '0') =>
      v === undefined || v === null ? fallback : String(v);

    const pendingApprovalsNum = typeof dashboardData?.pending_approvals === 'number'
      ? dashboardData.pending_approvals
      : 0;
    const successRate = dashboardData?.overall_success_rate ?? dashboardData?.success_rate;
    const avgMinutes = dashboardData?.avg_execution_minutes ?? dashboardData?.avg_remediation_time;

    const stats: StatCard[] = [
      {
        label: 'Total Executions',
        value: fmt(dashboardData?.total_executions),
        icon: <Activity className="w-6 h-6 text-blue-500" />,
      },
      {
        label: 'Success Rate',
        value: successRate !== undefined && successRate !== null ? `${successRate}%` : '—',
        icon: <CheckCircle2 className="w-6 h-6 text-green-500" />,
      },
      {
        label: 'Pending Approvals',
        value: fmt(pendingApprovalsNum),
        icon: <AlertCircle className="w-6 h-6 text-yellow-500" />,
        badge: pendingApprovalsNum || undefined,
      },
      {
        label: 'Avg Remediation Time',
        value: avgMinutes !== undefined && avgMinutes !== null ? `${avgMinutes}m` : '—',
        icon: <Clock className="w-6 h-6 text-orange-500" />,
      },
      {
        label: 'Active Policies',
        value: fmt(dashboardData?.active_policies),
        icon: <Shield className="w-6 h-6 text-purple-500" />,
      },
      {
        label: 'Actions Today',
        value: fmt(dashboardData?.actions_today),
        icon: <Zap className="w-6 h-6 text-amber-500" />,
      },
    ];

    return (
      <div className="space-y-6">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {stats.map((stat, idx) => (
            <div
              key={idx}
              className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
            >
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 font-medium">
                    {stat.label}
                  </p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white mt-2">
                    {stat.value}
                  </p>
                  {stat.trend && (
                    <p className="text-sm text-green-600 mt-1">{stat.trend}</p>
                  )}
                </div>
                <div className="p-3 bg-gray-100 dark:bg-gray-700 rounded-lg">
                  {stat.icon}
                </div>
              </div>
              {stat.badge !== undefined && (
                <div className="mt-4 inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                  {stat.badge} pending
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Execution Timeline */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Execution Timeline (7 Days)
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={executionTimelineData}>
                <defs>
                  <linearGradient id="colorSuccessful" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorFailed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" />
                <YAxis />
                <Tooltip />
                <Area
                  type="monotone"
                  dataKey="successful"
                  stroke="#10b981"
                  fillOpacity={1}
                  fill="url(#colorSuccessful)"
                />
                <Area
                  type="monotone"
                  dataKey="failed"
                  stroke="#ef4444"
                  fillOpacity={1}
                  fill="url(#colorFailed)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Actions by Type */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Actions by Type
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={actionTypeData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="type" angle={-45} textAnchor="end" height={80} />
                <YAxis />
                <Tooltip />
                <Bar dataKey="count" fill="#3b82f6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Executions Table */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Recent Executions
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Trigger
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Target
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Policy
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Duration
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {dashboardData?.recent_executions?.slice(0, 5).map((execution: any, idx: number) => (
                  <tr key={idx} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-100">
                      {execution.time}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {execution.trigger}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {execution.target}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {execution.policy}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span
                        className={clsx(
                          'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                          statusColors[execution.status] || 'bg-gray-100 text-gray-700'
                        )}
                      >
                        {execution.status === 'running' && (
                          <Loader className="w-3 h-3 mr-1 animate-spin" />
                        )}
                        {execution.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {execution.duration}s
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // Render Policies Tab
  const renderPolicies = () => {
    if (policiesLoading) {
      return <LoadingState />;
    }

    const allPolicies: Policy[] = Array.isArray(policiesData) ? policiesData : (policiesData?.items || policiesData?.policies || []);

    return (
      <div className="space-y-6">
        {/* Filters and Button */}
        <div className="flex flex-col lg:flex-row gap-4 items-center justify-between">
          <div className="flex flex-col sm:flex-row gap-4 items-center flex-1">
            <select
              value={policyTypeFilter}
              onChange={(e) => setPolicyTypeFilter(e.target.value)}
              className="px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
            >
              <option value="">All Types</option>
              <option value="auto_block">Auto Block</option>
              <option value="auto_isolate">Auto Isolate</option>
              <option value="auto_patch">Auto Patch</option>
              <option value="auto_disable">Auto Disable</option>
              <option value="notification">Notification</option>
              <option value="custom">Custom</option>
            </select>

            <select
              value={policyEnabledFilter}
              onChange={(e) => setPolicyEnabledFilter(e.target.value)}
              className="px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
            >
              <option value="">All States</option>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </select>
          </div>

          <button
            onClick={() => setShowCreatePolicyModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition"
          >
            <Plus className="w-5 h-5" />
            Create Policy
          </button>
        </div>

        {/* Built-in Policies Section */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Built-in Policies
          </h3>
          <div className="text-sm text-gray-600 dark:text-gray-400 mb-4">
            8 pre-configured policies available for immediate deployment
          </div>
        </div>

        {/* Policies Table */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Trigger
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Requires Approval
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Executions
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Success Rate
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Last Executed
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {allPolicies.map((policy: Policy, idx: number) => (
                  <tr key={idx} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                      {policy.name}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span
                        className={clsx(
                          'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
                          policyTypeColors[policy.policy_type] || 'bg-gray-100 text-gray-700'
                        )}
                      >
                        {policy.policy_type}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {policy.trigger_type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <button
                        onClick={async () => {
                          try {
                            await api.put(`/remediation/policies/${policy.id}`, {
                              is_enabled: !policy.is_enabled,
                            });
                            queryClient.invalidateQueries({ queryKey: ['remediation-policies'] });
                          } catch (err) {
                            console.error('Toggle policy failed:', err);
                          }
                        }}
                        className="flex items-center gap-2 px-3 py-1 rounded-lg transition"
                        title={policy.is_enabled ? 'Disable policy' : 'Enable policy'}
                      >
                        {policy.is_enabled ? (
                          <>
                            <ToggleRight className="w-5 h-5 text-green-600" />
                            <span className="text-sm font-medium text-green-600">Enabled</span>
                          </>
                        ) : (
                          <>
                            <ToggleLeft className="w-5 h-5 text-gray-400" />
                            <span className="text-sm font-medium text-gray-600 dark:text-gray-400">
                              Disabled
                            </span>
                          </>
                        )}
                      </button>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {policy.requires_approval ? (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200">
                          Required
                        </span>
                      ) : (
                        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300">
                          Not Required
                        </span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {policy.execution_count}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-green-500"
                            style={{ width: `${policy.success_rate ?? 0}%` }}
                          />
                        </div>
                        <span className="text-gray-600 dark:text-gray-400">{policy.success_rate ?? 0}%</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {policy.last_executed_at || 'Never'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // Render Executions Tab
  const renderExecutions = () => {
    if (executionsLoading || pendingApprovalsLoading) {
      return <LoadingState />;
    }

    const allExecutions: Execution[] = Array.isArray(executionsData) ? executionsData : (executionsData?.items || executionsData?.executions || []);
    const pendingApprovals = pendingApprovalsData?.executions || [];

    return (
      <div className="space-y-6">
        {/* Pending Approvals Section */}
        {pendingApprovals.length > 0 && (
          <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-lg p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-yellow-900 dark:text-yellow-100">
                  Pending Approvals
                </h3>
                <p className="text-sm text-yellow-700 dark:text-yellow-200 mt-1">
                  {pendingApprovals.length} execution(s) awaiting approval
                </p>
              </div>
            </div>
            <div className="space-y-3">
              {pendingApprovals.map((approval: any, idx: number) => (
                <div
                  key={idx}
                  className="flex items-center justify-between bg-white dark:bg-gray-800 p-4 rounded-lg border border-yellow-100 dark:border-yellow-700"
                >
                  <div>
                    <p className="font-medium text-gray-900 dark:text-white">{approval.policy}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                      Target: {approval.target}
                    </p>
                  </div>
                  <div className="flex gap-2">
                    <button
                      onClick={async () => {
                        try {
                          await api.post(
                            `/remediation/executions/${approval.id || approval.execution_id}/approve`,
                            { approver_id: '' }
                          );
                          queryClient.invalidateQueries({ queryKey: ['remediation-pending-approvals'] });
                          queryClient.invalidateQueries({ queryKey: ['remediation-executions'] });
                        } catch (err) {
                          console.error('Approve execution failed:', err);
                        }
                      }}
                      className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg font-medium transition"
                    >
                      Approve
                    </button>
                    <button
                      onClick={() =>
                        setRejectTarget({
                          id: approval.id || approval.execution_id,
                          policy: approval.policy,
                        })
                      }
                      className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg font-medium transition"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-4">
          <select
            value={executionStatusFilter}
            onChange={(e) => setExecutionStatusFilter(e.target.value)}
            className="px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
          >
            <option value="">All Statuses</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="awaiting_approval">Awaiting Approval</option>
            <option value="failed">Failed</option>
            <option value="rolled_back">Rolled Back</option>
          </select>

          <select
            value={executionTriggerFilter}
            onChange={(e) => setExecutionTriggerFilter(e.target.value)}
            className="px-4 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white"
          >
            <option value="">All Triggers</option>
            <option value="alert">Alert</option>
            <option value="anomaly">Anomaly</option>
            <option value="ueba">UEBA</option>
            <option value="deception">Deception</option>
          </select>
        </div>

        {/* Executions Table */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Time
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Trigger
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Target
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Policy
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Actions
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Duration
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Analyst
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {allExecutions.map((execution: Execution, idx: number) => (
                  <React.Fragment key={idx}>
                    <tr
                      className="hover:bg-gray-50 dark:hover:bg-gray-700 transition cursor-pointer"
                      onClick={() =>
                        setExpandedExecution(
                          expandedExecution === execution.id ? null : execution.id
                        )
                      }
                    >
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                        {new Date(execution.created_at || "").toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          {triggerIcons[execution.trigger_source] || <AlertCircle className="w-4 h-4" />}
                          <span className="text-sm text-gray-600 dark:text-gray-400">
                            {execution.trigger_source}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                        {execution.target_entity}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                        {execution.policy_id || 'Manual'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={clsx(
                            'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                            statusColors[execution.status] || 'bg-gray-100 text-gray-700'
                          )}
                        >
                          {execution.status === 'running' && (
                            <Loader className="w-3 h-3 mr-1 animate-spin" />
                          )}
                          {execution.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                        {execution.actions_completed?.length || 0}/{execution.actions_planned?.length || 0}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                        {execution.started_at && execution.completed_at
                          ? `${((new Date(execution.completed_at || "").getTime() - new Date(execution.started_at || "").getTime()) / 1000).toFixed(1)}s`
                          : execution.started_at ? 'Running' : '-'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                        {execution.created_by || 'System'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right">
                        <div className="flex items-center justify-end gap-2">
                          {(execution.status === 'awaiting_manual' || execution.status === 'awaiting_integration') && (
                            <>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setMarkCompleteTarget({ id: execution.id, target: execution.target_entity });
                                }}
                                className="px-2 py-1 text-xs font-medium rounded bg-green-600 hover:bg-green-700 text-white transition"
                                title="Confirm this remediation was completed out of band"
                              >
                                Mark Complete
                              </button>
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setMarkFailedTarget({ id: execution.id, target: execution.target_entity });
                                }}
                                className="px-2 py-1 text-xs font-medium rounded bg-red-600 hover:bg-red-700 text-white transition"
                                title="Confirm this remediation won't happen"
                              >
                                Mark Failed
                              </button>
                            </>
                          )}
                          <ChevronRight
                            className={clsx(
                              'w-5 h-5 text-gray-400 transition',
                              expandedExecution === execution.id && 'rotate-90'
                            )}
                          />
                        </div>
                      </td>
                    </tr>
                    {expandedExecution === execution.id && (
                      <tr className="bg-gray-50 dark:bg-gray-700">
                        <td colSpan={9} className="px-6 py-4">
                          <div className="space-y-3">
                            <h4 className="font-semibold text-gray-900 dark:text-white">
                              Action Results
                            </h4>
                            {/* Render the actual actions_completed /
                                actions_failed arrays from the execution
                                record. Previously this rendered a
                                hardcoded "Block IP: 192.168.1.100 /
                                Update Firewall Rules / Notify SOC
                                Team" trio for every expanded row,
                                regardless of what the playbook actually
                                ran — a decorative demo display. */}
                            {(() => {
                              const completed = Array.isArray(execution.actions_completed) ? execution.actions_completed : [];
                              const failed = Array.isArray((execution as any).actions_failed) ? (execution as any).actions_failed : [];
                              if (completed.length === 0 && failed.length === 0) {
                                return (
                                  <p className="text-sm text-gray-500 dark:text-gray-400">
                                    No action results recorded for this execution.
                                  </p>
                                );
                              }
                              const renderItem = (entry: any, ok: boolean, idx: number) => {
                                const label =
                                  typeof entry === 'string'
                                    ? entry
                                    : entry?.action || entry?.name || entry?.title || JSON.stringify(entry);
                                return (
                                  <div key={`${ok ? 'ok' : 'err'}-${idx}`} className="flex items-center gap-2">
                                    {ok ? (
                                      <CheckSquare className="w-4 h-4 text-green-600" />
                                    ) : (
                                      <XSquare className="w-4 h-4 text-red-600" />
                                    )}
                                    <span className="text-sm text-gray-700 dark:text-gray-300">{label}</span>
                                  </div>
                                );
                              };
                              return (
                                <div className="space-y-2">
                                  {completed.map((e, i) => renderItem(e, true, i))}
                                  {failed.map((e, i) => renderItem(e, false, i))}
                                </div>
                              );
                            })()}
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // Render Quick Actions Tab
  const renderQuickActions = () => {
    if (quickActionsLoading) {
      return <LoadingState />;
    }

    return (
      <div className="space-y-6">
        {/* Action Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Block IP Card */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Block IP</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Add IP to firewall blocklist
                </p>
              </div>
              <Network className="w-8 h-8 text-red-500" />
            </div>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Enter IP address"
                value={blockIPValue}
                onChange={(e) => setBlockIPValue(e.target.value)}
                className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              />
              <select
                value={blockDuration}
                onChange={(e) => setBlockDuration(e.target.value)}
                className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="1h">1 Hour</option>
                <option value="6h">6 Hours</option>
                <option value="24h">24 Hours</option>
                <option value="permanent">Permanent</option>
              </select>
              <button
                onClick={handleBlockIP}
                disabled={blockIPMutation.isPending || !blockIPValue.trim()}
                className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-gray-400 text-white rounded-lg font-medium transition"
              >
                {blockIPMutation.isPending ? 'Blocking...' : 'Block IP'}
              </button>
            </div>
          </div>

          {/* Isolate Host Card */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Isolate Host
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Disconnect from network
                </p>
              </div>
              <Server className="w-8 h-8 text-orange-500" />
            </div>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Enter hostname"
                value={isolateHostValue}
                onChange={(e) => setIsolateHostValue(e.target.value)}
                className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              />
              <input
                type="text"
                placeholder="Reason for isolation"
                value={isolateReason}
                onChange={(e) => setIsolateReason(e.target.value)}
                className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              />
              <button
                onClick={handleIsolateHost}
                disabled={isolateHostMutation.isPending || !isolateHostValue.trim()}
                className="w-full px-4 py-2 bg-orange-600 hover:bg-orange-700 disabled:bg-gray-400 text-white rounded-lg font-medium transition"
              >
                {isolateHostMutation.isPending ? 'Isolating...' : 'Isolate Host'}
              </button>
            </div>
          </div>

          {/* Disable Account Card */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Disable Account
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Lock user account
                </p>
              </div>
              <Lock className="w-8 h-8 text-yellow-500" />
            </div>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Enter username"
                value={disableUsername}
                onChange={(e) => setDisableUsername(e.target.value)}
                className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              />
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={forcePasswordReset}
                  onChange={(e) => setForcePasswordReset(e.target.checked)}
                  className="rounded border-gray-300"
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">
                  Force password reset
                </span>
              </label>
              <button
                onClick={handleDisableAccount}
                disabled={disableAccountMutation.isPending || !disableUsername.trim()}
                className="w-full px-4 py-2 bg-yellow-600 hover:bg-yellow-700 disabled:bg-gray-400 text-white rounded-lg font-medium transition"
              >
                {disableAccountMutation.isPending ? 'Disabling...' : 'Disable Account'}
              </button>
            </div>
          </div>

          {/* Quarantine File Card */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Quarantine File
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Isolate suspected malware
                </p>
              </div>
              <FileText className="w-8 h-8 text-purple-500" />
            </div>
            <div className="space-y-3">
              <input
                type="text"
                placeholder="Enter hostname"
                value={quarantineHost}
                onChange={(e) => setQuarantineHost(e.target.value)}
                className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              />
              <input
                type="text"
                placeholder="File path"
                value={quarantineFilePath}
                onChange={(e) => setQuarantineFilePath(e.target.value)}
                className="w-full px-3 py-2 border border-gray-200 dark:border-gray-700 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-gray-500"
              />
              <button
                onClick={handleQuarantineFile}
                disabled={
                  quarantineFileMutation.isPending ||
                  !quarantineHost.trim() ||
                  !quarantineFilePath.trim()
                }
                className="w-full px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 text-white rounded-lg font-medium transition"
              >
                {quarantineFileMutation.isPending ? 'Quarantining...' : 'Quarantine File'}
              </button>
            </div>
          </div>
        </div>

        {/* Recent Quick Actions */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Recent Quick Actions
            </h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Target
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Timestamp
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 dark:text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {(Array.isArray(quickActionsData) ? quickActionsData : (quickActionsData?.recent || [])).map((action: QuickAction, idx: number) => (
                  <tr key={idx} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                      {action.trigger_source}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {action.target_entity}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-gray-400">
                      {action.created_at ? new Date(action.created_at || "").toLocaleString() : '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span
                        className={clsx(
                          'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                          statusColors[action.status] || 'bg-gray-100 text-gray-700'
                        )}
                      >
                        {action.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  // Render Integrations Tab
  const renderIntegrations = () => {
    if (integrationsLoading) {
      return <LoadingState />;
    }

    const integrations: Integration[] = Array.isArray(integrationsData) ? integrationsData : (integrationsData?.items || integrationsData?.integrations || []);

    return (
      <div className="space-y-6">
        {/* Action Buttons */}
        <div className="flex flex-col sm:flex-row gap-4">
          <button
            onClick={() => setShowAddIntegrationModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition"
          >
            <Plus className="w-5 h-5" />
            Add Integration
          </button>
        </div>

        {/* Integrations Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {integrations.map((integration: Integration, idx: number) => (
            <div
              key={idx}
              className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6"
            >
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                    {integration.name}
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    {integration.vendor}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <div
                    className={clsx(
                      'w-3 h-3 rounded-full',
                      integration.is_connected
                        ? 'bg-green-500'
                        : integration.health_status === 'error'
                          ? 'bg-red-500'
                          : 'bg-gray-400'
                    )}
                  />
                </div>
              </div>

              <div className="mb-4">
                <span
                  className={clsx(
                    'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
                    integrationTypeColors[integration.integration_type] || 'bg-gray-100 text-gray-700'
                  )}
                >
                  {integration.integration_type}
                </span>
              </div>

              <div className="mb-4">
                <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">
                  Capabilities
                </h4>
                <div className="flex flex-wrap gap-1">
                  {integration.capabilities.map((cap, capIdx) => (
                    <span
                      key={capIdx}
                      className="inline-flex items-center px-2 py-1 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300"
                    >
                      {cap}
                    </span>
                  ))}
                </div>
              </div>

              <div className="mb-4 pb-4 border-b border-gray-200 dark:border-gray-700">
                <p className="text-xs text-gray-600 dark:text-gray-400">
                  Last health check: {integration.last_health_check ? new Date(integration.last_health_check || "").toLocaleString() : 'Never'}
                </p>
              </div>

              {integrationTestResults[integration.id] && (
                <div
                  className={clsx(
                    'mb-3 px-3 py-2 rounded-lg text-xs border',
                    integrationTestResults[integration.id].ok
                      ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-700 dark:text-green-300'
                      : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-700 dark:text-red-300'
                  )}
                >
                  {integrationTestResults[integration.id].message}
                </div>
              )}

              <button
                onClick={async () => {
                  try {
                    const res = await api.post(
                      `/integrations/installed/${integration.id}/test`,
                      {}
                    );
                    setIntegrationTestResults((prev) => ({
                      ...prev,
                      [integration.id]: {
                        ok: true,
                        message: `Connection test: ${res.data?.status || 'completed'}`,
                      },
                    }));
                  } catch (err: any) {
                    setIntegrationTestResults((prev) => ({
                      ...prev,
                      [integration.id]: {
                        ok: false,
                        message: `Failed: ${err?.response?.data?.detail || err?.message || 'connection error'}`,
                      },
                    }));
                  }
                }}
                className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-900 dark:text-white rounded-lg font-medium transition text-sm"
              >
                Test Connection
              </button>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const renderLoading = () => (
    <div className="flex items-center justify-center h-96">
      <div className="text-center">
        <Loader className="w-12 h-12 animate-spin text-blue-600 mx-auto mb-4" />
        <p className="text-gray-600 dark:text-gray-400">Loading...</p>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div className="px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <Wrench className="w-8 h-8 text-blue-600" />
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              Automated Remediation Engine
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-400">
            Manage policies, executions, and automated response actions
          </p>
        </div>

        {/* Tabs */}
        <div className="mb-6">
          <div className="flex flex-wrap gap-2 border-b border-gray-200 dark:border-gray-700">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'px-4 py-2 font-medium border-b-2 transition-colors whitespace-nowrap',
                  activeTab === tab.id
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Tab Content */}
        <div>
          {activeTab === 'dashboard' && renderDashboard()}
          {activeTab === 'policies' && renderPolicies()}
          {activeTab === 'executions' && renderExecutions()}
          {activeTab === 'quick-actions' && renderQuickActions()}
          {activeTab === 'integrations' && renderIntegrations()}
        </div>
      </div>

      {/* Create Policy Modal */}
      {showCreatePolicyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setShowCreatePolicyModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
              <h2 className="text-lg font-semibold">Create Remediation Policy</h2>
              <button onClick={() => setShowCreatePolicyModal(false)} className="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <form className="p-6 space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                // Previous payload sent `enabled` (backend expects
                // `is_enabled`) and `action_type`+`action_config` keys
                // that the schema drops, leaving the new policy with
                // an empty actions list — created but non-functional.
                // Send matching field names + a single concrete action
                // derived from policy_type so the policy actually runs.
                const policyType = String(fd.get('policy_type') || 'auto_block');
                const severity = String(fd.get('severity') || 'critical');
                await api.post('/remediation/policies', {
                  name: fd.get('name'),
                  description: fd.get('description'),
                  policy_type: policyType,
                  trigger_type: fd.get('trigger_type'),
                  trigger_conditions: { severity },
                  actions: [{ type: policyType, params: {} }],
                  is_enabled: true,
                  priority: 50,
                  cooldown_minutes: 15,
                });
                setShowCreatePolicyModal(false);
                queryClient.invalidateQueries({ queryKey: ['remediation-policies'] });
              } catch (err: any) {
                console.error('Create policy failed:', err);
                alert(`Create policy failed: ${err?.response?.data?.detail || err?.message || 'unknown error'}`);
              }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Policy Name</label>
                <input name="name" required className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" placeholder="e.g., Auto-block critical threats" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea name="description" rows={2} className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Policy Type</label>
                  <select name="policy_type" required className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                    <option value="auto_block">Auto Block</option>
                    <option value="auto_isolate">Auto Isolate</option>
                    <option value="auto_patch">Auto Patch</option>
                    <option value="auto_disable">Auto Disable</option>
                    <option value="auto_quarantine">Auto Quarantine</option>
                    <option value="notification">Notification</option>
                    <option value="escalation">Escalation</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Trigger</label>
                  <select name="trigger_type" required className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                    <option value="alert_severity">Alert Severity</option>
                    <option value="anomaly_score">Anomaly Score</option>
                    <option value="threat_intel_match">Threat Intel Match</option>
                    <option value="vulnerability_score">Vulnerability Score</option>
                    <option value="ueba_risk">UEBA Risk</option>
                    <option value="detection_rule">Detection Rule</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity Threshold</label>
                <select name="severity" className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                </select>
              </div>
              <div className="flex gap-3 pt-4">
                <button type="button" onClick={() => setShowCreatePolicyModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg">Create Policy</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add Integration Modal */}
      {showAddIntegrationModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setShowAddIntegrationModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg mx-4" onClick={(e) => e.stopPropagation()}>
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
              <h2 className="text-lg font-semibold">Add Integration</h2>
              <button onClick={() => setShowAddIntegrationModal(false)} className="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <form className="p-6 space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.post('/integrations/install', {
                  connector_id: fd.get('connector_id'),
                  display_name: fd.get('display_name'),
                  config: { api_key: fd.get('api_key'), endpoint: fd.get('endpoint') },
                });
                setShowAddIntegrationModal(false);
                queryClient.invalidateQueries({ queryKey: ['remediation-integrations'] });
              } catch (err: any) { console.error('Add integration failed:', err); }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Integration Type</label>
                {(() => {
                  const connectors: Array<{ id: string; name?: string; display_name?: string; vendor?: string | null; category?: string }> =
                    Array.isArray(connectorsData)
                      ? connectorsData
                      : (connectorsData?.items || connectorsData?.connectors || []);
                  return (
                    <select
                      name="connector_id"
                      required
                      defaultValue=""
                      className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    >
                      <option value="" disabled>
                        {connectors.length === 0 ? 'No connectors available' : 'Select a connector'}
                      </option>
                      {connectors.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.display_name || c.name || c.id}
                          {c.vendor ? ` (${c.vendor})` : ''}
                        </option>
                      ))}
                    </select>
                  );
                })()}
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Display Name</label>
                <input
                  name="display_name"
                  required
                  minLength={1}
                  maxLength={255}
                  className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                  placeholder="e.g., Production Splunk"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">API Endpoint</label>
                <input name="endpoint" className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" placeholder="https://api.example.com" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">API Key</label>
                <input name="api_key" type="password" className="w-full border border-gray-300 dark:border-gray-600 rounded-lg px-3 py-2 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" placeholder="Enter API key" />
              </div>
              <div className="flex gap-3 pt-4">
                <button type="button" onClick={() => setShowAddIntegrationModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg">Connect</button>
              </div>
            </form>
          </div>
        </div>
      )}

      <FormModal
        open={!!rejectTarget}
        onClose={() => setRejectTarget(null)}
        title="Reject Remediation Execution"
        description={
          rejectTarget?.policy
            ? `Rejecting: ${rejectTarget.policy}`
            : 'Reject this pending remediation action. The rejection is recorded in the audit trail.'
        }
        submitLabel="Reject"
        fields={[
          {
            name: 'reason',
            label: 'Rejection Reason',
            type: 'textarea',
            required: true,
            placeholder: 'Explain why this remediation is being rejected',
            help: 'This reason is written to the audit log and visible to the requester.',
          },
        ]}
        onSubmit={async (values) => {
          if (!rejectTarget) return;
          await api.post(
            `/remediation/executions/${rejectTarget.id}/reject`,
            { approver_id: '', reason: values.reason }
          );
          queryClient.invalidateQueries({ queryKey: ['remediation-pending-approvals'] });
          queryClient.invalidateQueries({ queryKey: ['remediation-executions'] });
          setRejectTarget(null);
        }}
      />

      <FormModal
        open={!!markCompleteTarget}
        onClose={() => setMarkCompleteTarget(null)}
        title="Mark Execution Complete"
        description={
          markCompleteTarget?.target
            ? `Confirm that remediation on ${markCompleteTarget.target} was completed out of band.`
            : 'Confirm this awaiting_manual / awaiting_integration execution was completed out of band.'
        }
        submitLabel="Mark Complete"
        fields={[
          {
            name: 'notes',
            label: 'Notes (optional)',
            type: 'textarea',
            required: false,
            placeholder: 'e.g. "Blocked on Palo Alto manually — ticket FW-1423"',
            help: 'Notes are recorded on the execution and in the audit log.',
          },
        ]}
        onSubmit={async (values) => {
          if (!markCompleteTarget) return;
          await api.post(
            `/remediation/executions/${markCompleteTarget.id}/mark-complete`,
            { notes: values.notes || null }
          );
          queryClient.invalidateQueries({ queryKey: ['remediation-executions'] });
          queryClient.invalidateQueries({ queryKey: ['remediation-dashboard'] });
          setMarkCompleteTarget(null);
        }}
      />

      <FormModal
        open={!!markFailedTarget}
        onClose={() => setMarkFailedTarget(null)}
        title="Mark Execution Failed"
        description={
          markFailedTarget?.target
            ? `Confirm that remediation on ${markFailedTarget.target} will not be completed.`
            : 'Confirm this awaiting_manual / awaiting_integration execution will not be completed.'
        }
        submitLabel="Mark Failed"
        fields={[
          {
            name: 'reason',
            label: 'Failure Reason',
            type: 'textarea',
            required: true,
            placeholder: 'Explain why this remediation cannot or will not happen',
            help: 'Required. Written to the execution\'s failure_reason and to the audit log.',
          },
        ]}
        onSubmit={async (values) => {
          if (!markFailedTarget) return;
          if (!values.reason || !String(values.reason).trim()) return;
          await api.post(
            `/remediation/executions/${markFailedTarget.id}/mark-failed`,
            { reason: values.reason }
          );
          queryClient.invalidateQueries({ queryKey: ['remediation-executions'] });
          queryClient.invalidateQueries({ queryKey: ['remediation-dashboard'] });
          setMarkFailedTarget(null);
        }}
      />
    </div>
  );
}

function LoadingState() {
  return (
    <div className="flex items-center justify-center h-96">
      <div className="text-center">
        <Loader className="w-12 h-12 animate-spin text-blue-600 mx-auto mb-4" />
        <p className="text-gray-600 dark:text-gray-400">Loading...</p>
      </div>
    </div>
  );
}
