import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  BarChart3,
  Plus,
  Filter,
  Shield,
  Loader2,
  Zap,
  AlertCircle,
  CheckCircle,
  AlertTriangle,
  Clock,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';
import DetailDrawer, { DetailSection } from '../components/DetailDrawer';
import FormModal from '../components/FormModal';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';

const NA = 'not available';

// Posture checks the device trust profile carries (src/zerotrust/engine.py):
// the first four are measured by the endpoint agent, the last two only come
// from an explicit administrator override.
const AGENT_POSTURE_CHECKS = ['os_patched', 'av_active', 'encryption_enabled', 'firewall_on'] as const;
const OVERRIDE_ONLY_CHECKS = ['certificate_valid', 'jailbroken'] as const;
const CHECK_LABELS: Record<string, string> = {
  os_patched: 'OS patched',
  av_active: 'Antivirus active',
  encryption_enabled: 'Disk encryption',
  firewall_on: 'Firewall on',
  certificate_valid: 'Device certificate valid',
  jailbroken: 'Jailbroken / rooted',
};

function checkLabel(value: unknown): string {
  if (value === true) return 'yes';
  if (value === false) return 'no';
  return 'not reported';
}

type TabType = 'overview' | 'access-control' | 'devices' | 'segmentation' | 'policies';

type MaturityLevel = 'traditional' | 'initial' | 'advanced' | 'optimal';

function getMaturityColor(level: string) {
  const colors: Record<string, string> = {
    traditional: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    initial: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
    advanced: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
    optimal: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  };
  return colors[level] || colors.traditional;
}

function getStatusColor(status: string) {
  const colors: Record<string, string> = {
    healthy: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
    'at-risk': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
    critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400',
    active: 'bg-green-100 text-green-800',
    inactive: 'bg-gray-100 text-gray-800',
  };
  return colors[status] || colors.healthy;
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
  pillars?: Record<string, Row>;
  not_reported_devices?: number;
  access_decisions_24h?: number;
  configured_pillars?: number;
}

// GET /zerotrust/decisions row (zerotrust.py list_access_decisions):
// subject/resource are "type:id" strings; there is no reason field.
interface AccessDecision {
  id: string;
  created_at: string;
  subject: string;
  resource: string;
  decision: string;
  risk_score: number;
}

// GET /zerotrust/devices row (_device_summary): stored fields plus the
// posture derived from what the agent (or an admin override) reported.
interface Device {
  id: string;
  device_id: string;
  hostname: string | null;
  device_type: string;
  os_type?: string | null;
  os_version?: string | null;
  trust_score: number;
  trust_level: string;
  last_seen: string | null;
  last_assessment_at?: string | null;
  compliance_checks?: Record<string, boolean | string>;
  is_compliant?: boolean | null;
  posture_status?: 'reported' | 'partial' | 'not_reported' | string;
  posture_source?: string | null;
  posture_reported_at?: string | null;
}

// MicroSegmentResponse
interface Segment {
  id: string;
  name: string;
  segment_type: string;
  member_assets: string[];
  allowed_protocols: string[];
  violation_count: number;
  is_active: boolean;
}

// ZeroTrustPolicyResponse
interface Policy {
  id: string;
  name: string;
  policy_type: string;
  risk_threshold: number;
  requires_mfa: boolean;
  requires_device_trust: boolean;
  hit_count: number;
  is_enabled: boolean;
}

interface DeviceStats {
  total: number;
  trusted: number;
  conditional: number;
  untrusted: number;
  blocked: number;
  not_reported?: number;
}

export default function ZeroTrustDashboard() {
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [expandedDevice, setExpandedDevice] = useState<string | null>(null);
  const [decisionFilter, setDecisionFilter] = useState<string>('all');
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  const queryClient = useQueryClient();

  const { data: dashboardData, isLoading: dashboardLoading, error: dashboardError } = useQuery<DashboardData>({
    queryKey: ['zerotrust-dashboard'],
    queryFn: async () => {
      const response = await api.get('/zerotrust/dashboard');
      return response.data;
    },
  });

  const { data: deviceStats, isLoading: statsLoading, error: statsError } = useQuery<DeviceStats>({
    queryKey: ['zerotrust-device-stats'],
    queryFn: async () => {
      const response = await api.get('/zerotrust/device-stats');
      return response.data;
    },
  });

  const { data: devicesRaw, isLoading: devicesLoading, error: devicesError } = useQuery<Row>({
    queryKey: ['zerotrust-devices'],
    queryFn: async () => {
      const response = await api.get('/zerotrust/devices');
      return response.data;
    },
  });
  const devices: Device[] = Array.isArray(devicesRaw) ? devicesRaw : (devicesRaw?.devices || devicesRaw?.items || []);

  // Real access decisions feed — previously the Access Control tab
  // received a hardcoded `[]` for recentDecisions so the live decisions
  // table was always empty despite /zerotrust/decisions returning real
  // rows.
  const { data: accessDecisionsRaw, isLoading: accessDecisionsLoading, error: accessDecisionsError } = useQuery<Row>({
    queryKey: ['zerotrust-decisions', 'access-control'],
    queryFn: async () => {
      // The handler pages with skip/limit (it ignores `size`).
      const response = await api.get('/zerotrust/decisions', { params: { limit: 50 } });
      return response.data;
    },
  });
  const accessDecisions: AccessDecision[] = Array.isArray(accessDecisionsRaw)
    ? accessDecisionsRaw
    : (accessDecisionsRaw?.decisions || accessDecisionsRaw?.items || []);

  const { data: segmentsRaw, isLoading: segmentsLoading, error: segmentsError } = useQuery<Row>({
    queryKey: ['zerotrust-segments'],
    queryFn: async () => {
      const response = await api.get('/zerotrust/segments');
      return response.data;
    },
  });
  const segments: Segment[] = Array.isArray(segmentsRaw) ? segmentsRaw : (segmentsRaw?.segments || segmentsRaw?.items || []);

  const { data: policiesRaw, isLoading: policiesLoading, error: policiesError } = useQuery<Row>({
    queryKey: ['zerotrust-policies'],
    queryFn: async () => {
      // enabled_only defaults to true server-side, which hid disabled
      // policies while `total` still counted them.
      const response = await api.get('/zerotrust/policies', { params: { enabled_only: false } });
      return response.data;
    },
  });
  const policies: Policy[] = Array.isArray(policiesRaw) ? policiesRaw : (policiesRaw?.policies || policiesRaw?.items || []);

  const assessDevicesMutation = useMutation({
    mutationFn: async () => {
      const response = await api.post('/zerotrust/assess-devices');
      return response.data;
    },
    onSuccess: () => {
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['zerotrust-devices'] });
      queryClient.invalidateQueries({ queryKey: ['zerotrust-device-stats'] });
    },
    onError: (err: unknown) => setActionError({ what: 'assess devices', error: err }),
  });

  const evaluateAccessMutation = useMutation({
    // Backend AccessRequestSchema requires:
    //   subject_type, subject_id, resource_type, resource_id, context (dict)
    // Do NOT swallow errors here — surface them so users see the failure.
    mutationFn: async (data: {
      subject_type: string;
      subject_id: string;
      resource_type: string;
      resource_id: string;
      context: Record<string, unknown>;
    }) => {
      const response = await api.post('/zerotrust/evaluate-access', data);
      return response.data;
    },
    onSuccess: () => {
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['zerotrust-dashboard'] });
      queryClient.invalidateQueries({ queryKey: ['zerotrust-decisions'] });
    },
    onError: (err: unknown) => setActionError({ what: 'evaluate access', error: err }),
  });

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const _getMaturityColor = (level: MaturityLevel) => {
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
        <>
          <LoadErrorBanner what="the Zero Trust dashboard" error={dashboardError} />
          <LoadErrorBanner what="access decisions" error={accessDecisionsError} />
          <OverviewTab
            data={dashboardData}
            recentDecisions={accessDecisions}
            loading={dashboardLoading}
          />
        </>
      )}

      {/* Access Control Tab */}
      {activeTab === 'access-control' && (
        <>
        <LoadErrorBanner what="the Zero Trust dashboard" error={dashboardError} />
        <LoadErrorBanner what="access decisions" error={accessDecisionsError} />
        <AccessControlTab
          recentDecisions={accessDecisions}
          accessDecisions24h={dashboardData ? { allowed: dashboardData.allowed_decisions, denied: dashboardData.denied_decisions, challenged: dashboardData.challenged_decisions } : undefined}
          loading={dashboardLoading || accessDecisionsLoading}
          decisionFilter={decisionFilter}
          setDecisionFilter={setDecisionFilter}
          onEvaluateAccess={(data) => evaluateAccessMutation.mutate(data)}
        />
        </>
      )}

      {/* Device Trust Tab */}
      {activeTab === 'devices' && (
        <>
        <LoadErrorBanner what="device trust stats" error={statsError} />
        <LoadErrorBanner what="devices" error={devicesError} />
        <DeviceTrustTab
          devices={devices || []}
          stats={deviceStats}
          loading={devicesLoading || statsLoading}
          expandedDevice={expandedDevice}
          setExpandedDevice={setExpandedDevice}
          onAssessDevices={() => assessDevicesMutation.mutate()}
          onChanged={() => {
            queryClient.invalidateQueries({ queryKey: ['zerotrust-devices'] });
            queryClient.invalidateQueries({ queryKey: ['zerotrust-device-stats'] });
            queryClient.invalidateQueries({ queryKey: ['zerotrust-dashboard'] });
          }}
        />
        </>
      )}

      {/* Micro-Segmentation Tab */}
      {activeTab === 'segmentation' && (
        <>
          <LoadErrorBanner what="micro-segments" error={segmentsError} />
          <SegmentationTab
            segments={segments || []}
            loading={segmentsLoading}
          />
        </>
      )}

      {/* Policies Tab */}
      {activeTab === 'policies' && (
        <>
          <LoadErrorBanner what="Zero Trust policies" error={policiesError} />
          <PoliciesTab
            policies={policies || []}
            loading={policiesLoading}
          />
        </>
      )}
    </div>
  );
}

function OverviewTab({
  data,
  recentDecisions,
  loading,
}: {
  data?: DashboardData;
  recentDecisions?: AccessDecision[];
  accessDecisions24h?: { allowed: number; denied: number; challenged: number };
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  // Each pillar is assessed from the tenant's stored configuration
  // (policies, device profiles, segments, enforced sessions, agents);
  // a pillar with nothing configured is "not_configured", not a low score.
  const pillarArray: Row[] = Object.entries(data?.pillars || {}).map(([k, v]) => ({
    name: k,
    score: Number(v?.score ?? 0),
    maturity_level: v?.maturity_level,
    configured: v?.status !== 'not_configured',
    status: v?.status === 'not_configured' ? 'not_configured' : Number(v?.score ?? 0) >= 70 ? 'healthy' : Number(v?.score ?? 0) >= 40 ? 'at-risk' : 'critical',
    criteria: Array.isArray(v?.criteria) ? v.criteria : [],
  }));

  const maturityLevels = (() => {
    const levels: { level: MaturityLevel; label: string; pillarCount: number }[] = [
      { level: 'traditional', label: 'Traditional', pillarCount: 0 },
      { level: 'initial', label: 'Initial', pillarCount: 0 },
      { level: 'advanced', label: 'Advanced', pillarCount: 0 },
      { level: 'optimal', label: 'Optimal', pillarCount: 0 },
    ];
    pillarArray.filter((p) => p.configured).forEach((pillar) => {
      if (pillar.score >= 90) levels[3].pillarCount += 1;
      else if (pillar.score >= 70) levels[2].pillarCount += 1;
      else if (pillar.score >= 40) levels[1].pillarCount += 1;
      else levels[0].pillarCount += 1;
    });
    return levels;
  })();

  return (
    <div className="space-y-6">
      {/* Maturity Level Banner */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">
          Zero Trust Maturity
        </h2>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
          Score {data ? data.maturity_score.toFixed(1) : NA} from stored configuration · {data?.configured_pillars ?? NA} of {pillarArray.length || NA} pillars configured ·{' '}
          {data?.access_decisions_24h ?? NA} access decision(s) in the last 24 h · {data?.not_reported_devices ?? NA} device(s) without reported posture
        </p>
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
        {pillarArray.map((pillar) => (
          <div
            key={pillar.name}
            className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-5"
          >
            <h3 className="font-semibold text-gray-900 dark:text-white mb-3 capitalize">
              {String(pillar.name).replace(/_/g, ' ')}
            </h3>

            <div className="space-y-3">
              {!pillar.configured ? (
                <p className="text-xs text-gray-500 dark:text-gray-400">Nothing configured for this pillar yet; no score is claimed.</p>
              ) : (
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
              )}

              {/* Status */}
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  pillar.configured ? getStatusColor(pillar.status) : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
                )}
              >
                {String(pillar.status || '').replace(/[-_]/g, ' ')}
              </span>
              {pillar.criteria.length > 0 && (
                <ul className="text-xs text-gray-600 dark:text-gray-400 space-y-0.5">
                  {pillar.criteria.map((c: Row) => (
                    <li key={c.key} title={`evidence: ${typeof c.evidence === 'object' ? JSON.stringify(c.evidence) : String(c.evidence)}`}>
                      {String(c.key).replace(/_/g, ' ')}: {c.points}/{c.weight}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Access Decisions Chart */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-6">
          Access Decisions (all time)
        </h2>
        <div className="grid grid-cols-3 gap-4">
          <DecisionChart
            label="Allowed"
            value={data?.allowed_decisions ?? 'not available'}
            icon={CheckCircle}
            color="green"
          />
          <DecisionChart
            label="Denied"
            value={data?.denied_decisions ?? 'not available'}
            icon={AlertTriangle}
            color="red"
          />
          <DecisionChart
            label="Challenged"
            value={data?.challenged_decisions ?? 'not available'}
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
          {(recentDecisions || []).length === 0 ? (
            <div className="text-sm text-gray-500 dark:text-gray-400 px-3 py-6 text-center">
              No access decisions recorded yet. Policy hits, challenges, and denials will appear here.
            </div>
          ) : null}
          {(recentDecisions || []).slice(0, 5).map((decision) => (
            <div
              key={decision.id}
              className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
            >
              <div className="flex-1">
                <div className="text-sm font-medium text-gray-900 dark:text-white">
                  {decision.subject} → {decision.resource}
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
    subject_type: string;
    subject_id: string;
    resource_type: string;
    resource_id: string;
    context: Record<string, unknown>;
  }) => void;
}) {
  const [evalSubjectType, setEvalSubjectType] = useState('user');
  const [evalSubjectId, setEvalSubjectId] = useState('');
  const [evalResourceType, setEvalResourceType] = useState('application');
  const [evalResourceId, setEvalResourceId] = useState('');
  const [evalContext, setEvalContext] = useState('{}');
  const [evalContextError, setEvalContextError] = useState<string | null>(null);

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
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Subject Type
            </label>
            <select
              value={evalSubjectType}
              onChange={(e) => setEvalSubjectType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="user">User</option>
              <option value="service">Service</option>
              <option value="device">Device</option>
              <option value="application">Application</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Subject ID
            </label>
            <input
              type="text"
              value={evalSubjectId}
              onChange={(e) => setEvalSubjectId(e.target.value)}
              placeholder="user@domain.com or service-account-1"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Resource Type
            </label>
            <select
              value={evalResourceType}
              onChange={(e) => setEvalResourceType(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            >
              <option value="application">Application</option>
              <option value="data">Data</option>
              <option value="network_segment">Network Segment</option>
              <option value="api">API</option>
              <option value="file">File</option>
              <option value="database">Database</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              Resource ID
            </label>
            <input
              type="text"
              value={evalResourceId}
              onChange={(e) => setEvalResourceId(e.target.value)}
              placeholder="api/secrets or finance-db"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            />
          </div>
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
            Context (JSON)
          </label>
          <textarea
            value={evalContext}
            onChange={(e) => {
              setEvalContext(e.target.value);
              setEvalContextError(null);
            }}
            rows={4}
            placeholder='{"location": "remote", "device_trust": "high", "behavior_score": 0.2}'
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm font-mono"
          />
          {evalContextError && (
            <p className="mt-1 text-xs text-red-600 dark:text-red-400">{evalContextError}</p>
          )}
        </div>
        <button
          onClick={() => {
            let parsedContext: Record<string, any> = {};
            const trimmed = (evalContext || '').trim();
            if (trimmed.length > 0) {
              try {
                const parsed = JSON.parse(trimmed);
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                  parsedContext = parsed;
                } else {
                  setEvalContextError('Context must be a JSON object (e.g. {"key": "value"})');
                  return;
                }
              } catch {
                setEvalContextError('Context is not valid JSON');
                return;
              }
            }
            setEvalContextError(null);
            onEvaluateAccess({
              subject_type: evalSubjectType,
              subject_id: evalSubjectId,
              resource_type: evalResourceType,
              resource_id: evalResourceId,
              context: parsedContext,
            });
          }}
          className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium text-sm"
        >
          Evaluate Access
        </button>
      </div>

      {/* Decisions Statistics */}
      <div className="grid grid-cols-3 gap-4">
        <DecisionChart
          label="Allowed"
          value={accessDecisions24h?.allowed ?? 'not available'}
          icon={CheckCircle}
          color="green"
        />
        <DecisionChart
          label="Denied"
          value={accessDecisions24h?.denied ?? 'not available'}
          icon={AlertTriangle}
          color="red"
        />
        <DecisionChart
          label="Challenged"
          value={accessDecisions24h?.challenged ?? 'not available'}
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
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {recentDecisions.map((decision) => (
              <tr key={decision.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {new Date(decision.created_at || "").toLocaleTimeString()}
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
  onChanged,
}: {
  devices: Device[];
  stats?: DeviceStats;
  loading: boolean;
  expandedDevice: string | null;
  setExpandedDevice: (id: string | null) => void;
  onAssessDevices: () => void;
  onChanged: () => void;
}) {
  const [detailDevice, setDetailDevice] = useState<Row | null>(null);
  const [reassessedDevices, setReassessedDevices] = useState<Record<string, number>>({});
  const [detailError, setDetailError] = useState<unknown>(null);
  const [overrideDevice, setOverrideDevice] = useState<Device | { device_id: string; hostname: null } | null>(null);
  const [overrideError, setOverrideError] = useState<unknown>(null);

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
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <StatCard label="Total Devices" value={stats?.total ?? NA} color="blue" />
        <StatCard label="Trusted" value={stats?.trusted ?? NA} color="green" />
        <StatCard label="Conditional" value={stats?.conditional ?? NA} color="yellow" />
        <StatCard label="Untrusted" value={stats?.untrusted ?? NA} color="orange" />
        <StatCard label="Blocked" value={stats?.blocked ?? NA} color="red" />
        <StatCard label="Posture Not Reported" value={stats?.not_reported ?? NA} color="blue" />
      </div>

      <p className="text-xs text-gray-500 dark:text-gray-400">
        Posture comes from the endpoint agent (OS patched, antivirus, encryption, firewall). A device whose agent never reported is
        &quot;not reported&quot;: it is counted neither compliant nor non-compliant.
      </p>

      <div className="flex flex-wrap gap-3">
        <button
          onClick={onAssessDevices}
          className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
        >
          <Zap className="w-5 h-5" />
          Re-score All Devices
        </button>
        <button
          onClick={() => { setOverrideError(null); setOverrideDevice({ device_id: '', hostname: null }); }}
          className="inline-flex items-center gap-2 px-4 py-3 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-sm"
          title="Record posture for a device by hand (admin; marked as an override)"
        >
          <Shield className="w-4 h-4" />
          Record Posture Override
        </button>
      </div>

      <LoadErrorBanner what="the device" error={detailError} />
      {devices.length === 0 && (
        <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
          No device trust profile yet. Profiles are created when an endpoint agent reports posture or an administrator records one.
        </p>
      )}

      {/* Devices Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {devices.map((device) => (
          <div
            key={device.id}
            className="rounded-lg border p-5 cursor-pointer transition-all bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700 hover:border-blue-400 dark:hover:border-blue-600"
            onClick={() => setExpandedDevice(expandedDevice === device.id ? null : device.id)}
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">
                  {device.hostname}
                </h3>
                <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
                  {(device.device_type || 'unknown').charAt(0).toUpperCase() + (device.device_type || 'unknown').slice(1)}
                </p>
              </div>
              <div className="flex flex-col items-end gap-1">
                <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300">
                  {device.trust_level || 'unknown'}
                </span>
                <span
                  className={clsx(
                    'inline-flex items-center px-2 py-0.5 rounded-full text-xs',
                    device.is_compliant === true
                      ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                      : device.is_compliant === false
                      ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                      : 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400'
                  )}
                >
                  {device.is_compliant === true ? 'compliant' : device.is_compliant === false ? 'non-compliant' : String(device.posture_status || 'not_reported').replace(/_/g, ' ')}
                </span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-1 text-xs mb-3">
              {AGENT_POSTURE_CHECKS.map((k) => {
                const v = device.compliance_checks?.[k];
                return (
                  <span key={k} className={clsx(v === true ? 'text-green-700 dark:text-green-400' : v === false ? 'text-red-700 dark:text-red-400' : 'text-gray-400')}>
                    {CHECK_LABELS[k]}: {checkLabel(v)}
                  </span>
                );
              })}
            </div>
            {device.posture_source && (
              <p className="text-xs text-gray-500 mb-2">
                Source: {device.posture_source === 'admin_override' ? 'administrator override (not measured)' : device.posture_source}
                {device.posture_reported_at ? ` · ${new Date(device.posture_reported_at).toLocaleString()}` : ''}
              </p>
            )}

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

            {/* Compliance checks live on the device detail (View Details),
                not on the list rows, so none are drawn here. */}

            {/* Last Seen */}
            <div className="text-xs text-gray-500 dark:text-gray-400 mt-3 pt-3 border-t border-gray-200 dark:border-gray-700">
              Last seen: {device.last_seen ? new Date(device.last_seen).toLocaleString() : 'never reported'}
            </div>

            {/* Expanded Details */}
            {expandedDevice === device.id && (
              <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 space-y-2">
                <button
                  onClick={async () => {
                    try {
                      const res = await api.get(`/zerotrust/devices/${encodeURIComponent(device.device_id)}`);
                      setDetailError(null);
                      setDetailDevice(res.data);
                    } catch (err) {
                      setDetailError(err);
                    }
                  }}
                  className="w-full px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-xs font-medium"
                >
                  View Details
                </button>
                <button
                  onClick={async () => {
                    try {
                      await api.post('/zerotrust/assess-devices', { device_ids: [device.device_id] });
                      setDetailError(null);
                      setReassessedDevices((prev) => ({ ...prev, [device.id]: Date.now() }));
                    } catch (err) {
                      setDetailError(err);
                    }
                  }}
                  className="w-full px-3 py-2 bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 text-xs font-medium"
                >
                  {reassessedDevices[device.id]
                    ? `Re-assessed ${new Date(reassessedDevices[device.id]).toLocaleTimeString()}`
                    : 'Re-assess'}
                </button>
                <button
                  onClick={(e) => { e.stopPropagation(); setOverrideError(null); setOverrideDevice(device); }}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-xs font-medium"
                >
                  Record Posture Override (admin)
                </button>
              </div>
            )}
          </div>
        ))}
      </div>

      {overrideDevice && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setOverrideDevice(null)}>
          <form
            className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-md mx-4 p-6 space-y-3"
            onClick={(e) => e.stopPropagation()}
            onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              const deviceId = String(fd.get('device_id') || overrideDevice.device_id).trim();
              const body: Record<string, boolean> = {};
              for (const k of [...AGENT_POSTURE_CHECKS, ...OVERRIDE_ONLY_CHECKS]) {
                const v = String(fd.get(k) || '');
                if (v === 'yes') body[k] = true;
                else if (v === 'no') body[k] = false;
              }
              try {
                await api.put(`/zerotrust/devices/${encodeURIComponent(deviceId)}/compliance`, body);
                setOverrideDevice(null);
                onChanged();
              } catch (err) {
                setOverrideError(err);
              }
            }}
          >
            <h2 className="text-lg font-semibold">Posture override{overrideDevice.device_id ? `: ${overrideDevice.hostname || overrideDevice.device_id}` : ''}</h2>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Admin only. Stored with source &quot;admin_override&quot; and written to the audit log; it feeds the device check of access decisions.
              Leave a check unset to keep what was reported.
            </p>
            <ActionErrorBanner what="record the posture override" error={overrideError} />
            {!overrideDevice.device_id && (
              <input name="device_id" required placeholder="device id" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm" />
            )}
            {[...AGENT_POSTURE_CHECKS, ...OVERRIDE_ONLY_CHECKS].map((k) => (
              <label key={k} className="flex items-center justify-between text-sm">
                <span>{CHECK_LABELS[k]}</span>
                <select name={k} defaultValue="" className="px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-sm">
                  <option value="">unset</option>
                  <option value="yes">yes</option>
                  <option value="no">no</option>
                </select>
              </label>
            ))}
            <div className="flex gap-2 pt-2">
              <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Save override</button>
              <button type="button" onClick={() => setOverrideDevice(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
            </div>
          </form>
        </div>
      )}

      <DetailDrawer
        open={!!detailDevice}
        onClose={() => setDetailDevice(null)}
        title={detailDevice?.hostname || detailDevice?.device_id || 'Device Trust Profile'}
        subtitle={detailDevice ? `${detailDevice.device_type || 'device'} · trust score ${detailDevice.trust_score ?? '—'}` : undefined}
        sections={
          detailDevice
            ? ([
                {
                  title: 'Identity',
                  fields: [
                    { label: 'Device ID', value: detailDevice.device_id, mono: true, full: true },
                    { label: 'Hostname', value: detailDevice.hostname },
                    { label: 'Type', value: detailDevice.device_type },
                    { label: 'Owner', value: detailDevice.owner_id },
                    { label: 'OS', value: detailDevice.os_type },
                    { label: 'OS Version', value: detailDevice.os_version },
                  ],
                },
                {
                  title: 'Trust Posture',
                  fields: [
                    { label: 'Trust Score', value: detailDevice.trust_score },
                    { label: 'Trust Level', value: detailDevice.trust_level },
                    {
                      label: 'Compliant',
                      value: detailDevice.is_compliant === true ? 'yes' : detailDevice.is_compliant === false ? 'no' : `not determined (${String(detailDevice.posture_status || 'not_reported').replace(/_/g, ' ')})`,
                    },
                    {
                      label: 'Posture source',
                      value: detailDevice.posture_source === 'admin_override' ? 'administrator override (not measured)' : detailDevice.posture_source,
                    },
                    ...[...AGENT_POSTURE_CHECKS, ...OVERRIDE_ONLY_CHECKS].map((k) => ({
                      label: CHECK_LABELS[k],
                      value: checkLabel(detailDevice.compliance_checks?.[k]),
                    })),
                    {
                      label: 'Risk Factors',
                      value: Array.isArray(detailDevice.risk_factors) && detailDevice.risk_factors.length > 0
                        ? detailDevice.risk_factors.join(', ')
                        : null,
                      full: true,
                    },
                  ],
                },
                {
                  title: 'Activity',
                  fields: [
                    { label: 'Last Seen', value: detailDevice.last_seen_at ? new Date(detailDevice.last_seen_at).toLocaleString() : null },
                    { label: 'Last Assessed', value: detailDevice.last_assessment_at ? new Date(detailDevice.last_assessment_at).toLocaleString() : null },
                    { label: 'Enrolled', value: detailDevice.enrolled_at ? new Date(detailDevice.enrolled_at).toLocaleString() : null },
                  ],
                },
              ] as DetailSection[])
            : undefined
        }
      />
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
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const createSegment = async (values: Record<string, string>) => {
    const allowed_protocols = (values.allowed_protocols || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const cidr_ranges = (values.cidr_ranges || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    await api.post('/zerotrust/segments', {
      name: values.name.trim(),
      segment_type: values.segment_type || 'workload',
      description: values.description?.trim() || '',
      trust_level: values.trust_level || 'zero',
      allowed_protocols,
      cidr_ranges,
      is_active: true,
    });
    queryClient.invalidateQueries({ queryKey: ['zerotrust-segments'] });
    queryClient.invalidateQueries({ queryKey: ['zerotrust-dashboard'] });
  };

  return (
    <div className="space-y-6">
      {/* Create Segment Button */}
      <button
        onClick={() => setShowCreateModal(true)}
        className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
      >
        <Plus className="w-5 h-5" />
        Create Segment
      </button>

      <FormModal
        open={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create Micro-Segment"
        description="Define an isolated network/workload zone for Zero Trust enforcement."
        submitLabel="Create Segment"
        fields={[
          { name: 'name', label: 'Segment Name', required: true, placeholder: 'e.g. PCI Cardholder Zone' },
          {
            name: 'segment_type',
            label: 'Segment Type',
            type: 'select' as const,
            required: true,
            defaultValue: 'workload',
            options: [
              { value: 'network', label: 'Network' },
              { value: 'application', label: 'Application' },
              { value: 'data', label: 'Data' },
              { value: 'workload', label: 'Workload' },
            ],
          },
          { name: 'description', label: 'Description', type: 'textarea' as const, placeholder: 'Purpose, scope, owner' },
          {
            name: 'trust_level',
            label: 'Trust Level',
            type: 'select' as const,
            defaultValue: 'zero',
            options: [
              { value: 'zero', label: 'Zero (deny by default)' },
              { value: 'basic', label: 'Basic' },
              { value: 'advanced', label: 'Advanced' },
            ],
          },
          { name: 'cidr_ranges', label: 'CIDR Ranges', placeholder: '10.0.1.0/24, 10.0.2.0/24', help: 'Comma-separated. Optional.' },
          { name: 'allowed_protocols', label: 'Allowed Protocols', placeholder: 'tcp, https, ssh', help: 'Comma-separated. Optional.' },
        ]}
        onSubmit={createSegment}
      />

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
                  Type: {segment.segment_type}
                </p>
              </div>
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium',
                  segment.is_active
                    ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                    : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-400'
                )}
              >
                {segment.is_active ? 'active' : 'inactive'}
              </span>
            </div>

            <div className="space-y-3 text-sm">
              <div className="flex items-center justify-between text-gray-600 dark:text-gray-400">
                <span>Members</span>
                <span className="font-medium text-gray-900 dark:text-white">
                  {(segment.member_assets || []).length}
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
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const createPolicy = async (values: Record<string, string>) => {
    const riskThreshold = Number(values.risk_threshold);
    await api.post('/zerotrust/policies', {
      name: values.name.trim(),
      policy_type: values.policy_type || 'access',
      description: values.description?.trim() || '',
      risk_threshold: Number.isFinite(riskThreshold) ? riskThreshold : 50,
      requires_mfa: values.requires_mfa === 'true',
      requires_device_trust: values.requires_device_trust === 'true',
      is_enabled: true,
      conditions: [],
      actions: [],
    });
    queryClient.invalidateQueries({ queryKey: ['zerotrust-policies'] });
    queryClient.invalidateQueries({ queryKey: ['zerotrust-dashboard'] });
  };

  return (
    <div className="space-y-6">
      {/* Create Policy Button */}
      <button
        onClick={() => setShowCreateModal(true)}
        className="inline-flex items-center gap-2 px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
      >
        <Plus className="w-5 h-5" />
        Create Policy
      </button>

      <FormModal
        open={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create Zero Trust Policy"
        description="Define enforcement rules for access decisions. Add conditions/actions in the policy editor after create."
        submitLabel="Create Policy"
        fields={[
          { name: 'name', label: 'Policy Name', required: true, placeholder: 'e.g. Enforce MFA for Finance Apps' },
          {
            name: 'policy_type',
            label: 'Policy Type',
            type: 'select' as const,
            required: true,
            defaultValue: 'access',
            options: [
              { value: 'access', label: 'Access' },
              { value: 'network', label: 'Network' },
              { value: 'identity', label: 'Identity' },
              { value: 'device', label: 'Device' },
              { value: 'data', label: 'Data' },
              { value: 'workload', label: 'Workload' },
              { value: 'visibility', label: 'Visibility' },
            ],
          },
          { name: 'description', label: 'Description', type: 'textarea' as const, placeholder: 'What does this policy enforce?' },
          {
            name: 'risk_threshold',
            label: 'Risk Threshold (0-100)',
            type: 'number' as const,
            defaultValue: 50,
            help: 'Block when calculated risk exceeds this score.',
          },
          {
            name: 'requires_mfa',
            label: 'Require MFA',
            type: 'select' as const,
            defaultValue: 'true',
            options: [
              { value: 'true', label: 'Yes' },
              { value: 'false', label: 'No' },
            ],
          },
          {
            name: 'requires_device_trust',
            label: 'Require Device Trust',
            type: 'select' as const,
            defaultValue: 'true',
            options: [
              { value: 'true', label: 'Yes' },
              { value: 'false', label: 'No' },
            ],
          },
        ]}
        onSubmit={createPolicy}
      />

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
                  {policy.policy_type}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {policy.risk_threshold}%
                </td>
                <td className="px-6 py-4 text-sm">
                  {policy.requires_mfa ? (
                    <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-gray-400" />
                  )}
                </td>
                <td className="px-6 py-4 text-sm">
                  {policy.requires_device_trust ? (
                    <CheckCircle className="w-4 h-4 text-green-600 dark:text-green-400" />
                  ) : (
                    <AlertCircle className="w-4 h-4 text-gray-400" />
                  )}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {policy.hit_count}
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
                    {policy.is_enabled ? 'enabled' : 'disabled'}
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
  value: number | string;
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
  value: number | string;
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
