import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import {
  EyeOff,
  Plus,
  RotateCcw,
  Trash2,
  Eye,
  Globe,
  Clock,
  AlertTriangle,
  Zap,
  TrendingUp,
  Key,
  Unlock,
  Network,
  Copy,
} from 'lucide-react';
// recharts imports removed - timeline chart not available in dashboard response
import clsx from 'clsx';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';

interface DeceptionDashboardStats {
  total_decoys: number;
  active_decoys: number;
  disabled_decoys: number;
  total_honeytokens: number;
  active_tokens: number;
  triggered_tokens: number;
  active_campaigns: number;
  completed_campaigns: number;
  interactions_today: number;
  interactions_this_week: number;
  unique_attackers_today: number;
  unique_attackers_this_week: number;
  high_severity_interactions: number;
  critical_interactions: number;
  average_interaction_response_time_seconds: number;
}

interface DeceptionDashboard {
  stats: DeceptionDashboardStats;
  recent_interactions: Interaction[];
  active_campaigns: Campaign[];
  top_attacker_profiles: Record<string, any>[];
  recommendations: string[];
}

/** configuration.deployment / .listener / .removal written by the deploy path (src/deception/engine.py). */
interface DeploymentState {
  state?: string;
  note?: string;
  error?: string;
  agent_id?: string;
  agent_hostname?: string;
  command_id?: string;
  port?: number;
}

interface Decoy {
  id: string;
  name: string;
  decoy_type: string;
  category: string;
  // deploying | active | failed | not_deployed | record_only | disabled | inactive | triggered
  status: string;
  emulated_service?: string;
  deployment_target?: string | null;
  configuration?: {
    deployment?: DeploymentState;
    listener?: DeploymentState;
    removal?: DeploymentState;
    [key: string]: unknown;
  };
  interaction_count: number;
  last_interaction_at: string | null;
  fidelity_level: 'low' | 'medium' | 'high';
}

interface HoneyToken {
  id: string;
  name: string;
  token_type: string;
  status: string;
  deployment_location: string | null;
  deployment_context?: string | null;
  triggered_count: number;
  last_triggered_at?: string | null;
  last_triggered_by?: string | null;
  token_preview?: string;
  canary_path?: string;
  trigger_mechanism?: string;
}

/** GET /deception/tokens/types */
interface TokenTypeInfo {
  token_type: string;
  supported: boolean;
  trigger_mechanism: string;
  reason: string;
}

/** POST /deception/tokens: the value is returned once, never again. */
interface GeneratedToken extends HoneyToken {
  token_value: string;
  canary_url: string;
  planting: Record<string, unknown>;
  value_shown_once: boolean;
}

/** GET /deception/tokens/{id}/triggers */
interface TokenTrigger {
  id: string;
  source_ip: string | null;
  forwarded_for: string | null;
  user_agent: string | null;
  http_method: string;
  value_presented: boolean | null;
  alert_id: string | null;
  created_at: string | null;
}

/** POST /deception/tokens/{id}/check */
interface TokenCheck {
  has_been_used: boolean;
  triggered_count: number;
  triggers_with_value_presented: number;
  last_triggered_at: string | null;
  last_triggered_by: string | null;
  status: string;
}

interface Interaction {
  id: string;
  created_at: string;
  decoy_id: string;
  source_ip: string;
  geo_location?: Record<string, any> | null;
  interaction_type: string;
  protocol: string | null;
  session_duration_seconds: number | null;
  threat_assessment: 'low' | 'medium' | 'high' | 'critical';
  commands_captured?: string[];
  mitre_techniques?: string[];
  credentials_captured?: Record<string, any> | null;
}

interface Campaign {
  id: string;
  name: string;
  objective: string;
  description?: string;
  status: 'draft' | 'active' | 'paused' | 'completed';
  decoy_ids: string[];
  total_interactions: number;
  unique_attackers: number;
  effectiveness_score: number | null;
}

// TimelinePoint removed - not used in current dashboard response

const decoyTypeColors: Record<string, string> = {
  honeypot: 'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400',
  honeytoken: 'bg-purple-50 dark:bg-purple-900/20 text-purple-600 dark:text-purple-400',
  honeyfile: 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400',
  honeycred: 'bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400',
};

/** Decoy types the deploy route accepts; honeydns / honeynet are stored as not_deployed (no agent can deploy them). */
const DECOY_TYPES: { value: string; label: string; note?: string }[] = [
  { value: 'honeypot', label: 'Honeypot (listener on a deception agent)' },
  { value: 'honeyfile', label: 'Honeyfile' },
  { value: 'honeycred', label: 'Honeycred' },
  { value: 'canary_file', label: 'Canary file' },
  { value: 'breadcrumb', label: 'Breadcrumb' },
  { value: 'honeytoken', label: 'Honeytoken decoy' },
  { value: 'honeydns', label: 'Honey DNS (record only)', note: 'A DNS decoy needs an authoritative DNS server, which PySOAR does not run: it is stored as not deployed.' },
  { value: 'honeynet', label: 'Honeynet (record only)', note: 'A decoy network needs infrastructure no endpoint agent provisions: it is stored as not deployed.' },
];

const DECOY_STATUSES = ['deploying', 'active', 'failed', 'not_deployed', 'record_only', 'disabled'];

const statusColors: Record<string, string> = {
  active: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300',
  deploying: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300',
  failed: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
  not_deployed: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300',
  record_only: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300',
  disabled: 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300',
  inactive: 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300',
  expired: 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300',
  triggered: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
};

const threatColors = {
  low: 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400',
  medium: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600 dark:text-yellow-400',
  high: 'bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400',
  critical: 'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400',
};

const campaignStatusColors = {
  draft: 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300',
  active: 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-300',
  paused: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-300',
  completed: 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-300',
};

const statusDots: Record<string, string> = {
  active: 'bg-green-500',
  deploying: 'bg-blue-500',
  failed: 'bg-red-500',
  not_deployed: 'bg-yellow-500',
  record_only: 'bg-yellow-500',
  disabled: 'bg-gray-400',
  triggered: 'bg-red-500',
};

function humanize(value: string | null | undefined): string {
  if (!value) return 'Not available';
  return value.replace(/_/g, ' ');
}

export default function DeceptionTech() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'decoys' | 'tokens' | 'interactions' | 'campaigns'>('dashboard');
  const [decoyTypeFilter, setDecoyTypeFilter] = useState('all');
  const [decoyStatusFilter, setDecoyStatusFilter] = useState('all');
  const [threatLevelFilter, setThreatLevelFilter] = useState('all');
  const [expandedInteraction, setExpandedInteraction] = useState<string | null>(null);
  // timeRangeFilter removed - backend does not support time_range parameter
  const [showDeployModal, setShowDeployModal] = useState(false);
  const [showGenerateTokenModal, setShowGenerateTokenModal] = useState(false);
  const [showCreateCampaignModal, setShowCreateCampaignModal] = useState(false);
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);
  const [configDecoy, setConfigDecoy] = useState<Decoy | null>(null);

  // Deploy Decoy form state
  const [deployName, setDeployName] = useState('');
  const [deployType, setDeployType] = useState('honeypot');
  const [deployCategory, setDeployCategory] = useState('network');
  const [deployFidelity, setDeployFidelity] = useState('medium');
  const [deployTarget, setDeployTarget] = useState('');
  const [deployedDecoy, setDeployedDecoy] = useState<Decoy | null>(null);

  // Generate Token form state
  const [tokenName, setTokenName] = useState('');
  const [tokenType, setTokenType] = useState('');
  const [tokenLocation, setTokenLocation] = useState('');
  const [tokenContext, setTokenContext] = useState('');
  const [generatedToken, setGeneratedToken] = useState<GeneratedToken | null>(null);
  const [triggersToken, setTriggersToken] = useState<HoneyToken | null>(null);
  const [tokenChecks, setTokenChecks] = useState<Record<string, TokenCheck>>({});
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);

  // Create Campaign form state
  const [campaignName, setCampaignName] = useState('');
  const [campaignObjective, setCampaignObjective] = useState('general_detection');
  const [campaignDescription, setCampaignDescription] = useState('');

  // Configure Decoy form state
  const [configName, setConfigName] = useState('');
  const [configFidelity, setConfigFidelity] = useState('medium');

  // Modal error state (rendered with ActionErrorBanner: code, reason and itemised details)
  const [modalError, setModalError] = useState<unknown>(null);

  const queryClient = useQueryClient();

  // Fetch deception dashboard
  const { data: dashboard, isLoading: dashboardLoading, error: dashboardError } = useQuery({
    queryKey: ['deceptionDashboard'],
    queryFn: async () => {
      const response = await api.get<DeceptionDashboard>('/deception/dashboard');
      return response.data;
    },
  });

  // Fetch decoys
  const { data: decoys, isLoading: decoysLoading, error: decoysError } = useQuery({
    queryKey: ['decoys', decoyTypeFilter, decoyStatusFilter],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (decoyTypeFilter !== 'all') params.decoy_type = decoyTypeFilter;
      if (decoyStatusFilter !== 'all') params.status = decoyStatusFilter;

      const response = await api.get<Decoy[]>('/deception/decoys', { params });
      return response.data;
    },
  });

  // Fetch honey tokens
  const { data: tokens, isLoading: tokensLoading, error: tokensError } = useQuery({
    queryKey: ['honeyTokens'],
    queryFn: async () => {
      const response = await api.get<HoneyToken[]>('/deception/tokens');
      return response.data;
    },
  });

  // Token types the backend can generate (unsupported ones carry the reason)
  const { data: tokenTypes, error: tokenTypesError } = useQuery({
    queryKey: ['honeyTokenTypes'],
    queryFn: async () => (await api.get<TokenTypeInfo[]>('/deception/tokens/types')).data,
    enabled: activeTab === 'tokens' || showGenerateTokenModal,
  });
  const supportedTokenTypes = (tokenTypes || []).filter((t) => t.supported);
  const unsupportedTokenTypes = (tokenTypes || []).filter((t) => !t.supported);
  const selectedTokenType = tokenType || supportedTokenTypes[0]?.token_type || '';

  const checkTokenMutation = useMutation({
    mutationFn: async (token: HoneyToken) => (await api.post<TokenCheck>(`/deception/tokens/${token.id}/check`)).data,
    onSuccess: (data, token) => {
      setTokenChecks((prev) => ({ ...prev, [token.id]: data }));
      queryClient.invalidateQueries({ queryKey: ['honeyTokens'] });
    },
    onError: (err, token) => setActionError({ what: `check token ${token.name}`, error: err }),
  });

  // Fetch interactions
  const { data: interactions, isLoading: interactionsLoading, error: interactionsError } = useQuery({
    queryKey: ['interactions', threatLevelFilter],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (threatLevelFilter !== 'all') params.threat_level = threatLevelFilter;

      const response = await api.get<Interaction[]>('/deception/interactions', { params });
      return response.data;
    },
  });

  // Fetch campaigns
  const { data: campaigns, isLoading: campaignsLoading, error: campaignsError } = useQuery({
    queryKey: ['campaigns'],
    queryFn: async () => {
      const response = await api.get<Campaign[]>('/deception/campaigns');
      return response.data;
    },
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Deception Technology</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">Detect attackers with deception controls</p>
        </div>
        <EyeOff className="w-10 h-10 text-indigo-600 dark:text-indigo-400" />
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <div className="flex space-x-8 overflow-x-auto">
          {[
            { id: 'dashboard', label: 'Dashboard', icon: TrendingUp },
            { id: 'decoys', label: 'Decoys', icon: Network },
            { id: 'tokens', label: 'Honey Tokens', icon: Key },
            { id: 'interactions', label: 'Interactions', icon: AlertTriangle },
            { id: 'campaigns', label: 'Campaigns', icon: Zap },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => { setActiveTab(tab.id as typeof activeTab); setActionError(null); }}
                className={clsx(
                  'px-4 py-3 border-b-2 font-medium text-sm transition-colors flex items-center gap-2 whitespace-nowrap',
                  activeTab === tab.id
                    ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400'
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
          {/* Stats */}
          {dashboardLoading ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading dashboard...</div>
          ) : dashboardError ? (
            <LoadErrorBanner what="the deception dashboard" error={dashboardError} />
          ) : (
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Active Decoys</p>
              <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-2">{dashboard?.stats?.active_decoys ?? 'not available'}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Tokens Deployed</p>
              <p className="text-3xl font-bold text-purple-600 dark:text-purple-400 mt-2">{dashboard?.stats?.total_honeytokens ?? 'not available'}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Interactions Today</p>
              <p className="text-3xl font-bold text-orange-600 dark:text-orange-400 mt-2">{dashboard?.stats?.interactions_today ?? 'not available'}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Unique Attackers</p>
              <p className="text-3xl font-bold text-red-600 dark:text-red-400 mt-2">{dashboard?.stats?.unique_attackers_today ?? 'not available'}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Active Campaigns</p>
              <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-2">{dashboard?.stats?.active_campaigns ?? 'not available'}</p>
            </div>
          </div>
          )}

          {/* Interaction Timeline - placeholder, backend does not return timeline in dashboard */}

          {/* Recent Interactions */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Interactions</h3>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Time</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Decoy</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Source IP</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Threat Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {dashboardError ? (
                  <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">Recent interactions not available.</td></tr>
                ) : (dashboard?.recent_interactions || []).length === 0 ? (
                  <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No recent interactions</td></tr>
                ) : (dashboard?.recent_interactions || []).slice(0, 10).map((interaction) => (
                  <tr key={interaction.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {interaction.created_at ? new Date(interaction.created_at || "").toLocaleString() : '—'}
                    </td>
                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{interaction.decoy_id}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">{interaction.source_ip}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{interaction.interaction_type}</td>
                    <td className="px-6 py-4">
                      <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', threatColors[interaction.threat_assessment] || '')}>
                        {interaction.threat_assessment ? interaction.threat_assessment.charAt(0).toUpperCase() + interaction.threat_assessment.slice(1) : '—'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Decoys Tab */}
      {activeTab === 'decoys' && (
        <div className="space-y-6">
          <div className="flex gap-4">
            <button
              onClick={() => setShowDeployModal(true)}
              className="px-4 py-2 rounded-lg bg-indigo-600 dark:bg-indigo-700 text-white hover:bg-indigo-700 dark:hover:bg-indigo-600 font-medium transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />
              Deploy New Decoy
            </button>
            <select
              value={decoyTypeFilter}
              onChange={(e) => setDecoyTypeFilter(e.target.value)}
              className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="all">All Types</option>
              {DECOY_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            <select
              value={decoyStatusFilter}
              onChange={(e) => setDecoyStatusFilter(e.target.value)}
              className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="all">All Status</option>
              {DECOY_STATUSES.map((st) => (
                <option key={st} value={st}>{humanize(st)}</option>
              ))}
            </select>
          </div>
          {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}

          {/* Decoys Grid */}
          {decoysLoading ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading decoys...</div>
          ) : decoysError ? (
            <LoadErrorBanner what="decoys" error={decoysError} />
          ) : (decoys || []).length === 0 ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">No decoys found. Deploy one to get started.</div>
          ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(decoys || []).map((decoy) => (
              <div key={decoy.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white">{decoy.name}</h3>
                    <div className="flex items-center gap-2 mt-1">
                      <div className={clsx('w-2 h-2 rounded-full', statusDots[decoy.status] || 'bg-gray-400')} />
                      <span className={clsx('px-2 py-0.5 rounded text-xs font-medium', statusColors[decoy.status] || 'bg-gray-100 text-gray-700')}>{humanize(decoy.status)}</span>
                    </div>
                  </div>
                  <span className={clsx('px-2 py-1 rounded text-xs font-medium', decoyTypeColors[decoy.decoy_type] || 'bg-gray-100 text-gray-600')}>
                    {decoy.decoy_type}
                  </span>
                </div>

                {decoy.emulated_service && (
                  <p className="text-sm text-gray-600 dark:text-gray-400">{decoy.emulated_service}</p>
                )}

                <DecoyDeploymentNote decoy={decoy} />

                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Interactions</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{decoy.interaction_count ?? 0}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Fidelity</p>
                    <p className="text-sm font-bold text-gray-900 dark:text-white mt-1 capitalize">{decoy.fidelity_level}</p>
                  </div>
                </div>

                <p className="text-xs text-gray-600 dark:text-gray-400">
                  Last: {decoy.last_interaction_at ? new Date(decoy.last_interaction_at || "").toLocaleDateString() : 'Never'}
                </p>

                <div className="flex gap-2 pt-2 border-t border-gray-200 dark:border-gray-700">
                  <button
                    onClick={() => setConfigDecoy(decoy)}
                    className="flex-1 px-3 py-2 rounded-lg text-xs bg-gray-100 dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors font-medium flex items-center justify-center gap-1"
                  >
                    <RotateCcw className="w-3 h-3" />
                    Configure
                  </button>
                  <button
                    onClick={async () => {
                      if (confirm('Are you sure you want to disable this decoy?')) {
                        setActionError(null);
                        try {
                          await api.post(`/deception/decoys/${decoy.id}/disable`);
                          queryClient.invalidateQueries({ queryKey: ['decoys'] });
                          queryClient.invalidateQueries({ queryKey: ['deceptionDashboard'] });
                        } catch (error: unknown) {
                          setActionError({ what: `disable decoy ${decoy.name}`, error });
                        }
                      }
                    }}
                    className="flex-1 px-3 py-2 rounded-lg text-xs bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40 transition-colors font-medium flex items-center justify-center gap-1"
                  >
                    <Trash2 className="w-3 h-3" />
                    Disable
                  </button>
                </div>
              </div>
            ))}
          </div>
          )}
        </div>
      )}

      {/* Honey Tokens Tab */}
      {activeTab === 'tokens' && (
        <div className="space-y-6">
          <button
            onClick={() => { setModalError(null); setShowGenerateTokenModal(true); }}
            className="px-4 py-2 rounded-lg bg-indigo-600 dark:bg-indigo-700 text-white hover:bg-indigo-700 dark:hover:bg-indigo-600 font-medium transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Generate Token
          </button>
          <LoadErrorBanner what="the honeytoken types" error={tokenTypesError} />
          {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
          {generatedToken && <GeneratedTokenPanel token={generatedToken} onDismiss={() => setGeneratedToken(null)} />}
          {triggersToken && <TokenTriggersPanel token={triggersToken} onClose={() => setTriggersToken(null)} />}

          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Value</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Location</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Triggered</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Last Triggered</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {tokensLoading ? (
                  <tr><td colSpan={8} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">Loading tokens...</td></tr>
                ) : tokensError ? (
                  <tr><td colSpan={8} className="px-6 py-4"><LoadErrorBanner what="honey tokens" error={tokensError} /></td></tr>
                ) : (tokens || []).length === 0 ? (
                  <tr><td colSpan={8} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No honey tokens found. Generate one to get started.</td></tr>
                ) : (tokens || []).map((token) => (
                  <tr key={token.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{token.name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400" title={token.trigger_mechanism || undefined}>{humanize(token.token_type)}</td>
                    <td className="px-6 py-4 text-xs font-mono text-gray-600 dark:text-gray-400" title="Only a preview is stored; the full value was shown once at creation">{token.token_preview || 'Not available'}</td>
                    <td className="px-6 py-4">
                      <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', statusColors[token.status] || '')}>
                        {token.status ? token.status.charAt(0).toUpperCase() + token.status.slice(1) : '—'}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{token.deployment_location || '—'}</td>
                    <td className="px-6 py-4">
                      <p className="font-semibold text-gray-900 dark:text-white">{token.triggered_count ?? 0}</p>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {token.last_triggered_at ? new Date(token.last_triggered_at).toLocaleString() : 'Never'}
                      {token.last_triggered_by && <p className="text-xs font-mono">{token.last_triggered_by}</p>}
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex gap-2">
                        <button
                          onClick={() => { setActionError(null); checkTokenMutation.mutate(token); }}
                          disabled={checkTokenMutation.isPending}
                          className="text-xs px-2 py-1 rounded bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/40 transition-colors font-medium disabled:opacity-50"
                        >
                          Check
                        </button>
                        <button
                          onClick={() => setTriggersToken(token)}
                          className="text-xs px-2 py-1 rounded bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors font-medium"
                        >
                          Triggers
                        </button>
                      </div>
                      {tokenChecks[token.id] && (
                        <p className="mt-1 text-xs text-gray-600 dark:text-gray-400">
                          {tokenChecks[token.id].has_been_used
                            ? `Used: ${tokenChecks[token.id].triggered_count} trigger(s), ${tokenChecks[token.id].triggers_with_value_presented} presenting the value`
                            : 'Not used yet'}
                        </p>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Interactions Tab */}
      {activeTab === 'interactions' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="flex flex-wrap gap-4">
            <select
              value={threatLevelFilter}
              onChange={(e) => setThreatLevelFilter(e.target.value)}
              className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="all">All Threat Levels</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          {/* Interactions Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Time</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Decoy</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Source IP</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Geo</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Duration</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Threat</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {interactionsLoading ? (
                  <tr><td colSpan={7} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">Loading interactions...</td></tr>
                ) : interactionsError ? (
                  <tr><td colSpan={7} className="px-6 py-4"><LoadErrorBanner what="interactions" error={interactionsError} /></td></tr>
                ) : (interactions || []).length === 0 ? (
                  <tr><td colSpan={7} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No interactions found.</td></tr>
                ) : (interactions || []).slice(0, 20).map((interaction) => (
                  <tr
                    key={interaction.id}
                    onClick={() => setExpandedInteraction(expandedInteraction === interaction.id ? null : interaction.id)}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {interaction.created_at ? new Date(interaction.created_at || "").toLocaleString() : '—'}
                    </td>
                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{interaction.decoy_id}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">{interaction.source_ip}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{interaction.geo_location ? JSON.stringify(interaction.geo_location) : '—'}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{interaction.interaction_type}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{interaction.session_duration_seconds ?? 0}s</td>
                    <td className="px-6 py-4">
                      <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', threatColors[interaction.threat_assessment] || '')}>
                        {interaction.threat_assessment ? interaction.threat_assessment.charAt(0).toUpperCase() + interaction.threat_assessment.slice(1) : '—'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Campaigns Tab */}
      {activeTab === 'campaigns' && (
        <div className="space-y-6">
          <button
            onClick={() => setShowCreateCampaignModal(true)}
            className="px-4 py-2 rounded-lg bg-indigo-600 dark:bg-indigo-700 text-white hover:bg-indigo-700 dark:hover:bg-indigo-600 font-medium transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Create Campaign
          </button>

          {/* Campaigns Grid */}
          {campaignsLoading ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading campaigns...</div>
          ) : campaignsError ? (
            <LoadErrorBanner what="campaigns" error={campaignsError} />
          ) : (campaigns || []).length === 0 ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">No campaigns found. Create one to get started.</div>
          ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(campaigns || []).map((campaign) => {
              const effectivenessScore = campaign.effectiveness_score ?? 0;
              return (
              <div key={campaign.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white">{campaign.name}</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{campaign.objective}</p>
                  </div>
                  <span className={clsx('px-3 py-1 rounded-full text-xs font-medium whitespace-nowrap', campaignStatusColors[campaign.status] || '')}>
                    {campaign.status ? campaign.status.charAt(0).toUpperCase() + campaign.status.slice(1) : '—'}
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Decoys</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{(campaign.decoy_ids || []).length}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Interactions</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{campaign.total_interactions ?? 0}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Attackers</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{campaign.unique_attackers ?? 0}</p>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-xs font-semibold text-gray-900 dark:text-white">Effectiveness</p>
                    <p className="text-sm font-bold text-gray-900 dark:text-white">{effectivenessScore.toFixed(0)}%</p>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className={clsx(
                        'h-2 rounded-full transition-all',
                        effectivenessScore > 70 ? 'bg-green-500' : effectivenessScore > 50 ? 'bg-yellow-500' : 'bg-red-500'
                      )}
                      style={{ width: `${effectivenessScore}%` }}
                    />
                  </div>
                </div>

                <button
                  onClick={() => setSelectedCampaign(campaign)}
                  className="w-full px-4 py-2 rounded-lg bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-100 dark:hover:bg-indigo-900/40 font-medium text-sm transition-colors"
                >
                  View Details
                </button>
              </div>
              );
            })}
          </div>
          )}
        </div>
      )}
      {/* Deploy Decoy Modal */}
      {showDeployModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Deploy New Decoy</h2>
            <div className="mb-4"><ActionErrorBanner what="deploy the decoy" error={modalError} /></div>
            {deployedDecoy && (
              <div className="mb-4 rounded-lg border border-gray-200 dark:border-gray-700 p-3 text-sm">
                <p className="font-medium text-gray-900 dark:text-white">
                  {deployedDecoy.name}: <span className={clsx('px-2 py-0.5 rounded text-xs', statusColors[deployedDecoy.status] || '')}>{humanize(deployedDecoy.status)}</span>
                </p>
                <DecoyDeploymentNote decoy={deployedDecoy} />
              </div>
            )}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Name</label>
                <input type="text" placeholder="e.g., SSH Honeypot" value={deployName} onChange={(e) => setDeployName(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Type</label>
                <select value={deployType} onChange={(e) => setDeployType(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  {DECOY_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
                {DECOY_TYPES.find((t) => t.value === deployType)?.note && (
                  <p className="mt-1 text-xs text-yellow-700 dark:text-yellow-300">{DECOY_TYPES.find((t) => t.value === deployType)?.note}</p>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Target host (optional)</label>
                <input type="text" placeholder="hostname of a deception-capable agent" value={deployTarget} onChange={(e) => setDeployTarget(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
                <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Without one, the first active deception-capable agent is used; with none enrolled the decoy is a record only.</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Category</label>
                <select value={deployCategory} onChange={(e) => setDeployCategory(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="network">Network</option>
                  <option value="credential">Credential</option>
                  <option value="file">File</option>
                  <option value="dns">DNS</option>
                  <option value="email">Email</option>
                  <option value="cloud">Cloud</option>
                  <option value="active_directory">Active Directory</option>
                  <option value="database">Database</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Fidelity Level</label>
                <select value={deployFidelity} onChange={(e) => setDeployFidelity(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => { setShowDeployModal(false); setModalError(null); setDeployedDecoy(null); }} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">{deployedDecoy ? 'Close' : 'Cancel'}</button>
                <button
                  disabled={!deployName.trim()}
                  onClick={async () => {
                    setModalError(null);
                    setDeployedDecoy(null);
                    try {
                      const res = await api.post<Decoy>('/deception/decoys', {
                        name: deployName,
                        decoy_type: deployType,
                        category: deployCategory,
                        fidelity_level: deployFidelity,
                        deployment_target: deployTarget.trim() || undefined,
                      });
                      // The decoy's real state (deploying / not_deployed / record_only) and its reason.
                      setDeployedDecoy(res.data);
                      setDeployName(''); setDeployTarget('');
                      queryClient.invalidateQueries({ queryKey: ['decoys'] });
                      queryClient.invalidateQueries({ queryKey: ['deceptionDashboard'] });
                    } catch (error: unknown) {
                      setModalError(error);
                    }
                  }}
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition disabled:opacity-50"
                >
                  Deploy
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Generate Token Modal */}
      {showGenerateTokenModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Generate Honey Token</h2>
            <div className="mb-4"><ActionErrorBanner what="generate the token" error={modalError} /></div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Name</label>
                <input type="text" placeholder="e.g., Canary AWS Key" value={tokenName} onChange={(e) => setTokenName(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Token Type</label>
                {tokenTypesError ? (
                  <LoadErrorBanner what="the honeytoken types" error={tokenTypesError} />
                ) : (
                  <select value={selectedTokenType} onChange={(e) => setTokenType(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                    {supportedTokenTypes.map((t) => (
                      <option key={t.token_type} value={t.token_type}>{humanize(t.token_type)}</option>
                    ))}
                  </select>
                )}
                {supportedTokenTypes.find((t) => t.token_type === selectedTokenType)?.trigger_mechanism && (
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    Fires when: {supportedTokenTypes.find((t) => t.token_type === selectedTokenType)?.trigger_mechanism}
                  </p>
                )}
                {unsupportedTokenTypes.length > 0 && (
                  <details className="mt-2 text-xs text-gray-500 dark:text-gray-400">
                    <summary>Not available ({unsupportedTokenTypes.length})</summary>
                    <ul className="mt-1 list-disc pl-5 space-y-0.5">
                      {unsupportedTokenTypes.map((t) => (
                        <li key={t.token_type}><span className="font-medium">{humanize(t.token_type)}</span>: {t.reason || 'not supported'}</li>
                      ))}
                    </ul>
                  </details>
                )}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Planted at (optional)</label>
                <input type="text" placeholder="e.g., build-server:/home/ci/.aws/credentials" value={tokenLocation} onChange={(e) => setTokenLocation(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Context (optional)</label>
                <input type="text" value={tokenContext} onChange={(e) => setTokenContext(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => { setShowGenerateTokenModal(false); setModalError(null); }} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Cancel</button>
                <button
                  onClick={async () => {
                    setModalError(null);
                    try {
                      const res = await api.post<GeneratedToken>('/deception/tokens', {
                        name: tokenName.trim() || undefined,
                        token_type: selectedTokenType,
                        deployment_location: tokenLocation.trim() || undefined,
                        deployment_context: tokenContext.trim() || undefined,
                      });
                      // The value is returned once; show it on the page until dismissed.
                      setGeneratedToken(res.data);
                      setShowGenerateTokenModal(false);
                      setTokenName(''); setTokenType(''); setTokenLocation(''); setTokenContext('');
                      queryClient.invalidateQueries({ queryKey: ['honeyTokens'] });
                      queryClient.invalidateQueries({ queryKey: ['deceptionDashboard'] });
                    } catch (error: unknown) {
                      setModalError(error);
                    }
                  }}
                  disabled={!selectedTokenType}
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition disabled:opacity-50"
                >
                  Generate
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Create Campaign Modal */}
      {showCreateCampaignModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Create Campaign</h2>
            <div className="mb-4"><ActionErrorBanner what="save" error={modalError} /></div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Campaign Name</label>
                <input type="text" placeholder="e.g., Lateral Movement Detection" value={campaignName} onChange={(e) => setCampaignName(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Objective</label>
                <select value={campaignObjective} onChange={(e) => setCampaignObjective(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="general_detection">General Detection</option>
                  <option value="detect_lateral_movement">Detect Lateral Movement</option>
                  <option value="detect_insider">Detect Insider Threat</option>
                  <option value="detect_reconnaissance">Detect Reconnaissance</option>
                  <option value="detect_data_theft">Detect Data Theft</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Description</label>
                <textarea rows={3} placeholder="Describe the campaign..." value={campaignDescription} onChange={(e) => setCampaignDescription(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => { setShowCreateCampaignModal(false); setModalError(null); }} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Cancel</button>
                <button
                  onClick={async () => {
                    setModalError(null);
                    try {
                      await api.post('/deception/campaigns', { name: campaignName, objective: campaignObjective, description: campaignDescription });
                      setShowCreateCampaignModal(false);
                      setShowCreateCampaignModal(false);
                      setCampaignName(''); setCampaignObjective('general_detection'); setCampaignDescription('');
                      queryClient.invalidateQueries({ queryKey: ['campaigns'] });
                      queryClient.invalidateQueries({ queryKey: ['deceptionDashboard'] });
                    } catch (error: unknown) {
                      setModalError(error);
                    }
                  }}
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition"
                >
                  Create
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Campaign Detail Modal */}
      {selectedCampaign && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[500px] max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Campaign: {selectedCampaign.name}</h2>
            <div className="space-y-3 text-sm text-gray-900 dark:text-gray-100">
              <div><span className="font-medium">Objective:</span> {selectedCampaign.objective}</div>
              <div><span className="font-medium">Status:</span> {selectedCampaign.status}</div>
              <div><span className="font-medium">Decoys:</span> {(selectedCampaign.decoy_ids || []).length}</div>
              <div><span className="font-medium">Total Interactions:</span> {selectedCampaign.total_interactions ?? 0}</div>
              <div><span className="font-medium">Unique Attackers:</span> {selectedCampaign.unique_attackers ?? 0}</div>
              <div><span className="font-medium">Effectiveness:</span> {(selectedCampaign.effectiveness_score ?? 0).toFixed(0)}%</div>
            </div>
            <button onClick={() => setSelectedCampaign(null)} className="mt-6 w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Close</button>
          </div>
        </div>
      )}

      {/* Configure Decoy Modal */}
      {configDecoy && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Configure: {configDecoy.name}</h2>
            <div className="mb-4"><ActionErrorBanner what="save" error={modalError} /></div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Name</label>
                <input type="text" value={configName || configDecoy.name} onChange={(e) => setConfigName(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Fidelity Level</label>
                <select value={configFidelity || configDecoy.fidelity_level} onChange={(e) => setConfigFidelity(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => { setConfigDecoy(null); setModalError(null); setConfigName(''); setConfigFidelity('medium'); }} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Cancel</button>
                <button
                  onClick={async () => {
                    setModalError(null);
                    try {
                      await api.put(`/deception/decoys/${configDecoy.id}`, {
                        name: configName || configDecoy.name,
                        decoy_type: configDecoy.decoy_type,
                        category: configDecoy.category || 'network',
                        fidelity_level: configFidelity || configDecoy.fidelity_level,
                      });
                      setConfigDecoy(null);
                      setConfigDecoy(null);
                      setConfigName(''); setConfigFidelity('medium');
                      queryClient.invalidateQueries({ queryKey: ['decoys'] });
                    } catch (error: unknown) {
                      setModalError(error);
                    }
                  }}
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition"
                >
                  Save
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/** The decoy's deployment state and its reason (configuration.deployment / .listener / .removal). */
function DecoyDeploymentNote({ decoy }: { decoy: Decoy }) {
  const cfg = decoy.configuration || {};
  const dep = cfg.deployment || cfg.listener;
  const removal = cfg.removal;
  if (!dep && !removal) return null;
  const tone =
    decoy.status === 'failed'
      ? 'text-red-700 dark:text-red-300'
      : decoy.status === 'not_deployed' || decoy.status === 'record_only'
        ? 'text-yellow-800 dark:text-yellow-300'
        : 'text-gray-600 dark:text-gray-400';
  return (
    <div className={clsx('text-xs space-y-0.5', tone)}>
      {dep && (
        <p>
          <span className="font-medium">{humanize(dep.state)}</span>
          {dep.agent_hostname ? ` on ${dep.agent_hostname}` : ''}
          {dep.port ? ` (port ${dep.port})` : ''}
          {dep.note || dep.error ? `: ${dep.note || dep.error}` : ''}
        </p>
      )}
      {removal && (
        <p>
          Removal: <span className="font-medium">{humanize(removal.state)}</span>
          {removal.note || removal.error ? `: ${removal.note || removal.error}` : ''}
        </p>
      )}
    </div>
  );
}

/** A freshly generated honeytoken: the value is shown once (PySOAR keeps only its hash and a preview). */
function GeneratedTokenPanel({ token, onDismiss }: { token: GeneratedToken; onDismiss: () => void }) {
  const [copied, setCopied] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<unknown>(null);
  const copy = async (label: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      setCopyError(null);
    } catch (err) {
      setCopyError(err);
    }
  };
  const planting = Object.entries(token.planting || {});
  return (
    <div className="rounded-lg border border-yellow-300 dark:border-yellow-700 bg-yellow-50 dark:bg-yellow-900/20 p-4 space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="font-semibold text-gray-900 dark:text-white">Token {token.name} generated</p>
          <p className="text-sm text-yellow-800 dark:text-yellow-300">
            Copy the value now: it is shown once and cannot be retrieved again (PySOAR stores only its hash and a preview).
          </p>
        </div>
        <button onClick={onDismiss} className="text-sm text-gray-600 dark:text-gray-300 hover:underline">I have stored it</button>
      </div>
      <div>
        <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">Value</p>
        <div className="flex items-start gap-2">
          <pre className="flex-1 overflow-x-auto rounded bg-white dark:bg-gray-800 p-2 text-xs font-mono text-gray-900 dark:text-gray-100 whitespace-pre-wrap break-all">{token.token_value}</pre>
          <button
            onClick={() => copy('value', token.token_value)}
            className="px-2 py-1 rounded bg-indigo-600 text-white text-xs flex items-center gap-1"
          >
            <Copy className="w-3 h-3" />
            {copied === 'value' ? 'Copied' : 'Copy'}
          </button>
        </div>
      </div>
      {token.canary_url && (
        <div>
          <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">Canary URL (any request here records a trigger and raises an alert)</p>
          <div className="flex items-start gap-2">
            <code className="flex-1 break-all rounded bg-white dark:bg-gray-800 p-2 text-xs text-gray-900 dark:text-gray-100">{token.canary_url}</code>
            <button
              onClick={() => copy('url', token.canary_url)}
              className="px-2 py-1 rounded bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-100 text-xs flex items-center gap-1"
            >
              <Copy className="w-3 h-3" />
              {copied === 'url' ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      )}
      {token.trigger_mechanism && <p className="text-xs text-gray-700 dark:text-gray-300">Fires when: {token.trigger_mechanism}</p>}
      {planting.length > 0 && (
        <div>
          <p className="text-xs text-gray-600 dark:text-gray-400 mb-1">How to plant it</p>
          <dl className="text-xs space-y-1">
            {planting.map(([k, v]) => (
              <div key={k}>
                <dt className="font-medium text-gray-800 dark:text-gray-200">{humanize(k)}</dt>
                <dd className="font-mono whitespace-pre-wrap break-all text-gray-700 dark:text-gray-300">
                  {typeof v === 'string' ? v : JSON.stringify(v, null, 2)}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      )}
      <ActionErrorBanner what="copy to the clipboard" error={copyError} />
    </div>
  );
}

/** Canary triggers recorded for one token (GET /deception/tokens/{id}/triggers). */
function TokenTriggersPanel({ token, onClose }: { token: HoneyToken; onClose: () => void }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['honeyTokenTriggers', token.id],
    queryFn: async () => (await api.get<TokenTrigger[]>(`/deception/tokens/${token.id}/triggers`)).data,
  });
  return (
    <div className="rounded-lg border border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-gray-900 dark:text-white">Canary triggers: {token.name}</h3>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-600">✕</button>
      </div>
      {token.canary_path && (
        <p className="text-xs text-gray-600 dark:text-gray-400">Canary endpoint: <code>{token.canary_path}</code></p>
      )}
      <LoadErrorBanner what="the token's triggers" error={error} />
      {isLoading ? (
        <p className="text-sm text-gray-500">Loading triggers...</p>
      ) : !error && (data || []).length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">No triggers recorded: the canary has not been hit.</p>
      ) : (data || []).length > 0 ? (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs uppercase text-gray-500 dark:text-gray-400">
              <th className="py-1 pr-3">When</th>
              <th className="py-1 pr-3">Source IP</th>
              <th className="py-1 pr-3">Method</th>
              <th className="py-1 pr-3">User agent</th>
              <th className="py-1 pr-3">Value presented</th>
              <th className="py-1">Alert</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
            {(data || []).map((t) => (
              <tr key={t.id} className="text-gray-700 dark:text-gray-300">
                <td className="py-1 pr-3">{t.created_at ? new Date(t.created_at).toLocaleString() : 'Not available'}</td>
                <td className="py-1 pr-3 font-mono">{t.source_ip || 'Not available'}{t.forwarded_for ? ` (via ${t.forwarded_for})` : ''}</td>
                <td className="py-1 pr-3">{t.http_method}</td>
                <td className="py-1 pr-3 truncate max-w-xs" title={t.user_agent || undefined}>{t.user_agent || 'Not available'}</td>
                <td className="py-1 pr-3">{t.value_presented === null ? 'Not checked' : t.value_presented ? 'Yes' : 'No'}</td>
                <td className="py-1 font-mono text-xs">{t.alert_id || 'none'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </div>
  );
}
