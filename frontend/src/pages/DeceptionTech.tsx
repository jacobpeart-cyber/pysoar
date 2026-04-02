import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
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
} from 'lucide-react';
// recharts imports removed - timeline chart not available in dashboard response
import clsx from 'clsx';

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

interface Decoy {
  id: string;
  name: string;
  decoy_type: string;
  category: string;
  status: 'active' | 'disabled' | 'triggered';
  emulated_service?: string;
  interaction_count: number;
  last_interaction_at: string | null;
  fidelity_level: 'low' | 'medium' | 'high';
}

interface HoneyToken {
  id: string;
  name: string;
  token_type: 'aws_key' | 'api_key' | 'jwt' | 'password' | 'certificate';
  status: 'active' | 'triggered' | 'revoked';
  deployment_location: string;
  triggered_count: number;
  last_triggered?: string;
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

const decoyTypeColors = {
  honeypot: 'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400',
  honeytoken: 'bg-purple-50 dark:bg-purple-900/20 text-purple-600 dark:text-purple-400',
  honeyfile: 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400',
  honeycred: 'bg-orange-50 dark:bg-orange-900/20 text-orange-600 dark:text-orange-400',
};

const statusColors = {
  active: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300',
  disabled: 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300',
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

const statusDots = {
  active: 'bg-green-500',
  disabled: 'bg-gray-400',
  triggered: 'bg-red-500',
};

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

  // Generate Token form state
  const [tokenName, setTokenName] = useState('');
  const [tokenType, setTokenType] = useState('aws_key');

  // Create Campaign form state
  const [campaignName, setCampaignName] = useState('');
  const [campaignObjective, setCampaignObjective] = useState('general_detection');
  const [campaignDescription, setCampaignDescription] = useState('');

  // Configure Decoy form state
  const [configName, setConfigName] = useState('');
  const [configFidelity, setConfigFidelity] = useState('medium');

  // Modal error state
  const [modalError, setModalError] = useState<string | null>(null);

  const queryClient = useQueryClient();

  // Fetch deception dashboard
  const { data: dashboard, isLoading: dashboardLoading } = useQuery({
    queryKey: ['deceptionDashboard'],
    queryFn: async () => {
      const response = await api.get<DeceptionDashboard>('/deception/dashboard');
      return response.data;
    },
  });

  // Fetch decoys
  const { data: decoys, isLoading: decoysLoading } = useQuery({
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
  const { data: tokens, isLoading: tokensLoading } = useQuery({
    queryKey: ['honeyTokens'],
    queryFn: async () => {
      const response = await api.get<HoneyToken[]>('/deception/tokens');
      return response.data;
    },
  });

  // Fetch interactions
  const { data: interactions, isLoading: interactionsLoading } = useQuery({
    queryKey: ['interactions', threatLevelFilter],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (threatLevelFilter !== 'all') params.threat_level = threatLevelFilter;

      const response = await api.get<Interaction[]>('/deception/interactions', { params });
      return response.data;
    },
  });

  // Fetch campaigns
  const { data: campaigns, isLoading: campaignsLoading } = useQuery({
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
                onClick={() => setActiveTab(tab.id as any)}
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
          ) : (
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Active Decoys</p>
              <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-2">{dashboard?.stats?.active_decoys ?? 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Tokens Deployed</p>
              <p className="text-3xl font-bold text-purple-600 dark:text-purple-400 mt-2">{dashboard?.stats?.total_honeytokens ?? 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Interactions Today</p>
              <p className="text-3xl font-bold text-orange-600 dark:text-orange-400 mt-2">{dashboard?.stats?.interactions_today ?? 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Unique Attackers</p>
              <p className="text-3xl font-bold text-red-600 dark:text-red-400 mt-2">{dashboard?.stats?.unique_attackers_today ?? 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Active Campaigns</p>
              <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-2">{dashboard?.stats?.active_campaigns ?? 0}</p>
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
                {(dashboard?.recent_interactions || []).length === 0 ? (
                  <tr><td colSpan={5} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No recent interactions</td></tr>
                ) : (dashboard?.recent_interactions || []).slice(0, 10).map((interaction) => (
                  <tr key={interaction.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {interaction.created_at ? new Date(interaction.created_at).toLocaleString() : '—'}
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
              <option value="honeypot">Honeypot</option>
              <option value="honeytoken">Honeytoken</option>
              <option value="honeyfile">Honeyfile</option>
              <option value="honeycred">Honeycred</option>
            </select>
            <select
              value={decoyStatusFilter}
              onChange={(e) => setDecoyStatusFilter(e.target.value)}
              className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="all">All Status</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
              <option value="triggered">Triggered</option>
            </select>
          </div>

          {/* Decoys Grid */}
          {decoysLoading ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">Loading decoys...</div>
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
                      <span className="text-xs text-gray-600 dark:text-gray-400 capitalize">{decoy.status}</span>
                    </div>
                  </div>
                  <span className={clsx('px-2 py-1 rounded text-xs font-medium', decoyTypeColors[decoy.decoy_type as keyof typeof decoyTypeColors] || 'bg-gray-100 text-gray-600')}>
                    {decoy.decoy_type}
                  </span>
                </div>

                {decoy.emulated_service && (
                  <p className="text-sm text-gray-600 dark:text-gray-400">{decoy.emulated_service}</p>
                )}

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
                  Last: {decoy.last_interaction_at ? new Date(decoy.last_interaction_at).toLocaleDateString() : 'Never'}
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
                        try {
                          await api.post(`/deception/decoys/${decoy.id}/disable`);
                          alert('Decoy disabled: ' + decoy.name);
                          queryClient.invalidateQueries({ queryKey: ['decoys'] });
                        } catch (error: any) {
                          alert('Failed to disable decoy: ' + (error?.response?.data?.detail || error.message));
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
            onClick={() => setShowGenerateTokenModal(true)}
            className="px-4 py-2 rounded-lg bg-indigo-600 dark:bg-indigo-700 text-white hover:bg-indigo-700 dark:hover:bg-indigo-600 font-medium transition-colors flex items-center gap-2"
          >
            <Plus className="w-4 h-4" />
            Generate Token
          </button>

          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Name</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Location</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Triggered</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Last Triggered</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {tokensLoading ? (
                  <tr><td colSpan={7} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">Loading tokens...</td></tr>
                ) : (tokens || []).length === 0 ? (
                  <tr><td colSpan={7} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No honey tokens found. Generate one to get started.</td></tr>
                ) : (tokens || []).slice(0, 15).map((token) => (
                  <tr key={token.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{token.name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 capitalize">{token.token_type}</td>
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
                      {token.last_triggered ? new Date(token.last_triggered).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-6 py-4">
                      <button
                        onClick={async () => {
                          try {
                            await api.post(`/deception/tokens/${token.id}/check`);
                            alert('Token check initiated for: ' + token.name);
                          } catch (error: any) {
                            alert('Failed to check token: ' + (error?.response?.data?.detail || error.message));
                          }
                        }}
                        className="text-xs px-2 py-1 rounded bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/40 transition-colors font-medium"
                      >
                        Check
                      </button>
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
                ) : (interactions || []).length === 0 ? (
                  <tr><td colSpan={7} className="px-6 py-8 text-center text-gray-500 dark:text-gray-400">No interactions found.</td></tr>
                ) : (interactions || []).slice(0, 20).map((interaction) => (
                  <tr
                    key={interaction.id}
                    onClick={() => setExpandedInteraction(expandedInteraction === interaction.id ? null : interaction.id)}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {interaction.created_at ? new Date(interaction.created_at).toLocaleString() : '—'}
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
            {modalError && <div className="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 text-sm">{modalError}</div>}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Name</label>
                <input type="text" placeholder="e.g., SSH Honeypot" value={deployName} onChange={(e) => setDeployName(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Type</label>
                <select value={deployType} onChange={(e) => setDeployType(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="honeypot">Honeypot</option>
                  <option value="honeytoken">Honeytoken</option>
                  <option value="honeyfile">Honeyfile</option>
                  <option value="honeycred">Honeycred</option>
                </select>
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
                <button onClick={() => { setShowDeployModal(false); setModalError(null); }} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Cancel</button>
                <button
                  onClick={async () => {
                    setModalError(null);
                    try {
                      await api.post('/deception/decoys', { name: deployName, decoy_type: deployType, category: deployCategory, fidelity_level: deployFidelity, organization_id: 'default' });
                      alert('Decoy deployed successfully.');
                      setShowDeployModal(false);
                      setDeployName(''); setDeployType('honeypot'); setDeployCategory('network'); setDeployFidelity('medium');
                      queryClient.invalidateQueries({ queryKey: ['decoys'] });
                      queryClient.invalidateQueries({ queryKey: ['deceptionDashboard'] });
                    } catch (error: any) {
                      setModalError(error?.response?.data?.detail || error.message || 'Failed to deploy decoy');
                    }
                  }}
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition"
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
            {modalError && <div className="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 text-sm">{modalError}</div>}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Name</label>
                <input type="text" placeholder="e.g., Canary AWS Key" value={tokenName} onChange={(e) => setTokenName(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Token Type</label>
                <select value={tokenType} onChange={(e) => setTokenType(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="aws_key">AWS Key</option>
                  <option value="api_key">API Key</option>
                  <option value="jwt_token">JWT Token</option>
                  <option value="database_cred">Database Credential</option>
                  <option value="ssh_key">SSH Key</option>
                  <option value="certificate">Certificate</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => { setShowGenerateTokenModal(false); setModalError(null); }} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Cancel</button>
                <button
                  onClick={async () => {
                    setModalError(null);
                    try {
                      await api.post('/deception/tokens', { token_type: tokenType, organization_id: 'default' });
                      alert('Token generated successfully.');
                      setShowGenerateTokenModal(false);
                      setTokenName(''); setTokenType('aws_key');
                      queryClient.invalidateQueries({ queryKey: ['honeyTokens'] });
                      queryClient.invalidateQueries({ queryKey: ['deceptionDashboard'] });
                    } catch (error: any) {
                      setModalError(error?.response?.data?.detail || error.message || 'Failed to generate token');
                    }
                  }}
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition"
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
            {modalError && <div className="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 text-sm">{modalError}</div>}
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
                      await api.post('/deception/campaigns', { name: campaignName, objective: campaignObjective, description: campaignDescription, organization_id: 'default', created_by: 'current_user' });
                      alert('Campaign created successfully.');
                      setShowCreateCampaignModal(false);
                      setCampaignName(''); setCampaignObjective('general_detection'); setCampaignDescription('');
                      queryClient.invalidateQueries({ queryKey: ['campaigns'] });
                      queryClient.invalidateQueries({ queryKey: ['deceptionDashboard'] });
                    } catch (error: any) {
                      setModalError(error?.response?.data?.detail || error.message || 'Failed to create campaign');
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
            {modalError && <div className="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 text-sm">{modalError}</div>}
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
                        organization_id: 'default',
                      });
                      alert('Decoy configuration saved.');
                      setConfigDecoy(null);
                      setConfigName(''); setConfigFidelity('medium');
                      queryClient.invalidateQueries({ queryKey: ['decoys'] });
                    } catch (error: any) {
                      setModalError(error?.response?.data?.detail || error.message || 'Failed to update decoy');
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
