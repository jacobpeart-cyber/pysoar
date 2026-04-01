import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
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
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, BarChart, Bar } from 'recharts';
import clsx from 'clsx';

interface DeceptionDashboard {
  active_decoys: number;
  honeytokens_deployed: number;
  interactions_today: number;
  unique_attackers: number;
  campaign_effectiveness: number;
  interaction_timeline: TimelinePoint[];
  recent_interactions: Interaction[];
}

interface Decoy {
  id: string;
  name: string;
  type: 'honeypot' | 'honeytoken' | 'honeyfile' | 'honeycred';
  status: 'active' | 'disabled' | 'triggered';
  service?: string;
  interactions_count: number;
  last_interaction: string;
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
  timestamp: string;
  decoy_name: string;
  source_ip: string;
  geo?: string;
  interaction_type: string;
  protocol: string;
  duration_seconds: number;
  threat_assessment: 'low' | 'medium' | 'high' | 'critical';
  commands_captured?: string;
  mitre_techniques?: string[];
  credentials_captured?: boolean;
}

interface Campaign {
  id: string;
  name: string;
  objective: string;
  status: 'draft' | 'active' | 'paused' | 'completed';
  active_decoys_count: number;
  total_interactions: number;
  unique_attackers: number;
  effectiveness_score: number;
}

interface TimelinePoint {
  date: string;
  interactions: number;
}

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
  const [timeRangeFilter, setTimeRangeFilter] = useState('7d');
  const [showDeployModal, setShowDeployModal] = useState(false);
  const [showGenerateTokenModal, setShowGenerateTokenModal] = useState(false);
  const [showCreateCampaignModal, setShowCreateCampaignModal] = useState(false);
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);
  const [configDecoy, setConfigDecoy] = useState<Decoy | null>(null);

  // Fetch deception dashboard
  const { data: dashboard } = useQuery({
    queryKey: ['deceptionDashboard'],
    queryFn: async () => {
      const response = await api.get<DeceptionDashboard>('/deception/dashboard');
      return response.data;
    },
  });

  // Fetch decoys
  const { data: decoys } = useQuery({
    queryKey: ['decoys', decoyTypeFilter, decoyStatusFilter],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (decoyTypeFilter !== 'all') params.type = decoyTypeFilter;
      if (decoyStatusFilter !== 'all') params.status = decoyStatusFilter;

      const response = await api.get<Decoy[]>('/deception/decoys', { params });
      return response.data;
    },
  });

  // Fetch honey tokens
  const { data: tokens } = useQuery({
    queryKey: ['honeyTokens'],
    queryFn: async () => {
      const response = await api.get<HoneyToken[]>('/deception/tokens');
      return response.data;
    },
  });

  // Fetch interactions
  const { data: interactions } = useQuery({
    queryKey: ['interactions', threatLevelFilter, timeRangeFilter],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (threatLevelFilter !== 'all') params.threat_level = threatLevelFilter;
      if (timeRangeFilter !== '7d') params.time_range = timeRangeFilter;

      const response = await api.get<Interaction[]>('/deception/interactions', { params });
      return response.data;
    },
  });

  // Fetch campaigns
  const { data: campaigns } = useQuery({
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
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Active Decoys</p>
              <p className="text-3xl font-bold text-green-600 dark:text-green-400 mt-2">{dashboard?.active_decoys || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Tokens Deployed</p>
              <p className="text-3xl font-bold text-purple-600 dark:text-purple-400 mt-2">{dashboard?.honeytokens_deployed || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Interactions Today</p>
              <p className="text-3xl font-bold text-orange-600 dark:text-orange-400 mt-2">{dashboard?.interactions_today || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Unique Attackers</p>
              <p className="text-3xl font-bold text-red-600 dark:text-red-400 mt-2">{dashboard?.unique_attackers || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Effectiveness</p>
              <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-2">{dashboard?.campaign_effectiveness?.toFixed(0) || 0}%</p>
            </div>
          </div>

          {/* Interaction Timeline */}
          {dashboard?.interaction_timeline && dashboard.interaction_timeline.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Interaction Timeline (Last 7 Days)</h3>
              <ResponsiveContainer width="100%" height={300}>
                <AreaChart data={dashboard.interaction_timeline}>
                  <defs>
                    <linearGradient id="colorInteractions" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#4f46e5" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#4f46e5" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                  <XAxis dataKey="date" stroke="#6b7280" />
                  <YAxis stroke="#6b7280" />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1f2937',
                      border: 'none',
                      borderRadius: '0.5rem',
                      color: '#fff',
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="interactions"
                    stroke="#4f46e5"
                    fillOpacity={1}
                    fill="url(#colorInteractions)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

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
                {dashboard?.recent_interactions?.slice(0, 10).map((interaction) => (
                  <tr key={interaction.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {new Date(interaction.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{interaction.decoy_name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">{interaction.source_ip}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{interaction.interaction_type}</td>
                    <td className="px-6 py-4">
                      <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', threatColors[interaction.threat_assessment])}>
                        {interaction.threat_assessment.charAt(0).toUpperCase() + interaction.threat_assessment.slice(1)}
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
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {decoys?.map((decoy) => (
              <div key={decoy.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white">{decoy.name}</h3>
                    <div className="flex items-center gap-2 mt-1">
                      <div className={clsx('w-2 h-2 rounded-full', statusDots[decoy.status])} />
                      <span className="text-xs text-gray-600 dark:text-gray-400 capitalize">{decoy.status}</span>
                    </div>
                  </div>
                  <span className={clsx('px-2 py-1 rounded text-xs font-medium', decoyTypeColors[decoy.type])}>
                    {decoy.type}
                  </span>
                </div>

                {decoy.service && (
                  <p className="text-sm text-gray-600 dark:text-gray-400">{decoy.service}</p>
                )}

                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Interactions</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{decoy.interactions_count}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Fidelity</p>
                    <p className="text-sm font-bold text-gray-900 dark:text-white mt-1 capitalize">{decoy.fidelity_level}</p>
                  </div>
                </div>

                <p className="text-xs text-gray-600 dark:text-gray-400">
                  Last: {new Date(decoy.last_interaction).toLocaleDateString()}
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
                          await api.delete(`/deception/decoys/${decoy.id}`);
                          alert('Decoy disabled: ' + decoy.name);
                        } catch (error) {
                          console.error('Error disabling decoy:', error);
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
                {tokens?.slice(0, 15).map((token) => (
                  <tr key={token.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{token.name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 capitalize">{token.token_type}</td>
                    <td className="px-6 py-4">
                      <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', statusColors[token.status])}>
                        {token.status.charAt(0).toUpperCase() + token.status.slice(1)}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{token.deployment_location}</td>
                    <td className="px-6 py-4">
                      <p className="font-semibold text-gray-900 dark:text-white">{token.triggered_count}</p>
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
                          } catch (error) {
                            console.error('Error checking token:', error);
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
            <select
              value={timeRangeFilter}
              onChange={(e) => setTimeRangeFilter(e.target.value)}
              className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
              <option value="90d">Last 90 Days</option>
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
                {interactions?.slice(0, 20).map((interaction) => (
                  <tr
                    key={interaction.id}
                    onClick={() => setExpandedInteraction(expandedInteraction === interaction.id ? null : interaction.id)}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {new Date(interaction.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{interaction.decoy_name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 font-mono">{interaction.source_ip}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{interaction.geo || '—'}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{interaction.interaction_type}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{interaction.duration_seconds}s</td>
                    <td className="px-6 py-4">
                      <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', threatColors[interaction.threat_assessment])}>
                        {interaction.threat_assessment.charAt(0).toUpperCase() + interaction.threat_assessment.slice(1)}
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
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {campaigns?.map((campaign) => (
              <div key={campaign.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <h3 className="font-semibold text-gray-900 dark:text-white">{campaign.name}</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{campaign.objective}</p>
                  </div>
                  <span className={clsx('px-3 py-1 rounded-full text-xs font-medium whitespace-nowrap', campaignStatusColors[campaign.status])}>
                    {campaign.status.charAt(0).toUpperCase() + campaign.status.slice(1)}
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Decoys</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{campaign.active_decoys_count}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Interactions</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{campaign.total_interactions}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Attackers</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{campaign.unique_attackers}</p>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-xs font-semibold text-gray-900 dark:text-white">Effectiveness</p>
                    <p className="text-sm font-bold text-gray-900 dark:text-white">{campaign.effectiveness_score}%</p>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className={clsx(
                        'h-2 rounded-full transition-all',
                        campaign.effectiveness_score > 70 ? 'bg-green-500' : campaign.effectiveness_score > 50 ? 'bg-yellow-500' : 'bg-red-500'
                      )}
                      style={{ width: `${campaign.effectiveness_score}%` }}
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
            ))}
          </div>
        </div>
      )}
      {/* Deploy Decoy Modal */}
      {showDeployModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Deploy New Decoy</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Name</label>
                <input type="text" placeholder="e.g., SSH Honeypot" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Type</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="honeypot">Honeypot</option>
                  <option value="honeytoken">Honeytoken</option>
                  <option value="honeyfile">Honeyfile</option>
                  <option value="honeycred">Honeycred</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Fidelity Level</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => setShowDeployModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Cancel</button>
                <button
                  onClick={async () => {
                    try {
                      await api.post('/deception/decoys', { name: 'New Decoy', type: 'honeypot' });
                      alert('Decoy deployed successfully.');
                      setShowDeployModal(false);
                    } catch (error) {
                      console.error('Error deploying decoy:', error);
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
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Name</label>
                <input type="text" placeholder="e.g., Canary AWS Key" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Token Type</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="aws_key">AWS Key</option>
                  <option value="api_key">API Key</option>
                  <option value="jwt">JWT</option>
                  <option value="password">Password</option>
                  <option value="certificate">Certificate</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => setShowGenerateTokenModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Cancel</button>
                <button
                  onClick={async () => {
                    try {
                      await api.post('/deception/tokens', { name: 'New Token', type: 'aws_key' });
                      alert('Token generated successfully.');
                      setShowGenerateTokenModal(false);
                    } catch (error) {
                      console.error('Error generating token:', error);
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
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Campaign Name</label>
                <input type="text" placeholder="e.g., Lateral Movement Detection" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Objective</label>
                <textarea rows={3} placeholder="Describe the campaign objective..." className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => setShowCreateCampaignModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Cancel</button>
                <button
                  onClick={async () => {
                    try {
                      await api.post('/deception/campaigns', { name: 'New Campaign', objective: 'Detection' });
                      alert('Campaign created successfully.');
                      setShowCreateCampaignModal(false);
                    } catch (error) {
                      console.error('Error creating campaign:', error);
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
              <div><span className="font-medium">Active Decoys:</span> {selectedCampaign.active_decoys_count}</div>
              <div><span className="font-medium">Total Interactions:</span> {selectedCampaign.total_interactions}</div>
              <div><span className="font-medium">Unique Attackers:</span> {selectedCampaign.unique_attackers}</div>
              <div><span className="font-medium">Effectiveness:</span> {selectedCampaign.effectiveness_score}%</div>
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
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Name</label>
                <input type="text" defaultValue={configDecoy.name} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-900 dark:text-white mb-1">Fidelity Level</label>
                <select defaultValue={configDecoy.fidelity_level} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => setConfigDecoy(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition text-gray-900 dark:text-white">Cancel</button>
                <button onClick={() => { alert('Decoy configuration saved.'); setConfigDecoy(null); }} className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition">Save</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
