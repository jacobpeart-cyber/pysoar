import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import {
  Users,
  TrendingUp,
  AlertTriangle,
  Eye,
  Activity,
  Search,
  Filter,
  Clock,
  Zap,
  BarChart3,
} from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend, BarChart, Bar } from 'recharts';
import clsx from 'clsx';

interface UEBADashboard {
  entities_monitored: number;
  high_risk_entities: number;
  alerts_24h: number;
  avg_risk_score: number;
  top_entities: Entity[];
  risk_trend: TrendPoint[];
  heatmap_data: HeatmapData;
}

interface Entity {
  id: string;
  name: string;
  type: 'user' | 'host' | 'service_account';
  department?: string;
  risk_score: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  anomaly_count_30d: number;
  last_activity: string;
  is_watched: boolean;
  behavior_timeline?: BehaviorEvent[];
  risk_factors?: string[];
}

interface RiskAlert {
  id: string;
  timestamp: string;
  entity_name: string;
  entity_type: string;
  alert_type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  status: 'new' | 'investigating' | 'confirmed' | 'dismissed';
}

interface PeerGroup {
  id: string;
  name: string;
  type: string;
  member_count: number;
  avg_risk: number;
  highest_risk_member: string;
  highest_risk_score: number;
}

interface BehaviorEvent {
  timestamp: string;
  event_type: string;
  description: string;
  is_anomaly: boolean;
  severity?: string;
}

interface TrendPoint {
  date: string;
  risk_score: number;
}

interface HeatmapData {
  entity_types: string[];
  risk_levels: string[];
  matrix: Record<string, Record<string, number>>;
}

const riskLevelColors = {
  critical: 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20',
  high: 'text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-900/20',
  medium: 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20',
  low: 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20',
};

const severityColors = {
  critical: 'text-red-600 dark:text-red-400',
  high: 'text-orange-600 dark:text-orange-400',
  medium: 'text-yellow-600 dark:text-yellow-400',
  low: 'text-blue-600 dark:text-blue-400',
};

const statusBadgeColors = {
  new: 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400',
  investigating: 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-600 dark:text-yellow-400',
  confirmed: 'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400',
  dismissed: 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400',
};

const eventTypeColors = {
  auth: 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300',
  data_access: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300',
  network: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300',
  privilege: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
};

export default function UEBADashboard() {
  const [activeTab, setActiveTab] = useState<'overview' | 'entities' | 'alerts' | 'peers' | 'timeline'>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [entityTypeFilter, setEntityTypeFilter] = useState('all');
  const [riskLevelFilter, setRiskLevelFilter] = useState('all');
  const [selectedEntity, setSelectedEntity] = useState<Entity | null>(null);
  const [expandedEntity, setExpandedEntity] = useState<string | null>(null);

  // Fetch UEBA dashboard
  const { data: dashboard } = useQuery({
    queryKey: ['uebaDashboard'],
    queryFn: async () => {
      const response = await api.get<UEBADashboard>('/ueba/dashboard');
      return response.data;
    },
  });

  // Fetch entities
  const { data: entities } = useQuery({
    queryKey: ['ueba-entities', entityTypeFilter, riskLevelFilter, searchQuery],
    queryFn: async () => {
      const params: Record<string, any> = {};
      if (entityTypeFilter !== 'all') params.type = entityTypeFilter;
      if (riskLevelFilter !== 'all') params.risk_level = riskLevelFilter;
      if (searchQuery) params.search = searchQuery;

      const response = await api.get<Entity[]>('/ueba/entities', { params });
      return response.data;
    },
  });

  // Fetch risk alerts
  const { data: alerts } = useQuery({
    queryKey: ['ueba-alerts'],
    queryFn: async () => {
      const response = await api.get<RiskAlert[]>('/ueba/alerts');
      return response.data;
    },
  });

  // Fetch peer groups
  const { data: peerGroups } = useQuery({
    queryKey: ['ueba-peer-groups'],
    queryFn: async () => {
      const response = await api.get<PeerGroup[]>('/ueba/peer-groups');
      return response.data;
    },
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">User & Entity Behavior Analytics</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">Monitor behavioral anomalies and risk factors</p>
        </div>
        <Users className="w-10 h-10 text-purple-600 dark:text-purple-400" />
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <div className="flex space-x-8">
          {[
            { id: 'overview', label: 'Risk Overview', icon: TrendingUp },
            { id: 'entities', label: 'Entities', icon: Users },
            { id: 'alerts', label: 'Risk Alerts', icon: AlertTriangle },
            { id: 'peers', label: 'Peer Groups', icon: BarChart3 },
            { id: 'timeline', label: 'Behavior Timeline', icon: Clock },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={clsx(
                  'px-4 py-3 border-b-2 font-medium text-sm transition-colors flex items-center gap-2',
                  activeTab === tab.id
                    ? 'border-purple-600 text-purple-600 dark:text-purple-400'
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

      {/* Risk Overview */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Entities Monitored</p>
              <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">{dashboard?.entities_monitored || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">High-Risk Entities</p>
              <p className="text-3xl font-bold text-red-600 dark:text-red-400 mt-2">{dashboard?.high_risk_entities || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Alerts (24h)</p>
              <p className="text-3xl font-bold text-orange-600 dark:text-orange-400 mt-2">{dashboard?.alerts_24h || 0}</p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <p className="text-gray-600 dark:text-gray-400 text-sm">Avg Risk Score</p>
              <p className="text-3xl font-bold text-blue-600 dark:text-blue-400 mt-2">{dashboard?.avg_risk_score?.toFixed(2) || 0}</p>
            </div>
          </div>

          {/* Risk Trend Chart */}
          {dashboard?.risk_trend && dashboard.risk_trend.length > 0 && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Risk Trend (7 Days)</h3>
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={dashboard.risk_trend}>
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
                  <Line
                    type="monotone"
                    dataKey="risk_score"
                    stroke="#9333ea"
                    strokeWidth={2}
                    dot={{ fill: '#9333ea', r: 4 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Top Entities */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Top 10 Highest Risk Entities</h3>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Entity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Risk Score</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Level</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Anomalies (30d)</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Last Activity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {dashboard?.top_entities?.slice(0, 10).map((entity) => (
                  <tr key={entity.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                    <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{entity.name}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 capitalize">{entity.type}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={clsx(
                              'h-2 rounded-full',
                              entity.risk_score > 0.7 ? 'bg-red-500' : entity.risk_score > 0.5 ? 'bg-orange-500' : 'bg-yellow-500'
                            )}
                            style={{ width: `${entity.risk_score * 100}%` }}
                          />
                        </div>
                        <span className="text-sm font-medium text-gray-900 dark:text-white">{(entity.risk_score * 100).toFixed(0)}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', riskLevelColors[entity.risk_level])}>
                        {entity.risk_level.charAt(0).toUpperCase() + entity.risk_level.slice(1)}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{entity.anomaly_count_30d}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {new Date(entity.last_activity).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Entities Tab */}
      {activeTab === 'entities' && (
        <div className="space-y-6">
          {/* Search and Filters */}
          <div className="flex flex-col md:flex-row gap-4">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search entities..."
                className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-purple-500"
              />
            </div>
            <select
              value={entityTypeFilter}
              onChange={(e) => setEntityTypeFilter(e.target.value)}
              className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
            >
              <option value="all">All Types</option>
              <option value="user">User</option>
              <option value="host">Host</option>
              <option value="service_account">Service Account</option>
            </select>
            <select
              value={riskLevelFilter}
              onChange={(e) => setRiskLevelFilter(e.target.value)}
              className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
            >
              <option value="all">All Risk Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Entities Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Entity</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Department</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Risk Score</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Anomalies</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Watched</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Last Activity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {entities?.slice(0, 15).map((entity) => (
                  <tr
                    key={entity.id}
                    onClick={() => setExpandedEntity(expandedEntity === entity.id ? null : entity.id)}
                    className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors cursor-pointer"
                  >
                    <td className="px-6 py-4">
                      <p className="font-medium text-gray-900 dark:text-white">{entity.name}</p>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 capitalize">{entity.type}</td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{entity.department || '—'}</td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={clsx(
                              'h-2 rounded-full',
                              entity.risk_score > 0.7 ? 'bg-red-500' : entity.risk_score > 0.5 ? 'bg-orange-500' : 'bg-green-500'
                            )}
                            style={{ width: `${entity.risk_score * 100}%` }}
                          />
                        </div>
                        <span className="text-sm font-medium text-gray-900 dark:text-white">{(entity.risk_score * 100).toFixed(0)}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{entity.anomaly_count_30d}</td>
                    <td className="px-6 py-4">
                      {entity.is_watched && (
                        <Eye className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                      )}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                      {new Date(entity.last_activity).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Risk Alerts Tab */}
      {activeTab === 'alerts' && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Time</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Entity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Alert Type</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Severity</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Description</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {alerts?.slice(0, 20).map((alert) => (
                <tr key={alert.id} className="hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                    {new Date(alert.timestamp).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 font-medium text-gray-900 dark:text-white">{alert.entity_name}</td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{alert.alert_type}</td>
                  <td className="px-6 py-4">
                    <span className={clsx('text-sm font-medium', severityColors[alert.severity])}>
                      {alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1)}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400 truncate">{alert.description}</td>
                  <td className="px-6 py-4">
                    <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', statusBadgeColors[alert.status])}>
                      {alert.status.charAt(0).toUpperCase() + alert.status.slice(1)}
                    </span>
                  </td>
                  <td className="px-6 py-4 flex gap-2">
                    <button className="text-xs px-2 py-1 rounded bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-900/40 transition-colors">
                      Investigate
                    </button>
                    <button className="text-xs px-2 py-1 rounded bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40 transition-colors">
                      Escalate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Peer Groups Tab */}
      {activeTab === 'peers' && (
        <div className="space-y-6">
          <button className="px-4 py-2 rounded-lg bg-purple-600 dark:bg-purple-700 text-white hover:bg-purple-700 dark:hover:bg-purple-600 font-medium transition-colors">
            Auto-Cluster
          </button>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {peerGroups?.map((group) => (
              <div key={group.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 space-y-4">
                <div>
                  <h3 className="font-semibold text-gray-900 dark:text-white">{group.name}</h3>
                  <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">{group.type}</p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Members</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{group.member_count}</p>
                  </div>
                  <div className="p-3 rounded-lg bg-gray-50 dark:bg-gray-700">
                    <p className="text-xs text-gray-600 dark:text-gray-400">Avg Risk</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white mt-1">{(group.avg_risk * 100).toFixed(0)}</p>
                  </div>
                </div>

                <div className="pt-4 border-t border-gray-200 dark:border-gray-700">
                  <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Highest Risk Member</p>
                  <p className="font-medium text-gray-900 dark:text-white">{group.highest_risk_member}</p>
                  <div className="mt-2 w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className="bg-red-500 h-2 rounded-full"
                      style={{ width: `${group.highest_risk_score * 100}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Behavior Timeline Tab */}
      {activeTab === 'timeline' && (
        <div className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-gray-900 dark:text-white mb-2">Select Entity</label>
            <select
              onChange={(e) => {
                const entity = entities?.find(e => e.id === e.target.value);
                setSelectedEntity(entity || null);
              }}
              className="w-full md:w-64 px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-500"
            >
              <option value="">Choose an entity...</option>
              {entities?.map((entity) => (
                <option key={entity.id} value={entity.id}>{entity.name}</option>
              ))}
            </select>
          </div>

          {selectedEntity?.behavior_timeline && selectedEntity.behavior_timeline.length > 0 && (
            <div className="space-y-4">
              {selectedEntity.behavior_timeline.map((event, idx) => {
                const eventColor = eventTypeColors[event.event_type as keyof typeof eventTypeColors] || 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300';
                return (
                  <div key={idx} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 flex gap-4">
                    <div className="flex-shrink-0">
                      <div className={clsx('w-10 h-10 rounded-full flex items-center justify-center font-semibold text-xs', eventColor)}>
                        {event.event_type.charAt(0).toUpperCase()}
                      </div>
                    </div>
                    <div className="flex-1">
                      <div className="flex items-start justify-between">
                        <div>
                          <p className="font-medium text-gray-900 dark:text-white">{event.description}</p>
                          <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{new Date(event.timestamp).toLocaleString()}</p>
                        </div>
                        {event.is_anomaly && (
                          <span className="px-2 py-1 rounded-full text-xs font-medium bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400">
                            Anomaly
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
