import { useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';
import {
  Activity,
  AlertTriangle,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  ChevronLeft,
  Play,
  Plus,
  ToggleLeft,
  ToggleRight,
  Zap,
  Server,
  Clock,
  TrendingUp,
  Eye,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
  info: 'bg-gray-100 text-gray-700 border-gray-200',
};

const ruleStatusColors = {
  enabled: 'text-green-600 bg-green-50',
  disabled: 'text-gray-600 bg-gray-50',
};

const sourceStatusColors = {
  connected: 'bg-green-100 text-green-700',
  error: 'bg-red-100 text-red-700',
  disabled: 'bg-gray-100 text-gray-700',
};

const chartColors = ['#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6', '#ec4899'];

export default function SIEMDashboard() {
  const [activeTab, setActiveTab] = useState<'overview' | 'search' | 'rules' | 'sources' | 'correlation'>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [timeRange, setTimeRange] = useState('24h');
  const [sourceTypeFilter, setSourceTypeFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchPage, setSearchPage] = useState(1);
  const [selectedLogDetail, setSelectedLogDetail] = useState<any>(null);
  const [ruleStatusFilter, setRuleStatusFilter] = useState('');
  const [selectedRule, setSelectedRule] = useState<any>(null);
  const [selectedSource, setSelectedSource] = useState<any>(null);
  const [sourceModalMode, setSourceModalMode] = useState<'view' | 'config' | 'add'>('view');
  const [newSourceForm, setNewSourceForm] = useState({ name: '', description: '', source_type: 'syslog' });

  // Fetch dashboard stats
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['siem-stats'],
    queryFn: async () => {
      const response = await api.get('/siem/logs/stats');
      return response.data;
    },
  });

  // Fetch logs for search
  const { data: logsData, isLoading: logsLoading } = useQuery({
    queryKey: ['siem-logs', searchQuery, timeRange, sourceTypeFilter, severityFilter, searchPage],
    queryFn: async () => {
      const response = await api.post('/siem/logs/search', {
        query: searchQuery || undefined,
        source_types: sourceTypeFilter ? [sourceTypeFilter] : undefined,
        severities: severityFilter ? [severityFilter] : undefined,
        page: searchPage,
        size: 15,
      });
      return response.data;
    },
    enabled: activeTab === 'search',
  });

  // Fetch detection rules
  const { data: rulesData, isLoading: rulesLoading } = useQuery({
    queryKey: ['siem-rules'],
    queryFn: async () => {
      const response = await api.get('/siem/rules');
      return response.data;
    },
    enabled: activeTab === 'rules',
  });

  // Fetch data sources
  const { data: sourcesData, isLoading: sourcesLoading } = useQuery({
    queryKey: ['siem-sources'],
    queryFn: async () => {
      const response = await api.get('/siem/sources');
      return response.data;
    },
    enabled: activeTab === 'sources',
  });

  // Fetch correlations
  const { data: correlationsData, isLoading: correlationsLoading } = useQuery({
    queryKey: ['siem-correlations'],
    queryFn: async () => {
      const response = await api.get('/siem/correlations');
      return response.data;
    },
    enabled: activeTab === 'correlation',
  });

  // Toggle rule mutation
  const toggleRuleMutation = useMutation({
    mutationFn: async ({ ruleId, enabled }: { ruleId: string; enabled: boolean }) => {
      const response = await api.put(`/siem/rules/${ruleId}`, { enabled });
      return response.data;
    },
  });

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Activity },
    { id: 'search', label: 'Log Search', icon: Search },
    { id: 'rules', label: 'Detection Rules', icon: Zap },
    { id: 'sources', label: 'Data Sources', icon: Server },
    { id: 'correlation', label: 'Correlation', icon: TrendingUp },
  ];

  const logs = logsData?.items || [];
  const logTotal = logsData?.total || 0;
  const rules = rulesData?.items || [];
  const sources = Array.isArray(sourcesData) ? sourcesData : (sourcesData?.items || []);
  const correlations = Array.isArray(correlationsData) ? correlationsData : (correlationsData?.items || []);

  const logPages = Math.ceil(logTotal / 15);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">SIEM Dashboard</h1>
          <p className="text-gray-500 mt-1">Security information and event management</p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="bg-white rounded-lg border border-gray-200">
        <div className="flex border-b border-gray-200">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={clsx(
                  'flex items-center space-x-2 px-6 py-4 font-medium border-b-2 transition-colors',
                  activeTab === tab.id
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-600 hover:text-gray-900'
                )}
              >
                <Icon className="w-5 h-5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
            <StatsCard
              title="Total Logs"
              value={statsLoading ? '-' : (stats?.total_logs_ingested || 0).toLocaleString()}
              subtext="24 hours"
              icon={Activity}
            />
            <StatsCard
              title="Events/Second"
              value={statsLoading ? '-' : (stats?.events_per_second || 0).toFixed(1)}
              subtext="Current rate"
              icon={TrendingUp}
            />
            <StatsCard
              title="Active Rules"
              value={statsLoading ? '-' : stats?.active_detection_rules || 0}
              subtext="Detection rules"
              icon={Zap}
            />
            <StatsCard
              title="Alerts (24h)"
              value={statsLoading ? '-' : stats?.alerts_triggered_24h || 0}
              subtext="Total triggered"
              icon={AlertTriangle}
            />
            <StatsCard
              title="Data Sources"
              value={statsLoading ? '-' : stats?.active_data_sources || 0}
              subtext="Connected"
              icon={Server}
            />
          </div>

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Log Ingestion Chart */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Log Ingestion Volume (24h)</h3>
              {stats?.log_ingestion_chart ? (
                <ResponsiveContainer width="100%" height={300}>
                  <AreaChart data={stats.log_ingestion_chart}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                    <XAxis dataKey="time" stroke="#6b7280" />
                    <YAxis stroke="#6b7280" />
                    <Tooltip />
                    <Area type="monotone" dataKey="count" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[300px] bg-gray-50 rounded flex items-center justify-center">
                  <p className="text-gray-500">Loading chart...</p>
                </div>
              )}
            </div>

            {/* Events by Severity */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Events by Severity</h3>
              {stats?.events_by_severity ? (
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={stats.events_by_severity}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                    <XAxis dataKey="severity" stroke="#6b7280" />
                    <YAxis stroke="#6b7280" />
                    <Tooltip />
                    <Bar dataKey="count" fill="#3b82f6" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[300px] bg-gray-50 rounded flex items-center justify-center">
                  <p className="text-gray-500">Loading chart...</p>
                </div>
              )}
            </div>

            {/* Events by Source Type */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Events by Source Type</h3>
              {stats?.events_by_source ? (
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={stats.events_by_source}
                      dataKey="count"
                      nameKey="source_type"
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      label
                    >
                      {stats.events_by_source.map((_: any, index: number) => (
                        <Cell key={`cell-${index}`} fill={chartColors[index % chartColors.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-[300px] bg-gray-50 rounded flex items-center justify-center">
                  <p className="text-gray-500">Loading chart...</p>
                </div>
              )}
            </div>

            {/* Recent Detections */}
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Detections</h3>
              {stats?.recent_detections && stats.recent_detections.length > 0 ? (
                <div className="space-y-3">
                  {stats.recent_detections.slice(0, 6).map((detection: any, idx: number) => (
                    <div key={idx} className="flex items-start justify-between pb-3 border-b border-gray-100 last:border-0">
                      <div className="flex-1">
                        <p className="text-sm font-medium text-gray-900">{detection.rule_name}</p>
                        <p className="text-xs text-gray-500 mt-1">{new Date(detection.timestamp).toLocaleTimeString()}</p>
                      </div>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                          severityColors[detection.severity] || severityColors.info
                        )}
                      >
                        {detection.severity}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <p>No recent detections</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Log Search Tab */}
      {activeTab === 'search' && (
        <div className="space-y-6">
          {/* Search Filters */}
          <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Search Query</label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setSearchPage(1);
                  }}
                  placeholder="Enter search query..."
                  className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
                <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2">
                  <Search className="w-5 h-5" />
                  Search
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Time Range</label>
                <select
                  value={timeRange}
                  onChange={(e) => {
                    setTimeRange(e.target.value);
                    setSearchPage(1);
                  }}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="1h">Last 1 hour</option>
                  <option value="6h">Last 6 hours</option>
                  <option value="24h">Last 24 hours</option>
                  <option value="7d">Last 7 days</option>
                  <option value="30d">Last 30 days</option>
                  <option value="custom">Custom range</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Source Type</label>
                <select
                  value={sourceTypeFilter}
                  onChange={(e) => {
                    setSourceTypeFilter(e.target.value);
                    setSearchPage(1);
                  }}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="">All Sources</option>
                  <option value="firewall">Firewall</option>
                  <option value="proxy">Proxy</option>
                  <option value="edr">EDR</option>
                  <option value="waf">WAF</option>
                  <option value="ids">IDS</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">Severity</label>
                <select
                  value={severityFilter}
                  onChange={(e) => {
                    setSeverityFilter(e.target.value);
                    setSearchPage(1);
                  }}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                  <option value="">All Severities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
            </div>
          </div>

          {/* Results Table */}
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {logsLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : logs.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                <Search className="w-12 h-12 mb-4 text-gray-300" />
                <p>No logs found</p>
              </div>
            ) : (
              <>
                <table className="w-full">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Timestamp
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Source
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Severity
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Message
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Source IP
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Dest IP
                      </th>
                      <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {logs.map((log: any) => (
                      <tr key={log.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 text-sm text-gray-500">
                          {new Date(log.timestamp).toLocaleString()}
                        </td>
                        <td className="px-6 py-4 text-sm font-medium text-gray-900">{log.source}</td>
                        <td className="px-6 py-4">
                          <span
                            className={clsx(
                              'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                              severityColors[log.severity] || severityColors.info
                            )}
                          >
                            {log.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-900 max-w-xs truncate">{log.message}</td>
                        <td className="px-6 py-4 text-sm font-mono text-gray-600">{log.source_ip}</td>
                        <td className="px-6 py-4 text-sm font-mono text-gray-600">{log.dest_ip}</td>
                        <td className="px-6 py-4 text-right">
                          <button
                            onClick={() => setSelectedLogDetail(log)}
                            className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                {/* Pagination */}
                {logPages > 1 && (
                  <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between">
                    <p className="text-sm text-gray-500">
                      Showing {(searchPage - 1) * 15 + 1} to {Math.min(searchPage * 15, logTotal)} of {logTotal}
                    </p>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => setSearchPage(searchPage - 1)}
                        disabled={searchPage === 1}
                        className="p-2 border border-gray-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
                      >
                        <ChevronLeft className="w-5 h-5" />
                      </button>
                      <span className="text-sm text-gray-700">
                        Page {searchPage} of {logPages}
                      </span>
                      <button
                        onClick={() => setSearchPage(searchPage + 1)}
                        disabled={searchPage === logPages}
                        className="p-2 border border-gray-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
                      >
                        <ChevronRight className="w-5 h-5" />
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>

          {/* Log Detail Modal */}
          {selectedLogDetail && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
                  <h2 className="text-lg font-semibold text-gray-900">Log Details</h2>
                  <button
                    onClick={() => setSelectedLogDetail(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    ✕
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Timestamp</label>
                      <p className="text-gray-900">{new Date(selectedLogDetail.timestamp).toLocaleString()}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Source</label>
                      <p className="text-gray-900">{selectedLogDetail.source}</p>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Severity</label>
                    <span
                      className={clsx(
                        'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                        severityColors[selectedLogDetail.severity]
                      )}
                    >
                      {selectedLogDetail.severity}
                    </span>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Message</label>
                    <p className="text-gray-900 text-sm">{selectedLogDetail.message}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Source IP</label>
                      <p className="text-gray-900 font-mono">{selectedLogDetail.source_ip}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Destination IP</label>
                      <p className="text-gray-900 font-mono">{selectedLogDetail.dest_ip}</p>
                    </div>
                  </div>
                  {selectedLogDetail.raw_data && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Raw Data</label>
                      <pre className="text-xs text-gray-600 bg-gray-50 p-3 rounded overflow-x-auto">
                        {JSON.stringify(selectedLogDetail.raw_data, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Detection Rules Tab */}
      {activeTab === 'rules' && (
        <div className="space-y-6">
          {/* Filter Buttons */}
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-500" />
            <button
              onClick={() => setRuleStatusFilter('')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                ruleStatusFilter === '' ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              All
            </button>
            <button
              onClick={() => setRuleStatusFilter('enabled')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                ruleStatusFilter === 'enabled' ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Enabled
            </button>
            <button
              onClick={() => setRuleStatusFilter('disabled')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                ruleStatusFilter === 'disabled' ? 'bg-red-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Disabled
            </button>
          </div>

          {/* Rules Table */}
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {rulesLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : rules.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                <Zap className="w-12 h-12 mb-4 text-gray-300" />
                <p>No detection rules found</p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Rule Name
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      MITRE Tactic
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Last Triggered
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Hit Count
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {rules
                    .filter((rule: any) => !ruleStatusFilter || rule.enabled === (ruleStatusFilter === 'enabled'))
                    .map((rule: any) => (
                      <tr key={rule.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 text-sm font-medium text-gray-900">{rule.name}</td>
                        <td className="px-6 py-4">
                          <span
                            className={clsx(
                              'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                              severityColors[rule.severity] || severityColors.info
                            )}
                          >
                            {rule.severity}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600">{rule.mitre_tactic || '-'}</td>
                        <td className="px-6 py-4">
                          <button
                            onClick={() => {
                              toggleRuleMutation.mutate({
                                ruleId: rule.id,
                                enabled: !rule.enabled,
                              });
                            }}
                            className="flex items-center gap-2"
                          >
                            {rule.enabled ? (
                              <>
                                <ToggleRight className="w-5 h-5 text-green-600" />
                                <span className="text-sm font-medium text-green-600">Enabled</span>
                              </>
                            ) : (
                              <>
                                <ToggleLeft className="w-5 h-5 text-gray-400" />
                                <span className="text-sm font-medium text-gray-500">Disabled</span>
                              </>
                            )}
                          </button>
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-600">
                          {rule.last_triggered ? new Date(rule.last_triggered).toLocaleDateString() : '-'}
                        </td>
                        <td className="px-6 py-4 text-sm font-medium text-gray-900">{rule.hit_count || 0}</td>
                        <td className="px-6 py-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => setSelectedRule(rule)}
                              className="flex items-center gap-1 px-3 py-1 text-sm bg-blue-50 text-blue-600 rounded hover:bg-blue-100"
                            >
                              <Play className="w-4 h-4" />
                              Test
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Test Rule Modal */}
          {selectedRule && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-lg mx-4">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">Test Rule: {selectedRule.name}</h2>
                  <button
                    onClick={() => setSelectedRule(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    ✕
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Test Log Data</label>
                    <textarea
                      rows={6}
                      placeholder="Enter test log data (JSON format)"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent font-mono text-sm"
                    />
                  </div>
                  <div className="flex justify-end gap-3">
                    <button
                      onClick={() => setSelectedRule(null)}
                      className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
                    >
                      Cancel
                    </button>
                    <button className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                      Run Test
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Data Sources Tab */}
      {activeTab === 'sources' && (
        <div className="space-y-6">
          <button
            onClick={() => { setSourceModalMode('add'); setSelectedSource({}); setNewSourceForm({ name: '', description: '', source_type: 'syslog' }); }}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <Plus className="w-5 h-5" />
            Add Data Source
          </button>

          {sourcesLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : sources.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-gray-500">
              <Server className="w-12 h-12 mb-4 text-gray-300" />
              <p>No data sources configured</p>
            </div>
          ) : (
            <>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {sources.map((source: any) => (
                <div key={source.id} className="bg-white rounded-lg border border-gray-200 p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <Server className="w-6 h-6 text-blue-600" />
                      <div>
                        <h3 className="font-semibold text-gray-900">{source.name}</h3>
                        <p className="text-sm text-gray-500">{source.source_type || source.type}</p>
                      </div>
                    </div>
                    <div
                      className={clsx(
                        'w-3 h-3 rounded-full',
                        source.enabled !== false
                          ? 'bg-green-500'
                          : 'bg-gray-400'
                      )}
                    />
                  </div>

                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Status</span>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full capitalize',
                          source.enabled !== false
                            ? 'bg-green-100 text-green-700'
                            : 'bg-gray-100 text-gray-700'
                        )}
                      >
                        {source.enabled !== false ? 'Connected' : 'Disabled'}
                      </span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Events Today</span>
                      <span className="text-sm font-medium text-gray-900">{source.events_today || 0}</span>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Last Event</span>
                      <span className="text-sm text-gray-600">
                        {source.last_event_at ? new Date(source.last_event_at).toLocaleTimeString() : '-'}
                      </span>
                    </div>

                    {source.description && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-gray-600">Description</span>
                        <span className="text-sm text-gray-600 truncate max-w-[200px]">{source.description}</span>
                      </div>
                    )}

                    {source.error_count > 0 && (
                      <div className="flex items-center justify-between">
                        <span className="text-sm text-red-600">Errors</span>
                        <span className="text-sm font-medium text-red-600">{source.error_count}</span>
                      </div>
                    )}
                  </div>

                  <div className="mt-4 flex gap-2">
                    <button
                      onClick={() => { setSourceModalMode('config'); setSelectedSource(source); setNewSourceForm({ name: source.name, description: source.description || '', source_type: source.source_type || 'syslog' }); }}
                      className="flex-1 px-3 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50"
                    >
                      Config
                    </button>
                    <button
                      onClick={() => { setSourceModalMode('view'); setSelectedSource(source); }}
                      className="flex-1 px-3 py-2 bg-blue-50 text-blue-600 rounded-lg text-sm font-medium hover:bg-blue-100"
                    >
                      View
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Source Modal - View / Config / Add */}
            {selectedSource && (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
                  <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
                    <h2 className="text-lg font-semibold text-gray-900">
                      {sourceModalMode === 'add' ? 'Add Data Source' : sourceModalMode === 'config' ? 'Configure Source' : 'Data Source Details'}
                    </h2>
                    <button onClick={() => setSelectedSource(null)} className="text-gray-400 hover:text-gray-600">✕</button>
                  </div>
                  <div className="p-6 space-y-5">
                    {/* Add / Config Mode - Editable Form */}
                    {(sourceModalMode === 'add' || sourceModalMode === 'config') ? (
                      <>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">Source Name *</label>
                          <input
                            type="text"
                            value={newSourceForm.name}
                            onChange={(e) => setNewSourceForm({ ...newSourceForm, name: e.target.value })}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                            placeholder="e.g., Edge Firewall"
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                          <textarea
                            value={newSourceForm.description}
                            onChange={(e) => setNewSourceForm({ ...newSourceForm, description: e.target.value })}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                            rows={3}
                            placeholder="Describe this data source..."
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">Source Type *</label>
                          <select
                            value={newSourceForm.source_type}
                            onChange={(e) => setNewSourceForm({ ...newSourceForm, source_type: e.target.value })}
                            className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                          >
                            <option value="syslog">Syslog</option>
                            <option value="json_api">JSON API</option>
                            <option value="cef">CEF</option>
                            <option value="leef">LEEF</option>
                            <option value="windows_event">Windows Event</option>
                            <option value="cloud_trail">Cloud Trail</option>
                            <option value="custom">Custom</option>
                          </select>
                        </div>
                        {sourceModalMode === 'config' && selectedSource.id && (
                          <div className="border-t pt-4">
                            <div className="flex items-center justify-between">
                              <span className="text-sm text-gray-600">Enabled</span>
                              <button
                                onClick={async () => {
                                  try {
                                    await api.put(`/siem/sources/${selectedSource.id}`, { enabled: !selectedSource.enabled });
                                    setSelectedSource({ ...selectedSource, enabled: !selectedSource.enabled });
                                  } catch {}
                                }}
                                className={clsx('px-3 py-1 rounded-full text-xs font-medium', selectedSource.enabled !== false ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600')}
                              >
                                {selectedSource.enabled !== false ? 'Enabled' : 'Disabled'}
                              </button>
                            </div>
                          </div>
                        )}
                        <div className="flex gap-3 pt-2 border-t">
                          <button
                            onClick={async () => {
                              try {
                                if (sourceModalMode === 'add') {
                                  await api.post('/siem/sources', newSourceForm);
                                } else {
                                  await api.put(`/siem/sources/${selectedSource.id}`, newSourceForm);
                                }
                                setSelectedSource(null);
                                window.location.reload();
                              } catch {}
                            }}
                            disabled={!newSourceForm.name}
                            className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 disabled:opacity-50"
                          >
                            {sourceModalMode === 'add' ? 'Create Source' : 'Save Changes'}
                          </button>
                          <button onClick={() => setSelectedSource(null)} className="flex-1 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-200">
                            Cancel
                          </button>
                        </div>
                      </>
                    ) : (
                      /* View Mode - Read Only */
                      <>
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label className="block text-sm font-medium text-gray-500 mb-1">Name</label>
                            <p className="text-gray-900 font-medium">{selectedSource.name}</p>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-500 mb-1">Type</label>
                            <p className="text-gray-900">{selectedSource.source_type}</p>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-500 mb-1">Status</label>
                            <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', selectedSource.enabled !== false ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-700')}>
                              {selectedSource.enabled !== false ? 'Connected' : 'Disabled'}
                            </span>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-500 mb-1">Events Today</label>
                            <p className="text-gray-900">{selectedSource.events_today || 0}</p>
                          </div>
                        </div>
                        {selectedSource.description && (
                          <div>
                            <label className="block text-sm font-medium text-gray-500 mb-1">Description</label>
                            <p className="text-gray-900 text-sm">{selectedSource.description}</p>
                          </div>
                        )}
                        <div className="grid grid-cols-2 gap-4">
                          <div>
                            <label className="block text-sm font-medium text-gray-500 mb-1">Created</label>
                            <p className="text-gray-900 text-sm">{selectedSource.created_at ? new Date(selectedSource.created_at).toLocaleString() : '-'}</p>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-500 mb-1">Error Count</label>
                            <p className="text-gray-900 text-sm">{selectedSource.error_count || 0}</p>
                          </div>
                        </div>
                        {selectedSource.last_error && (
                          <div>
                            <label className="block text-sm font-medium text-gray-500 mb-1">Last Error</label>
                            <p className="text-red-600 text-sm bg-red-50 p-3 rounded">{selectedSource.last_error}</p>
                          </div>
                        )}
                        <div className="border-t pt-4">
                          <label className="block text-sm font-medium text-gray-500 mb-1">Source ID</label>
                          <p className="text-gray-600 text-sm font-mono">{selectedSource.id}</p>
                        </div>
                        <div className="flex gap-3 pt-2">
                          <button
                            onClick={() => { setSourceModalMode('config'); setNewSourceForm({ name: selectedSource.name, description: selectedSource.description || '', source_type: selectedSource.source_type || 'syslog' }); }}
                            className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700"
                          >
                            Edit Configuration
                          </button>
                          <button onClick={() => setSelectedSource(null)} className="flex-1 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-200">
                            Close
                          </button>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              </div>
            )}
            </>
          )}
        </div>
      )}

      {/* Correlation Tab */}
      {activeTab === 'correlation' && (
        <div className="space-y-6">
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {correlationsLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : correlations.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                <TrendingUp className="w-12 h-12 mb-4 text-gray-300" />
                <p>No correlation events</p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Time
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Correlation Type
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Matched Rules
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Related Events
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {correlations.map((correlation: any) => (
                    <tr key={correlation.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {new Date(correlation.time).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">{correlation.type}</td>
                      <td className="px-6 py-4">
                        <span
                          className={clsx(
                            'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                            severityColors[correlation.severity] || severityColors.info
                          )}
                        >
                          {correlation.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">{correlation.matched_rules_count || 0}</td>
                      <td className="px-6 py-4 text-sm text-gray-600">{correlation.related_events_count || 0}</td>
                      <td className="px-6 py-4">
                        <span className="px-2 py-1 text-xs font-medium rounded-full bg-blue-100 text-blue-700">
                          {correlation.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <button className="text-blue-600 hover:text-blue-800 text-sm font-medium flex items-center gap-1 ml-auto">
                          <Eye className="w-4 h-4" />
                          View
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function StatsCard({ title, value, subtext, icon: Icon }: any) {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
          <p className="text-xs text-gray-500 mt-2">{subtext}</p>
        </div>
        <Icon className="w-8 h-8 text-blue-600 opacity-10" />
      </div>
    </div>
  );
}
