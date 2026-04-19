import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Search,
  ShieldAlert,
  AlertTriangle,
  TrendingUp,
  BarChart3,
  Clock,
  AlertCircle,
  CheckCircle,
  Loader2,
  RefreshCw,
  Download,
  Plus,
  Filter,
  Eye,
  Zap,
  Activity,
  Target,
  Shield,
  TrendingDown,
  Globe,
  Cloud,
  Package,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, AreaChart, Area, PieChart, Pie, Cell } from 'recharts';

interface DashboardStats {
  total_assets: number;
  internet_facing_assets: number;
  critical_vulns: number;
  overdue_tickets: number;
  overall_risk_score: number;
  mean_time_to_remediate_days: number;
  exposure_trend?: Array<{ date: string; exposures: number }>;
}

interface Asset {
  id: string;
  hostname: string;
  ip_address: string;
  type: string;
  environment: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  risk_score: number;
  vulnerability_count: number;
  last_scan: string;
  status: 'active' | 'inactive' | 'quarantined';
}

interface Vulnerability {
  id: string;
  cve_id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss: number;
  epss: number;
  has_exploit: boolean;
  kev_listed: boolean;
  affected_assets: number;
  patch_available: boolean;
  status: 'open' | 'mitigated' | 'patched';
}

interface RemediationTicket {
  id: string;
  title: string;
  priority: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'in_progress' | 'verification' | 'closed';
  assigned_to: string;
  affected_assets: number;
  due_date: string;
  sla_status: 'on_track' | 'at_risk' | 'overdue';
}

interface AttackSurface {
  id: string;
  name: string;
  type: 'external' | 'internal' | 'cloud' | 'application';
  risk_score: number;
  total_assets: number;
  exposed_assets: number;
  critical_exposures: number;
  last_assessed: string;
}

interface ComplianceFramework {
  id: string;
  name: string;
  pass_percentage: number;
  total_controls: number;
}

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
    case 'high':
      return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
    case 'medium':
      return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
    case 'low':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400';
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
  }
};

const getRiskColor = (score: number) => {
  if (score >= 80) return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
  if (score >= 60) return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
  if (score >= 40) return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
  return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
};

const getStatusColor = (status: string) => {
  switch (status) {
    case 'active':
    case 'open':
    case 'on_track':
      return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
    case 'inactive':
    case 'in_progress':
    case 'at_risk':
      return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
    case 'quarantined':
    case 'verification':
    case 'overdue':
      return 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400';
    case 'closed':
    case 'patched':
      return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400';
    default:
      return 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-400';
  }
};

export default function ExposureManagement() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'dashboard' | 'assets' | 'vulnerabilities' | 'remediation' | 'attack-surface' | 'compliance'>('dashboard');
  const [assetSearch, setAssetSearch] = useState('');
  const [assetTypeFilter, setAssetTypeFilter] = useState('all');
  const [environmentFilter, setEnvironmentFilter] = useState('all');
  const [criticalityFilter, setCriticalityFilter] = useState('all');
  const [internetFacingFilter, setInternetFacingFilter] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [exploitFilter, setExploitFilter] = useState('all');
  const [priorityFilter, setPriorityFilter] = useState<string[]>([]);
  const [ticketStatusFilter, setTicketStatusFilter] = useState<string[]>([]);
  const [showImportModal, setShowImportModal] = useState(false);
  const [showCreateTicketModal, setShowCreateTicketModal] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);

  const { data: stats, isLoading: statsLoading } = useQuery<DashboardStats>({
    queryKey: ['exposure', 'dashboard'],
    queryFn: async () => {
      try {
      const response = await api.get('/exposure/dashboard');
      return response.data;
      } catch { return null; }
    },
  });

  const { data: assetsData, isLoading: assetsLoading } = useQuery<any>({
    queryKey: ['exposure', 'assets', assetSearch, assetTypeFilter, environmentFilter, criticalityFilter, internetFacingFilter],
    queryFn: async () => {
      const response = await api.get('/exposure/assets', {
        params: {
          search: assetSearch,
          asset_type: assetTypeFilter !== 'all' ? assetTypeFilter : undefined,
          environment: environmentFilter !== 'all' ? environmentFilter : undefined,
          criticality: criticalityFilter !== 'all' ? criticalityFilter : undefined,
          is_internet_facing: internetFacingFilter ? true : undefined,
        },
      });
      return response.data;
    },
  });
  const assets: Asset[] = Array.isArray(assetsData) ? assetsData : (assetsData?.items || []);

  const { data: vulnData, isLoading: vulnLoading } = useQuery<any>({
    queryKey: ['exposure', 'vulnerabilities', severityFilter, exploitFilter],
    queryFn: async () => {
      const response = await api.get('/exposure/vulnerabilities', {
        params: {
          severity: severityFilter.length > 0 ? severityFilter.join(',') : undefined,
          has_exploit: exploitFilter !== 'all' ? exploitFilter : undefined,
        },
      });
      return response.data;
    },
  });
  const vulnerabilities: Vulnerability[] = Array.isArray(vulnData) ? vulnData : (vulnData?.items || []);

  const { data: ticketData, isLoading: ticketsLoading } = useQuery<any>({
    queryKey: ['exposure', 'tickets', priorityFilter, ticketStatusFilter],
    queryFn: async () => {
      const response = await api.get('/exposure/tickets', {
        params: {
          priority: priorityFilter.length > 0 ? priorityFilter.join(',') : undefined,
          status: ticketStatusFilter.length > 0 ? ticketStatusFilter.join(',') : undefined,
        },
      });
      return response.data;
    },
  });
  const tickets: RemediationTicket[] = Array.isArray(ticketData) ? ticketData : (ticketData?.items || []);

  const { data: surfaceData } = useQuery<any>({
    queryKey: ['exposure', 'attack-surface'],
    queryFn: async () => {
      try {
      const response = await api.get('/exposure/attack-surface');
      return response.data;
      } catch { return null; }
    },
  });
  const attackSurfaces: AttackSurface[] = Array.isArray(surfaceData) ? surfaceData : (surfaceData?.items || []);

  const { data: compliance } = useQuery<ComplianceFramework[]>({
    queryKey: ['exposure', 'compliance'],
    queryFn: async () => {
      const response = await api.get('/exposure/compliance');
      const data = response.data;
      // Backend returns ComplianceSummary object; transform frameworks map into array
      if (data.frameworks && !Array.isArray(data.frameworks)) {
        return Object.entries(data.frameworks).map(([key, value]: [string, any]) => ({
          id: key,
          name: value.name || key,
          pass_percentage: value.pass_percentage ?? (value.passed_checks && value.total_controls ? Math.round((value.passed_checks / value.total_controls) * 100) : 0),
          total_controls: value.total_controls || 0,
        }));
      }
      // If it's already an array, return as-is
      if (Array.isArray(data)) return data;
      return [];
    },
  });

  const vulnerabilityData = vulnerabilities ? vulnerabilities.reduce((acc, v) => {
    const existing = acc.find(item => item.severity === v.severity);
    if (existing) {
      existing.count += 1;
    } else {
      acc.push({ severity: v.severity, count: 1 });
    }
    return acc;
  }, [] as Array<{ severity: string; count: number }>) : [];

  const topVulnerableAssets = assets
    ?.slice()
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10)
    .map(a => ({ name: a.hostname, risk: a.risk_score })) || [];

  const trendData = stats?.exposure_trend && stats.exposure_trend.length > 0
    ? stats.exposure_trend
    : Array.from({ length: 30 }, (_, i) => ({
        date: new Date(Date.now() - (29 - i) * 24 * 60 * 60 * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
        exposures: stats?.critical_vulns ?? 0,
      }));

  const colors = ['#ef4444', '#f97316', '#eab308', '#3b82f6'];

  const tabs = [
    { id: 'dashboard', name: 'Dashboard', icon: BarChart3 },
    { id: 'assets', name: 'Assets', icon: Package },
    { id: 'vulnerabilities', name: 'Vulnerabilities', icon: AlertTriangle },
    { id: 'remediation', name: 'Remediation', icon: Zap },
    { id: 'attack-surface', name: 'Attack Surface', icon: Target },
    { id: 'compliance', name: 'Compliance', icon: Shield },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Exposure Management</h1>
          <p className="text-gray-500 dark:text-gray-400">
            Comprehensive cyber risk and threat exposure platform
          </p>
        </div>
        <button
          onClick={() => queryClient.invalidateQueries({ queryKey: ['exposure'] })}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-1 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={clsx(
                  'flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap',
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
                )}
              >
                <Icon className="w-4 h-4" />
                {tab.name}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Dashboard Tab */}
      {activeTab === 'dashboard' && (
        <div className="space-y-6">
          {/* Stats Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                  <Package className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Total Assets</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                    {stats?.total_assets || 0}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                  <Globe className="w-5 h-5 text-orange-600 dark:text-orange-400" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Internet-Facing</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                    {stats?.internet_facing_assets || 0}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg">
                  <AlertCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Critical Vulns</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                    {stats?.critical_vulns || 0}
                  </p>
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                  <Zap className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
                </div>
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Overdue Tickets</p>
                  <p className="text-2xl font-semibold text-gray-900 dark:text-white">
                    {stats?.overdue_tickets || 0}
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Risk and MTTA Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Overall Risk Score</p>
                  <p className="text-4xl font-bold text-gray-900 dark:text-white mt-2">
                    {stats?.overall_risk_score || 0}
                  </p>
                </div>
                <div className={clsx('w-20 h-20 rounded-full flex items-center justify-center text-2xl font-bold', getRiskColor(stats?.overall_risk_score || 0))}>
                  {stats?.overall_risk_score || 0}
                </div>
              </div>
            </div>

            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-500 dark:text-gray-400">Mean Time to Remediate</p>
                  <p className="text-4xl font-bold text-gray-900 dark:text-white mt-2">
                    {stats?.mean_time_to_remediate_days || 0}
                  </p>
                  <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">days</p>
                </div>
                <Clock className="w-16 h-16 text-gray-400" />
              </div>
            </div>
          </div>

          {/* Charts Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Vulnerabilities by Severity */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Vulnerabilities by Severity</h3>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={vulnerabilityData}
                    dataKey="count"
                    nameKey="severity"
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                  >
                    {colors.map((color, index) => (
                      <Cell key={`cell-${index}`} fill={color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Top Vulnerable Assets */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Top 10 Vulnerable Assets</h3>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={topVulnerableAssets}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                  <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                  <YAxis tick={{ fontSize: 12 }} />
                  <Tooltip />
                  <Bar dataKey="risk" fill="#ef4444" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Exposure Trend */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Exposure Trend (30 days)</h3>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Area type="monotone" dataKey="exposures" stroke="#f97316" fill="#fed7aa" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Assets Tab */}
      {activeTab === 'assets' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <div className="flex flex-col gap-4">
              <div className="flex gap-3">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    value={assetSearch}
                    onChange={(e) => setAssetSearch(e.target.value)}
                    placeholder="Search by hostname or IP..."
                    className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              </div>
              <div className="flex flex-wrap gap-3">
                <select
                  value={assetTypeFilter}
                  onChange={(e) => setAssetTypeFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                >
                  <option value="all">All Types</option>
                  <option value="server">Server</option>
                  <option value="workstation">Workstation</option>
                  <option value="network">Network Device</option>
                </select>
                <select
                  value={environmentFilter}
                  onChange={(e) => setEnvironmentFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                >
                  <option value="all">All Environments</option>
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
                <select
                  value={criticalityFilter}
                  onChange={(e) => setCriticalityFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                >
                  <option value="all">All Criticalities</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <label className="flex items-center gap-2 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={internetFacingFilter}
                    onChange={(e) => setInternetFacingFilter(e.target.checked)}
                    className="w-4 h-4"
                  />
                  <span className="text-sm text-gray-900 dark:text-white">Internet-Facing Only</span>
                </label>
              </div>
            </div>
          </div>

          {/* Assets Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 dark:bg-gray-700/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Hostname</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">IP Address</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Type</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Environment</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Criticality</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Risk Score</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Vulns</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Last Scan</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {assetsLoading ? (
                    <tr><td colSpan={10} className="px-4 py-12 text-center text-gray-500"><Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />Loading assets...</td></tr>
                  ) : assets.length === 0 ? (
                    <tr><td colSpan={10} className="px-4 py-12 text-center text-gray-500">No assets found. Add assets to start monitoring exposure.</td></tr>
                  ) : null}
                  {assets?.map((asset) => (
                    <tr key={asset.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white font-medium">{asset.hostname}</td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{asset.ip_address}</td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{asset.asset_type || asset.type}</td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{asset.environment || asset.network_zone}</td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getSeverityColor(asset.criticality))}>
                          {asset.criticality}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <div className="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className={clsx('h-2 rounded-full', asset.risk_score >= 80 ? 'bg-red-500' : asset.risk_score >= 60 ? 'bg-orange-500' : 'bg-yellow-500')}
                            style={{ width: `${asset.risk_score}%` }}
                          />
                        </div>
                        <span className="text-xs text-gray-500 dark:text-gray-400">{asset.risk_score}</span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">{asset.vulnerability_count}</td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                        {asset.last_scan_at ? new Date(asset.last_scan_at || "").toLocaleDateString() : asset.last_scan ? new Date(asset.last_scan || "").toLocaleDateString() : '-'}
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getStatusColor(asset.status))}>
                          {asset.status}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <button
                          onClick={() => setSelectedAsset(asset)}
                          className="text-blue-600 dark:text-blue-400 hover:text-blue-700 text-sm font-medium"
                        >
                          View Details
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Vulnerabilities Tab */}
      {activeTab === 'vulnerabilities' && (
        <div className="space-y-4">
          {/* Filters and Actions */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <div className="flex flex-wrap gap-2">
                  {['critical', 'high', 'medium', 'low'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() =>
                        setSeverityFilter(
                          severityFilter.includes(sev)
                            ? severityFilter.filter(s => s !== sev)
                            : [...severityFilter, sev]
                        )
                      }
                      className={clsx(
                        'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
                        severityFilter.includes(sev)
                          ? getSeverityColor(sev)
                          : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                      )}
                    >
                      {sev.charAt(0).toUpperCase() + sev.slice(1)}
                    </button>
                  ))}
                </div>
                <button
                  onClick={() => setShowImportModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
                >
                  <Download className="w-4 h-4" />
                  Import Scan Results
                </button>
              </div>
              <select
                value={exploitFilter}
                onChange={(e) => setExploitFilter(e.target.value)}
                className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm max-w-xs"
              >
                <option value="all">All Vulnerabilities</option>
                <option value="has_exploit">Has Known Exploit</option>
                <option value="kev">KEV Listed</option>
              </select>
            </div>
          </div>

          {/* Vulnerabilities Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 dark:bg-gray-700/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">CVE ID</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Title</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Severity</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">CVSS</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">EPSS</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Exploit</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Assets</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Patch</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {vulnLoading ? (
                    <tr><td colSpan={9} className="px-4 py-12 text-center text-gray-500"><Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />Loading vulnerabilities...</td></tr>
                  ) : vulnerabilities.length === 0 ? (
                    <tr><td colSpan={9} className="px-4 py-12 text-center text-gray-500">No vulnerabilities found. Import scan results to populate.</td></tr>
                  ) : null}
                  {vulnerabilities?.map((vuln) => (
                    <tr key={vuln.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                      <td className="px-4 py-3 text-sm font-mono text-gray-900 dark:text-white">{vuln.cve_id}</td>
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white max-w-xs truncate">{vuln.title}</td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getSeverityColor(vuln.severity))}>
                          {vuln.severity}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm font-mono text-gray-900 dark:text-white">{(vuln.cvss_v3_score ?? vuln.cvss ?? 0).toFixed(1)}</td>
                      <td className="px-4 py-3 text-sm font-mono text-gray-900 dark:text-white">{((vuln.epss_score ?? vuln.epss ?? 0) * 100).toFixed(1)}%</td>
                      <td className="px-4 py-3">
                        {(vuln.exploit_available ?? vuln.has_exploit) ? (
                          <span className="px-2 py-1 text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded-full">
                            Yes
                          </span>
                        ) : (
                          <span className="px-2 py-1 text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-full">
                            No
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">{vuln.affected_assets ?? vuln.affected_products?.length ?? 0}</td>
                      <td className="px-4 py-3">
                        {vuln.patch_available ? (
                          <CheckCircle className="w-5 h-5 text-green-500" />
                        ) : (
                          <AlertCircle className="w-5 h-5 text-gray-400" />
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getStatusColor(vuln.status))}>
                          {vuln.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Remediation Tab */}
      {activeTab === 'remediation' && (
        <div className="space-y-4">
          {/* Quick Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Open Tickets</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {tickets?.filter(t => t.status === 'open').length || 0}
              </p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Overdue</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {tickets?.filter(t => t.sla_status === 'overdue').length || 0}
              </p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Avg SLA Compliance</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {tickets && tickets.length > 0
                  ? `${Math.round(tickets.filter(t => t.sla_status !== 'overdue').length / (tickets.length || 1) * 100)}%`
                  : '0%'}
              </p>
            </div>
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
              <p className="text-sm text-gray-500 dark:text-gray-400">Closed This Week</p>
              <p className="text-2xl font-semibold text-gray-900 dark:text-white mt-1">
                {tickets?.filter(t => t.status === 'closed').length || 0}
              </p>
            </div>
          </div>

          {/* Filters and Actions */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
            <div className="flex flex-col gap-4">
              <div className="flex items-center justify-between">
                <div className="flex flex-wrap gap-2">
                  <div>
                    <p className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">Priority:</p>
                    <div className="flex flex-wrap gap-2">
                      {['critical', 'high', 'medium', 'low'].map((pri) => (
                        <button
                          key={pri}
                          onClick={() =>
                            setPriorityFilter(
                              priorityFilter.includes(pri)
                                ? priorityFilter.filter(p => p !== pri)
                                : [...priorityFilter, pri]
                            )
                          }
                          className={clsx(
                            'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
                            priorityFilter.includes(pri)
                              ? getSeverityColor(pri)
                              : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                          )}
                        >
                          {pri.charAt(0).toUpperCase() + pri.slice(1)}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-2">Status:</p>
                    <div className="flex flex-wrap gap-2">
                      {['open', 'in_progress', 'verification', 'closed'].map((stat) => (
                        <button
                          key={stat}
                          onClick={() =>
                            setTicketStatusFilter(
                              ticketStatusFilter.includes(stat)
                                ? ticketStatusFilter.filter(s => s !== stat)
                                : [...ticketStatusFilter, stat]
                            )
                          }
                          className={clsx(
                            'px-3 py-1.5 text-xs font-medium rounded-lg transition-colors',
                            ticketStatusFilter.includes(stat)
                              ? getStatusColor(stat)
                              : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400'
                          )}
                        >
                          {stat.replace('_', ' ').charAt(0).toUpperCase() + stat.replace('_', ' ').slice(1)}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setShowCreateTicketModal(true)}
                  className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm"
                >
                  <Plus className="w-4 h-4" />
                  Create Ticket
                </button>
              </div>
            </div>
          </div>

          {/* Tickets Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-50 dark:bg-gray-700/50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Title</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Priority</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Assigned To</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Assets</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">Due Date</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">SLA Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                  {ticketsLoading ? (
                    <tr><td colSpan={7} className="px-4 py-12 text-center text-gray-500"><Loader2 className="w-6 h-6 animate-spin mx-auto mb-2" />Loading tickets...</td></tr>
                  ) : tickets.length === 0 ? (
                    <tr><td colSpan={7} className="px-4 py-12 text-center text-gray-500">No remediation tickets. Create a ticket to track remediation efforts.</td></tr>
                  ) : null}
                  {tickets?.map((ticket) => (
                    <tr key={ticket.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white font-medium">{ticket.title}</td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getSeverityColor(ticket.priority))}>
                          {ticket.priority}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getStatusColor(ticket.status))}>
                          {(ticket.status || 'open').replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">{ticket.assigned_to || '-'}</td>
                      <td className="px-4 py-3 text-sm text-gray-900 dark:text-white">{ticket.affected_assets?.length ?? ticket.affected_assets ?? 0}</td>
                      <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                        {ticket.due_date ? new Date(ticket.due_date || "").toLocaleDateString() : '-'}
                      </td>
                      <td className="px-4 py-3">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full', getStatusColor(ticket.sla_status || 'on_track'))}>
                          {(ticket.sla_status || 'on_track').replace('_', ' ')}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Attack Surface Tab */}
      {activeTab === 'attack-surface' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Overall Attack Surface Score</h3>
            <div className="text-4xl font-bold text-gray-900 dark:text-white">
              {Math.round((attackSurfaces?.reduce((sum, s) => sum + s.risk_score, 0) || 0) / (attackSurfaces?.length || 1))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {attackSurfaces?.map((surface) => (
              <div key={surface.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h4 className="font-semibold text-gray-900 dark:text-white">{surface.name}</h4>
                    <p className="text-sm text-gray-500 dark:text-gray-400 capitalize">{surface.type}</p>
                  </div>
                  <div className="w-12 h-12 rounded-full flex items-center justify-center text-lg font-bold" style={{ background: surface.risk_score >= 70 ? '#fee2e2' : '#fef3c7', color: surface.risk_score >= 70 ? '#dc2626' : '#d97706' }}>
                    {surface.risk_score}
                  </div>
                </div>
                <div className="space-y-2">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Total Assets</span>
                    <span className="font-semibold text-gray-900 dark:text-white">{surface.total_assets}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Exposed Assets</span>
                    <span className="font-semibold text-orange-600 dark:text-orange-400">{surface.exposed_assets}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-gray-500 dark:text-gray-400">Critical Exposures</span>
                    <span className="font-semibold text-red-600 dark:text-red-400">{surface.critical_exposures}</span>
                  </div>
                  <div className="text-xs text-gray-500 dark:text-gray-400 pt-2 border-t border-gray-200 dark:border-gray-700">
                    Last assessed: {new Date(surface.last_assessed || "").toLocaleDateString()}
                  </div>
                </div>
                <button
                  onClick={async () => {
                    try {
                      await api.post('/exposure/attack-surface/assess', null, { params: { surface_id: surface.id } });
                      queryClient.invalidateQueries({ queryKey: ['attackSurfaces'] });
                    } catch (err) {
                      console.error('Failed to assess attack surface:', err);
                    }
                  }}
                  className="w-full mt-4 px-4 py-2 bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/40 text-sm font-medium"
                >
                  Assess Now
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Compliance Tab */}
      {activeTab === 'compliance' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {compliance?.map((framework) => (
              <div key={framework.id} className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-semibold text-gray-900 dark:text-white">{framework.name}</h4>
                  <span className={clsx('px-3 py-1 text-sm font-medium rounded-full', framework.pass_percentage >= 80 ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' : 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400')}>
                    {framework.pass_percentage}%
                  </span>
                </div>
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mb-2">
                  <div
                    className="h-2 rounded-full bg-green-500"
                    style={{ width: `${framework.pass_percentage}%` }}
                  />
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  {Math.round((framework.pass_percentage / 100) * framework.total_controls)} of {framework.total_controls} controls passed
                </p>
              </div>
            ))}
          </div>

          {/* Compliance Trend Chart */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <h4 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Compliance Trend</h4>
            <ResponsiveContainer width="100%" height={300}>
              <AreaChart data={trendData.map(d => ({ ...d, compliance: compliance && compliance.length > 0 ? Math.round(compliance.reduce((sum, f) => sum + f.pass_percentage, 0) / (compliance.length || 1)) : 0 }))}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} domain={[0, 100]} />
                <Tooltip />
                <Area type="monotone" dataKey="compliance" stroke="#10b981" fill="#d1fae5" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}
      {/* Create Ticket Modal */}
      {showCreateTicketModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg mx-4">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Create Remediation Ticket</h2>
              <button onClick={() => setShowCreateTicketModal(false)} className="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <form onSubmit={async (e) => {
              e.preventDefault();
              const form = e.target as HTMLFormElement;
              const formData = new FormData(form);
              try {
                await api.post('/exposure/tickets', {
                  title: formData.get('title'),
                  description: formData.get('description'),
                  priority: formData.get('priority'),
                  assigned_to: formData.get('assigned_to') || undefined,
                  due_date: formData.get('due_date') || undefined,
                });
                setShowCreateTicketModal(false);
                queryClient.invalidateQueries({ queryKey: ['exposure'] });
              } catch (err) {
                console.error('Failed to create ticket');
              }
            }} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Title *</label>
                <input name="title" required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" placeholder="Remediation ticket title" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                <textarea name="description" rows={3} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" placeholder="Describe the remediation needed..." />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Priority *</label>
                  <select name="priority" required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium" selected>Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Due Date</label>
                  <input name="due_date" type="date" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Assigned To</label>
                <input name="assigned_to" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white" placeholder="Username or email" />
              </div>
              <div className="flex gap-3 pt-2">
                <button type="submit" className="flex-1 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 font-medium">Create Ticket</button>
                <button type="button" onClick={() => setShowCreateTicketModal(false)} className="flex-1 px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Import Scan Results Modal */}
      {showImportModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg mx-4">
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Import Scan Results</h2>
              <button onClick={() => setShowImportModal(false)} className="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <form onSubmit={async (e) => {
              e.preventDefault();
              const form = e.target as HTMLFormElement;
              const formData = new FormData(form);
              try {
                // Backend ScannerImportRequest expects scanner_name + scan_format,
                // not scanner_type. scan_format is the parser id (nessus, qualys,
                // tenable, openvas, custom).
                await api.post('/exposure/scans/import', {
                  scanner_name: formData.get('scanner_name'),
                  scan_format: formData.get('scan_format'),
                  scan_data: formData.get('scan_data'),
                });
                setShowImportModal(false);
                queryClient.invalidateQueries({ queryKey: ['exposure'] });
              } catch (err) {
                console.error('Failed to import scan results');
              }
            }} className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Scanner Name *</label>
                <input
                  name="scanner_name"
                  required
                  placeholder="e.g. corporate-nessus-01"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Scan Format *</label>
                <select name="scan_format" required defaultValue="nessus" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                  <option value="nessus">Nessus</option>
                  <option value="qualys">Qualys</option>
                  <option value="rapid7">Rapid7</option>
                  <option value="openvas">OpenVAS</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Scan Data (JSON) *</label>
                <textarea name="scan_data" required rows={8} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white font-mono text-sm" placeholder='{"vulnerabilities": [...], "assets": [...]}' />
              </div>
              <div className="flex gap-3 pt-2">
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium">Import</button>
                <button type="button" onClick={() => setShowImportModal(false)} className="flex-1 px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
