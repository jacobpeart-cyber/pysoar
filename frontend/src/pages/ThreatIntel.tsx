import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  Search,
  Globe,
  Shield,
  AlertTriangle,
  Activity,
  ExternalLink,
  RefreshCw,
  Loader2,
  CheckCircle,
  XCircle,
  Clock,
  Server,
  Mail,
  Hash,
  FileText,
  TrendingUp,
  Eye,
  Download,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';

interface ThreatFeed {
  id: string;
  name: string;
  provider: string;
  type: string;
  enabled: boolean;
  last_updated: string | null;
  indicator_count: number;
  status: 'active' | 'error' | 'disabled';
}

interface IOCLookupResult {
  indicator: string;
  type: string;
  reputation: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  confidence: number;
  sources: Array<{
    name: string;
    verdict: string;
    last_seen: string;
    details: Record<string, unknown>;
  }>;
  tags: string[];
  first_seen: string | null;
  last_seen: string | null;
}

interface ThreatStats {
  total_indicators: number;
  malicious_ips: number;
  malicious_domains: number;
  malicious_hashes: number;
  feeds_active: number;
  last_update: string | null;
}

const indicatorTypes = [
  { value: 'ip', label: 'IP Address', icon: Server },
  { value: 'domain', label: 'Domain', icon: Globe },
  { value: 'url', label: 'URL', icon: ExternalLink },
  { value: 'hash', label: 'File Hash', icon: Hash },
  { value: 'email', label: 'Email', icon: Mail },
];

export default function ThreatIntel() {
  const [searchQuery, setSearchQuery] = useState('');
  const [searchType, setSearchType] = useState('auto');
  const [activeTab, setActiveTab] = useState<'lookup' | 'feeds' | 'iocs'>('lookup');

  const { data: stats } = useQuery<ThreatStats>({
    queryKey: ['threat-intel', 'stats'],
    queryFn: async () => {
      const response = await api.get('/threat-intel/stats');
      return response.data;
    },
  });

  const { data: feeds, refetch: refetchFeeds } = useQuery<ThreatFeed[]>({
    queryKey: ['threat-intel', 'feeds'],
    queryFn: async () => {
      const response = await api.get('/threat-intel/feeds');
      return response.data;
    },
  });

  const lookupMutation = useMutation<IOCLookupResult, Error, { indicator: string; type: string }>({
    mutationFn: async ({ indicator, type }) => {
      const response = await api.post('/threat-intel/lookup', { indicator, type });
      return response.data;
    },
  });

  const syncFeedMutation = useMutation({
    mutationFn: async (feedId: string) => {
      const response = await api.post(`/threat-intel/feeds/${feedId}/sync`);
      return response.data;
    },
    onSuccess: () => {
      refetchFeeds();
    },
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      lookupMutation.mutate({ indicator: searchQuery.trim(), type: searchType });
    }
  };

  const getReputationColor = (reputation: string) => {
    switch (reputation) {
      case 'malicious':
        return 'text-red-600 bg-red-50 dark:bg-red-900/20 dark:text-red-400';
      case 'suspicious':
        return 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'clean':
        return 'text-green-600 bg-green-50 dark:bg-green-900/20 dark:text-green-400';
      default:
        return 'text-gray-600 bg-gray-50 dark:bg-gray-700 dark:text-gray-400';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Threat Intelligence</h1>
          <p className="text-gray-500 dark:text-gray-400">
            Look up indicators and manage threat intelligence feeds
          </p>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
              <Activity className="w-5 h-5 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Total Indicators</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.total_indicators?.toLocaleString() || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-50 dark:bg-red-900/20 rounded-lg">
              <Server className="w-5 h-5 text-red-600 dark:text-red-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Malicious IPs</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.malicious_ips?.toLocaleString() || 0}
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
              <p className="text-sm text-gray-500 dark:text-gray-400">Malicious Domains</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.malicious_domains?.toLocaleString() || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
              <Hash className="w-5 h-5 text-purple-600 dark:text-purple-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Malicious Hashes</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.malicious_hashes?.toLocaleString() || 0}
              </p>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-50 dark:bg-green-900/20 rounded-lg">
              <TrendingUp className="w-5 h-5 text-green-600 dark:text-green-400" />
            </div>
            <div>
              <p className="text-sm text-gray-500 dark:text-gray-400">Active Feeds</p>
              <p className="text-xl font-semibold text-gray-900 dark:text-white">
                {stats?.feeds_active || 0}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-4">
          <button
            onClick={() => setActiveTab('lookup')}
            className={clsx(
              'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'lookup'
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
            )}
          >
            <Search className="w-4 h-4 inline mr-2" />
            IOC Lookup
          </button>
          <button
            onClick={() => setActiveTab('feeds')}
            className={clsx(
              'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'feeds'
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
            )}
          >
            <Activity className="w-4 h-4 inline mr-2" />
            Threat Feeds
          </button>
          <button
            onClick={() => setActiveTab('iocs')}
            className={clsx(
              'px-4 py-2 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'iocs'
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400'
            )}
          >
            <Shield className="w-4 h-4 inline mr-2" />
            IOC Database
          </button>
        </nav>
      </div>

      {/* Lookup Tab */}
      {activeTab === 'lookup' && (
        <div className="space-y-6">
          {/* Search Form */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
            <form onSubmit={handleSearch} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Search for an indicator
                </label>
                <div className="flex gap-3">
                  <select
                    value={searchType}
                    onChange={(e) => setSearchType(e.target.value)}
                    className="rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm text-gray-900 dark:text-white focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  >
                    <option value="auto">Auto-detect</option>
                    {indicatorTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Enter IP, domain, URL, hash, or email..."
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={lookupMutation.isPending || !searchQuery.trim()}
                    className="flex items-center gap-2 px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
                  >
                    {lookupMutation.isPending ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Search className="w-4 h-4" />
                    )}
                    Lookup
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Lookup Result */}
          {lookupMutation.data && (
            <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="flex items-center gap-3">
                      <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        {lookupMutation.data.indicator}
                      </h3>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full',
                          getReputationColor(lookupMutation.data.reputation)
                        )}
                      >
                        {lookupMutation.data.reputation.charAt(0).toUpperCase() +
                          lookupMutation.data.reputation.slice(1)}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                      Type: {lookupMutation.data.type} | Confidence:{' '}
                      {lookupMutation.data.confidence}%
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700">
                      <Eye className="w-4 h-4" />
                    </button>
                    <button className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700">
                      <Download className="w-4 h-4" />
                    </button>
                  </div>
                </div>

                {lookupMutation.data.tags.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-3">
                    {lookupMutation.data.tags.map((tag, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 rounded"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Sources */}
              <div className="p-6">
                <h4 className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-4">
                  Intelligence Sources ({lookupMutation.data.sources.length})
                </h4>
                <div className="space-y-3">
                  {lookupMutation.data.sources.map((source, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                    >
                      <div className="flex items-center gap-3">
                        <Shield className="w-5 h-5 text-gray-400" />
                        <div>
                          <p className="text-sm font-medium text-gray-900 dark:text-white">
                            {source.name}
                          </p>
                          <p className="text-xs text-gray-500 dark:text-gray-400">
                            Last seen: {new Date(source.last_seen).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded',
                          source.verdict === 'malicious'
                            ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'
                            : source.verdict === 'suspicious'
                            ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400'
                            : source.verdict === 'clean'
                            ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                            : 'bg-gray-100 text-gray-700 dark:bg-gray-600 dark:text-gray-300'
                        )}
                      >
                        {source.verdict}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Error State */}
          {lookupMutation.isError && (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
              <div className="flex items-center gap-3">
                <XCircle className="w-5 h-5 text-red-600 dark:text-red-400" />
                <p className="text-sm text-red-700 dark:text-red-300">
                  Failed to lookup indicator. Please try again.
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Feeds Tab */}
      {activeTab === 'feeds' && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h3 className="font-medium text-gray-900 dark:text-white">Threat Intelligence Feeds</h3>
            <button
              onClick={() => refetchFeeds()}
              className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
            >
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {feeds?.map((feed) => (
              <div key={feed.id} className="p-4 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div
                    className={clsx(
                      'w-2 h-2 rounded-full',
                      feed.status === 'active'
                        ? 'bg-green-500'
                        : feed.status === 'error'
                        ? 'bg-red-500'
                        : 'bg-gray-400'
                    )}
                  />
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="font-medium text-gray-900 dark:text-white">{feed.name}</p>
                      <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded">
                        {feed.type}
                      </span>
                    </div>
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      {feed.provider} | {feed.indicator_count.toLocaleString()} indicators
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <p className="text-xs text-gray-500 dark:text-gray-400">Last Updated</p>
                    <p className="text-sm text-gray-900 dark:text-white">
                      {feed.last_updated
                        ? new Date(feed.last_updated).toLocaleString()
                        : 'Never'}
                    </p>
                  </div>
                  <button
                    onClick={() => syncFeedMutation.mutate(feed.id)}
                    disabled={syncFeedMutation.isPending}
                    className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 rounded-lg hover:bg-blue-100 dark:hover:bg-blue-900/40 disabled:opacity-50"
                  >
                    {syncFeedMutation.isPending ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <RefreshCw className="w-4 h-4" />
                    )}
                    Sync
                  </button>
                </div>
              </div>
            )) || (
              <div className="p-8 text-center text-gray-500 dark:text-gray-400">
                <Activity className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No threat feeds configured</p>
                <p className="text-sm">Configure feeds in Settings &gt; Integrations</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* IOCs Tab */}
      {activeTab === 'iocs' && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="p-4 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <h3 className="font-medium text-gray-900 dark:text-white">IOC Database</h3>
            <div className="flex items-center gap-2">
              <select className="text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 rounded-lg px-3 py-1.5 text-gray-700 dark:text-gray-300">
                <option value="all">All Types</option>
                <option value="ip">IP Addresses</option>
                <option value="domain">Domains</option>
                <option value="hash">File Hashes</option>
                <option value="url">URLs</option>
              </select>
              <select className="text-sm border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 rounded-lg px-3 py-1.5 text-gray-700 dark:text-gray-300">
                <option value="all">All Reputation</option>
                <option value="malicious">Malicious</option>
                <option value="suspicious">Suspicious</option>
                <option value="clean">Clean</option>
              </select>
              <button className="flex items-center gap-2 px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg">
                <Download className="w-4 h-4" />
                Export
              </button>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-700/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Indicator
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Reputation
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Source
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Last Seen
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
                {/* Sample data - in production this would come from an API */}
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-4 py-3">
                    <code className="text-sm text-gray-900 dark:text-white">192.168.1.100</code>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded">
                      IP
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 text-xs font-medium bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded-full">
                      Malicious
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                    AbuseIPDB
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                    2 hours ago
                  </td>
                  <td className="px-4 py-3">
                    <button className="text-blue-600 dark:text-blue-400 hover:text-blue-700 text-sm">
                      Details
                    </button>
                  </td>
                </tr>
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-4 py-3">
                    <code className="text-sm text-gray-900 dark:text-white">malware.example.com</code>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded">
                      Domain
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 text-xs font-medium bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 rounded-full">
                      Suspicious
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                    VirusTotal
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                    1 day ago
                  </td>
                  <td className="px-4 py-3">
                    <button className="text-blue-600 dark:text-blue-400 hover:text-blue-700 text-sm">
                      Details
                    </button>
                  </td>
                </tr>
                <tr className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="px-4 py-3">
                    <code className="text-sm text-gray-900 dark:text-white truncate max-w-[200px] block">
                      d41d8cd98f00b204e9800998ecf8427e
                    </code>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 rounded">
                      MD5
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-1 text-xs font-medium bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded-full">
                      Clean
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                    VirusTotal
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500 dark:text-gray-400">
                    3 days ago
                  </td>
                  <td className="px-4 py-3">
                    <button className="text-blue-600 dark:text-blue-400 hover:text-blue-700 text-sm">
                      Details
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div className="p-4 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between">
            <p className="text-sm text-gray-500 dark:text-gray-400">
              Showing 1-3 of {stats?.total_indicators?.toLocaleString() || 0} indicators
            </p>
            <div className="flex gap-2">
              <button
                disabled
                className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-400 cursor-not-allowed"
              >
                Previous
              </button>
              <button className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700">
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
