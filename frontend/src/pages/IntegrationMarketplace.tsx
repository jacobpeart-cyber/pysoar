import React, { useState } from 'react';
import {
  Plug,
  Download,
  Activity,
  CheckCircle,
  Settings,
  Plus,
  Edit,
  Eye,
  Trash2,
  Search,
  Filter,
  Star,
  AlertCircle,
  TrendingUp,
  Clock,
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../lib/api';
import { integrationsApi } from '../api/endpoints';

const getHealthColor = (health: string | null) => {
  switch (health) {
    case 'healthy':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'warning':
      return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
    case 'error':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

const getStatusColor = (status: string) => {
  switch (status) {
    case 'success':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'failed':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'active':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'inactive':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

export default function IntegrationMarketplace() {
  const [activeTab, setActiveTab] = useState('marketplace');
  const [connectors, setConnectors] = useState<any[]>([]);
  const [installed, setInstalled] = useState<any[]>([]);
  const [executions, setExecutions] = useState<any[]>([]);
  const [webhooks, setWebhooks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [showNewWebhookModal, setShowNewWebhookModal] = useState(false);
  const [selectedConnector, setSelectedConnector] = useState<any>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [connectorsData, installedData] = await Promise.all([
        integrationsApi.getConnectors(),
        integrationsApi.getInstalled(),
      ]);
      setConnectors(connectorsData);
      setInstalled(installedData);
      setExecutions([]);
      setWebhooks([]);
    } catch (error) {
      console.error('Error loading integration data:', error);
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    loadData();
  }, []);

  const availableConnectors = connectors.filter(c => !c.installed).length;
  const installedCount = connectors.filter(c => c.installed).length;
  const activeIntegrations = connectors.filter(c => c.installed && c.health === 'healthy').length;
  const healthScore = Math.round((activeIntegrations / installedCount) * 100) || 0;

  const categories = ['all', ...new Set(connectors.map(c => c.category))];
  const filteredConnectors = connectors.filter(c => {
    const matchesSearch = (c.name || c.display_name || '').toLowerCase().includes(searchQuery.toLowerCase());
    const matchesCategory = categoryFilter === 'all' || c.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  const tabs = [
    { id: 'marketplace', label: 'Marketplace', icon: Plug },
    { id: 'installed', label: 'Installed', icon: CheckCircle },
    { id: 'executions', label: 'Executions', icon: Activity },
    { id: 'webhooks', label: 'Webhooks', icon: Settings },
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Plug className="w-8 h-8 text-cyan-600" />
            <h1 className="text-3xl font-bold">Integration Marketplace</h1>
          </div>
          <button
            onClick={() => setShowNewWebhookModal(true)}
            className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            New Webhook
          </button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Available Connectors</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{availableConnectors}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">ready to install</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">Installed</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{installedCount}</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">active integrations</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Active</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{activeIntegrations}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">healthy status</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Health Score</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{healthScore}%</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">system health</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6">
        <div className="flex gap-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'py-4 px-2 border-b-2 font-medium flex items-center gap-2 transition',
                  activeTab === tab.id
                    ? 'border-cyan-600 text-cyan-600 dark:text-cyan-400'
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

      {/* Content */}
      <div className="p-6">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <p className="text-gray-500 dark:text-gray-400">Loading...</p>
          </div>
        ) : (
          <>
            {/* Marketplace Tab */}
            {activeTab === 'marketplace' && (
              <div className="space-y-6">
                <div className="flex gap-4 items-end">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search connectors..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <div className="flex gap-2">
                    <label className="flex items-center gap-2 text-sm">
                      <span className="text-gray-600 dark:text-gray-400">Category:</span>
                      <select
                        value={categoryFilter}
                        onChange={(e) => setCategoryFilter(e.target.value)}
                        className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                      >
                        {categories.map((cat) => (
                          <option key={cat} value={cat}>
                            {cat.charAt(0).toUpperCase() + cat.slice(1)}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {filteredConnectors.map((connector) => (
                    <div key={connector.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition flex flex-col">
                      <div className="flex items-start justify-between mb-3">
                        <div className="text-3xl">{connector.icon}</div>
                        <div className="flex items-center gap-1">
                          <Star className="w-4 h-4 text-yellow-500 fill-yellow-500" />
                          <span className="text-sm font-semibold">{connector.rating}</span>
                          <span className="text-xs text-gray-600 dark:text-gray-400">({connector.reviews})</span>
                        </div>
                      </div>
                      <h3 className="font-semibold text-lg mb-1">{connector.name}</h3>
                      <span className="text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100 rounded w-fit mb-2">
                        {connector.category}
                      </span>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-4 flex-grow">{connector.description}</p>
                      {connector.installed ? (
                        <div className="space-y-2">
                          <div className="flex items-center gap-2 text-xs">
                            <div className={`w-2 h-2 rounded-full ${connector.health === 'healthy' ? 'bg-green-600' : 'bg-yellow-600'}`} />
                            <span className="capitalize">{connector.health}</span>
                          </div>
                          <button onClick={() => setSelectedConnector(connector)} className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                            Manage
                          </button>
                        </div>
                      ) : (
                        <button onClick={async () => { try { await api.post(`/integrations/connectors/${connector.id}/install`, { config: {} }); loadData(); } catch(e) { console.error(e); } }} className="w-full px-3 py-2 text-sm bg-cyan-600 hover:bg-cyan-700 text-white rounded transition flex items-center justify-center gap-2">
                          <Download className="w-4 h-4" />
                          Install
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Installed Tab */}
            {activeTab === 'installed' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 gap-4">
                  {installed.map((integration) => (
                    <div key={integration.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-4">
                        <div className="flex-1">
                          <h3 className="font-semibold text-lg">{integration.name}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">v{integration.version}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getHealthColor(integration.health)}`}>
                          {integration.health}
                        </span>
                      </div>
                      <div className="grid grid-cols-4 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Last Sync</p>
                          <p className="font-medium">{new Date(integration.lastSync || "").toLocaleDateString()}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Frequency</p>
                          <p className="font-medium">{integration.syncFrequency}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Events</p>
                          <p className="font-medium">{(integration.eventsProcessed / 1000000).toFixed(1)}M</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Success Rate</p>
                          <p className="font-medium">{integration.successRate}%</p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => setSelectedConnector(integration)} className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          Configure
                        </button>
                        <button onClick={async () => { try { await api.post(`/integrations/connectors/${integration.id}/test`); } catch(e) { console.error(e); } }} className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          Test
                        </button>
                        <button onClick={() => setSelectedConnector(integration)} className="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          <Settings className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Executions Tab */}
            {activeTab === 'executions' && (
              <div className="space-y-6">
                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Connector</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Execution Time</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Records</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Duration</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {executions.map((exec) => (
                        <tr key={exec.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{exec.connector}</td>
                          <td className="px-6 py-4 text-sm">{new Date(exec.executionTime || "").toLocaleString()}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(exec.status)}`}>
                              {exec.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm">{exec.recordsProcessed.toLocaleString()}</td>
                          <td className="px-6 py-4 text-sm">{exec.duration}s</td>
                          <td className="px-6 py-4 text-sm">
                            <button className="text-blue-600 dark:text-blue-400 hover:underline">
                              <Eye className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Webhooks Tab */}
            {activeTab === 'webhooks' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 gap-4">
                  {webhooks.map((webhook) => (
                    <div key={webhook.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <h3 className="font-semibold">{webhook.name}</h3>
                          <p className="text-xs font-mono text-gray-600 dark:text-gray-400 mt-1 truncate">{webhook.url}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(webhook.status)}`}>
                          {webhook.status}
                        </span>
                      </div>
                      <div className="grid grid-cols-4 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Event Type</p>
                          <p className="font-medium">{webhook.event}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Last Triggered</p>
                          <p className="font-medium">{webhook.lastTriggered ? new Date(webhook.lastTriggered || "").toLocaleDateString() : 'Never'}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Success Count</p>
                          <p className="font-medium">{webhook.successCount}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Status</p>
                          <p className="font-medium capitalize">{webhook.status}</p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          Test
                        </button>
                        <button className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          Edit
                        </button>
                        <button className="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* New Webhook Modal */}
      {showNewWebhookModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create Webhook</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.post('/integrations/webhooks', { name: fd.get('name'), url: fd.get('url'), event_type: fd.get('event') });
                setShowNewWebhookModal(false);
                loadData();
              } catch (err) { console.error('Failed to create webhook:', err); }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Webhook Name</label>
                <input name="name" required type="text" placeholder="e.g., Slack Alert Webhook" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Webhook URL</label>
                <input name="url" required type="url" placeholder="https://..." className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Event Type</label>
                <select name="event" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option>alert.critical</option>
                  <option>alert.high</option>
                  <option>incident.created</option>
                  <option>ticket.created</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setShowNewWebhookModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg transition">Create</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
