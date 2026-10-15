import React, { useState } from 'react';
import {
  Plug,
  Download,
  Activity,
  CheckCircle,
  Settings,
  Plus,
  Eye,
  Trash2,
  Search,
  Star,
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../lib/api';
import LoadErrorBanner from '../components/LoadErrorBanner';
import { describeLoadError } from '../lib/loadError';
import DetailDrawer, { DetailSection } from '../components/DetailDrawer';
import type { Row } from '../lib/apiRow';

const getHealthColor = (health: string | null) => {
  switch (health) {
    case 'healthy':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'degraded':
      return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
    case 'unhealthy':
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
  const [connectorsError, setConnectorsError] = useState<unknown>(null);
  const [installedError, setInstalledError] = useState<unknown>(null);
  const [executionsError, setExecutionsError] = useState<unknown>(null);
  const [executionsTotal, setExecutionsTotal] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [showNewWebhookModal, setShowNewWebhookModal] = useState(false);
  const [selectedConnector, setSelectedConnector] = useState<any>(null);
  const [detailExec, setDetailExec] = useState<any | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      // size=100: the backend defaults to 20, which hid most of the
      // registry's connectors. Both lists return {items, total, ...}.
      const [connectorsRes, installedRes, executionsRes] = await Promise.allSettled([
        api.get('/integrations/connectors', { params: { size: 100 } }),
        api.get('/integrations/installed', { params: { size: 100 } }),
        // Newest first, this organisation only.
        api.get('/integrations/executions', { params: { size: 100 } }),
      ]);
      setConnectors(connectorsRes.status === 'fulfilled' ? (connectorsRes.value.data?.items ?? []) : []);
      setConnectorsError(connectorsRes.status === 'rejected' ? (connectorsRes.reason ?? new Error('request failed')) : null);
      setInstalled(installedRes.status === 'fulfilled' ? (installedRes.value.data?.items ?? []) : []);
      setInstalledError(installedRes.status === 'rejected' ? (installedRes.reason ?? new Error('request failed')) : null);
      setExecutions(executionsRes.status === 'fulfilled' ? (executionsRes.value.data?.items ?? []) : []);
      setExecutionsTotal(executionsRes.status === 'fulfilled' ? (executionsRes.value.data?.total ?? null) : null);
      setExecutionsError(executionsRes.status === 'rejected' ? (executionsRes.reason ?? new Error('request failed')) : null);
      // Webhooks are not loaded by this page yet.
      setWebhooks([]);
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    loadData();
  }, []);

  // ConnectorResponse has no installed/health fields: installation state
  // and health come from the org's installed_integrations rows.
  const installedByConnector = new Map<string, any>(installed.map((i: any) => [i.connector_id, i]));
  const availableConnectors: number | null = connectorsError || installedError
    ? null
    : connectors.filter(c => !installedByConnector.has(c.id)).length;
  const installedCount: number | null = installedError ? null : installed.length;
  const activeIntegrations: number | null = installedError
    ? null
    : installed.filter((i: any) => i.health_status === 'healthy').length;
  const healthScore: number | null = installedCount && activeIntegrations !== null
    ? Math.round((activeIntegrations / installedCount) * 100)
    : null;
  const shown = (n: number | null, suffix = '') => (n === null ? 'not available' : `${n}${suffix}`);
  // Execution rows carry the installed integration id; name it from the
  // installed list and the connector registry.
  const integrationLabel = (installedId: string | null | undefined): string => {
    const inst = installed.find((i: Row) => i.id === installedId);
    if (!inst) return installedId ? `integration ${String(installedId).slice(0, 8)}` : 'unknown integration';
    const conn = connectors.find((c: Row) => c.id === inst.connector_id);
    return inst.name || conn?.display_name || conn?.name || inst.connector_id || String(installedId).slice(0, 8);
  };

  const categories = ['all', ...new Set(connectors.map(c => c.category))];
  const filteredConnectors = connectors.filter(c => {
    const matchesSearch = (c.display_name || c.name || '').toLowerCase().includes(searchQuery.toLowerCase());
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
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{shown(availableConnectors)}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">ready to install</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">Installed</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{shown(installedCount)}</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">active integrations</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Active</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{shown(activeIntegrations)}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">healthy status</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Health Score</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{shown(healthScore, '%')}</p>
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
                <LoadErrorBanner what="connectors" error={connectorsError} />
                <LoadErrorBanner what="installed integrations" error={installedError} />
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
                  {filteredConnectors.map((connector) => {
                    const installation = installedByConnector.get(connector.id);
                    return (
                    <div key={connector.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition flex flex-col">
                      <div className="flex items-start justify-between mb-3">
                        <span className="text-xs text-gray-600 dark:text-gray-400">{connector.vendor || ''}</span>
                        {connector.rating !== null && connector.rating !== undefined ? (
                          <div className="flex items-center gap-1">
                            <Star className="w-4 h-4 text-yellow-500 fill-yellow-500" />
                            <span className="text-sm font-semibold">{connector.rating}</span>
                          </div>
                        ) : (
                          <span className="text-xs text-gray-400">not rated</span>
                        )}
                      </div>
                      <h3 className="font-semibold text-lg mb-1">{connector.display_name || connector.name}</h3>
                      <div className="flex gap-2 mb-2 flex-wrap">
                        <span className="text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100 rounded w-fit">
                          {connector.category}
                        </span>
                        {/* External-SIEM badge — distinguishes optional
                            interop connectors from PySOAR's native SIEM
                            so operators aren't misled into thinking they
                            need to install Splunk to have a SIEM. */}
                        {connector.integration_role === 'external_siem' && (
                          <span
                            title="Optional interop — PySOAR already ships its own native SIEM. Install this only if you have an existing Splunk/Elastic/QRadar/etc. deployment you want to pull events from."
                            className="text-xs px-2 py-1 bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-200 rounded w-fit border border-amber-300 dark:border-amber-800"
                          >
                            Optional · External SIEM
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400 mb-4 flex-grow">{connector.description}</p>
                      {installation ? (
                        <div className="space-y-2">
                          <div className="flex items-center gap-2 text-xs">
                            <div className={`w-2 h-2 rounded-full ${installation.health_status === 'healthy' ? 'bg-green-600' : 'bg-yellow-600'}`} />
                            <span className="capitalize">{installation.health_status || 'unknown'}</span>
                          </div>
                          <button onClick={() => setSelectedConnector(connector)} className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                            Manage
                          </button>
                        </div>
                      ) : (
                        <button onClick={async () => {
                          try {
                            // display_name is required by IntegrationInstallRequest.
                            await api.post('/integrations/install', {
                              connector_id: connector.id,
                              display_name: connector.display_name || connector.name,
                              config: {},
                            });
                            loadData();
                          } catch (e) {
                            alert(`Install failed: ${describeLoadError(e)}`);
                          }
                        }} className="w-full px-3 py-2 text-sm bg-cyan-600 hover:bg-cyan-700 text-white rounded transition flex items-center justify-center gap-2">
                          <Download className="w-4 h-4" />
                          Install
                        </button>
                      )}
                    </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Installed Tab */}
            {activeTab === 'installed' && (
              <div className="space-y-6">
                <LoadErrorBanner what="installed integrations" error={installedError} />
                <div className="grid grid-cols-1 gap-4">
                  {installed.map((integration) => (
                    <div key={integration.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-4">
                        <div className="flex-1">
                          <h3 className="font-semibold text-lg">{integration.display_name}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400 font-mono">{integration.connector_id}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getHealthColor(integration.health_status || null)}`}>
                          {integration.health_status || 'unknown'}
                        </span>
                      </div>
                      <div className="grid grid-cols-4 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Last Health Check</p>
                          <p className="font-medium">{integration.last_health_check ? new Date(integration.last_health_check).toLocaleString() : 'Never'}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Status</p>
                          <p className="font-medium capitalize">{integration.status || 'not available'}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Last Successful Action</p>
                          <p className="font-medium">{integration.last_successful_action ? new Date(integration.last_successful_action).toLocaleString() : 'Never'}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Last Error</p>
                          <p className="font-medium break-words">{integration.error_message || 'None'}</p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => setSelectedConnector(integration)} className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          Configure
                        </button>
                        <button onClick={async () => {
                          try {
                            const res = await api.post(`/integrations/installed/${integration.id}/test`);
                            alert(`Test result: ${res.data?.status ?? 'unknown'}${res.data?.message ? ` — ${res.data.message}` : ''}`);
                            loadData();
                          } catch (e) {
                            alert(`Test failed: ${describeLoadError(e)}`);
                          }
                        }} className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
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
                <LoadErrorBanner what="integration executions" error={executionsError} />
                {!executionsError && executions.length === 0 && !loading && (
                  <p className="text-sm text-gray-500 dark:text-gray-400">
                    No integration action has run in this organisation yet. Executions are recorded when a playbook step
                    or an analyst runs an installed integration&apos;s action.
                  </p>
                )}
                {executionsTotal !== null && executionsTotal > executions.length && (
                  <p className="text-xs text-gray-500 dark:text-gray-400">Showing the newest {executions.length} of {executionsTotal}.</p>
                )}
                {executions.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Integration</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Started</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Trigger</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Duration</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {executions.map((exec) => (
                        <tr key={exec.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{integrationLabel(exec.installed_id)}</td>
                          <td className="px-6 py-4 text-sm">{exec.started_at || exec.created_at ? new Date(exec.started_at || exec.created_at).toLocaleString() : 'not started'}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(exec.status)}`}>
                              {exec.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm">{exec.triggered_by || 'not recorded'}</td>
                          <td className="px-6 py-4 text-sm">{typeof exec.duration_ms === 'number' ? `${exec.duration_ms} ms` : 'not recorded'}</td>
                          <td className="px-6 py-4 text-sm">
                            <button
                              onClick={() => setDetailExec(exec)}
                              className="text-blue-600 dark:text-blue-400 hover:underline"
                              title="View execution details"
                            >
                              <Eye className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                )}
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
                        <button
                          onClick={async () => {
                            const integrationId = (webhook as any).installation_id;
                            if (!integrationId) {
                              alert('This webhook has no installation id, so it cannot be tested.');
                              return;
                            }
                            try {
                              const res = await api.post(
                                `/integrations/installed/${integrationId}/webhooks/${webhook.id}/test`
                              );
                              setDetailExec(res.data);
                              loadData();
                            } catch (err) {
                              alert(`Webhook test failed: ${describeLoadError(err)}`);
                            }
                          }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                          title="Fire a synthetic test event through the webhook pipeline"
                        >
                          Test
                        </button>
                        <button
                          onClick={async () => {
                            if (!window.confirm(`Delete webhook ${webhook.name}?`)) return;
                            const integrationId = (webhook as any).installation_id;
                            if (!integrationId) {
                              alert('This webhook has no installation id, so it cannot be deleted.');
                              return;
                            }
                            try {
                              await api.delete(
                                `/integrations/installed/${integrationId}/webhooks/${webhook.id}`
                              );
                              loadData();
                            } catch (err) {
                              alert(`Webhook delete failed: ${describeLoadError(err)}`);
                            }
                          }}
                          className="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
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
              const integrationId = fd.get('integration_id');
              if (!integrationId) { alert('Select an installed integration first.'); return; }
              try {
                await api.post(`/integrations/installed/${integrationId}/webhooks`, { endpoint_path: fd.get('url'), http_method: 'POST', event_types: [fd.get('event')] });
                setShowNewWebhookModal(false);
                loadData();
              } catch (err) { alert(`Create webhook failed: ${describeLoadError(err)}`); }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Integration</label>
                <select name="integration_id" required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="">Select an integration...</option>
                  {installed.map((inst) => (
                    <option key={inst.id} value={inst.id}>{inst.display_name || inst.connector_id}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Endpoint Path</label>
                <input name="url" required type="text" placeholder="/webhooks/my-hook" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
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

      {/* Execution detail drawer */}
      <DetailDrawer
        open={!!detailExec}
        onClose={() => setDetailExec(null)}
        title={`Execution · ${detailExec ? integrationLabel(detailExec.installed_id) : 'Integration'}`}
        subtitle={detailExec ? `${detailExec.status || 'unknown'} · ${detailExec.triggered_by || 'trigger not recorded'}` : undefined}
        sections={
          detailExec
            ? ([
                {
                  title: 'Execution',
                  fields: [
                    { label: 'Execution ID', value: detailExec.id, mono: true, full: true },
                    { label: 'Integration', value: integrationLabel(detailExec.installed_id) },
                    { label: 'Action ID', value: detailExec.action_id, mono: true },
                    { label: 'Status', value: detailExec.status },
                    { label: 'Triggered by', value: detailExec.triggered_by },
                    { label: 'Playbook run', value: detailExec.playbook_run_id, mono: true },
                    { label: 'Duration', value: detailExec.duration_ms != null ? `${detailExec.duration_ms} ms` : null },
                    { label: 'Retries', value: detailExec.retry_count },
                    { label: 'Started', value: detailExec.started_at ? new Date(detailExec.started_at).toLocaleString() : null },
                    { label: 'Completed', value: detailExec.completed_at ? new Date(detailExec.completed_at).toLocaleString() : null },
                  ],
                },
                {
                  title: 'Input and result',
                  fields: [
                    { label: 'Error', value: detailExec.error_message, full: true, mono: true },
                    { label: 'Input', value: detailExec.input_data, full: true, mono: true },
                    { label: 'Output', value: detailExec.output_data, full: true, mono: true },
                  ],
                },
              ] as DetailSection[])
            : undefined
        }
      />
    </div>
  );
}
