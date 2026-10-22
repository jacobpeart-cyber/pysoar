import React, { useCallback, useState } from 'react';
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
  Play,
  Power,
  Loader2,
} from 'lucide-react';
import clsx from 'clsx';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import DetailDrawer, { DetailSection } from '../components/DetailDrawer';
import { integrationsApi } from '../api/endpoints';
import { useRoleGate, ADMIN_ONLY_REASON, ANALYST_ONLY_REASON } from '../lib/roles';
import {
  ExecutionStatusBadge,
  HealthBadge,
  ImplementationBadge,
  IngestBadge,
  SideEffectBadge,
} from '../components/integrations/Badges';
import ConnectorFormModal from '../components/integrations/ConnectorFormModal';
import ActionRunnerDrawer from '../components/integrations/ActionRunnerDrawer';
import ServerMessage from '../components/integrations/ServerMessage';
import WebhookFormModal from '../components/integrations/WebhookFormModal';
import WebhooksPanel from '../components/integrations/WebhooksPanel';
import type {
  Connector,
  ConnectorField,
  InstalledIntegration,
  IntegrationExecution,
  IntegrationTestResult,
  WebhookEndpointRow,
} from '../components/integrations/types';
import { errorDetailText, formatJson, formatTime, httpStatusOf } from '../components/integrations/types';

const BTN =
  'px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2';

/** The inline outcome of a Test press on one installed row. */
type TestOutcome =
  | { kind: 'result'; result: IntegrationTestResult }
  | { kind: 'not_testable'; detail: string }
  | { kind: 'error'; error: unknown };

function FieldsTable({ fields, title }: { fields: ConnectorField[]; title: string }) {
  if (!fields.length) return <p className="text-sm text-gray-500 dark:text-gray-400">No {title.toLowerCase()} fields.</p>;
  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-left text-xs text-gray-500 dark:text-gray-400">
          <th className="py-1 pr-2">Field</th>
          <th className="py-1 pr-2">Type</th>
          <th className="py-1">Description</th>
        </tr>
      </thead>
      <tbody>
        {fields.map((f) => (
          <tr key={f.name} className="border-t border-gray-100 dark:border-gray-800 align-top">
            <td className="py-1 pr-2">
              <span className="font-mono">{f.name}</span>
              {f.required ? <span className="text-red-500 ml-1" title="required">*</span> : <span className="text-xs text-gray-500 ml-1">(optional)</span>}
              {f.secret && <span className="block text-xs text-amber-700 dark:text-amber-300">secret</span>}
            </td>
            <td className="py-1 pr-2">{f.type}</td>
            <td className="py-1">
              {f.description || f.display_name}
              {f.default !== undefined && f.default !== null && (
                <span className="block text-xs text-gray-500 dark:text-gray-400">Default: {String(f.default)}</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function IntegrationMarketplace() {
  const gate = useRoleGate();
  // A custom-role holder's tiers are known only to the server: offer the
  // control and let the server answer (same rule as Settings / Identity).
  const canAdmin = gate.isAdmin || gate.hasCustomRole;
  const canOperate = gate.isAnalyst || gate.hasCustomRole;

  const [activeTab, setActiveTab] = useState('marketplace');
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [installed, setInstalled] = useState<InstalledIntegration[]>([]);
  const [executions, setExecutions] = useState<IntegrationExecution[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookEndpointRow[]>([]);
  const [webhooksError, setWebhooksError] = useState<unknown>(null);
  const [webhooksTotal, setWebhooksTotal] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [connectorsError, setConnectorsError] = useState<unknown>(null);
  const [installedError, setInstalledError] = useState<unknown>(null);
  const [executionsError, setExecutionsError] = useState<unknown>(null);
  const [executionsTotal, setExecutionsTotal] = useState<number | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  // The create form, pre-selecting an install when opened from its group.
  const [webhookFormFor, setWebhookFormFor] = useState<{ integrationId: string | null } | null>(null);
  const [detailConnector, setDetailConnector] = useState<Connector | null>(null);
  const [formTarget, setFormTarget] = useState<{ connector: Connector; installation: InstalledIntegration | null } | null>(null);
  const [runnerFor, setRunnerFor] = useState<InstalledIntegration | null>(null);
  const [detailExec, setDetailExec] = useState<IntegrationExecution | null>(null);
  const [testOutcomes, setTestOutcomes] = useState<Record<string, TestOutcome>>({});
  const [busy, setBusy] = useState<Record<string, string>>({});
  const [rowErrors, setRowErrors] = useState<Record<string, { what: string; error: unknown }>>({});
  const [confirmDelete, setConfirmDelete] = useState<InstalledIntegration | null>(null);
  const [highlightId, setHighlightId] = useState<string | null>(null);

  const loadInstalled = useCallback(async () => {
    try {
      setInstalled(await integrationsApi.getInstalled());
      setInstalledError(null);
    } catch (e) {
      setInstalled([]);
      setInstalledError(e ?? new Error('request failed'));
    }
  }, []);

  const loadExecutions = useCallback(async () => {
    try {
      const res = await integrationsApi.getExecutions();
      setExecutions(res.items);
      setExecutionsTotal(res.total);
      setExecutionsError(null);
    } catch (e) {
      setExecutions([]);
      setExecutionsTotal(null);
      setExecutionsError(e ?? new Error('request failed'));
    }
  }, []);

  const loadWebhooks = useCallback(async () => {
    try {
      const res = await integrationsApi.getWebhooks();
      setWebhooks(res.items);
      setWebhooksTotal(res.total);
      setWebhooksError(null);
    } catch (e) {
      setWebhooks([]);
      setWebhooksTotal(null);
      setWebhooksError(e ?? new Error('request failed'));
    }
  }, []);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const loadConnectors = async () => {
        try {
          setConnectors(await integrationsApi.getConnectors());
          setConnectorsError(null);
        } catch (e) {
          setConnectors([]);
          setConnectorsError(e ?? new Error('request failed'));
        }
      };
      await Promise.all([loadConnectors(), loadInstalled(), loadExecutions(), loadWebhooks()]);
    } finally {
      setLoading(false);
    }
  }, [loadInstalled, loadExecutions, loadWebhooks]);

  React.useEffect(() => {
    loadData();
  }, [loadData]);

  // Installation state and health come from the org's installed rows.
  const installedByConnector = new Map<string, InstalledIntegration>(installed.map((i) => [i.connector_id, i]));
  const connectorById = new Map<string, Connector>(connectors.map((c) => [c.id, c]));
  const installableNotInstalled: number | null =
    connectorsError || installedError ? null : connectors.filter((c) => c.installable && !installedByConnector.has(c.id)).length;
  const installedCount: number | null = installedError ? null : installed.length;
  const healthCounts = installed.reduce<Record<string, number>>((acc, i) => {
    const k = i.health_status || 'unknown';
    acc[k] = (acc[k] ?? 0) + 1;
    return acc;
  }, {});
  const healthyCount: number | null = installedError ? null : healthCounts.healthy ?? 0;
  const shown = (n: number | null) => (n === null ? 'not available' : `${n}`);

  // Execution rows carry the installed integration id; name it from the
  // installed list and the connector registry.
  const integrationLabel = (installedId: string | null | undefined): string => {
    const inst = installed.find((i) => i.id === installedId);
    if (!inst) return installedId ? `integration ${String(installedId).slice(0, 8)}` : 'unknown integration';
    const conn = connectorById.get(inst.connector_id);
    return inst.display_name || conn?.display_name || conn?.name || inst.connector_id || String(installedId).slice(0, 8);
  };
  const execInstallId = (e: IntegrationExecution) => e.installed_id ?? e.installation_id ?? null;

  const categories = ['all', ...new Set(connectors.map((c) => c.category).filter(Boolean))];
  const filteredConnectors = connectors.filter((c) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      (c.display_name || c.name || '').toLowerCase().includes(q) || (c.vendor || '').toLowerCase().includes(q);
    const matchesCategory = categoryFilter === 'all' || c.category === categoryFilter;
    return matchesSearch && matchesCategory;
  });

  const tabs = [
    { id: 'marketplace', label: 'Marketplace', icon: Plug },
    { id: 'installed', label: 'Installed', icon: CheckCircle },
    { id: 'executions', label: 'Executions', icon: Activity },
    { id: 'webhooks', label: 'Webhooks', icon: Settings },
  ];

  const openInstalledEntry = (inst: InstalledIntegration) => {
    setDetailConnector(null);
    setActiveTab('installed');
    setHighlightId(inst.id);
    window.setTimeout(() => document.getElementById(`installed-${inst.id}`)?.scrollIntoView({ block: 'center' }), 0);
  };

  const withRow = async (inst: InstalledIntegration, what: string, fn: () => Promise<void>) => {
    setBusy((b) => ({ ...b, [inst.id]: what }));
    setRowErrors((r) => {
      const next = { ...r };
      delete next[inst.id];
      return next;
    });
    try {
      await fn();
    } catch (error) {
      setRowErrors((r) => ({ ...r, [inst.id]: { what, error } }));
    } finally {
      setBusy((b) => {
        const next = { ...b };
        delete next[inst.id];
        return next;
      });
    }
  };

  const runTest = (inst: InstalledIntegration) =>
    withRow(inst, 'test the connection', async () => {
      try {
        const result = await integrationsApi.test(inst.id);
        setTestOutcomes((t) => ({ ...t, [inst.id]: { kind: 'result', result } }));
      } catch (error) {
        if (httpStatusOf(error) === 501) {
          setTestOutcomes((t) => ({
            ...t,
            [inst.id]: { kind: 'not_testable', detail: errorDetailText(error) || 'no connection test for this connector' },
          }));
        } else {
          setTestOutcomes((t) => ({ ...t, [inst.id]: { kind: 'error', error } }));
        }
      }
      // The test persists health_status / last_health_check / error_message.
      await loadInstalled();
    });

  const toggleEnabled = (inst: InstalledIntegration) =>
    withRow(inst, inst.status === 'active' ? 'disable the integration' : 'enable the integration', async () => {
      if (inst.status === 'active') await integrationsApi.disable(inst.id);
      else await integrationsApi.enable(inst.id);
      await loadInstalled();
    });

  const doDelete = (inst: InstalledIntegration) =>
    withRow(inst, 'delete the integration', async () => {
      await integrationsApi.uninstall(inst.id);
      setConfirmDelete(null);
      await loadInstalled();
    });

  const openConfigure = (inst: InstalledIntegration) => {
    const connector = connectorById.get(inst.connector_id);
    if (!connector) {
      setRowErrors((r) => ({
        ...r,
        [inst.id]: { what: 'configure', error: new Error(`connector ${inst.connector_id} is not in the catalogue`) },
      }));
      return;
    }
    setFormTarget({ connector, installation: inst });
  };

  const testOutcomeView = (inst: InstalledIntegration) => {
    const o = testOutcomes[inst.id];
    if (!o) return null;
    if (o.kind === 'not_testable') {
      return <p className="text-sm text-gray-600 dark:text-gray-300">Not testable: {o.detail}</p>;
    }
    if (o.kind === 'error') return <ActionErrorBanner what="test the connection" error={o.error} />;
    const r = o.result;
    const ok = r.status === 'healthy' || r.status === 'success';
    const checked = typeof r.details?.checked === 'string' ? r.details.checked : null;
    const http = r.details?.http_status;
    return (
      <div
        className={clsx(
          'text-sm rounded p-3 border',
          ok
            ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-800 dark:text-green-200'
            : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-800 dark:text-red-200',
        )}
      >
        <p>
          Test result: <span className="font-semibold">{r.status}</span>
        </p>
        <ServerMessage text={r.message} className="break-words" />
        <p className="text-xs mt-1 opacity-80">
          {checked ? `Checked: ${checked} · ` : ''}
          {http !== undefined && http !== null ? `HTTP ${String(http)} · ` : ''}
          {formatTime(r.timestamp) ?? 'no timestamp'}
        </p>
      </div>
    );
  };

  const detailInstallation = detailConnector ? installedByConnector.get(detailConnector.id) ?? null : null;

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
            onClick={() => {
              setActiveTab('webhooks');
              setWebhookFormFor({ integrationId: null });
            }}
            disabled={!canAdmin}
            title={canAdmin ? undefined : ADMIN_ONLY_REASON}
            className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Plus className="w-4 h-4" />
            New Webhook
          </button>
        </div>

        {/* Summary Cards: counts only, from the catalogue and this org's installed rows. */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Available Connectors</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{shown(installableNotInstalled)}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">installable, not yet installed</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">Installed</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{shown(installedCount)}</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">in this organisation</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Healthy</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{shown(healthyCount)}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">last connection test passed</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Health</p>
            {installedError ? (
              <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">not available</p>
            ) : installed.length === 0 ? (
              <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">none installed</p>
            ) : (
              <p className="text-sm font-semibold text-orange-900 dark:text-orange-100 mt-2 leading-6">
                {healthCounts.healthy ?? 0} healthy · {healthCounts.unhealthy ?? 0} unhealthy · {healthCounts.unknown ?? 0} unknown
                {healthCounts.unavailable ? ` · ${healthCounts.unavailable} unavailable` : ''}
              </p>
            )}
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">recorded by the last test of each install</p>
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

                {!connectorsError && connectors.length === 0 && (
                  <p className="text-sm text-gray-500 dark:text-gray-400">The connector catalogue returned no entries.</p>
                )}
                {connectors.length > 0 && filteredConnectors.length === 0 && (
                  <p className="text-sm text-gray-500 dark:text-gray-400">No connector matches the search and category filter.</p>
                )}

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {filteredConnectors.map((connector) => {
                    const installation = installedByConnector.get(connector.id);
                    return (
                      <div
                        key={connector.id}
                        role="button"
                        tabIndex={0}
                        onClick={() => setDetailConnector(connector)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' && e.target === e.currentTarget) setDetailConnector(connector);
                        }}
                        className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition flex flex-col cursor-pointer"
                      >
                        <div className="flex items-start justify-between mb-3 gap-2">
                          <span className="text-xs text-gray-600 dark:text-gray-400">{connector.vendor || ''}</span>
                          <span className="flex gap-1 flex-wrap justify-end">
                            <ImplementationBadge status={connector.implementation_status} />
                            {connector.ingest && <IngestBadge />}
                          </span>
                        </div>
                        <h3 className="font-semibold text-lg mb-1">{connector.display_name || connector.name}</h3>
                        <div className="flex gap-2 mb-2 flex-wrap">
                          <span className="text-xs px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100 rounded w-fit">
                            {connector.category}
                          </span>
                          {/* External-SIEM badge: distinguishes optional interop
                              connectors from PySOAR's native SIEM. */}
                          {connector.integration_role === 'external_siem' && (
                            <span
                              title="Optional interop. PySOAR already ships its own native SIEM. Install this only if you have an existing deployment you want to pull events from."
                              className="text-xs px-2 py-1 bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-200 rounded w-fit border border-amber-300 dark:border-amber-800"
                            >
                              Optional · External SIEM
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{connector.description}</p>
                        <p className="text-xs text-gray-500 dark:text-gray-400 italic mb-4 flex-grow">{connector.verification}</p>
                        {installation ? (
                          <div className="space-y-2">
                            <HealthBadge health={installation.health_status} />
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                openInstalledEntry(installation);
                              }}
                              className={clsx(BTN, 'w-full')}
                            >
                              Open installed entry
                            </button>
                          </div>
                        ) : connector.installable ? (
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setFormTarget({ connector, installation: null });
                            }}
                            disabled={!canAdmin}
                            title={canAdmin ? undefined : ADMIN_ONLY_REASON}
                            className="w-full px-3 py-2 text-sm bg-cyan-600 hover:bg-cyan-700 text-white rounded transition flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                          >
                            <Download className="w-4 h-4" />
                            Install
                          </button>
                        ) : (
                          <p className="text-sm text-gray-500 dark:text-gray-400">Planned: not installable in this release</p>
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
                {!installedError && installed.length === 0 && (
                  <p className="text-sm text-gray-500 dark:text-gray-400">No integrations installed. Install one from the Marketplace.</p>
                )}
                <div className="grid grid-cols-1 gap-4">
                  {installed.map((integration) => {
                    const rowBusy = busy[integration.id];
                    const rowError = rowErrors[integration.id];
                    const connector = connectorById.get(integration.connector_id);
                    return (
                      <div
                        key={integration.id}
                        id={`installed-${integration.id}`}
                        className={clsx(
                          'bg-white dark:bg-gray-800 border rounded-lg p-4 hover:shadow-lg transition space-y-4',
                          highlightId === integration.id ? 'border-cyan-500 ring-2 ring-cyan-500/40' : 'border-gray-200 dark:border-gray-700',
                        )}
                      >
                        <div className="flex justify-between items-start gap-4">
                          <div className="flex-1">
                            <h3 className="font-semibold text-lg">{integration.display_name}</h3>
                            <p className="text-sm text-gray-600 dark:text-gray-400 font-mono">
                              {integration.connector_id}
                              {connector ? ` · ${connector.display_name}` : ''}
                            </p>
                          </div>
                          <HealthBadge health={integration.health_status} />
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Last Health Check</p>
                            <p className="font-medium">{formatTime(integration.last_health_check) ?? 'Never tested'}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Status</p>
                            <p className="font-medium capitalize">{integration.status || 'not available'}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Last Successful Action</p>
                            <p className="font-medium">{formatTime(integration.last_successful_action) ?? 'Never'}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Last Error</p>
                            {integration.error_message ? (
                              <ServerMessage text={integration.error_message} className="font-medium break-words" />
                            ) : (
                              <p className="font-medium">None</p>
                            )}
                          </div>
                        </div>
                        {testOutcomeView(integration)}
                        {rowError && <ActionErrorBanner what={rowError.what} error={rowError.error} />}
                        <div className="flex gap-2 flex-wrap">
                          <button
                            onClick={() => runTest(integration)}
                            disabled={!canOperate || !!rowBusy}
                            title={canOperate ? "Runs the connector's read-only test call" : ANALYST_ONLY_REASON}
                            className={clsx(BTN, 'flex-1')}
                          >
                            {rowBusy === 'test the connection' && <Loader2 className="w-4 h-4 animate-spin" />}
                            Test
                          </button>
                          <button
                            onClick={() => openConfigure(integration)}
                            disabled={!canAdmin || !!rowBusy}
                            title={canAdmin ? undefined : ADMIN_ONLY_REASON}
                            className={clsx(BTN, 'flex-1')}
                          >
                            <Settings className="w-4 h-4" />
                            Configure
                          </button>
                          <button
                            onClick={() => setRunnerFor(integration)}
                            className={clsx(BTN, 'flex-1')}
                            title="Declared actions of this integration"
                          >
                            <Play className="w-4 h-4" />
                            Actions
                          </button>
                          <button
                            onClick={() => toggleEnabled(integration)}
                            disabled={!canAdmin || !!rowBusy}
                            title={canAdmin ? undefined : ADMIN_ONLY_REASON}
                            className={clsx(BTN, 'flex-1')}
                          >
                            <Power className="w-4 h-4" />
                            {integration.status === 'active' ? 'Disable' : 'Enable'}
                          </button>
                          <button
                            onClick={() => setConfirmDelete(integration)}
                            disabled={!canAdmin || !!rowBusy}
                            title={canAdmin ? 'Delete this integration' : ADMIN_ONLY_REASON}
                            className={clsx(BTN, 'text-red-600 dark:text-red-400')}
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
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
                          <td className="px-6 py-4 text-sm font-medium">{integrationLabel(execInstallId(exec))}</td>
                          <td className="px-6 py-4 text-sm">{formatTime(exec.started_at || exec.created_at) ?? 'not started'}</td>
                          <td className="px-6 py-4">
                            <ExecutionStatusBadge status={exec.status} httpStatus={exec.http_status} />
                            {exec.error_code && (
                              <span className="block mt-1 text-xs font-mono text-gray-500 dark:text-gray-400">{exec.error_code}</span>
                            )}
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
              <WebhooksPanel
                webhooks={webhooks}
                total={webhooksTotal}
                loadError={webhooksError}
                installed={installed}
                integrationLabel={integrationLabel}
                canAdmin={canAdmin}
                canOperate={canOperate}
                onCreate={(integrationId) => setWebhookFormFor({ integrationId })}
                testWebhook={integrationsApi.testWebhook}
                deleteWebhook={integrationsApi.deleteWebhook}
                onChanged={loadWebhooks}
              />
            )}
          </>
        )}
      </div>

      {/* New webhook endpoint */}
      <WebhookFormModal
        open={!!webhookFormFor}
        installed={installed}
        initialIntegrationId={webhookFormFor?.integrationId ?? null}
        onClose={() => setWebhookFormFor(null)}
        onCreate={async (integrationId, body) => {
          await integrationsApi.createWebhook(integrationId, body);
          await loadWebhooks();
        }}
      />

      {/* Install / configure form */}
      <ConnectorFormModal
        open={!!formTarget}
        connector={formTarget?.connector ?? null}
        installation={formTarget?.installation ?? null}
        onClose={() => setFormTarget(null)}
        onInstall={async (body) => {
          const inst = await integrationsApi.install(body);
          await loadInstalled();
          setTestOutcomes((t) => {
            const next = { ...t };
            delete next[inst.id];
            return next;
          });
        }}
        onUpdate={async (id, body) => {
          await integrationsApi.update(id, body);
          setTestOutcomes((t) => {
            const next = { ...t };
            delete next[id];
            return next;
          });
          await loadInstalled();
        }}
      />

      {/* Connector detail drawer */}
      <DetailDrawer
        open={!!detailConnector}
        onClose={() => setDetailConnector(null)}
        title={detailConnector ? detailConnector.display_name || detailConnector.name : 'Connector'}
        subtitle={detailConnector ? `${detailConnector.vendor || 'vendor not named'} · ${detailConnector.category}` : undefined}
        sections={
          detailConnector
            ? ([
                {
                  title: 'Connector',
                  fields: [
                    { label: 'Description', value: detailConnector.description, full: true },
                    { label: 'Vendor', value: detailConnector.vendor },
                    { label: 'Identifier', value: detailConnector.id, mono: true },
                    {
                      label: 'Status',
                      value: (
                        <span className="flex gap-1 flex-wrap">
                          <ImplementationBadge status={detailConnector.implementation_status} />
                          {detailConnector.ingest && <IngestBadge />}
                        </span>
                      ),
                    },
                    ...(detailConnector.ingest
                      ? [
                          {
                            label: 'Ingest',
                            value: "Once installed, the SIEM cloud poller pulls this connector's events on a schedule.",
                            full: true,
                          },
                        ]
                      : []),
                    { label: 'Installed here', value: detailInstallation ? <HealthBadge health={detailInstallation.health_status} /> : 'no' },
                    { label: 'Verification', value: detailConnector.verification, full: true },
                    { label: 'Read-only test call', value: detailConnector.test_call || 'none', mono: true, full: true },
                  ],
                },
                {
                  title: 'Fields',
                  fields: [
                    { label: 'Configuration', value: <FieldsTable fields={detailConnector.config_fields} title="Configuration" />, full: true },
                    { label: 'Credentials (stored encrypted, never returned)', value: <FieldsTable fields={detailConnector.credential_fields} title="Credential" />, full: true },
                  ],
                },
                {
                  title: 'Actions',
                  fields: [
                    {
                      label: detailConnector.actions.length ? `${detailConnector.actions.length} declared` : 'Declared actions',
                      full: true,
                      value: detailConnector.actions.length ? (
                        <table className="w-full text-sm">
                          <thead>
                            <tr className="text-left text-xs text-gray-500 dark:text-gray-400">
                              <th className="py-1 pr-2">Action</th>
                              <th className="py-1 pr-2">Description</th>
                              <th className="py-1">Kind</th>
                            </tr>
                          </thead>
                          <tbody>
                            {detailConnector.actions.map((a) => (
                              <tr key={a.name} className="border-t border-gray-100 dark:border-gray-800 align-top">
                                <td className="py-1 pr-2 font-mono">{a.name}</td>
                                <td className="py-1 pr-2">{a.description}</td>
                                <td className="py-1 space-y-1">
                                  {a.side_effect ? <SideEffectBadge /> : <span className="text-xs text-gray-500 dark:text-gray-400 block">read-only</span>}
                                  {a.idempotent && <span className="text-xs text-gray-500 dark:text-gray-400 block">idempotent</span>}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : (
                        'This connector declares no actions.'
                      ),
                    },
                  ],
                },
              ] as DetailSection[])
            : undefined
        }
        actions={
          detailConnector ? (
            detailInstallation ? (
              <button onClick={() => openInstalledEntry(detailInstallation)} className={BTN}>
                Open installed entry
              </button>
            ) : detailConnector.installable ? (
              <button
                onClick={() => {
                  const c = detailConnector;
                  setDetailConnector(null);
                  setFormTarget({ connector: c, installation: null });
                }}
                disabled={!canAdmin}
                title={canAdmin ? undefined : ADMIN_ONLY_REASON}
                className="px-4 py-2 text-sm bg-cyan-600 hover:bg-cyan-700 text-white rounded flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <Download className="w-4 h-4" />
                Install
              </button>
            ) : (
              <span className="text-sm text-gray-500 dark:text-gray-400">Planned: not installable in this release</span>
            )
          ) : undefined
        }
      />

      {/* Action runner */}
      <ActionRunnerDrawer
        installation={runnerFor}
        isAdmin={canAdmin}
        isAnalyst={canOperate}
        onClose={() => setRunnerFor(null)}
        loadActions={integrationsApi.getActions}
        execute={integrationsApi.executeAction}
        onExecuted={() => {
          loadExecutions();
          loadInstalled();
        }}
        onShowExecutions={() => {
          setRunnerFor(null);
          setActiveTab('executions');
        }}
      />

      {/* Delete confirmation */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" aria-modal="true" role="dialog">
          <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => !busy[confirmDelete.id] && setConfirmDelete(null)} />
          <div className="relative w-full max-w-md bg-white dark:bg-gray-900 rounded-lg shadow-2xl border border-gray-200 dark:border-gray-700 p-6 space-y-4">
            <h2 className="text-lg font-semibold">Delete {confirmDelete.display_name}?</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              The installed integration and its stored credentials are removed from this organisation. Playbook steps that use it will stop working.
            </p>
            {rowErrors[confirmDelete.id] && (
              <ActionErrorBanner what={rowErrors[confirmDelete.id].what} error={rowErrors[confirmDelete.id].error} />
            )}
            <div className="flex justify-end gap-2">
              <button onClick={() => setConfirmDelete(null)} disabled={!!busy[confirmDelete.id]} className={BTN}>
                Cancel
              </button>
              <button
                onClick={() => doDelete(confirmDelete)}
                disabled={!!busy[confirmDelete.id]}
                className="px-4 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded flex items-center gap-2 disabled:opacity-50"
              >
                {busy[confirmDelete.id] && <Loader2 className="w-4 h-4 animate-spin" />}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Execution detail drawer */}
      <DetailDrawer
        open={!!detailExec}
        onClose={() => setDetailExec(null)}
        title={`Execution · ${detailExec ? integrationLabel(execInstallId(detailExec)) : 'Integration'}`}
        subtitle={detailExec ? `${detailExec.status || 'unknown'} · ${detailExec.triggered_by || 'trigger not recorded'}` : undefined}
        sections={
          detailExec
            ? ([
                {
                  title: 'Execution',
                  fields: [
                    { label: 'Execution ID', value: detailExec.id, mono: true, full: true },
                    { label: 'Integration', value: integrationLabel(execInstallId(detailExec)) },
                    { label: 'Action ID', value: detailExec.action_id, mono: true },
                    { label: 'Status', value: <ExecutionStatusBadge status={detailExec.status} httpStatus={detailExec.http_status} /> },
                    { label: 'Triggered by', value: detailExec.triggered_by },
                    { label: 'Playbook run', value: detailExec.playbook_run_id, mono: true },
                    { label: 'Duration', value: detailExec.duration_ms != null ? `${detailExec.duration_ms} ms` : null },
                    { label: 'Retries', value: detailExec.retry_count },
                    // Stored on the execution row since migration 039; older rows have neither.
                    { label: 'Error code', value: detailExec.error_code || 'none recorded', mono: true },
                    { label: 'HTTP status', value: detailExec.http_status ?? 'none recorded' },
                    { label: 'Started', value: formatTime(detailExec.started_at) },
                    { label: 'Completed', value: formatTime(detailExec.completed_at) },
                  ],
                },
                {
                  title: 'Input and result',
                  fields: [
                    {
                      label: 'Error',
                      value: detailExec.error_message ? (
                        <ServerMessage text={detailExec.error_message} className="font-mono text-sm break-words" />
                      ) : null,
                      full: true,
                    },
                    {
                      label: 'Input',
                      value: formatJson(detailExec.input_data) ? <pre className="text-xs whitespace-pre-wrap">{formatJson(detailExec.input_data)}</pre> : null,
                      full: true,
                    },
                    {
                      label: 'Output',
                      value: formatJson(detailExec.output_data) ? <pre className="text-xs whitespace-pre-wrap">{formatJson(detailExec.output_data)}</pre> : null,
                      full: true,
                    },
                  ],
                },
              ] as DetailSection[])
            : undefined
        }
      />
    </div>
  );
}
