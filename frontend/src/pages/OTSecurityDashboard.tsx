import { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  AlertTriangle,
  Server,
  Cpu,
  Network,
  Eye,
  Search,
  Layers,
  Wifi,
  WifiOff,
  Lock,
  Download,
  Power,
  BookOpen,
  RefreshCw,
} from 'lucide-react';
import clsx from 'clsx';
import { otsecurityApi } from '../api/endpoints';
import { api } from '../lib/api';
import DetailDrawer, { DetailSection } from '../components/DetailDrawer';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';

const NA = 'not available';

// Agent capabilities the OT actions are commanded through
// (src/agents/capabilities.py); both go through the agent approval queue.
const SAFE_SHUTDOWN_CAPABILITY = 'ot_safe_shutdown';
const SEGMENTATION_CAPABILITY = 'ot_segmentation_probe';

const actionStatusColor = (status: string | null | undefined) => {
  switch (status) {
    case 'completed':
    case 'verified':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'failed':
    case 'violations':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'pending':
    case 'awaiting_approval':
    case 'dispatched':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

const getSeverityColor = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'high':
      return 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-100';
    case 'medium':
      return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
    case 'low':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

const getStatusColor = (status: string) => {
  switch (status?.toLowerCase()) {
    case 'online':
    case 'active':
    case 'secure':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'offline':
    case 'inactive':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    case 'warning':
    case 'degraded':
      return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
    case 'critical':
    case 'breached':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'monitoring':
    case 'in-progress':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'acknowledged':
      return 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

const getPurdueLevel = (level: number) => {
  switch (level) {
    case 0:
      return { label: 'Level 0 - Process', color: 'bg-red-600', description: 'Physical process sensors & actuators' };
    case 1:
      return { label: 'Level 1 - Basic Control', color: 'bg-orange-600', description: 'PLCs, RTUs, safety systems' };
    case 2:
      return { label: 'Level 2 - Area Control', color: 'bg-yellow-600', description: 'HMIs, SCADA, DCS' };
    case 3:
      return { label: 'Level 3 - Site Operations', color: 'bg-blue-600', description: 'Historians, MES, operations management' };
    case 4:
      return { label: 'Level 4 - Enterprise', color: 'bg-green-600', description: 'ERP, email, business network' };
    case 5:
      return { label: 'Level 5 - DMZ / Cloud', color: 'bg-purple-600', description: 'Cloud services, remote access' };
    default:
      return { label: `Level ${level}`, color: 'bg-gray-600', description: 'Unknown level' };
  }
};

export default function OTSecurityDashboard() {
  const [activeTab, setActiveTab] = useState('assets');
  const [assets, setAssets] = useState<Row[]>([]);
  const [alerts, setAlerts] = useState<Row[]>([]);
  const [zones, setZones] = useState<Row[]>([]);
  const [incidents, setIncidents] = useState<Row[]>([]);
  const [purdueMap, setPurdueMap] = useState<Row | null>(null);
  const [advisoryFeed, setAdvisoryFeed] = useState<Row | null>(null);
  const [advisories, setAdvisories] = useState<Row | null>(null);
  const [agentsByCapability, setAgentsByCapability] = useState<Record<string, Row[]>>({});
  const [loadErrors, setLoadErrors] = useState<Record<string, unknown>>({});
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [detailAsset, setDetailAsset] = useState<Row | null>(null);
  const [detailAlert, setDetailAlert] = useState<Row | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [actionTarget, setActionTarget] = useState<{ kind: 'shutdown' | 'segmentation'; row: Row } | null>(null);
  const [actionAgent, setActionAgent] = useState('');
  const [actionViews, setActionViews] = useState<Record<string, Row>>({});
  const [notice, setNotice] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const results = await Promise.allSettled([
        otsecurityApi.getAssets(),
        otsecurityApi.getAlerts(),
        otsecurityApi.getZones(),
        otsecurityApi.getPurdueMap(),
        api.get('/ot_security/incidents').then((r) => r.data),
        api.get('/ot_security/advisories/status').then((r) => r.data),
        api.get('/agents', { params: { capability: SAFE_SHUTDOWN_CAPABILITY, status: 'active' } }).then((r) => r.data),
        api.get('/agents', { params: { capability: SEGMENTATION_CAPABILITY, status: 'active' } }).then((r) => r.data),
      ]);
      const keys = ['assets', 'alerts', 'zones', 'purdue', 'incidents', 'feed', 'shutdownAgents', 'probeAgents'];
      const errs: Record<string, unknown> = {};
      results.forEach((r, i) => { if (r.status === 'rejected') errs[keys[i]] = r.reason; });
      setLoadErrors(errs);
      const value = (i: number): Row | Row[] | null => (results[i].status === 'fulfilled' ? (results[i] as PromiseFulfilledResult<Row>).value : null);
      const toItems = (d: Row | Row[] | null): Row[] => (Array.isArray(d) ? d : (d?.items || []));
      setAssets(toItems(value(0)));
      setAlerts(toItems(value(1)));
      setZones(toItems(value(2)));
      setPurdueMap((value(3) as Row | null) || null);
      setIncidents(toItems(value(4)));
      setAdvisoryFeed((value(5) as Row | null) || null);
      setAgentsByCapability({
        [SAFE_SHUTDOWN_CAPABILITY]: ((value(6) as Row | null)?.agents ?? []) as Row[],
        [SEGMENTATION_CAPABILITY]: ((value(7) as Row | null)?.agents ?? []) as Row[],
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const loadAdvisories = async () => {
    setBusy('advisories');
    setActionError(null);
    try {
      const res = await api.get('/ot_security/advisories');
      setAdvisories(res.data);
      if (res.data?.advisory_feed) setAdvisoryFeed(res.data.advisory_feed);
    } catch (error) {
      setActionError({ what: 'load matched advisories', error });
    } finally {
      setBusy(null);
    }
  };

  const refreshAdvisories = async (force: boolean) => {
    setBusy('refresh');
    setActionError(null);
    setNotice(null);
    try {
      const res = await api.post('/ot_security/advisories/refresh', null, { params: { force } });
      setNotice(`Advisory feed ${String(res.data?.status ?? '').replace(/_/g, ' ')}: ${res.data?.entries ?? res.data?.feed?.entries ?? 0} cached advisories.`);
      if (res.data?.feed) setAdvisoryFeed(res.data.feed);
      await loadAdvisories();
    } catch (error) {
      setActionError({ what: 'refresh the CISA ICS advisory feed', error });
    } finally {
      setBusy(null);
    }
  };

  // GET .../safe_shutdown and .../segmentation_audit refresh the state from
  // the agent command (approval, dispatch, result).
  const loadActionStatus = async (kind: 'shutdown' | 'segmentation', id: string) => {
    setActionError(null);
    try {
      const url = kind === 'shutdown' ? `/ot_security/incidents/${id}/safe_shutdown` : `/ot_security/zones/${id}/segmentation_audit`;
      const res = await api.get(url);
      setActionViews((prev) => ({ ...prev, [`${kind}:${id}`]: res.data }));
    } catch (error) {
      setActionError({ what: kind === 'shutdown' ? 'read the safe shutdown status' : 'read the segmentation audit status', error });
    }
  };

  const submitAction = async () => {
    if (!actionTarget) return;
    const { kind, row } = actionTarget;
    setBusy('action');
    setActionError(null);
    try {
      const url = kind === 'shutdown' ? `/ot_security/incidents/${row.id}/safe_shutdown` : `/ot_security/zones/${row.id}/segmentation_audit`;
      const res = await api.post(url, actionAgent ? { agent_id: actionAgent } : {});
      setActionViews((prev) => ({ ...prev, [`${kind}:${row.id}`]: res.data }));
      setActionTarget(null);
      setNotice(
        kind === 'shutdown'
          ? `Safe shutdown command queued (${String(res.data?.status ?? '').replace(/_/g, ' ')}). It waits for a second administrator's approval in the agent queue.`
          : `Segmentation probe queued (${String(res.data?.status ?? '').replace(/_/g, ' ')}, ${res.data?.probes_planned ?? 0} probe(s) planned). It waits for approval in the agent queue.`,
      );
      await loadData();
    } catch (error) {
      setActionError({ what: kind === 'shutdown' ? 'command a safe shutdown' : 'start the segmentation audit', error });
    } finally {
      setBusy(null);
    }
  };

  const exportReport = async (format: 'json' | 'csv') => {
    setActionError(null);
    try {
      const res = await api.get('/ot_security/export', { params: { format }, responseType: 'blob' });
      // Force a non-executable MIME type on the download regardless of what the
      // response carried; the file is saved, never rendered.
      const safeType = format === 'json' ? 'application/json' : 'text/csv';
      const url = URL.createObjectURL(new Blob([res.data as Blob], { type: safeType }));
      const a = document.createElement('a');
      a.href = url;
      a.download = `ot-security-report.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (error) {
      setActionError({ what: 'export the OT report', error });
    }
  };

  const totalAssets: number | null = loadErrors.assets ? null : assets.length;
  const onlineAssets: number | null = loadErrors.assets ? null : assets.filter((a) => a.is_online === true || a.status === 'online').length;
  const activeAlerts: number | null = loadErrors.alerts ? null : alerts.filter((a) => !['resolved', 'contained', 'false_positive'].includes(a.status)).length;
  const securityZones: number | null = loadErrors.zones ? null : zones.length;

  const tabs = [
    { id: 'assets', label: 'Assets', icon: Server },
    { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
    { id: 'incidents', label: 'Incidents', icon: Power },
    { id: 'zones', label: 'Zones', icon: Shield },
    { id: 'advisories', label: 'ICS Advisories', icon: BookOpen },
    { id: 'purdue', label: 'Purdue Model', icon: Layers },
  ];

  const filteredAssets = assets.filter(
    (a) =>
      (a.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.asset_type || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.vendor || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredAlerts = alerts.filter(
    (a) =>
      (a.description || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.source_ip || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (a.alert_type || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const purdueDevices = purdueMap?.levels || [];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Cpu className="w-8 h-8 text-indigo-600" />
            <h1 className="text-3xl font-bold">OT/ICS Security</h1>
          </div>
          <div className="flex gap-2">
            <button onClick={() => exportReport('json')} className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
              <Download className="w-4 h-4" />
              Export JSON
            </button>
            <button onClick={() => exportReport('csv')} className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
              <Download className="w-4 h-4" />
              Export CSV
            </button>
          </div>
        </div>

        <div className="space-y-2 mb-4 empty:hidden">
          {actionError && !actionTarget && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
          {notice && (
            <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 flex justify-between gap-4">
              <span>{notice}</span>
              <button onClick={() => setNotice(null)} className="text-xs underline">dismiss</button>
            </div>
          )}
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-indigo-50 to-indigo-100 dark:from-indigo-900 dark:to-indigo-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-indigo-600 dark:text-indigo-300">Total OT Assets</p>
            <p className="text-3xl font-bold text-indigo-900 dark:text-indigo-100 mt-2">{totalAssets ?? NA}</p>
            <p className="text-xs text-indigo-600 dark:text-indigo-300 mt-1">across all zones</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">Online Assets</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{onlineAssets ?? NA}</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">currently communicating</p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Active Alerts</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{activeAlerts ?? NA}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">requiring attention</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Security Zones</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{securityZones ?? NA}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">configured</p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6">
        <div className="flex gap-8 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'py-4 px-2 border-b-2 font-medium flex items-center gap-2 transition whitespace-nowrap',
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

      {/* Content */}
      <div className="p-6">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="flex flex-col items-center gap-3">
              <div className="w-8 h-8 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin" />
              <p className="text-gray-500 dark:text-gray-400">Loading OT security data...</p>
            </div>
          </div>
        ) : (
          <>
            {/* Assets Tab */}
            {activeTab === 'assets' && (
              <div className="space-y-6">
                <LoadErrorBanner what="OT assets" error={loadErrors.assets} />
                {/* Asset summary cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Asset Types</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>PLCs / RTUs</span>
                        <span className="font-semibold">{assets.filter((a) => a.asset_type === 'plc' || a.asset_type === 'rtu').length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>HMIs / SCADA</span>
                        <span className="font-semibold">{assets.filter((a) => a.asset_type === 'hmi' || a.asset_type === 'scada_server').length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Engineering Workstations</span>
                        <span className="font-semibold">{assets.filter((a) => a.asset_type === 'engineering_workstation').length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Network Devices</span>
                        <span className="font-semibold">{assets.filter((a) => a.asset_type === 'network_switch' || a.asset_type === 'firewall').length}</span>
                      </div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Communication Protocols</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Modbus TCP</span>
                        <span className="font-semibold">{assets.filter((a) => a.protocol === 'modbus_tcp').length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>EtherNet/IP</span>
                        <span className="font-semibold">{assets.filter((a) => a.protocol === 'ethernetip').length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>DNP3</span>
                        <span className="font-semibold">{assets.filter((a) => a.protocol === 'dnp3').length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>OPC UA</span>
                        <span className="font-semibold">{assets.filter((a) => a.protocol === 'opc_ua').length}</span>
                      </div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Firmware &amp; Advisories</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Marked current (recorded, not verified)</span>
                        <span className="font-semibold text-green-600">{assets.filter((a) => a.firmware_current === true).length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Assets with matched ICS advisories</span>
                        <span className="font-semibold text-red-600">{assets.filter((a) => (a.known_vulnerabilities_count || 0) > 0).length}</span>
                      </div>
                      <p className="text-xs text-gray-500">
                        Advisories are matched by vendor and model; firmware versions are never compared against affected ranges.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Search & filter */}
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search by name, type, or vendor..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                {/* Assets Table */}
                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Asset Name</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Type</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Vendor</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">IP Address</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Protocol</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Zone</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Last Seen</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAssets.length === 0 ? (
                        <tr>
                          <td colSpan={9} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                            No data available
                          </td>
                        </tr>
                      ) : (
                        filteredAssets.map((asset) => {
                          const online = asset.is_online === true || asset.status === 'online';
                          return (
                          <tr key={asset.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-medium flex items-center gap-2">
                              {online ? (
                                <Wifi className="w-4 h-4 text-green-500 flex-shrink-0" />
                              ) : (
                                <WifiOff className="w-4 h-4 text-gray-400 flex-shrink-0" />
                              )}
                              {asset.name}
                            </td>
                            <td className="px-6 py-4 text-sm uppercase">{asset.asset_type}</td>
                            <td className="px-6 py-4 text-sm">{asset.vendor}</td>
                            <td className="px-6 py-4 text-sm font-mono">{asset.ip_address}</td>
                            <td className="px-6 py-4 text-sm">{asset.protocol}</td>
                            <td className="px-6 py-4 text-sm">{asset.zone}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(online ? 'online' : 'offline')}`}>
                                {online ? 'online' : 'offline'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {asset.last_seen ? new Date(asset.last_seen).toLocaleString() : '\u2014'}
                            </td>
                            <td className="px-6 py-4 text-sm">
                              <button
                                onClick={() => setDetailAsset(asset)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                                title="View asset details"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                            </td>
                          </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Incidents Tab */}
            {activeTab === 'incidents' && (
              <div className="space-y-4">
                <LoadErrorBanner what="OT incidents" error={loadErrors.incidents} />
                <LoadErrorBanner what="agents with the ot_safe_shutdown capability" error={loadErrors.shutdownAgents} />
                <div className="text-sm bg-amber-50 dark:bg-amber-900/30 border border-amber-200 dark:border-amber-700 rounded p-3">
                  A safe shutdown is commanded through an endpoint agent enrolled with the <span className="font-mono">{SAFE_SHUTDOWN_CAPABILITY}</span> capability
                  ({(agentsByCapability[SAFE_SHUTDOWN_CAPABILITY] ?? []).length} active) and waits for a second administrator&apos;s approval.
                  &quot;Initiated&quot; is shown only after the agent reports success.
                </div>
                {!loadErrors.incidents && incidents.length === 0 && (
                  <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">No OT incident recorded.</p>
                )}
                {incidents.map((inc) => {
                  const view = actionViews[`shutdown:${inc.id}`];
                  const status = view?.status ?? inc.safe_shutdown_status ?? 'not_requested';
                  return (
                    <div key={inc.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 space-y-2">
                      <div className="flex justify-between items-start gap-4">
                        <div>
                          <h3 className="font-semibold">{inc.title}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">{inc.description}</p>
                          <p className="text-xs text-gray-500 mt-1">
                            {String(inc.incident_type || '').replace(/_/g, ' ')} · {inc.status} · {(inc.affected_assets ?? []).length} affected asset(s) · physical impact {inc.physical_impact_risk}
                          </p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(inc.severity)}`}>{inc.severity}</span>
                      </div>
                      <div className="flex flex-wrap items-center gap-2 text-sm">
                        <span>Safe shutdown:</span>
                        <span className={`px-2 py-0.5 rounded text-xs ${actionStatusColor(status)}`}>{String(status).replace(/_/g, ' ')}</span>
                        {(view?.safe_shutdown_initiated ?? inc.safe_shutdown_initiated) && <span className="text-xs text-green-700">initiated (agent reported success)</span>}
                        {(view?.detail ?? inc.safe_shutdown_detail) && <span className="text-xs text-gray-500">{view?.detail ?? inc.safe_shutdown_detail}</span>}
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => { setActionError(null); setActionAgent(''); setActionTarget({ kind: 'shutdown', row: inc }); }}
                          className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-700 text-white rounded"
                        >
                          Command Safe Shutdown (admin)
                        </button>
                        <button
                          onClick={() => loadActionStatus('shutdown', inc.id)}
                          className="flex items-center gap-1 px-3 py-1.5 text-xs border border-gray-300 dark:border-gray-600 rounded"
                        >
                          <RefreshCw className="w-3 h-3" /> Refresh Status
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Advisories Tab */}
            {activeTab === 'advisories' && (
              <div className="space-y-4">
                <LoadErrorBanner what="the advisory feed status" error={loadErrors.feed} />
                <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 text-sm space-y-2">
                  <div className="flex flex-wrap justify-between gap-2">
                    <div>
                      <p className="font-semibold">{advisoryFeed?.source ?? 'CISA ICS advisories'}</p>
                      <p className="text-gray-600 dark:text-gray-400">
                        Status: {String(advisoryFeed?.status ?? NA).replace(/_/g, ' ')} · {advisoryFeed?.entries ?? 0} cached ·
                        last success {advisoryFeed?.last_success_at ? new Date(advisoryFeed.last_success_at).toLocaleString() : 'never'}
                      </p>
                      {advisoryFeed?.last_error && <p className="text-red-600 text-xs">Last error: {advisoryFeed.last_error}</p>}
                    </div>
                    <div className="flex gap-2 items-start">
                      <button onClick={loadAdvisories} disabled={busy !== null} className="px-3 py-1.5 text-xs border border-gray-300 dark:border-gray-600 rounded disabled:opacity-50">
                        {busy === 'advisories' ? 'Matching...' : 'Match Assets'}
                      </button>
                      <button onClick={() => refreshAdvisories(false)} disabled={busy !== null} className="px-3 py-1.5 text-xs bg-indigo-600 text-white rounded disabled:opacity-50" title="Admin; served from cache when younger than 6 hours">
                        {busy === 'refresh' ? 'Refreshing...' : 'Refresh Feed'}
                      </button>
                      <button onClick={() => refreshAdvisories(true)} disabled={busy !== null} className="px-3 py-1.5 text-xs border border-indigo-600 text-indigo-700 dark:text-indigo-300 rounded disabled:opacity-50">
                        Force Refetch
                      </button>
                    </div>
                  </div>
                  <p className="text-xs text-gray-500">
                    Advisories are matched to stored assets by vendor and model only; affected firmware versions are not evaluated.
                  </p>
                </div>
                {advisories && (
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg overflow-x-auto">
                    <p className="text-xs text-gray-500 p-3">
                      {advisories.total} match(es) across {advisories.assets_checked} asset(s); {advisories.unmatchable_assets} asset(s) lack a vendor or model and cannot be matched.
                    </p>
                    {(advisories.items ?? []).length > 0 && (
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-gray-200 dark:border-gray-700 text-left">
                            <th className="px-4 py-2">Asset</th>
                            <th className="px-4 py-2">Advisory</th>
                            <th className="px-4 py-2">CVEs</th>
                            <th className="px-4 py-2">CVSS</th>
                            <th className="px-4 py-2">Firmware (not compared)</th>
                          </tr>
                        </thead>
                        <tbody>
                          {advisories.items.map((m: Row, i: number) => (
                            <tr key={`${m.asset_id}-${m.advisory_id}-${i}`} className="border-b border-gray-100 dark:border-gray-700">
                              <td className="px-4 py-2">{assets.find((a) => a.id === m.asset_id)?.name ?? m.asset_id}</td>
                              <td className="px-4 py-2">
                                {m.url ? <a href={m.url} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline">{m.advisory_id}</a> : m.advisory_id}
                                <div className="text-xs text-gray-500">{m.title}</div>
                              </td>
                              <td className="px-4 py-2 text-xs font-mono">{(m.cve_ids ?? []).join(', ') || '-'}</td>
                              <td className="px-4 py-2">{m.cvss_score ?? NA}</td>
                              <td className="px-4 py-2 font-mono text-xs">{m.firmware_version || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Alerts Tab */}
            {activeTab === 'alerts' && (
              <div className="space-y-6">
                <LoadErrorBanner what="OT alerts" error={loadErrors.alerts} />
                {/* Alert severity breakdown */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                  <div className="bg-white dark:bg-gray-800 border border-red-200 dark:border-red-700 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-1">
                      <AlertTriangle className="w-4 h-4 text-red-600" />
                      <p className="text-sm font-medium text-red-600 dark:text-red-300">Critical</p>
                    </div>
                    <p className="text-2xl font-bold">{alerts.filter((a) => a.severity === 'critical').length}</p>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-orange-200 dark:border-orange-700 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-1">
                      <Activity className="w-4 h-4 text-orange-600" />
                      <p className="text-sm font-medium text-orange-600 dark:text-orange-300">High</p>
                    </div>
                    <p className="text-2xl font-bold">{alerts.filter((a) => a.severity === 'high').length}</p>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-1">
                      <Activity className="w-4 h-4 text-yellow-600" />
                      <p className="text-sm font-medium text-yellow-600 dark:text-yellow-300">Medium</p>
                    </div>
                    <p className="text-2xl font-bold">{alerts.filter((a) => a.severity === 'medium').length}</p>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-green-200 dark:border-green-700 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-1">
                      <Activity className="w-4 h-4 text-green-600" />
                      <p className="text-sm font-medium text-green-600 dark:text-green-300">Low</p>
                    </div>
                    <p className="text-2xl font-bold">{alerts.filter((a) => a.severity === 'low').length}</p>
                  </div>
                </div>

                {/* Search */}
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search alerts by title or source..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                {/* Alerts Table */}
                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Alert</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Source IP</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Type</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">MITRE ICS</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Timestamp</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredAlerts.length === 0 ? (
                        <tr>
                          <td colSpan={8} className="px-6 py-12 text-center text-gray-500 dark:text-gray-400">
                            No data available
                          </td>
                        </tr>
                      ) : (
                        filteredAlerts.map((otAlert) => (
                          <tr key={otAlert.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-medium">{otAlert.description}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(otAlert.severity)}`}>
                                {(otAlert.severity || '').toUpperCase()}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm font-mono">{otAlert.source_ip || '\u2014'}</td>
                            <td className="px-6 py-4 text-sm">{otAlert.alert_type}</td>
                            <td className="px-6 py-4 text-sm">{otAlert.mitre_ics_technique || '\u2014'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(otAlert.status)}`}>
                                {otAlert.status}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {otAlert.created_at ? new Date(otAlert.created_at).toLocaleString() : '\u2014'}
                            </td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => setDetailAlert(otAlert)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                                title="View alert details"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Zones Tab */}
            {activeTab === 'zones' && (
              <div className="space-y-6">
                <LoadErrorBanner what="OT zones" error={loadErrors.zones} />
                <LoadErrorBanner what="agents with the ot_segmentation_probe capability" error={loadErrors.probeAgents} />
                <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-4 mb-6">
                  <div className="flex items-center gap-2">
                    <Network className="w-5 h-5 text-blue-600 dark:text-blue-300" />
                    <p className="text-sm text-blue-800 dark:text-blue-200">
                      Segmentation is verified only by a probe run from an endpoint agent inside the zone
                      ({SEGMENTATION_CAPABILITY} capability, {(agentsByCapability[SEGMENTATION_CAPABILITY] ?? []).length} active),
                      approved in the agent queue; a zone is never marked verified without one.
                    </p>
                  </div>
                </div>

                {zones.length === 0 ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <Network className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <p className="text-gray-500 dark:text-gray-400">No data available</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 gap-4">
                    {zones.map((zone) => {
                      const compliant = zone.compliance_status === 'compliant';
                      const segView = actionViews[`segmentation:${zone.id}`];
                      return (
                      <div key={zone.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6 hover:shadow-lg transition">
                        <div className="flex justify-between items-start mb-4">
                          <div className="flex items-center gap-3">
                            <div className={clsx(
                              'w-10 h-10 rounded-lg flex items-center justify-center',
                              compliant ? 'bg-green-100 dark:bg-green-900' : 'bg-red-100 dark:bg-red-900'
                            )}>
                              {compliant ? (
                                <Lock className="w-5 h-5 text-green-600 dark:text-green-300" />
                              ) : (
                                <AlertTriangle className="w-5 h-5 text-red-600 dark:text-red-300" />
                              )}
                            </div>
                            <div>
                              <h3 className="font-semibold text-lg">{zone.name}</h3>
                              <p className="text-sm text-gray-600 dark:text-gray-400">{zone.description}</p>
                            </div>
                          </div>
                          <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(compliant ? 'secure' : 'warning')}`} title="Stored compliance status">
                            {zone.compliance_status || 'not assessed'}
                          </span>
                        </div>
                        <div className="grid grid-cols-4 gap-4 text-sm">
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Assets</p>
                            <p className="font-semibold">{zone.assets_count ?? '\u2014'}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Purdue Level</p>
                            <p className="font-semibold capitalize">{(zone.purdue_level || '').replace(/_/g, ' ')}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Network CIDR</p>
                            <p className="font-semibold font-mono text-xs">{zone.network_cidr || '\u2014'}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Segmentation</p>
                            <p className="font-semibold">{(segView?.segmentation_verified ?? zone.segmentation_verified) ? 'Verified by probe' : 'Unverified'}</p>
                          </div>
                        </div>
                        <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
                          <span>Last audit:</span>
                          <span className={`px-2 py-0.5 rounded text-xs ${actionStatusColor(segView?.status ?? zone.segmentation_audit_status)}`}>
                            {String(segView?.status ?? zone.segmentation_audit_status ?? 'not_audited').replace(/_/g, ' ')}
                          </span>
                          <span className="text-xs text-gray-500">
                            {(segView?.audited_at ?? zone.segmentation_audited_at) ? new Date(segView?.audited_at ?? zone.segmentation_audited_at).toLocaleString() : 'never'}
                          </span>
                          <button
                            onClick={() => { setActionError(null); setActionAgent(''); setActionTarget({ kind: 'segmentation', row: zone }); }}
                            className="ml-auto px-3 py-1.5 text-xs bg-indigo-600 hover:bg-indigo-700 text-white rounded"
                          >
                            Run Segmentation Audit (admin)
                          </button>
                          <button
                            onClick={() => loadActionStatus('segmentation', zone.id)}
                            className="flex items-center gap-1 px-3 py-1.5 text-xs border border-gray-300 dark:border-gray-600 rounded"
                          >
                            <RefreshCw className="w-3 h-3" /> Refresh Status
                          </button>
                        </div>
                        {segView && (
                          <div className="mt-2 text-xs space-y-1 bg-gray-50 dark:bg-gray-900 rounded p-2">
                            <p>{segView.probes_planned} probe(s) planned{segView.command_id ? ` · command ${segView.command_id}` : ''}</p>
                            {segView.error && <p className="text-red-600">Error: {segView.error}</p>}
                            {(segView.violations ?? []).length > 0 && (
                              <p className="text-red-700">Forbidden paths reachable: {segView.violations.map((v: Row) => `${v.target_ip}:${v.port}`).join(', ')}</p>
                            )}
                            {(segView.unexpected_blocked ?? []).length > 0 && (
                              <p className="text-orange-700">Allowed paths blocked: {segView.unexpected_blocked.map((v: Row) => `${v.target_ip}:${v.port}`).join(', ')}</p>
                            )}
                            {(segView.missing ?? []).length > 0 && (
                              <p className="text-gray-600">Unanswered probes: {segView.missing.length}</p>
                            )}
                          </div>
                        )}
                        {zone.allowed_protocols && zone.allowed_protocols.length > 0 && (
                          <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                            <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">Allowed Protocols</p>
                            <div className="flex flex-wrap gap-2">
                              {zone.allowed_protocols.map((proto: string, idx: number) => (
                                <span
                                  key={idx}
                                  className="px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded text-xs font-medium"
                                >
                                  {proto}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Purdue Model Tab */}
            {activeTab === 'purdue' && (
              <div className="space-y-6">
                <div className="bg-amber-50 dark:bg-amber-900 border border-amber-200 dark:border-amber-700 rounded-lg p-4 mb-6">
                  <div className="flex items-center gap-2">
                    <Layers className="w-5 h-5 text-amber-600 dark:text-amber-300" />
                    <p className="text-sm text-amber-800 dark:text-amber-200">
                      The Purdue Enterprise Reference Architecture (PERA) model defines network segmentation
                      levels for industrial control systems, from physical process (Level 0) to enterprise network (Level 5).
                    </p>
                  </div>
                </div>

                <LoadErrorBanner what="the Purdue map" error={loadErrors.purdue} />
                {purdueDevices.length === 0 && !purdueMap ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <Layers className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <p className="text-gray-500 dark:text-gray-400">No data available</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {/* Purdue level visualization */}
                    {[5, 4, 3, 2, 1, 0].map((level) => {
                      const info = getPurdueLevel(level);
                      const levelData = purdueDevices.find((l: Row) => l.level === level);
                      const deviceCount = levelData?.devices?.length || 0;
                      const displayAssets = levelData?.devices || [];

                      return (
                        <div key={level} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                          <div className={clsx('px-6 py-3 flex items-center justify-between', info.color)}>
                            <div className="flex items-center gap-3">
                              <span className="text-white font-bold text-lg">{info.label}</span>
                            </div>
                            <span className="text-white text-sm font-medium">
                              {displayAssets.length || deviceCount} device{(displayAssets.length || deviceCount) !== 1 ? 's' : ''}
                            </span>
                          </div>
                          <div className="px-6 py-3">
                            <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">{info.description}</p>
                            {displayAssets.length > 0 ? (
                              <div className="overflow-x-auto">
                                <table className="w-full text-sm">
                                  <thead>
                                    <tr className="border-b border-gray-200 dark:border-gray-700">
                                      <th className="py-2 text-left font-medium text-gray-600 dark:text-gray-400">Device</th>
                                      <th className="py-2 text-left font-medium text-gray-600 dark:text-gray-400">Type</th>
                                      <th className="py-2 text-left font-medium text-gray-600 dark:text-gray-400">IP Address</th>
                                      <th className="py-2 text-left font-medium text-gray-600 dark:text-gray-400">Status</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {displayAssets.map((device: Row, idx: number) => (
                                      <tr key={device.id || idx} className="border-b border-gray-100 dark:border-gray-700">
                                        <td className="py-2 font-medium">{device.name}</td>
                                        <td className="py-2 uppercase text-gray-600 dark:text-gray-400">{device.type}</td>
                                        <td className="py-2 font-mono text-gray-600 dark:text-gray-400">{device.ipAddress || device.ip}</td>
                                        <td className="py-2">
                                          <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${getStatusColor(device.status)}`}>
                                            {device.status}
                                          </span>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            ) : (
                              <p className="text-sm text-gray-400 dark:text-gray-500 italic">No devices at this level</p>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {/* Asset detail drawer */}
      <DetailDrawer
        open={!!detailAsset}
        onClose={() => setDetailAsset(null)}
        title={detailAsset?.name || 'OT Asset'}
        subtitle={detailAsset ? `${(detailAsset.asset_type || '').toUpperCase()} · ${detailAsset.vendor || 'Unknown vendor'}` : undefined}
        sections={
          detailAsset
            ? ([
                {
                  title: 'Identity',
                  fields: [
                    { label: 'Asset ID', value: detailAsset.id, mono: true, full: true },
                    { label: 'Name', value: detailAsset.name },
                    { label: 'Type', value: (detailAsset.asset_type || '').toUpperCase() },
                    { label: 'Vendor', value: detailAsset.vendor },
                    { label: 'Model', value: detailAsset.model },
                    { label: 'Serial', value: detailAsset.serial_number, mono: true },
                    { label: 'Firmware', value: detailAsset.firmware_version, mono: true },
                  ],
                },
                {
                  title: 'Network',
                  fields: [
                    { label: 'IP Address', value: detailAsset.ip_address, mono: true },
                    { label: 'MAC Address', value: detailAsset.mac_address, mono: true },
                    { label: 'Protocol', value: detailAsset.protocol },
                    { label: 'Zone', value: detailAsset.zone },
                    { label: 'Cell/Area', value: detailAsset.cell_area },
                    { label: 'Purdue Level', value: (detailAsset.purdue_level || '').replace(/_/g, ' ') },
                  ],
                },
                {
                  title: 'Security Posture',
                  fields: [
                    { label: 'Criticality', value: detailAsset.criticality },
                    { label: 'Online', value: detailAsset.is_online ? 'Yes' : 'No' },
                    { label: 'Firmware Marked Current (recorded)', value: detailAsset.firmware_current ? 'Yes' : 'No' },
                    { label: 'Matched ICS Advisories', value: detailAsset.known_vulnerabilities_count ?? 0 },
                    { label: 'Risk Score (stored)', value: detailAsset.risk_score ?? 0 },
                    { label: 'Last Seen', value: detailAsset.last_seen ? new Date(detailAsset.last_seen).toLocaleString() : null },
                  ],
                },
              ] as DetailSection[])
            : undefined
        }
      />

      {/* Alert detail drawer */}
      <DetailDrawer
        open={!!detailAlert}
        onClose={() => setDetailAlert(null)}
        title={detailAlert?.description || 'OT Alert'}
        subtitle={detailAlert ? `${(detailAlert.severity || '').toUpperCase()} · ${detailAlert.alert_type || ''}` : undefined}
        sections={
          detailAlert
            ? ([
                {
                  title: 'Alert',
                  fields: [
                    { label: 'Alert ID', value: detailAlert.id, mono: true, full: true },
                    { label: 'Type', value: detailAlert.alert_type },
                    { label: 'Severity', value: (detailAlert.severity || '').toUpperCase() },
                    { label: 'Status', value: detailAlert.status },
                    { label: 'MITRE ICS', value: detailAlert.mitre_ics_technique, mono: true },
                    { label: 'Description', value: detailAlert.description, full: true },
                  ],
                },
                {
                  title: 'Network Context',
                  fields: [
                    { label: 'Source IP', value: detailAlert.source_ip, mono: true },
                    { label: 'Destination IP', value: detailAlert.destination_ip, mono: true },
                    { label: 'Protocol', value: detailAlert.protocol_used },
                    { label: 'Command / Function', value: detailAlert.command_function_code, mono: true },
                    { label: 'Asset ID', value: detailAlert.asset_id, mono: true, full: true },
                  ],
                },
                {
                  title: 'Response',
                  fields: [
                    { label: 'Response Action', value: detailAlert.response_action, full: true },
                    { label: 'Created', value: detailAlert.created_at ? new Date(detailAlert.created_at).toLocaleString() : null },
                    { label: 'Updated', value: detailAlert.updated_at ? new Date(detailAlert.updated_at).toLocaleString() : null },
                  ],
                },
              ] as DetailSection[])
            : undefined
        }
      />

      {/* Agent action modal (safe shutdown / segmentation audit) */}
      {actionTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setActionTarget(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-md mx-4 p-6 space-y-3" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold">
              {actionTarget.kind === 'shutdown' ? `Safe shutdown: ${actionTarget.row.title}` : `Segmentation audit: ${actionTarget.row.name}`}
            </h2>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              {actionTarget.kind === 'shutdown'
                ? 'Queues an ot_safe_shutdown command for the incident\'s affected assets. Nothing runs until a second administrator approves it in the agent queue.'
                : 'Queues TCP probes from an agent inside this zone\'s CIDR to the assets of the other zones. Nothing runs until it is approved in the agent queue.'}
            </p>
            {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
            {(() => {
              const cap = actionTarget.kind === 'shutdown' ? SAFE_SHUTDOWN_CAPABILITY : SEGMENTATION_CAPABILITY;
              const agents = agentsByCapability[cap] ?? [];
              return (
                <label className="block text-sm">Agent ({cap})
                  <select value={actionAgent} onChange={(e) => setActionAgent(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm">
                    <option value="">{agents.length > 1 ? 'Choose an agent (required when several are enrolled)' : 'Automatic'}</option>
                    {agents.map((a) => <option key={a.id} value={a.id}>{a.hostname || a.id}{a.ip_address ? ` (${a.ip_address})` : ''}</option>)}
                  </select>
                  {agents.length === 0 && <span className="text-xs text-orange-700">No active agent carries this capability; the server will refuse with no_capable_agent.</span>}
                </label>
              );
            })()}
            <div className="flex gap-2 pt-2">
              <button onClick={submitAction} disabled={busy === 'action'} className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50">
                {busy === 'action' ? 'Queuing...' : 'Queue Command'}
              </button>
              <button onClick={() => setActionTarget(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
