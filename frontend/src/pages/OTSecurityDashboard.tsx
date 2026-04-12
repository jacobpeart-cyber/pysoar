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
  Filter,
  Layers,
  Wifi,
  WifiOff,
  Lock,
  Download,
} from 'lucide-react';
import clsx from 'clsx';
import { otsecurityApi } from '../api/endpoints';

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
  const [assets, setAssets] = useState<any[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [zones, setZones] = useState<any[]>([]);
  const [purdueMap, setPurdueMap] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [assetsData, alertsData, zonesData, purdueData] = await Promise.all([
          otsecurityApi.getAssets(),
          otsecurityApi.getAlerts(),
          otsecurityApi.getZones(),
          otsecurityApi.getPurdueMap(),
        ]);
        const toItems = (d: any) => Array.isArray(d) ? d : (d?.items || []);
        setAssets(toItems(assetsData));
        setAlerts(toItems(alertsData));
        setZones(toItems(zonesData));
        setPurdueMap(purdueData || null);
      } catch (error) {
        console.error('Error loading OT security data:', error);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const totalAssets = assets.length;
  const onlineAssets = assets.filter((a) => a.is_online === true || a.status === 'online').length;
  const activeAlerts = alerts.filter((a) => !['resolved', 'contained', 'false_positive'].includes(a.status)).length;
  const securityZones = zones.length;

  const tabs = [
    { id: 'assets', label: 'Assets', icon: Server },
    { id: 'alerts', label: 'Alerts', icon: AlertTriangle },
    { id: 'zones', label: 'Zones', icon: Shield },
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
          <button onClick={() => { const exportData = { assets, alerts, zones, purdue_model: purdueMap, dashboard: { total_assets: totalAssets, online_assets: onlineAssets, active_alerts: activeAlerts, security_zones: securityZones }, exported_at: new Date().toISOString() }; const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' }); const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = 'ot-security-report.json'; a.click(); URL.revokeObjectURL(url); }} className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
            <Download className="w-4 h-4" />
            Export Report
          </button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-indigo-50 to-indigo-100 dark:from-indigo-900 dark:to-indigo-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-indigo-600 dark:text-indigo-300">Total OT Assets</p>
            <p className="text-3xl font-bold text-indigo-900 dark:text-indigo-100 mt-2">{totalAssets}</p>
            <p className="text-xs text-indigo-600 dark:text-indigo-300 mt-1">across all zones</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">Online Assets</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{onlineAssets}</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">currently communicating</p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Active Alerts</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{activeAlerts}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">requiring attention</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Security Zones</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{securityZones}</p>
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
                    <h3 className="font-semibold mb-3">Firmware Status</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span>Up to Date</span>
                        <span className="font-semibold text-green-600">{assets.filter((a) => a.firmware_current === true).length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Update Needed</span>
                        <span className="font-semibold text-yellow-600">{assets.filter((a) => a.firmware_current === false).length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Known Vulnerabilities</span>
                        <span className="font-semibold text-red-600">{assets.filter((a) => (a.known_vulnerabilities_count || 0) > 0).length}</span>
                      </div>
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
                  <button
                    onClick={() => setSearchQuery('')}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                    title="Clear search"
                  >
                    <Filter className="w-4 h-4" />
                    Clear
                  </button>
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
                                onClick={() => alert(JSON.stringify(asset, null, 2))}
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

            {/* Alerts Tab */}
            {activeTab === 'alerts' && (
              <div className="space-y-6">
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
                  <button
                    onClick={() => setSearchQuery('')}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                    title="Clear search"
                  >
                    <Filter className="w-4 h-4" />
                    Clear
                  </button>
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
                                onClick={() => window.alert(JSON.stringify(otAlert, null, 2))}
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
                <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-4 mb-6">
                  <div className="flex items-center gap-2">
                    <Network className="w-5 h-5 text-blue-600 dark:text-blue-300" />
                    <p className="text-sm text-blue-800 dark:text-blue-200">
                      Network segmentation zones define trust boundaries between OT and IT environments.
                      Each zone enforces access control policies and traffic inspection rules.
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
                          <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(compliant ? 'secure' : 'warning')}`}>
                            {zone.compliance_status || 'unknown'}
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
                            <p className="font-semibold">{zone.segmentation_verified ? 'Verified' : 'Unverified'}</p>
                          </div>
                        </div>
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
                      const levelData = purdueDevices.find((l: any) => l.level === level);
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
                                    {displayAssets.map((device: any, idx: number) => (
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
    </div>
  );
}
