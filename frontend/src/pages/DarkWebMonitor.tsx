import React, { useState } from 'react';
import {
  Globe,
  Eye,
  Key,
  Shield,
  AlertOctagon,
  Plus,
  Edit,
  Eye as EyeIcon,
  Trash2,
  Search,
  Filter,
  AlertTriangle,
  CheckCircle,
  Clock,
  Zap,
} from 'lucide-react';
import clsx from 'clsx';
import { darkwebApi } from '../api/endpoints';

const getSeverityColor = (severity: string) => {
  switch (severity) {
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
  switch (status) {
    case 'active':
      return 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-100';
    case 'removed':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'completed':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'in-progress':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

export default function DarkWebMonitor() {
  const [activeTab, setActiveTab] = useState('monitors');
  const [monitors, setMonitors] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [credentials, setCredentials] = useState<any[]>([]);
  const [threats, setThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewMonitorModal, setShowNewMonitorModal] = useState(false);
  const [editingMonitor, setEditingMonitor] = useState<any | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [actionFinding, setActionFinding] = useState<any | null>(null);
  const [selectedCredential, setSelectedCredential] = useState<any | null>(null);
  const [newMonitorName, setNewMonitorName] = useState('');
  const [newMonitorKeywords, setNewMonitorKeywords] = useState('');
  const [newMonitorFrequency, setNewMonitorFrequency] = useState('Every 6 hours');

  React.useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [alertsData, credentialsData, brandData, monitorsData] = await Promise.all([
          // size=100 so the user sees all real findings on first load
          // instead of just the default first page (20).
          darkwebApi.getAlerts({ size: 100 }).catch(() => ({ items: [] })),
          darkwebApi.getCredentialLeaks({ size: 100 }).catch(() => ({ items: [] })),
          darkwebApi.getBrandMonitors().catch(() => []),
          darkwebApi.getMonitors().catch(() => []),
        ]);
        const alerts: any = alertsData;
        const creds: any = credentialsData;
        // Normalize backend snake_case fields to the camelCase shape
        // this page uses. Previously every finding, monitor, and
        // credential rendered fields like `discoveryDate`, `platform`,
        // `email`, `source` that don't exist on the response — so the
        // "New Findings" card always showed 0, tables rendered blank
        // columns, and filters matched nothing.
        const normMonitor = (m: any) => ({
          ...m,
          // Backend stores `enabled` as bool + `last_check` as iso string
          // (DarkWebMonitor model). Older versions had `last_scanned_at`;
          // accept both.
          status: m.status ?? (m.enabled ? 'active' : 'paused'),
          keyword: m.keyword ?? (Array.isArray(m.search_terms)
            ? m.search_terms.join(', ')
            : (typeof m.search_terms === 'string' ? m.search_terms : '')),
          lastScan: m.lastScan ?? m.last_check ?? m.last_scanned_at ?? m.last_scan_at ?? null,
          findingsCount: m.findingsCount ?? m.findings_count ?? 0,
          darkWebSources: m.darkWebSources ?? m.sources ?? m.platforms ?? [],
          createdDate: m.createdDate ?? m.created_at ?? null,
        });
        const normFinding = (f: any) => ({
          ...f,
          discoveryDate: f.discoveryDate ?? f.discovered_date ?? f.discovered_at ?? null,
          title: f.title ?? f.name ?? f.finding_type ?? '—',
          platform: f.platform ?? f.source_platform ?? f.source ?? '—',
        });
        const normCred = (c: any) => ({
          ...c,
          email: c.email ?? c.username ?? c.identifier ?? '—',
          source: c.source ?? c.source_platform ?? c.breach_source ?? '—',
        });
        const normThreat = (t: any) => ({
          ...t,
          threat: t.threat ?? t.target_brand ?? t.finding ?? '—',
          status: t.status ?? t.takedown_status ?? 'active',
          discoveryDate: t.discoveryDate ?? t.discovered_date ?? t.discovered_at ?? null,
          takedownAttempts: t.takedownAttempts ?? t.takedown_attempts ?? 0,
          resolutionDate: t.resolutionDate ?? t.resolved_at ?? null,
        });
        setMonitors(Array.isArray(monitorsData) ? monitorsData.map(normMonitor) : []);
        setFindings((Array.isArray(alerts) ? alerts : (alerts?.items || [])).map(normFinding));
        setCredentials((Array.isArray(creds) ? creds : (creds?.items || [])).map(normCred));
        setThreats(Array.isArray(brandData) ? brandData.map(normThreat) : []);
      } catch (error) {
        console.error('Error loading dark web data:', error);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const activeMonitors = monitors.filter(m => m.status === 'active').length;
  const newFindings = findings.filter(f => {
    const when = f.discoveryDate ?? f.discovered_date ?? f.discovered_at;
    if (!when) return false;
    const t = new Date(when).getTime();
    return Number.isFinite(t) && t > Date.now() - 7 * 24 * 60 * 60 * 1000;
  }).length;
  const exposedCredentials = credentials.length;
  const brandThreats = threats.filter(t => {
    const s = t.status ?? t.takedown_status;
    return s === 'active' || s === 'pending';
  }).length;

  const tabs = [
    { id: 'monitors', label: 'Monitors', icon: Eye },
    { id: 'findings', label: 'Findings', icon: AlertOctagon },
    { id: 'credentials', label: 'Credential Leaks', icon: Key },
    { id: 'brand-threats', label: 'Brand Threats', icon: Shield },
  ];

  const q = searchQuery.toLowerCase();
  const match = (v: any) => (v ?? '').toString().toLowerCase().includes(q);
  const filteredMonitors = monitors.filter(m => match(m.name) || match(m.keyword));
  const filteredFindings = findings.filter(f => match(f.title) || match(f.platform));
  const filteredCredentials = credentials.filter(c => match(c.email) || match(c.source));
  const filteredThreats = threats.filter(t => match(t.threat));

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Globe className="w-8 h-8 text-indigo-600" />
            <h1 className="text-3xl font-bold">Dark Web Monitor</h1>
          </div>
          <button
            onClick={() => setShowNewMonitorModal(true)}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            New Monitor
          </button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Active Monitors</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{activeMonitors}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">monitoring dark web</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">New Findings</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{newFindings}</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">last 7 days</p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Exposed Credentials</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{exposedCredentials}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">accounts affected</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Brand Threats</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{brandThreats}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">active threats</p>
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
            <p className="text-gray-500 dark:text-gray-400">Loading...</p>
          </div>
        ) : (
          <>
            {/* Monitors Tab */}
            {activeTab === 'monitors' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 gap-4">
                  {filteredMonitors.map((monitor) => (
                    <div key={monitor.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <h3 className="font-semibold text-lg">{monitor.name}</h3>
                          <p className="text-sm font-mono text-gray-600 dark:text-gray-400 mt-1">{monitor.keyword}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(monitor.status)}`}>
                          {monitor.status}
                        </span>
                      </div>
                      <div className="grid grid-cols-4 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Sources</p>
                          <p className="font-medium">{monitor.darkWebSources}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Findings</p>
                          <p className="font-medium">{monitor.findingsCount}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Created</p>
                          <p className="font-medium">{monitor.createdDate}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Last Scan</p>
                          <p className="font-medium">{new Date(monitor.lastScan || "").toLocaleDateString()}</p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => { setActiveTab('findings'); }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          View Findings
                        </button>
                        <button
                          onClick={() => setEditingMonitor(monitor)}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Edit
                        </button>
                        <button
                          onClick={async () => {
                            if (confirm('Are you sure you want to delete this monitor?')) {
                              try {
                                await darkwebApi.deleteMonitor(monitor.id);
                                setMonitors(prev => prev.filter(m => m.id !== monitor.id));
                              } catch (error) {
                                console.error('Error deleting monitor:', error);
                              }
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

            {/* Findings Tab */}
            {activeTab === 'findings' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search findings..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4">
                  {filteredFindings.map((finding) => (
                    <div key={finding.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <AlertOctagon className="w-5 h-5 text-orange-600" />
                            <h3 className="font-semibold">{finding.title}</h3>
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                              {finding.severity.toUpperCase()}
                            </span>
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{finding.description}</p>
                          <div className="flex gap-4 text-sm">
                            <span className="text-gray-600 dark:text-gray-400">Platform: {finding.platform}</span>
                            <span className="text-gray-600 dark:text-gray-400">Source: {finding.source}</span>
                          </div>
                        </div>
                      </div>
                      <div className="border-t border-gray-200 dark:border-gray-700 pt-3 mt-3">
                        <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Affected Assets:</p>
                        <div className="flex flex-wrap gap-2">
                          {(finding.affectedAssets || []).map((asset: any, idx: number) => (
                            <span key={idx} className="px-2 py-1 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100 rounded text-xs">
                              {asset}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div className="flex gap-2 mt-4">
                        <button
                          onClick={() => setActionFinding(finding)}
                          className="flex-1 px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded transition"
                        >
                          Take Action
                        </button>
                        <button
                          onClick={() => setSelectedFinding(finding)}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Details
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Credential Leaks Tab */}
            {activeTab === 'credentials' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search credentials..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Email</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Source Breach</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Breach Date</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Remediation</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredCredentials.map((cred) => (
                        <tr key={cred.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{cred.email}</td>
                          <td className="px-6 py-4 text-sm">{cred.source}</td>
                          <td className="px-6 py-4 text-sm">{cred.breachDate}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(cred.severity)}`}>
                              {cred.severity.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm">{cred.remediation}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(cred.status)}`}>
                              {cred.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm">
                            <button
                              onClick={() => setSelectedCredential(cred)}
                              className="text-blue-600 dark:text-blue-400 hover:underline"
                            >
                              <EyeIcon className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Brand Threats Tab */}
            {activeTab === 'brand-threats' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search threats..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4">
                  {filteredThreats.map((threat) => (
                    <div key={threat.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <AlertTriangle className="w-5 h-5 text-orange-600" />
                            <h3 className="font-semibold">{threat.threat}</h3>
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                              {threat.severity.toUpperCase()}
                            </span>
                          </div>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(threat.status)}`}>
                          {threat.status}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Discovered</p>
                          <p className="font-medium">{threat.discoveryDate}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Takedown Attempts</p>
                          <p className="font-medium">{threat.takedownAttempts}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Status</p>
                          <p className="font-medium capitalize">{threat.resolutionDate ? 'Resolved' : 'Pending'}</p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={async () => {
                            if (threat.status === 'active') {
                              if (confirm('Initiate takedown request for this threat?')) {
                                try {
                                  await darkwebApi.requestTakedown(threat.id);
                                  setThreats(prev => prev.map(t => t.id === threat.id ? { ...t, status: 'takedown_requested', takedownAttempts: (t.takedownAttempts || 0) + 1 } : t));
                                } catch (error) {
                                  console.error('Error initiating takedown:', error);
                                }
                              }
                            } else {
                              setSelectedFinding(threat);
                            }
                          }}
                          className="flex-1 px-3 py-2 text-sm bg-orange-600 hover:bg-orange-700 text-white rounded transition"
                        >
                          {threat.status === 'active' ? 'Initiate Takedown' : 'View Details'}
                        </button>
                        <button
                          onClick={async () => {
                            try {
                              await darkwebApi.exportReport('csv');
                            } catch (e) {
                              console.error('Export failed:', e);
                            }
                          }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Full Report
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

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[500px] max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Finding Details</h2>
            <div className="space-y-3 text-sm">
              <div><span className="font-medium">Title:</span> {selectedFinding.title || selectedFinding.threat}</div>
              {selectedFinding.description && <div><span className="font-medium">Description:</span> {selectedFinding.description}</div>}
              {selectedFinding.severity && <div><span className="font-medium">Severity:</span> {selectedFinding.severity}</div>}
              {selectedFinding.platform && <div><span className="font-medium">Platform:</span> {selectedFinding.platform}</div>}
              {selectedFinding.source && <div><span className="font-medium">Source:</span> {selectedFinding.source}</div>}
            </div>
            <button onClick={() => setSelectedFinding(null)} className="mt-6 w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Close</button>
          </div>
        </div>
      )}

      {/* Action Modal */}
      {actionFinding && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[500px] max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Take Action: {actionFinding.title}</h2>
            <div className="space-y-3">
              <button onClick={async () => { try { await darkwebApi.updateFinding(actionFinding.id, { status: 'escalated' }); setFindings(prev => prev.map(f => f.id === actionFinding.id ? { ...f, status: 'escalated' } : f)); } catch(e) { console.error(e); } setActionFinding(null); }} className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Escalate to Incident</button>
              <button onClick={async () => { try { await darkwebApi.updateFinding(actionFinding.id, { status: 'notified' }); setFindings(prev => prev.map(f => f.id === actionFinding.id ? { ...f, status: 'notified' } : f)); } catch(e) { console.error(e); } setActionFinding(null); }} className="w-full px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition">Notify Stakeholders</button>
              <button onClick={async () => { try { await darkwebApi.updateFinding(actionFinding.id, { status: 'reviewed' }); setFindings(prev => prev.map(f => f.id === actionFinding.id ? { ...f, status: 'reviewed' } : f)); } catch(e) { console.error(e); } setActionFinding(null); }} className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition">Mark as Reviewed</button>
              <button onClick={() => setActionFinding(null)} className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* Credential Detail Modal */}
      {selectedCredential && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[500px] max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Credential Leak Details</h2>
            <div className="space-y-3 text-sm">
              <div><span className="font-medium">Email:</span> {selectedCredential.email}</div>
              <div><span className="font-medium">Source Breach:</span> {selectedCredential.source}</div>
              <div><span className="font-medium">Breach Date:</span> {selectedCredential.breachDate}</div>
              <div><span className="font-medium">Severity:</span> {selectedCredential.severity}</div>
              <div><span className="font-medium">Remediation:</span> {selectedCredential.remediation}</div>
              <div><span className="font-medium">Status:</span> {selectedCredential.status}</div>
            </div>
            <button onClick={() => setSelectedCredential(null)} className="mt-6 w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Close</button>
          </div>
        </div>
      )}

      {/* Edit Monitor Modal */}
      {editingMonitor && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Edit Monitor: {editingMonitor.name}</h2>
            <form onSubmit={async (e) => {
              e.preventDefault();
              const formData = new FormData(e.currentTarget);
              const name = formData.get('name') as string;
              const keyword = formData.get('keyword') as string;
              try {
                const updated = await darkwebApi.updateMonitor(editingMonitor.id, {
                  name,
                  search_terms: keyword.split(',').map((k: string) => k.trim()).filter(Boolean),
                });
                setMonitors(prev => prev.map(m => m.id === editingMonitor.id ? { ...m, ...updated, name, keyword } : m));
                setEditingMonitor(null);
              } catch (error) {
                console.error('Error updating monitor:', error);
              }
            }} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Monitor Name</label>
                <input type="text" name="name" defaultValue={editingMonitor.name} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Keywords</label>
                <textarea name="keyword" defaultValue={editingMonitor.keyword} rows={3} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setEditingMonitor(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* New Monitor Modal */}
      {showNewMonitorModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create New Monitor</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Monitor Name</label>
                <input type="text" placeholder="e.g., Company Name Mentions" value={newMonitorName} onChange={(e) => setNewMonitorName(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Keywords</label>
                <textarea placeholder="e.g., PySOAR OR CompanyName" rows={3} value={newMonitorKeywords} onChange={(e) => setNewMonitorKeywords(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Scan Frequency</label>
                <select value={newMonitorFrequency} onChange={(e) => setNewMonitorFrequency(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option>Every 6 hours</option>
                  <option>Daily</option>
                  <option>Every 3 days</option>
                  <option>Weekly</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => setShowNewMonitorModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={async () => {
                    if (!newMonitorName.trim()) return;
                    try {
                      const created = await darkwebApi.createMonitor({
                        name: newMonitorName.trim(),
                        keywords: newMonitorKeywords.split(',').map(k => k.trim()).filter(Boolean),
                        monitor_type: 'keyword',
                      });
                      setMonitors(prev => [...prev, created]);
                      setNewMonitorName('');
                      setNewMonitorKeywords('');
                      setNewMonitorFrequency('Every 6 hours');
                      setShowNewMonitorModal(false);
                    } catch (error) {
                      console.error('Error creating monitor:', error);
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
    </div>
  );
}
