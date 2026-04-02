import React, { useState } from 'react';
import {
  Shield,
  FileWarning,
  Eye,
  Lock,
  AlertTriangle,
  Search,
  Filter,
  Plus,
  Edit,
  Download,
  CheckCircle,
  XCircle,
  FileText,
  Activity,
} from 'lucide-react';
import clsx from 'clsx';
import { dlpApi } from '../api/endpoints';

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
    case 'open':
    case 'active':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'investigating':
    case 'in-progress':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'resolved':
    case 'closed':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'enabled':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'disabled':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    case 'suppressed':
      return 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

export default function DLPDashboard() {
  const [activeTab, setActiveTab] = useState('policies');
  const [policies, setPolicies] = useState<any[]>([]);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [classifications, setClassifications] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewPolicyModal, setShowNewPolicyModal] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<any | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<any | null>(null);
  const [selectedClassification, setSelectedClassification] = useState<string | null>(null);
  const [showFilter, setShowFilter] = useState(false);

  React.useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        const [policiesData, incidentsData, classificationsData] = await Promise.all([
          dlpApi.getPolicies(),
          dlpApi.getIncidents(),
          dlpApi.getClassifications(),
        ]);
        setPolicies(Array.isArray(policiesData) ? policiesData : (policiesData?.items || []));
        setIncidents(Array.isArray(incidentsData) ? incidentsData : (incidentsData?.items || incidentsData?.data || []));
        setClassifications(Array.isArray(classificationsData) ? classificationsData : (classificationsData?.items || []));
      } catch (err) {
        console.error('Error loading DLP data:', err);
        setError('Failed to load DLP data. Please try again.');
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const activePolicies = policies.filter(p => p.enabled !== false).length;
  const openIncidents = incidents.filter(i => i.status === 'open' || i.status === 'investigating').length;
  const dataClassifications = classifications.length;
  const violationsThisWeek = incidents.filter(i => {
    const incDate = new Date(i.createdAt || i.created_at || '');
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    return incDate >= weekAgo;
  }).length;

  const tabs = [
    { id: 'policies', label: 'Policies', icon: Shield },
    { id: 'incidents', label: 'Incidents', icon: FileWarning },
    { id: 'classifications', label: 'Classifications', icon: Lock },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  const filteredPolicies = policies.filter(p =>
    (p.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (p.description || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredIncidents = incidents.filter(i =>
    (i.user || i.userName || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (i.action || i.description || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (i.policyName || i.policy_name || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-indigo-600" />
            <h1 className="text-3xl font-bold">Data Loss Prevention</h1>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                const data = { policies, incidents, classifications };
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'dlp-export.json';
                a.click();
                URL.revokeObjectURL(url);
              }}
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
            >
              <Download className="w-4 h-4" />
              Export
            </button>
            <button
              onClick={() => setShowNewPolicyModal(true)}
              className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg transition"
            >
              <Plus className="w-4 h-4" />
              New Policy
            </button>
          </div>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-indigo-50 to-indigo-100 dark:from-indigo-900 dark:to-indigo-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-indigo-600 dark:text-indigo-300">Active Policies</p>
            <p className="text-3xl font-bold text-indigo-900 dark:text-indigo-100 mt-2">{activePolicies}</p>
            <p className="text-xs text-indigo-600 dark:text-indigo-300 mt-1">enforcing data protection</p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Open Incidents</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{openIncidents}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">requiring investigation</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Data Classifications</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{dataClassifications}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">classification categories</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Violations This Week</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{violationsThisWeek}</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">policy violations detected</p>
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
            <p className="text-gray-500 dark:text-gray-400">Loading DLP data...</p>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center h-64">
            <div className="text-center">
              <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
              <p className="text-red-600 dark:text-red-400">{error}</p>
              <button
                onClick={() => window.location.reload()}
                className="mt-4 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition"
              >
                Retry
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Policies Tab */}
            {activeTab === 'policies' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search policies by name or description..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button
                    onClick={() => setShowFilter((prev) => !prev)}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  >
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                </div>

                {filteredPolicies.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Shield className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No DLP policies found</p>
                    <button
                      onClick={() => setShowNewPolicyModal(true)}
                      className="mt-3 text-indigo-600 dark:text-indigo-400 hover:underline text-sm"
                    >
                      Create your first policy
                    </button>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Policy Name</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Rules</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Matches</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Last Triggered</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPolicies.map((policy) => (
                          <tr key={policy.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4">
                              <div>
                                <p className="text-sm font-medium">{policy.name}</p>
                                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{policy.description || 'No description'}</p>
                              </div>
                            </td>
                            <td className="px-6 py-4">
                              {policy.enabled !== false ? (
                                <span className="flex items-center gap-1 text-green-600 dark:text-green-400 text-sm">
                                  <CheckCircle className="w-4 h-4" />
                                  Enabled
                                </span>
                              ) : (
                                <span className="flex items-center gap-1 text-gray-500 dark:text-gray-400 text-sm">
                                  <XCircle className="w-4 h-4" />
                                  Disabled
                                </span>
                              )}
                            </td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(policy.severity || 'medium')}`}>
                                {(policy.severity || 'medium').toUpperCase()}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm">{policy.rules?.length || policy.rule_count || 0}</td>
                            <td className="px-6 py-4 text-sm font-semibold">{policy.trigger_count || policy.match_count || 0}</td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {policy.last_triggered
                                ? new Date(policy.last_triggered).toLocaleDateString()
                                : 'Never'}
                            </td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => setSelectedPolicy(policy)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => setSelectedPolicy(policy)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                              >
                                <Edit className="w-4 h-4" />
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

            {/* Incidents Tab */}
            {activeTab === 'incidents' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Incident Severity Breakdown</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Critical</span><span className="font-semibold text-red-600">{incidents.filter(i => i.severity === 'critical').length}</span></div>
                      <div className="flex justify-between"><span>High</span><span className="font-semibold text-orange-600">{incidents.filter(i => i.severity === 'high').length}</span></div>
                      <div className="flex justify-between"><span>Medium</span><span className="font-semibold text-yellow-600">{incidents.filter(i => i.severity === 'medium').length}</span></div>
                      <div className="flex justify-between"><span>Low</span><span className="font-semibold text-green-600">{incidents.filter(i => i.severity === 'low').length}</span></div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Top Violation Types</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Email Exfiltration</span><span className="font-semibold">{incidents.filter(i => (i.action || i.description || '').toLowerCase().includes('email')).length}</span></div>
                      <div className="flex justify-between"><span>USB Transfer</span><span className="font-semibold">{incidents.filter(i => (i.action || i.description || '').toLowerCase().includes('usb')).length}</span></div>
                      <div className="flex justify-between"><span>Cloud Upload</span><span className="font-semibold">{incidents.filter(i => (i.action || i.description || '').toLowerCase().includes('cloud')).length}</span></div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Response Status</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Auto-Blocked</span><span className="font-semibold text-green-600">{incidents.filter(i => i.status === 'blocked' || i.status === 'auto-blocked').length}</span></div>
                      <div className="flex justify-between"><span>Quarantined</span><span className="font-semibold text-yellow-600">{incidents.filter(i => i.status === 'quarantined').length}</span></div>
                      <div className="flex justify-between"><span>Pending Review</span><span className="font-semibold text-red-600">{incidents.filter(i => i.status === 'open' || i.status === 'investigating').length}</span></div>
                    </div>
                  </div>
                </div>

                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search incidents by user, action, or policy..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button
                    onClick={() => setShowFilter((prev) => !prev)}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  >
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                </div>

                {filteredIncidents.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <FileWarning className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No DLP incidents found</p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Incident ID</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">User</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Action</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Policy</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Date</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredIncidents.map((incident) => (
                          <tr key={incident.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-mono font-medium">{incident.id}</td>
                            <td className="px-6 py-4 text-sm">{incident.user || incident.userName || 'Unknown'}</td>
                            <td className="px-6 py-4 text-sm">{incident.action || incident.description || '—'}</td>
                            <td className="px-6 py-4 text-sm">{incident.policyName || incident.policy_name || '—'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(incident.severity || 'medium')}`}>
                                {(incident.severity || 'medium').toUpperCase()}
                              </span>
                            </td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(incident.status || 'open')}`}>
                                {(incident.status || 'open')}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {incident.createdAt || incident.created_at
                                ? new Date(incident.createdAt || incident.created_at).toLocaleDateString()
                                : '—'}
                            </td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => setSelectedIncident(incident)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => setSelectedIncident(incident)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                              >
                                <Edit className="w-4 h-4" />
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

            {/* Classifications Tab */}
            {activeTab === 'classifications' && (
              <div className="space-y-6">
                <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-4 mb-6">
                  <p className="text-sm text-blue-800 dark:text-blue-200">
                    Data classifications define sensitivity levels for organizational data. Policies reference these classifications to enforce protection rules.
                  </p>
                </div>

                {classifications.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Lock className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No data classifications defined</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {classifications.map((classification, index) => (
                      <div key={index} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                        <div className="flex items-center gap-3 mb-3">
                          <Lock className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          <h3 className="font-semibold text-lg">{classification}</h3>
                        </div>
                        <div className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
                          <div className="flex justify-between">
                            <span>Policies using</span>
                            <span className="font-semibold text-gray-900 dark:text-gray-100">
                              {policies.filter(p => p.classification === classification || p.dataType === classification).length}
                            </span>
                          </div>
                          <div className="flex justify-between">
                            <span>Related incidents</span>
                            <span className="font-semibold text-gray-900 dark:text-gray-100">
                              {incidents.filter(i => i.classification === classification || i.dataType === classification).length}
                            </span>
                          </div>
                        </div>
                        <div className="flex gap-2 mt-4">
                          <button
                            onClick={() => setSelectedClassification(classification)}
                            className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                          >
                            View Details
                          </button>
                          <button
                            onClick={() => setSelectedClassification(classification)}
                            className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                          >
                            Edit
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Reports Tab */}
            {activeTab === 'reports' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <Activity className="w-6 h-6 text-indigo-600" />
                      <h3 className="font-semibold text-lg">Incident Trend</h3>
                    </div>
                    <div className="space-y-3 text-sm">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-600 dark:text-gray-400">Total Incidents (30 days)</span>
                        <span className="font-bold text-lg">{incidents.length}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-600 dark:text-gray-400">Open</span>
                        <span className="font-semibold text-red-600">{incidents.filter(i => i.status === 'open').length}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-600 dark:text-gray-400">Resolved</span>
                        <span className="font-semibold text-green-600">{incidents.filter(i => i.status === 'resolved' || i.status === 'closed').length}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <Shield className="w-6 h-6 text-indigo-600" />
                      <h3 className="font-semibold text-lg">Policy Effectiveness</h3>
                    </div>
                    <div className="space-y-3 text-sm">
                      <div className="flex justify-between items-center">
                        <span className="text-gray-600 dark:text-gray-400">Active Policies</span>
                        <span className="font-bold text-lg">{activePolicies}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-600 dark:text-gray-400">Disabled Policies</span>
                        <span className="font-semibold">{policies.length - activePolicies}</span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-gray-600 dark:text-gray-400">Classifications Covered</span>
                        <span className="font-semibold">{dataClassifications}</span>
                      </div>
                    </div>
                  </div>

                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <FileWarning className="w-6 h-6 text-orange-600" />
                      <h3 className="font-semibold text-lg">Top Offenders</h3>
                    </div>
                    <div className="space-y-3 text-sm">
                      {incidents.length === 0 ? (
                        <p className="text-gray-500 dark:text-gray-400">No incident data available</p>
                      ) : (
                        <p className="text-gray-500 dark:text-gray-400">User-level analytics available in full reports</p>
                      )}
                    </div>
                  </div>

                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <Download className="w-6 h-6 text-green-600" />
                      <h3 className="font-semibold text-lg">Export Reports</h3>
                    </div>
                    <div className="space-y-3">
                      <button
                        onClick={() => {
                          const blob = new Blob([JSON.stringify({ policies, incidents, classifications }, null, 2)], { type: 'application/json' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = 'dlp-summary-report.json';
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="w-full px-4 py-2 text-sm text-left border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                      >
                        DLP Summary Report (PDF)
                      </button>
                      <button
                        onClick={() => {
                          const headers = ['ID', 'User', 'Action', 'Policy', 'Severity', 'Status', 'Date'];
                          const rows = incidents.map((i) => [i.id, i.user || i.userName || '', i.action || i.description || '', i.policyName || i.policy_name || '', i.severity || '', i.status || '', i.createdAt || i.created_at || ''].join(','));
                          const csv = [headers.join(','), ...rows].join('\n');
                          const blob = new Blob([csv], { type: 'text/csv' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = 'dlp-incident-details.csv';
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="w-full px-4 py-2 text-sm text-left border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                      >
                        Incident Details (CSV)
                      </button>
                      <button
                        onClick={() => {
                          const blob = new Blob([JSON.stringify({ policies, classifications }, null, 2)], { type: 'application/json' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = 'dlp-policy-compliance-report.json';
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="w-full px-4 py-2 text-sm text-left border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                      >
                        Policy Compliance Report (PDF)
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* Policy Detail Modal */}
      {selectedPolicy && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setSelectedPolicy(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[32rem] max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Policy Details</h2>
            <div className="space-y-3 text-sm">
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Name:</span> <span className="ml-2">{selectedPolicy.name}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Description:</span> <span className="ml-2">{selectedPolicy.description || 'N/A'}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Status:</span> <span className="ml-2">{selectedPolicy.enabled !== false ? 'Enabled' : 'Disabled'}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Severity:</span> <span className="ml-2">{(selectedPolicy.severity || 'medium').toUpperCase()}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Rules:</span> <span className="ml-2">{selectedPolicy.rules?.length || selectedPolicy.rule_count || 0}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Matches:</span> <span className="ml-2">{selectedPolicy.trigger_count || selectedPolicy.match_count || 0}</span></div>
            </div>
            <pre className="text-xs bg-gray-100 dark:bg-gray-900 rounded p-4 overflow-auto max-h-48 mt-4">
              {JSON.stringify(selectedPolicy, null, 2)}
            </pre>
            <div className="mt-4 flex justify-end">
              <button onClick={() => setSelectedPolicy(null)} className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setSelectedIncident(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[32rem] max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Incident Details</h2>
            <div className="space-y-3 text-sm">
              <div><span className="font-medium text-gray-600 dark:text-gray-400">ID:</span> <span className="ml-2 font-mono">{selectedIncident.id}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">User:</span> <span className="ml-2">{selectedIncident.user || selectedIncident.userName || 'Unknown'}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Action:</span> <span className="ml-2">{selectedIncident.action || selectedIncident.description || 'N/A'}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Policy:</span> <span className="ml-2">{selectedIncident.policyName || selectedIncident.policy_name || 'N/A'}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Severity:</span> <span className="ml-2">{(selectedIncident.severity || 'medium').toUpperCase()}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Status:</span> <span className="ml-2">{selectedIncident.status || 'open'}</span></div>
            </div>
            <pre className="text-xs bg-gray-100 dark:bg-gray-900 rounded p-4 overflow-auto max-h-48 mt-4">
              {JSON.stringify(selectedIncident, null, 2)}
            </pre>
            <div className="mt-4 flex justify-end">
              <button onClick={() => setSelectedIncident(null)} className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Classification Detail Modal */}
      {selectedClassification && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setSelectedClassification(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[32rem] max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Classification: {selectedClassification}</h2>
            <div className="space-y-3 text-sm">
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Policies using this classification:</span> <span className="ml-2 font-semibold">{policies.filter(p => p.classification === selectedClassification || p.dataType === selectedClassification).length}</span></div>
              <div><span className="font-medium text-gray-600 dark:text-gray-400">Related incidents:</span> <span className="ml-2 font-semibold">{incidents.filter(i => i.classification === selectedClassification || i.dataType === selectedClassification).length}</span></div>
            </div>
            <div className="mt-4 flex justify-end">
              <button onClick={() => setSelectedClassification(null)} className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Close</button>
            </div>
          </div>
        </div>
      )}

      {/* New Policy Modal */}
      {showNewPolicyModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create DLP Policy</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Policy Name</label>
                <input type="text" placeholder="e.g., PII Protection Policy" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea placeholder="Describe the policy purpose..." rows={3} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Data Classification</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="">Select classification...</option>
                  {classifications.map((c, i) => (
                    <option key={i} value={c}>{c}</option>
                  ))}
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => setShowNewPolicyModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={() => setShowNewPolicyModal(false)}
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition"
                >
                  Create Policy
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
