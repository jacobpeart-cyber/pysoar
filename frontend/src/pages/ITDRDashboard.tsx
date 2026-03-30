import React, { useState } from 'react';
import {
  UserX,
  Key,
  ShieldAlert,
  Lock,
  Fingerprint,
  Plus,
  Edit,
  Eye,
  Trash2,
  Search,
  Filter,
  AlertTriangle,
  CheckCircle,
  Clock,
  Shield,
} from 'lucide-react';
import clsx from 'clsx';
import { itdrApi } from '../api/endpoints';

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
    case 'investigating':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'resolved':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'dismissed':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    case 'pending':
      return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
    case 'complete':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'in-progress':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

export default function ITDRDashboard() {
  const [activeTab, setActiveTab] = useState('identity-threats');
  const [identityThreats, setIdentityThreats] = useState<any[]>([]);
  const [credentialExposures, setCredentialExposures] = useState<any[]>([]);
  const [accessAnomalies, setAccessAnomalies] = useState<any[]>([]);
  const [privilegedAccess, setPrivilegedAccess] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewThreatModal, setShowNewThreatModal] = useState(false);

  React.useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [threatsData, accessData] = await Promise.all([
          itdrApi.getIdentityThreats(),
          itdrApi.getPrivilegedAccess(),
        ]);
        setIdentityThreats(threatsData.data || []);
        setCredentialExposures([]);
        setAccessAnomalies([]);
        setPrivilegedAccess(accessData.data || []);
      } catch (error) {
        console.error('Error loading ITDR data:', error);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const activeThreats = identityThreats.filter(t => t.status === 'investigating').length;
  const exposedCredentials = credentialExposures.filter(c => c.status !== 'complete').length;
  const highRiskIdentities = identityThreats.filter(t => t.riskScore >= 80).length;
  const mfaCoverage = 87;

  const tabs = [
    { id: 'identity-threats', label: 'Identity Threats', icon: UserX },
    { id: 'credential-exposure', label: 'Credential Exposure', icon: Key },
    { id: 'access-anomalies', label: 'Access Anomalies', icon: ShieldAlert },
    { id: 'privileged-access', label: 'Privileged Access', icon: Lock },
  ];

  const filteredThreats = identityThreats.filter(t =>
    t.threatName.toLowerCase().includes(searchQuery.toLowerCase()) ||
    t.identity.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredCredentials = credentialExposures.filter(c =>
    c.credential.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredAnomalies = accessAnomalies.filter(a =>
    a.user.toLowerCase().includes(searchQuery.toLowerCase()) ||
    a.resource.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredPrivileged = privilegedAccess.filter(p =>
    p.user.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <UserX className="w-8 h-8 text-orange-600" />
            <h1 className="text-3xl font-bold">Identity Threat Detection & Response</h1>
          </div>
          <button
            onClick={() => setShowNewThreatModal(true)}
            className="flex items-center gap-2 bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            New Threat
          </button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Active Threats</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{activeThreats}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">requiring investigation</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Exposed Credentials</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{exposedCredentials}</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">pending remediation</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">High-Risk Identities</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{highRiskIdentities}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">risk score ≥ 80</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">MFA Coverage</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{mfaCoverage}%</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">enrolled users</p>
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
                    ? 'border-orange-600 text-orange-600 dark:text-orange-400'
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
            {/* Identity Threats Tab */}
            {activeTab === 'identity-threats' && (
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
                  <button className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Threat Name</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Identity</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">MITRE Technique</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Risk Score</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredThreats.map((threat) => (
                        <tr key={threat.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{threat.threatName}</td>
                          <td className="px-6 py-4 text-sm">{threat.identity}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                              {threat.severity.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-xs font-mono">{threat.mitreTechnique}</td>
                          <td className="px-6 py-4 text-sm">
                            <div className="flex items-center gap-2">
                              <div className="w-20 bg-gray-200 dark:bg-gray-600 rounded-full h-2">
                                <div
                                  className={`h-2 rounded-full ${threat.riskScore >= 80 ? 'bg-red-600' : threat.riskScore >= 50 ? 'bg-orange-600' : 'bg-green-600'}`}
                                  style={{ width: `${threat.riskScore}%` }}
                                />
                              </div>
                              <span className="font-semibold">{threat.riskScore}</span>
                            </div>
                          </td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(threat.status)}`}>
                              {threat.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm flex gap-2">
                            <button className="text-blue-600 dark:text-blue-400 hover:underline">
                              <Eye className="w-4 h-4" />
                            </button>
                            <button className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100">
                              <Edit className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Credential Exposure Tab */}
            {activeTab === 'credential-exposure' && (
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
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Credential</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Exposure Type</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Discovery Date</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Remediation</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredCredentials.map((credential) => (
                        <tr key={credential.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{credential.credential}</td>
                          <td className="px-6 py-4 text-sm">{credential.exposureType}</td>
                          <td className="px-6 py-4 text-sm">{new Date(credential.discoveryDate).toLocaleDateString()}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(credential.severity)}`}>
                              {credential.severity.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm">{credential.remediation}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(credential.status)}`}>
                              {credential.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm flex gap-2">
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

            {/* Access Anomalies Tab */}
            {activeTab === 'access-anomalies' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search anomalies..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4">
                  {filteredAnomalies.map((anomaly) => (
                    <div key={anomaly.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <AlertTriangle className="w-5 h-5 text-orange-600" />
                            <h3 className="font-semibold">{anomaly.anomaly}</h3>
                            <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(anomaly.severity)}`}>
                              {anomaly.severity}
                            </span>
                          </div>
                          <div className="grid grid-cols-3 gap-4 text-sm">
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">User</p>
                              <p className="font-medium">{anomaly.user}</p>
                            </div>
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">Resource</p>
                              <p className="font-medium">{anomaly.resource}</p>
                            </div>
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">Deviation Score</p>
                              <p className="font-medium">{anomaly.deviationScore}%</p>
                            </div>
                          </div>
                          <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                            {new Date(anomaly.timestamp).toLocaleString()}
                          </p>
                        </div>
                        <button className="text-blue-600 dark:text-blue-400 hover:underline ml-4">
                          <Eye className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Privileged Access Tab */}
            {activeTab === 'privileged-access' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search privileged accounts..."
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
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">User</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Role</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Last Used</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">JIT Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Risk Level</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPrivileged.map((access) => (
                        <tr key={access.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{access.user}</td>
                          <td className="px-6 py-4 text-sm">{access.role}</td>
                          <td className="px-6 py-4 text-sm">{new Date(access.lastUsed).toLocaleDateString()}</td>
                          <td className="px-6 py-4">
                            <span className={access.jitStatus === 'enabled' ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}>
                              {access.jitStatus === 'enabled' ? (
                                <CheckCircle className="w-5 h-5" />
                              ) : (
                                <AlertTriangle className="w-5 h-5" />
                              )}
                            </span>
                          </td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(access.riskLevel)}`}>
                              {access.riskLevel.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm flex gap-2">
                            <button className="text-blue-600 dark:text-blue-400 hover:underline">
                              <Eye className="w-4 h-4" />
                            </button>
                            <button className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100">
                              <Edit className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* New Threat Modal */}
      {showNewThreatModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create New Threat Alert</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Threat Name</label>
                <input type="text" placeholder="Enter threat name" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Identity</label>
                <input type="text" placeholder="user@company.com" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option>Critical</option>
                  <option>High</option>
                  <option>Medium</option>
                  <option>Low</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => setShowNewThreatModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={() => setShowNewThreatModal(false)}
                  className="flex-1 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition"
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
