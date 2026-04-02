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
  const [identities, setIdentities] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewThreatModal, setShowNewThreatModal] = useState(false);
  const [newThreatForm, setNewThreatForm] = useState({
    threat_type: '',
    identity_id: '',
    severity: 'critical',
    confidence_score: 80,
  });
  const [submitting, setSubmitting] = useState(false);

  React.useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [threatsData, exposuresData, anomaliesData, accessData, identitiesData] = await Promise.all([
          itdrApi.getIdentityThreats().catch(() => null),
          itdrApi.getCredentialExposures().catch(() => null),
          itdrApi.getAccessAnomalies().catch(() => null),
          itdrApi.getPrivilegedAccess().catch(() => null),
          itdrApi.getIdentities().catch(() => null),
        ]);
        setIdentityThreats(threatsData?.items ?? []);
        setCredentialExposures(exposuresData?.items ?? []);
        setAccessAnomalies(anomaliesData?.items ?? []);
        setPrivilegedAccess(accessData?.items ?? []);
        setIdentities(identitiesData?.items ?? []);
      } catch (error) {
        console.error('Error loading ITDR data:', error);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const handleCreateThreat = async () => {
    if (!newThreatForm.threat_type || !newThreatForm.identity_id) return;
    setSubmitting(true);
    try {
      const created = await itdrApi.createThreat(newThreatForm);
      setIdentityThreats((prev) => [created, ...prev]);
      setShowNewThreatModal(false);
      setNewThreatForm({ threat_type: '', identity_id: '', severity: 'critical', confidence_score: 80 });
    } catch (error) {
      console.error('Error creating threat:', error);
    } finally {
      setSubmitting(false);
    }
  };

  const handleViewThreat = (threatId: string) => {
    console.log('View threat:', threatId);
  };

  const handleEditThreat = (threatId: string) => {
    console.log('Edit threat:', threatId);
  };

  const handleViewExposure = (exposureId: string) => {
    console.log('View exposure:', exposureId);
  };

  const handleViewAnomaly = (anomalyId: string) => {
    console.log('View anomaly:', anomalyId);
  };

  const handleViewAccess = (accessId: string) => {
    console.log('View access:', accessId);
  };

  const handleEditAccess = (accessId: string) => {
    console.log('Edit access:', accessId);
  };

  const activeThreats = identityThreats.filter(t => t.status === 'investigating').length;
  const exposedCredentials = credentialExposures.filter(c => !c.is_remediated).length;
  const highRiskIdentities = identityThreats.filter(t => (t.confidence_score ?? 0) >= 80).length;

  // Compute MFA coverage from identities data
  const mfaCoverage = identities.length > 0
    ? Math.round((identities.filter((i: any) => i.mfa_enabled).length / identities.length) * 100)
    : 0;

  const tabs = [
    { id: 'identity-threats', label: 'Identity Threats', icon: UserX },
    { id: 'credential-exposure', label: 'Credential Exposure', icon: Key },
    { id: 'access-anomalies', label: 'Access Anomalies', icon: ShieldAlert },
    { id: 'privileged-access', label: 'Privileged Access', icon: Lock },
  ];

  const filteredThreats = identityThreats.filter(t =>
    (t.threat_type ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (t.identity_id ?? '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredCredentials = credentialExposures.filter(c =>
    (c.exposure_source ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (c.credential_type ?? '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredAnomalies = accessAnomalies.filter(a =>
    (a.anomaly_type ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (a.identity_id ?? '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredPrivileged = privilegedAccess.filter(p =>
    (p.identity_id ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (p.event_type ?? '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  const renderEmptyState = (message: string) => (
    <div className="flex flex-col items-center justify-center py-16 text-gray-500 dark:text-gray-400">
      <Shield className="w-12 h-12 mb-4 opacity-50" />
      <p className="text-lg font-medium">{message}</p>
      <p className="text-sm mt-1">Data will appear here once available.</p>
    </div>
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
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">confidence score &gt;= 80</p>
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
            <div className="flex flex-col items-center gap-3">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-orange-600"></div>
              <p className="text-gray-500 dark:text-gray-400">Loading ITDR data...</p>
            </div>
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
                  <button
                    onClick={() => console.log('Open threat filters')}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  >
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                </div>

                {filteredThreats.length === 0 ? (
                  renderEmptyState('No identity threats found')
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Threat Type</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Identity</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">MITRE Technique</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Confidence</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredThreats.map((threat) => (
                          <tr key={threat.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-medium">{threat.threat_type ?? 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">{threat.identity_id ?? 'N/A'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(threat.severity ?? '')}`}>
                                {(threat.severity ?? 'unknown').toUpperCase()}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-xs font-mono">{threat.mitre_technique_id ?? 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">
                              <div className="flex items-center gap-2">
                                <div className="w-20 bg-gray-200 dark:bg-gray-600 rounded-full h-2">
                                  <div
                                    className={`h-2 rounded-full ${(threat.confidence_score ?? 0) >= 80 ? 'bg-red-600' : (threat.confidence_score ?? 0) >= 50 ? 'bg-orange-600' : 'bg-green-600'}`}
                                    style={{ width: `${Math.min(threat.confidence_score ?? 0, 100)}%` }}
                                  />
                                </div>
                                <span className="font-semibold">{threat.confidence_score ?? 0}</span>
                              </div>
                            </td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(threat.status ?? '')}`}>
                                {threat.status ?? 'unknown'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => handleViewThreat(threat.id)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                                title="View details"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => handleEditThreat(threat.id)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                                title="Edit threat"
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

                {filteredCredentials.length === 0 ? (
                  renderEmptyState('No credential exposures found')
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Exposure Source</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Credential Type</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Created At</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Identity</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Remediation</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredCredentials.map((credential) => (
                          <tr key={credential.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-medium">{credential.exposure_source ?? 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">{credential.credential_type ?? 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">{credential.created_at ? new Date(credential.created_at).toLocaleDateString() : 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">{credential.identity_id ?? 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">{credential.remediation_action ?? 'None'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${credential.is_remediated ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100' : 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100'}`}>
                                {credential.is_remediated ? 'Remediated' : 'Pending'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => handleViewExposure(credential.id)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                                title="View details"
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

                {filteredAnomalies.length === 0 ? (
                  renderEmptyState('No access anomalies found')
                ) : (
                  <div className="grid grid-cols-1 gap-4">
                    {filteredAnomalies.map((anomaly) => (
                      <div key={anomaly.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                        <div className="flex justify-between items-start">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <AlertTriangle className="w-5 h-5 text-orange-600" />
                              <h3 className="font-semibold">{anomaly.anomaly_type ?? 'Unknown Anomaly'}</h3>
                              <span className={`px-2 py-1 rounded text-xs font-medium ${anomaly.is_reviewed ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100' : 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100'}`}>
                                {anomaly.is_reviewed ? 'Reviewed' : 'Pending Review'}
                              </span>
                            </div>
                            <div className="grid grid-cols-3 gap-4 text-sm">
                              <div>
                                <p className="text-gray-600 dark:text-gray-400">Identity</p>
                                <p className="font-medium">{anomaly.identity_id ?? 'N/A'}</p>
                              </div>
                              <div>
                                <p className="text-gray-600 dark:text-gray-400">Anomaly Type</p>
                                <p className="font-medium">{anomaly.anomaly_type ?? 'N/A'}</p>
                              </div>
                              <div>
                                <p className="text-gray-600 dark:text-gray-400">Deviation Score</p>
                                <p className="font-medium">{anomaly.deviation_score ?? 0}%</p>
                              </div>
                            </div>
                            <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                              {anomaly.created_at ? new Date(anomaly.created_at).toLocaleString() : 'N/A'}
                            </p>
                          </div>
                          <button
                            onClick={() => handleViewAnomaly(anomaly.id)}
                            className="text-blue-600 dark:text-blue-400 hover:underline ml-4"
                            title="View details"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
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

                {filteredPrivileged.length === 0 ? (
                  renderEmptyState('No privileged access events found')
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Identity</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Event Type</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Created At</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Target Resource</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPrivileged.map((access) => (
                          <tr key={access.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-medium">{access.identity_id ?? 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">{access.event_type ?? 'N/A'}</td>
                            <td className="px-6 py-4 text-sm">{access.created_at ? new Date(access.created_at).toLocaleDateString() : 'N/A'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${access.was_revoked ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100' : 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100'}`}>
                                {access.was_revoked ? 'Revoked' : 'Active'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm">{access.target_resource ?? 'N/A'}</td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => handleViewAccess(access.id)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                                title="View details"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => handleEditAccess(access.id)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                                title="Edit access"
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
                <label className="block text-sm font-medium mb-1">Threat Type</label>
                <select
                  value={newThreatForm.threat_type}
                  onChange={(e) => setNewThreatForm((prev) => ({ ...prev, threat_type: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="">Select threat type...</option>
                  <option value="credential_stuffing">Credential Stuffing</option>
                  <option value="password_spray">Password Spray</option>
                  <option value="brute_force">Brute Force</option>
                  <option value="token_theft">Token Theft</option>
                  <option value="session_hijack">Session Hijack</option>
                  <option value="privilege_escalation">Privilege Escalation</option>
                  <option value="lateral_movement">Lateral Movement</option>
                  <option value="mfa_fatigue">MFA Fatigue</option>
                  <option value="impossible_travel">Impossible Travel</option>
                  <option value="account_takeover">Account Takeover</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Identity ID</label>
                <input
                  type="text"
                  placeholder="Enter identity ID"
                  value={newThreatForm.identity_id}
                  onChange={(e) => setNewThreatForm((prev) => ({ ...prev, identity_id: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select
                  value={newThreatForm.severity}
                  onChange={(e) => setNewThreatForm((prev) => ({ ...prev, severity: e.target.value }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Confidence Score</label>
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={newThreatForm.confidence_score}
                  onChange={(e) => setNewThreatForm((prev) => ({ ...prev, confidence_score: Number(e.target.value) }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => {
                    setShowNewThreatModal(false);
                    setNewThreatForm({ threat_type: '', identity_id: '', severity: 'critical', confidence_score: 80 });
                  }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  disabled={submitting}
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateThreat}
                  disabled={submitting || !newThreatForm.threat_type || !newThreatForm.identity_id}
                  className="flex-1 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {submitting ? 'Creating...' : 'Create'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
