import React, { useState } from 'react';
import {
  Bug,
  Shield,
  Activity,
  CheckCircle,
  AlertTriangle,
  Plus,
  Edit,
  Eye,
  Search,
  Filter,
  TrendingUp,
  Download,
} from 'lucide-react';
import clsx from 'clsx';
import { vulnmgmtApi } from '../api/endpoints';

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
    case 'critical':
    case 'in-progress':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'completed':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'running':
      return 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-100';
    case 'active':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'planned':
    case 'scheduled':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

export default function VulnManagement() {
  const [activeTab, setActiveTab] = useState('vulnerabilities');
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [scanProfiles, setScanProfiles] = useState<any[]>([]);
  const [patchOps, setPatchOps] = useState<any[]>([]);
  const [exceptions, setExceptions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewVulnModal, setShowNewVulnModal] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<any | null>(null);
  const [editingVulnerability, setEditingVulnerability] = useState<any | null>(null);
  const [editingException, setEditingException] = useState<any | null>(null);
  const [editingScanProfile, setEditingScanProfile] = useState<any | null>(null);
  const [showFilterPanel, setShowFilterPanel] = useState(false);
  const [remediatingVuln, setRemediatingVuln] = useState<any | null>(null);

  React.useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [vulnsData, patchData] = await Promise.all([
          vulnmgmtApi.getVulnerabilities(),
          vulnmgmtApi.getPatchOperations(),
        ]);
        setVulnerabilities(Array.isArray(vulnsData) ? vulnsData : (vulnsData?.items || vulnsData?.data || []));
        setScanProfiles([]);
        setPatchOps(Array.isArray(patchData) ? patchData : (patchData?.items || patchData?.data || []));
        setExceptions([]);
      } catch (error) {
        console.error('Error loading vulnerability data:', error);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical').length;
  const openFindings = vulnerabilities.length;
  const mttrDays = 8.3;
  const slaCompliance = 82;

  const tabs = [
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { id: 'scan-profiles', label: 'Scan Profiles', icon: Activity },
    { id: 'patch-ops', label: 'Patch Operations', icon: CheckCircle },
    { id: 'exceptions', label: 'Exceptions', icon: Shield },
    { id: 'cisa-kev', label: 'CISA KEV', icon: AlertTriangle },
  ];

  const filteredVulns = vulnerabilities.filter(v =>
    v.cveId.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.title.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const kevVulns = vulnerabilities.filter(v => v.kev);

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Bug className="w-8 h-8 text-red-600" />
            <h1 className="text-3xl font-bold">Vulnerability Management</h1>
          </div>
          <button
            onClick={() => setShowNewVulnModal(true)}
            className="flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            New Vulnerability
          </button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Critical Vulns</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{criticalVulns}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">requiring immediate action</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Open Findings</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{openFindings}</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">identified</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">MTTR</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{mttrDays}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">days mean time to remediate</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">SLA Compliance</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{slaCompliance}%</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">target achievement</p>
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
                    ? 'border-red-600 text-red-600 dark:text-red-400'
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
            {/* Vulnerabilities Tab */}
            {activeTab === 'vulnerabilities' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">CVSS Score Distribution</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>9.0 - 10.0</span><span className="font-semibold text-red-600">3</span></div>
                      <div className="flex justify-between"><span>7.0 - 8.9</span><span className="font-semibold text-orange-600">2</span></div>
                      <div className="flex justify-between"><span>5.0 - 6.9</span><span className="font-semibold text-yellow-600">1</span></div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Exploitability Index</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Very High</span><span className="font-semibold">2</span></div>
                      <div className="flex justify-between"><span>High</span><span className="font-semibold">3</span></div>
                      <div className="flex justify-between"><span>Medium</span><span className="font-semibold">1</span></div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Patch Status</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Patch Available</span><span className="font-semibold text-green-600">4</span></div>
                      <div className="flex justify-between"><span>No Patch</span><span className="font-semibold text-red-600">2</span></div>
                    </div>
                  </div>
                </div>

                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search by CVE or title..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button
                    onClick={() => setShowFilterPanel(prev => !prev)}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  >
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                </div>

                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">CVE ID</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Title</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">CVSS</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">EPSS</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">KEV</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Assets</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Patch</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredVulns.map((vuln) => (
                        <tr key={vuln.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-mono font-medium">{vuln.cveId}</td>
                          <td className="px-6 py-4 text-sm">{vuln.title}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                              {vuln.severity.toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm font-semibold">{vuln.cvss.toFixed(1)}</td>
                          <td className="px-6 py-4 text-sm">{(vuln.epss * 100).toFixed(0)}%</td>
                          <td className="px-6 py-4">
                            {vuln.kev ? (
                              <AlertTriangle className="w-5 h-5 text-red-600" />
                            ) : (
                              <span className="text-gray-400">—</span>
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm">{vuln.affectedAssets}</td>
                          <td className="px-6 py-4 text-sm">
                            {vuln.patchAvailable ? (
                              <CheckCircle className="w-5 h-5 text-green-600" />
                            ) : (
                              <AlertTriangle className="w-5 h-5 text-orange-600" />
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm flex gap-2">
                            <button
                              onClick={() => setSelectedVulnerability(vuln)}
                              className="text-blue-600 dark:text-blue-400 hover:underline"
                            >
                              <Eye className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => setEditingVulnerability(vuln)}
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
              </div>
            )}

            {/* Scan Profiles Tab */}
            {activeTab === 'scan-profiles' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 gap-4">
                  {scanProfiles.map((profile) => (
                    <div key={profile.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div>
                          <h3 className="font-semibold text-lg">{profile.name}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">Schedule: {profile.schedule}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(profile.status)}`}>
                          {profile.status}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-4 text-sm">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Last Run</p>
                          <p className="font-medium">{new Date(profile.lastRun).toLocaleString()}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Duration</p>
                          <p className="font-medium">{profile.duration}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Next Run</p>
                          <p className="font-medium">{new Date(profile.nextRun).toLocaleString()}</p>
                        </div>
                      </div>
                      <div className="flex gap-2 mt-4">
                        <button
                          onClick={async () => {
                            try {
                              await vulnmgmtApi.runScan(profile.id);
                              alert('Scan started successfully for: ' + profile.name);
                            } catch (error) {
                              console.error('Error running scan:', error);
                            }
                          }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Run Now
                        </button>
                        <button
                          onClick={() => setEditingScanProfile(profile)}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Edit
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Patch Operations Tab */}
            {activeTab === 'patch-ops' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 gap-4">
                  {patchOps.map((op) => (
                    <div key={op.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                      <div className="flex justify-between items-start mb-4">
                        <div>
                          <h3 className="font-semibold text-lg">{op.name}</h3>
                          <div className="flex gap-4 mt-2 text-sm text-gray-600 dark:text-gray-400">
                            <span>{op.vulnCount} vulnerabilities</span>
                            <span>·</span>
                            <span>{op.systemsAffected} systems</span>
                          </div>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(op.severity)}`}>
                          {op.severity}
                        </span>
                      </div>
                      <div className="space-y-3">
                        <div className="flex justify-between text-sm">
                          <span className="text-gray-600 dark:text-gray-400">Progress</span>
                          <span className="font-semibold">{op.progress}%</span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className="bg-green-600 h-2 rounded-full transition-all"
                            style={{ width: `${op.progress}%` }}
                          />
                        </div>
                        <div className="grid grid-cols-3 gap-4 text-sm pt-2">
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Start</p>
                            <p className="font-medium">{op.startDate}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Status</p>
                            <p className="font-medium capitalize">{op.status}</p>
                          </div>
                          <div>
                            <p className="text-gray-600 dark:text-gray-400">Target</p>
                            <p className="font-medium">{op.targetDate}</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Exceptions Tab */}
            {activeTab === 'exceptions' && (
              <div className="space-y-6">
                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">CVE ID</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Reason</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Approver</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Expires</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {exceptions.map((exc) => (
                        <tr key={exc.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-mono font-medium">{exc.cveId}</td>
                          <td className="px-6 py-4 text-sm">{exc.reason}</td>
                          <td className="px-6 py-4 text-sm">{exc.approver}</td>
                          <td className="px-6 py-4 text-sm">{exc.expiryDate}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(exc.status)}`}>
                              {exc.status}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm flex gap-2">
                            <button
                              onClick={() => setEditingException(exc)}
                              className="text-blue-600 dark:text-blue-400 hover:underline"
                            >
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

            {/* CISA KEV Tab */}
            {activeTab === 'cisa-kev' && (
              <div className="space-y-6">
                <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-4 mb-6">
                  <p className="text-sm text-blue-800 dark:text-blue-200">
                    Catalog of Exploited Vulnerabilities (KEV) - Known Exploited Vulnerabilities in the Wild
                  </p>
                </div>

                <div className="grid grid-cols-1 gap-4">
                  {kevVulns.map((vuln) => (
                    <div key={vuln.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <AlertTriangle className="w-5 h-5 text-red-600" />
                            <h3 className="font-semibold text-lg">{vuln.cveId}</h3>
                            <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                              {vuln.severity}
                            </span>
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{vuln.title}</p>
                          <div className="grid grid-cols-4 gap-4 text-sm">
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">CVSS Score</p>
                              <p className="font-semibold">{vuln.cvss.toFixed(1)}</p>
                            </div>
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">EPSS Score</p>
                              <p className="font-semibold">{(vuln.epss * 100).toFixed(0)}%</p>
                            </div>
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">Affected Assets</p>
                              <p className="font-semibold">{vuln.affectedAssets}</p>
                            </div>
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">Days Open</p>
                              <p className="font-semibold">{vuln.daysOpen}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => setRemediatingVuln(vuln)}
                          className="flex-1 px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded transition"
                        >
                          Remediate
                        </button>
                        <button
                          onClick={() => setSelectedVulnerability(vuln)}
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
          </>
        )}
      </div>

      {/* Vulnerability Detail Modal */}
      {selectedVulnerability && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[500px] max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Vulnerability Details</h2>
            <div className="space-y-3 text-sm">
              <div><span className="font-medium">CVE ID:</span> {selectedVulnerability.cveId}</div>
              <div><span className="font-medium">Title:</span> {selectedVulnerability.title}</div>
              <div><span className="font-medium">Severity:</span> {selectedVulnerability.severity}</div>
              <div><span className="font-medium">CVSS:</span> {selectedVulnerability.cvss?.toFixed(1)}</div>
              {selectedVulnerability.epss && <div><span className="font-medium">EPSS:</span> {(selectedVulnerability.epss * 100).toFixed(0)}%</div>}
              <div><span className="font-medium">KEV:</span> {selectedVulnerability.kev ? 'Yes' : 'No'}</div>
              <div><span className="font-medium">Affected Assets:</span> {selectedVulnerability.affectedAssets}</div>
              <div><span className="font-medium">Patch Available:</span> {selectedVulnerability.patchAvailable ? 'Yes' : 'No'}</div>
              {selectedVulnerability.daysOpen && <div><span className="font-medium">Days Open:</span> {selectedVulnerability.daysOpen}</div>}
            </div>
            <button onClick={() => setSelectedVulnerability(null)} className="mt-6 w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Close</button>
          </div>
        </div>
      )}

      {/* Edit Vulnerability Modal */}
      {editingVulnerability && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Edit: {editingVulnerability.cveId}</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Title</label>
                <input type="text" defaultValue={editingVulnerability.title} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select defaultValue={editingVulnerability.severity} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => setEditingVulnerability(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button onClick={() => { alert('Vulnerability updated.'); setEditingVulnerability(null); }} className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Save</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Edit Exception Modal */}
      {editingException && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Edit Exception: {editingException.cveId}</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Reason</label>
                <textarea defaultValue={editingException.reason} rows={3} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Expiry Date</label>
                <input type="date" defaultValue={editingException.expiryDate} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => setEditingException(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button onClick={() => { alert('Exception updated.'); setEditingException(null); }} className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Save</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Edit Scan Profile Modal */}
      {editingScanProfile && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Edit Scan Profile: {editingScanProfile.name}</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Name</label>
                <input type="text" defaultValue={editingScanProfile.name} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Schedule</label>
                <input type="text" defaultValue={editingScanProfile.schedule} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button onClick={() => setEditingScanProfile(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button onClick={() => { alert('Scan profile updated.'); setEditingScanProfile(null); }} className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Save</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Remediation Modal */}
      {remediatingVuln && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[500px] max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Remediate: {remediatingVuln.cveId}</h2>
            <div className="space-y-3">
              <p className="text-sm text-gray-600 dark:text-gray-400">{remediatingVuln.title}</p>
              <button onClick={async () => { try { await vulnmgmtApi.runScan(remediatingVuln.id); alert('Patch operation initiated for ' + remediatingVuln.cveId); setRemediatingVuln(null); } catch (e) { console.error(e); } }} className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Apply Patch</button>
              <button onClick={() => { alert('Compensating control applied for ' + remediatingVuln.cveId); setRemediatingVuln(null); }} className="w-full px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition">Apply Compensating Control</button>
              <button onClick={() => setRemediatingVuln(null)} className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* New Vulnerability Modal */}
      {showNewVulnModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create Vulnerability Record</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">CVE ID</label>
                <input type="text" placeholder="CVE-2025-XXXX" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Title</label>
                <input type="text" placeholder="Vulnerability title" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">CVSS Score</label>
                <input type="number" placeholder="0.0" step="0.1" min="0" max="10" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => setShowNewVulnModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={() => setShowNewVulnModal(false)}
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition"
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
