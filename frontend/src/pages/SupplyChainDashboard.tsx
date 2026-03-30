import React, { useState } from 'react';
import {
  Package,
  GitBranch,
  Shield,
  Building2,
  FileCheck,
  Plus,
  Edit,
  Eye,
  Search,
  Filter,
  AlertTriangle,
  CheckCircle,
  Star,
  Trash2,
} from 'lucide-react';
import clsx from 'clsx';
import { supplychainApi } from '../api/endpoints';


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
    case 'compliant':
    case 'resolved':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'investigating':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'open':
      return 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

export default function SupplyChainDashboard() {
  const [activeTab, setActiveTab] = useState('sboms');
  const [sboms, setSBOMs] = useState<any[]>([]);
  const [components, setComponents] = useState<any[]>([]);
  const [vendors, setVendors] = useState<any[]>([]);
  const [risks, setRisks] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewComponentModal, setShowNewComponentModal] = useState(false);

  React.useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [sbomData, vendorData, riskData] = await Promise.all([
          supplychainApi.getSBOMs(),
          supplychainApi.getVendorAssessments(),
          supplychainApi.getSupplyChainRisks(),
        ]);
        setSBOMs(sbomData.data || []);
        setComponents([]);
        setVendors(vendorData.data || []);
        setRisks(riskData.findings || []);
      } catch (error) {
        console.error('Error loading supply chain data:', error);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const totalComponents = components.length;
  const criticalRisks = risks.filter(r => r.severity === 'critical').length;
  const vendorScoreAvg = (vendors.reduce((sum, v) => sum + v.assessmentScore, 0) / vendors.length).toFixed(1);
  const sbomCompliance = sboms.filter(s => s.status === 'compliant').length * 25;

  const tabs = [
    { id: 'sboms', label: 'SBOMs', icon: FileCheck },
    { id: 'components', label: 'Components', icon: Package },
    { id: 'risks', label: 'Supply Chain Risks', icon: Shield },
    { id: 'vendors', label: 'Vendor Assessments', icon: Building2 },
  ];

  const filteredComponents = components.filter(c =>
    c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    c.version.includes(searchQuery)
  );

  const filteredRisks = risks.filter(r =>
    r.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    r.component.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredVendors = vendors.filter(v =>
    v.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Package className="w-8 h-8 text-purple-600" />
            <h1 className="text-3xl font-bold">Supply Chain Management</h1>
          </div>
          <button
            onClick={() => setShowNewComponentModal(true)}
            className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            New Component
          </button>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Total Components</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{totalComponents}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">tracked across SBOMs</p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Critical Risks</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{criticalRisks}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">requiring action</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">Vendor Score Avg</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{vendorScoreAvg}</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">assessment score</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">SBOM Compliance</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{sbomCompliance}%</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">coverage</p>
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
                    ? 'border-purple-600 text-purple-600 dark:text-purple-400'
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
            {/* SBOMs Tab */}
            {activeTab === 'sboms' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 gap-4">
                  {sboms.map((sbom) => (
                    <div key={sbom.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <h3 className="font-semibold text-lg">{sbom.name}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">Format: {sbom.format}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(sbom.status)}`}>
                          {sbom.status}
                        </span>
                      </div>
                      <div className="grid grid-cols-4 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Version</p>
                          <p className="font-medium">{sbom.version}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Components</p>
                          <p className="font-medium">{sbom.componentCount}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Compliance Score</p>
                          <p className="font-medium">{sbom.complianceScore}%</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Created</p>
                          <p className="font-medium">{sbom.createdDate}</p>
                        </div>
                      </div>
                      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mb-3">
                        <div
                          className="bg-purple-600 h-2 rounded-full"
                          style={{ width: `${sbom.complianceScore}%` }}
                        />
                      </div>
                      <div className="flex gap-2">
                        <button className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          View
                        </button>
                        <button className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          Download
                        </button>
                        <button className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          Edit
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Components Tab */}
            {activeTab === 'components' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search components..."
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
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Component</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Version</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Type</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">License</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Vulns</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Risk</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Latest</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredComponents.map((comp) => (
                        <tr key={comp.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{comp.name}</td>
                          <td className="px-6 py-4 text-sm font-mono">{comp.version}</td>
                          <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{comp.type}</td>
                          <td className="px-6 py-4 text-sm">{comp.license}</td>
                          <td className="px-6 py-4 text-sm font-semibold">{comp.vulnerabilities}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(comp.riskLevel)}`}>
                              {comp.riskLevel}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm font-mono text-gray-600 dark:text-gray-400">{comp.latestVersion}</td>
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

            {/* Supply Chain Risks Tab */}
            {activeTab === 'risks' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search risks..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4">
                  {filteredRisks.map((risk) => (
                    <div key={risk.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <AlertTriangle className="w-5 h-5 text-orange-600" />
                            <h3 className="font-semibold">{risk.title}</h3>
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{risk.component}</p>
                        </div>
                        <div className="text-right">
                          <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(risk.severity)}`}>
                            {risk.severity}
                          </span>
                        </div>
                      </div>
                      <div className="space-y-2">
                        <div>
                          <p className="text-xs text-gray-600 dark:text-gray-400">Recommendation</p>
                          <p className="text-sm font-medium">{risk.recommendation}</p>
                        </div>
                        <div className="flex justify-between items-center pt-2 border-t border-gray-200 dark:border-gray-700">
                          <div>
                            <p className="text-xs text-gray-600 dark:text-gray-400">Detected</p>
                            <p className="text-sm">{risk.detectedDate}</p>
                          </div>
                          <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(risk.status)}`}>
                            {risk.status}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Vendor Assessments Tab */}
            {activeTab === 'vendors' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search vendors..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {filteredVendors.map((vendor) => (
                    <div key={vendor.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-4">
                        <div>
                          <h3 className="font-semibold text-lg">{vendor.name}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">{vendor.components} components</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(vendor.riskLevel)}`}>
                          {vendor.riskLevel}
                        </span>
                      </div>
                      <div className="space-y-3">
                        <div>
                          <div className="flex justify-between mb-1">
                            <span className="text-sm text-gray-600 dark:text-gray-400">Assessment Score</span>
                            <span className="font-semibold">{vendor.assessmentScore}%</span>
                          </div>
                          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div
                              className={`h-2 rounded-full ${vendor.assessmentScore >= 90 ? 'bg-green-600' : vendor.assessmentScore >= 80 ? 'bg-yellow-600' : 'bg-orange-600'}`}
                              style={{ width: `${vendor.assessmentScore}%` }}
                            />
                          </div>
                        </div>
                        <div>
                          <p className="text-sm font-medium mb-2">Certifications</p>
                          <div className="flex flex-wrap gap-2">
                            {vendor.certifications.length > 0 ? (
                              vendor.certifications.map((cert, idx) => (
                                <span key={idx} className="px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100 rounded text-xs">
                                  {cert}
                                </span>
                              ))
                            ) : (
                              <span className="text-sm text-gray-600 dark:text-gray-400">No certifications</span>
                            )}
                          </div>
                        </div>
                        <div className="pt-2 border-t border-gray-200 dark:border-gray-700">
                          <p className="text-xs text-gray-600 dark:text-gray-400">Last Audit: {vendor.lastAudit}</p>
                        </div>
                        <button className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition">
                          View Full Assessment
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

      {/* New Component Modal */}
      {showNewComponentModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Add Component</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Component Name</label>
                <input type="text" placeholder="e.g., log4j-core" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Version</label>
                <input type="text" placeholder="e.g., 2.18.0" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">License</label>
                <input type="text" placeholder="e.g., Apache-2.0" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => setShowNewComponentModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={() => setShowNewComponentModal(false)}
                  className="flex-1 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition"
                >
                  Add
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
