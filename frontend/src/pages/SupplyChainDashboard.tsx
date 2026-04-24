import React, { useRef, useState } from 'react';
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
  Upload,
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../lib/api';
import { supplychainApi } from '../api/endpoints';


const riskScoreToLevel = (score: number | null | undefined): string => {
  const s = Number(score || 0);
  if (s >= 9) return 'critical';
  if (s >= 7) return 'high';
  if (s >= 4) return 'medium';
  if (s > 0) return 'low';
  return 'none';
};

const complianceScoreFromSbom = (sbom: any): number => {
  if (typeof sbom?.vulnerability_risk_score === 'number') {
    return Math.max(0, Math.min(100, Math.round(100 - sbom.vulnerability_risk_score)));
  }
  return sbom?.compliance_status === 'compliant' ? 100 : 0;
};

const parseCertifications = (raw: any): string[] => {
  if (!raw) return [];
  if (Array.isArray(raw)) {
    return raw.map((c: any) => (typeof c === 'string' ? c : c?.name || '')).filter(Boolean);
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return parseCertifications(parsed);
    } catch {
      return [raw];
    }
  }
  return [];
};

const shortDate = (iso: any): string => {
  if (!iso) return '—';
  try {
    return new Date(iso).toISOString().slice(0, 10);
  } catch {
    return String(iso).slice(0, 10);
  }
};


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
  const [showGenerateSBOMModal, setShowGenerateSBOMModal] = useState(false);
  const [editingSBOM, setEditingSBOM] = useState<any | null>(null);
  const [selectedSBOM, setSelectedSBOM] = useState<any | null>(null);
  const [selectedComponent, setSelectedComponent] = useState<any | null>(null);
  const [selectedVendor, setSelectedVendor] = useState<any | null>(null);
  const [showFilter, setShowFilter] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [sbomData, vendorData, riskData, compData] = await Promise.all([
        supplychainApi.getSBOMs(),
        supplychainApi.getVendorAssessments(),
        supplychainApi.getSupplyChainRisks(),
        api.get('/supplychain/components').then(r => Array.isArray(r.data) ? r.data : (r.data?.items || [])).catch(() => []),
      ]);
      setSBOMs(Array.isArray(sbomData) ? sbomData : (sbomData?.items || []));
      setComponents(compData);
      setVendors(Array.isArray(vendorData) ? vendorData : (vendorData?.items || []));
      setRisks(Array.isArray(riskData) ? riskData : (riskData?.items || riskData?.findings || []));
    } catch (error) {
      console.error('Error loading supply chain data:', error);
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    loadData();
  }, []);

  const totalComponents = components.length;
  const criticalRisks = risks.filter(r => r.severity === 'critical').length;
  const vendorScoreAvg = (
    vendors.reduce((sum, v) => sum + (Number(v.security_score) || 0), 0) / (vendors.length || 1)
  ).toFixed(1);
  const sbomCompliance = sboms.length
    ? Math.round(
        (sboms.filter((s) => s.compliance_status === 'compliant').length / sboms.length) * 100,
      )
    : 0;

  const uploadInputRef = useRef<HTMLInputElement | null>(null);
  const [uploadBusy, setUploadBusy] = useState(false);
  const [uploadMessage, setUploadMessage] = useState<string | null>(null);

  const handleSBOMUpload = async (file: File | null) => {
    if (!file) return;
    setUploadBusy(true);
    setUploadMessage(null);
    try {
      const fd = new FormData();
      fd.append('file', file);
      const r = await api.post('/supplychain/sboms/upload', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setUploadMessage(`Uploaded: ${r.data?.name || file.name}`);
      await loadData();
    } catch (err: any) {
      console.error('SBOM upload failed:', err);
      setUploadMessage(
        `Upload failed: ${err?.response?.data?.detail || err?.message || 'unknown error'}`,
      );
    } finally {
      setUploadBusy(false);
      if (uploadInputRef.current) uploadInputRef.current.value = '';
    }
  };

  const tabs = [
    { id: 'sboms', label: 'SBOMs', icon: FileCheck },
    { id: 'components', label: 'Components', icon: Package },
    { id: 'risks', label: 'Supply Chain Risks', icon: Shield },
    { id: 'vendors', label: 'Vendor Assessments', icon: Building2 },
  ];

  const filteredComponents = components.filter(c =>
    (c.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (c.version || '').includes(searchQuery)
  );

  const filteredRisks = risks.filter((r) => {
    const q = searchQuery.toLowerCase();
    return (
      (r.risk_type || '').toLowerCase().includes(q) ||
      (r.description || '').toLowerCase().includes(q) ||
      (r.severity || '').toLowerCase().includes(q)
    );
  });

  const filteredVendors = vendors.filter(v =>
    (v.vendor_name || '').toLowerCase().includes(searchQuery.toLowerCase())
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
                <div className="flex justify-end gap-2">
                  <input
                    ref={uploadInputRef}
                    type="file"
                    accept=".json,application/json"
                    className="hidden"
                    onChange={(e) => handleSBOMUpload(e.target.files?.[0] || null)}
                  />
                  <button
                    onClick={() => uploadInputRef.current?.click()}
                    disabled={uploadBusy}
                    className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg transition"
                  >
                    <Upload className="w-4 h-4" />
                    {uploadBusy ? 'Uploading…' : 'Upload SBOM (SPDX/CycloneDX)'}
                  </button>
                  <button
                    onClick={() => setShowGenerateSBOMModal(true)}
                    className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition"
                  >
                    <Plus className="w-4 h-4" />
                    Generate SBOM
                  </button>
                </div>
                {uploadMessage && (
                  <div className="text-sm px-4 py-2 rounded border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-800 text-gray-700 dark:text-gray-200">
                    {uploadMessage}
                  </div>
                )}
                {sboms.length === 0 && (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
                    No SBOMs yet. Upload an SPDX/CycloneDX JSON or click "Generate SBOM".
                  </div>
                )}
                <div className="grid grid-cols-1 gap-4">
                  {sboms.map((sbom) => {
                    const complianceScore = complianceScoreFromSbom(sbom);
                    return (
                    <div key={sbom.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <h3 className="font-semibold text-lg">{sbom.name}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">Format: {sbom.sbom_format}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(sbom.compliance_status || 'unknown')}`}>
                          {sbom.compliance_status || 'unknown'}
                        </span>
                      </div>
                      <div className="grid grid-cols-4 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Version</p>
                          <p className="font-medium">{sbom.application_version}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Components</p>
                          <p className="font-medium">{sbom.components_count ?? 0}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Compliance Score</p>
                          <p className="font-medium">{complianceScore}%</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Created</p>
                          <p className="font-medium">{shortDate(sbom.created_at)}</p>
                        </div>
                      </div>
                      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2 mb-3">
                        <div
                          className="bg-purple-600 h-2 rounded-full"
                          style={{ width: `${complianceScore}%` }}
                        />
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => setSelectedSBOM(sbom)}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          View
                        </button>
                        <button
                          onClick={async () => {
                            try {
                              const { blob, filename } = await supplychainApi.downloadSBOM(
                                sbom.id,
                                'cyclonedx_json'
                              );
                              const url = URL.createObjectURL(blob);
                              const a = document.createElement('a');
                              a.href = url;
                              a.download = filename;
                              document.body.appendChild(a);
                              a.click();
                              document.body.removeChild(a);
                              URL.revokeObjectURL(url);
                            } catch (err) {
                              console.error('Error downloading SBOM:', err);
                            }
                          }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Download
                        </button>
                        <button
                          onClick={() => setEditingSBOM(sbom)}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Edit
                        </button>
                      </div>
                    </div>
                    );
                  })}
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
                  <button
                    onClick={() => setShowFilter((prev) => !prev)}
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  >
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                </div>

                {filteredComponents.length === 0 && (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
                    No components. Upload an SBOM or add components via the New Component button.
                  </div>
                )}
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
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Score</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredComponents.map((comp) => {
                        const level = riskScoreToLevel(comp.risk_score);
                        const license = comp.license_spdx_id || comp.license_type || '—';
                        return (
                        <tr key={comp.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{comp.name}</td>
                          <td className="px-6 py-4 text-sm font-mono">{comp.version}</td>
                          <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{comp.package_type || '—'}</td>
                          <td className="px-6 py-4 text-sm">{license}</td>
                          <td className="px-6 py-4 text-sm font-semibold">{comp.known_vulnerabilities_count ?? 0}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(level)}`}>
                              {level}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm font-mono text-gray-600 dark:text-gray-400">{(comp.risk_score ?? 0).toFixed ? comp.risk_score.toFixed(1) : comp.risk_score}</td>
                          <td className="px-6 py-4 text-sm flex gap-2">
                            <button
                              onClick={() => setSelectedComponent(comp)}
                              className="text-blue-600 dark:text-blue-400 hover:underline"
                            >
                              <Eye className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => setSelectedComponent(comp)}
                              className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                            >
                              <Edit className="w-4 h-4" />
                            </button>
                          </td>
                        </tr>
                        );
                      })}
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

                {filteredRisks.length === 0 && (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
                    No supply-chain risks detected yet. The daily cross-org sweep populates typosquat and CVE risks automatically.
                  </div>
                )}
                <div className="grid grid-cols-1 gap-4">
                  {filteredRisks.map((risk) => (
                    <div key={risk.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <AlertTriangle className="w-5 h-5 text-orange-600" />
                            <h3 className="font-semibold">{risk.risk_type || 'Risk'}</h3>
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{risk.description}</p>
                        </div>
                        <div className="text-right">
                          <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(risk.severity)}`}>
                            {risk.severity}
                          </span>
                        </div>
                      </div>
                      <div className="space-y-2">
                        <div>
                          <p className="text-xs text-gray-600 dark:text-gray-400">Remediation</p>
                          <p className="text-sm font-medium">{risk.remediation_advice || 'Pending analyst triage'}</p>
                        </div>
                        <div className="flex justify-between items-center pt-2 border-t border-gray-200 dark:border-gray-700">
                          <div>
                            <p className="text-xs text-gray-600 dark:text-gray-400">Detected</p>
                            <p className="text-sm">{shortDate(risk.detected_date || risk.created_at)}</p>
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

                {filteredVendors.length === 0 && (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
                    No vendor assessments yet.
                  </div>
                )}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {filteredVendors.map((vendor) => {
                    const score = Number(vendor.security_score) || 0;
                    const certs = parseCertifications(vendor.certifications);
                    return (
                    <div key={vendor.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-4">
                        <div>
                          <h3 className="font-semibold text-lg">{vendor.vendor_name}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">{vendor.assessment_type || 'assessment'}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(vendor.risk_tier || 'medium')}`}>
                          {vendor.risk_tier || 'medium'}
                        </span>
                      </div>
                      <div className="space-y-3">
                        <div>
                          <div className="flex justify-between mb-1">
                            <span className="text-sm text-gray-600 dark:text-gray-400">Security Score</span>
                            <span className="font-semibold">{score.toFixed(1)}%</span>
                          </div>
                          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                            <div
                              className={`h-2 rounded-full ${score >= 90 ? 'bg-green-600' : score >= 80 ? 'bg-yellow-600' : 'bg-orange-600'}`}
                              style={{ width: `${score}%` }}
                            />
                          </div>
                        </div>
                        <div>
                          <p className="text-sm font-medium mb-2">Certifications</p>
                          <div className="flex flex-wrap gap-2">
                            {certs.length > 0 ? (
                              certs.map((cert: string, idx: number) => (
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
                          <p className="text-xs text-gray-600 dark:text-gray-400">Assessed: {shortDate(vendor.assessment_date)}</p>
                          {vendor.incident_count > 0 && (
                            <p className="text-xs text-red-600 dark:text-red-400 mt-1">{vendor.incident_count} incident(s) on file</p>
                          )}
                        </div>
                        <button
                          onClick={() => setSelectedVendor(vendor)}
                          className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          View Full Assessment
                        </button>
                      </div>
                    </div>
                    );
                  })}
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
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.post('/supplychain/components', { name: fd.get('name'), version: fd.get('version'), license: fd.get('license') });
                setShowNewComponentModal(false);
                loadData();
              } catch (err) { console.error('Failed to add component:', err); }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Component Name</label>
                <input name="name" required type="text" placeholder="e.g., log4j-core" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Version</label>
                <input name="version" type="text" placeholder="e.g., 2.18.0" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">License</label>
                <input name="license" type="text" placeholder="e.g., Apache-2.0" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setShowNewComponentModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition">Add</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Generate SBOM Modal */}
      {showGenerateSBOMModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setShowGenerateSBOMModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Generate SBOM</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.post('/supplychain/sboms/generate', {
                  name: fd.get('name'),
                  application_name: fd.get('application_name'),
                  application_version: fd.get('application_version') || '1.0',
                  sbom_format: fd.get('sbom_format') || 'cyclonedx_json',
                  spec_version: fd.get('spec_version') || '1.5',
                });
                setShowGenerateSBOMModal(false);
                loadData();
              } catch (err: any) {
                console.error('Generate SBOM failed:', err);
                alert(err?.response?.data?.detail || 'Failed to generate SBOM');
              }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">SBOM Name</label>
                <input name="name" required type="text" placeholder="PySOAR Production SBOM" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Application Name</label>
                <input name="application_name" required type="text" placeholder="PySOAR" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Version</label>
                <input name="application_version" type="text" placeholder="1.0" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Format</label>
                <select name="sbom_format" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                  <option value="cyclonedx_json">CycloneDX JSON</option>
                  <option value="spdx_json">SPDX JSON</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Spec Version</label>
                <input name="spec_version" type="text" defaultValue="1.5" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setShowGenerateSBOMModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition">Generate</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit SBOM Modal */}
      {editingSBOM && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setEditingSBOM(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Edit SBOM</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.patch(`/supplychain/sboms/${editingSBOM.id}`, {
                  name: fd.get('name'),
                  compliance_status: fd.get('compliance_status') || undefined,
                });
                setEditingSBOM(null);
                loadData();
              } catch (err: any) {
                console.error('Edit SBOM failed:', err);
                alert(err?.response?.data?.detail || 'Failed to update SBOM');
              }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Name</label>
                <input name="name" required type="text" defaultValue={editingSBOM.name || ''} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Compliance Status</label>
                <select name="compliance_status" defaultValue={editingSBOM.compliance_status || 'compliant'} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                  <option value="compliant">compliant</option>
                  <option value="non_compliant">non_compliant</option>
                  <option value="unknown">unknown</option>
                </select>
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400">Only name and compliance_status are updatable. Version/format changes require regenerating the SBOM.</p>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setEditingSBOM(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
