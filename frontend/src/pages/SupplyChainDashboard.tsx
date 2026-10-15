import React, { useRef, useState } from 'react';
import {
  Package,
  Shield,
  Building2,
  FileCheck,
  Plus,
  Eye,
  Search,
  AlertTriangle,
  Trash2,
  Upload,
  RefreshCw,
  GitCompare,
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../lib/api';
import { supplychainApi } from '../api/endpoints';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';

const NA = 'not available';

const riskScoreToLevel = (score: number | null | undefined): string => {
  const s = Number(score || 0);
  if (s >= 9) return 'critical';
  if (s >= 7) return 'high';
  if (s >= 4) return 'medium';
  if (s > 0) return 'low';
  return 'none';
};

// Package types the component model accepts; the OSV lookup needs the
// ecosystem (or a purl) to query.
const PACKAGE_TYPES = ['npm', 'pypi', 'maven', 'nuget', 'gem', 'cargo', 'go_module', 'apt', 'rpm', 'container_image', 'binary'];

const parseCertifications = (raw: unknown): string[] => {
  if (!raw) return [];
  if (Array.isArray(raw)) {
    return raw.map((c: unknown) => (typeof c === 'string' ? c : (c as Row)?.name || '')).filter(Boolean);
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

const shortDate = (iso: string | null | undefined): string => {
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
    case 'assessed':
    case 'scanned':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'non_compliant':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
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
  const [sboms, setSBOMs] = useState<Row[]>([]);
  const [components, setComponents] = useState<Row[]>([]);
  const [vendors, setVendors] = useState<Row[]>([]);
  const [risks, setRisks] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewComponentModal, setShowNewComponentModal] = useState(false);
  const [showGenerateSBOMModal, setShowGenerateSBOMModal] = useState(false);
  const [editingSBOM, setEditingSBOM] = useState<Row | null>(null);
  const [selectedSBOM, setSelectedSBOM] = useState<Row | null>(null);
  const [sbomCompliance, setSbomCompliance] = useState<{ data?: Row; error?: unknown } | null>(null);
  const [selectedComponent, setSelectedComponent] = useState<Row | null>(null);
  const [componentVulns, setComponentVulns] = useState<{ data?: Row; error?: unknown } | null>(null);
  const [selectedVendor, setSelectedVendor] = useState<Row | null>(null);
  const [vendorForm, setVendorForm] = useState<Row | null>(null);
  const [questionnaire, setQuestionnaire] = useState<Row | null>(null);
  const [scanStatusFilter, setScanStatusFilter] = useState('');
  const [vulnSources, setVulnSources] = useState<Row | null>(null);
  const [lookupResult, setLookupResult] = useState<Row | null>(null);
  const [compareIds, setCompareIds] = useState<{ a: string; b: string }>({ a: '', b: '' });
  const [compareResult, setCompareResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  // Per-list load failures; each list's tab and card report its own error
  // instead of rendering an empty list / zero.
  const [loadErrors, setLoadErrors] = useState<{
    sboms?: unknown; components?: unknown; vendors?: unknown; risks?: unknown; sources?: unknown;
  }>({});

  const loadData = async () => {
    setLoading(true);
    try {
      const [sbomData, vendorData, riskData, compData, sourcesData] = await Promise.allSettled([
        supplychainApi.getSBOMs({ size: 100 }),
        supplychainApi.getVendorAssessments(),
        supplychainApi.getSupplyChainRisks(),
        api.get('/supplychain/components', { params: { size: 100, scan_status: scanStatusFilter || undefined } })
          .then(r => Array.isArray(r.data) ? r.data : (r.data?.items || [])),
        api.get('/supplychain/vulnerability-sources').then(r => r.data),
      ]);
      setLoadErrors({
        sboms: sbomData.status === 'rejected' ? sbomData.reason : undefined,
        vendors: vendorData.status === 'rejected' ? vendorData.reason : undefined,
        risks: riskData.status === 'rejected' ? riskData.reason : undefined,
        components: compData.status === 'rejected' ? compData.reason : undefined,
        sources: sourcesData.status === 'rejected' ? sourcesData.reason : undefined,
      });
      if (sourcesData.status === 'fulfilled') setVulnSources(sourcesData.value);
      if (sbomData.status === 'fulfilled') {
        const v = sbomData.value;
        setSBOMs(Array.isArray(v) ? v : (v?.items || []));
      }
      if (compData.status === 'fulfilled') setComponents(compData.value);
      if (vendorData.status === 'fulfilled') {
        const v = vendorData.value;
        setVendors(Array.isArray(v) ? v : (v?.items || []));
      }
      if (riskData.status === 'fulfilled') {
        const v = riskData.value;
        setRisks(Array.isArray(v) ? v : (v?.items || []));
      }
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanStatusFilter]);

  const runAction = async (key: string, what: string, fn: () => Promise<void>) => {
    setBusy(key);
    setActionError(null);
    try {
      await fn();
      await loadData();
    } catch (error) {
      setActionError({ what, error });
    } finally {
      setBusy(null);
    }
  };

  const openSBOM = async (sbom: Row) => {
    setSelectedSBOM(sbom);
    setSbomCompliance(null);
    try {
      setSbomCompliance({ data: (await api.get(`/supplychain/sboms/${sbom.id}/compliance`)).data });
    } catch (error) {
      setSbomCompliance({ error });
    }
  };

  const openComponent = async (comp: Row) => {
    setSelectedComponent(comp);
    setComponentVulns(null);
    try {
      setComponentVulns({ data: (await api.get(`/supplychain/components/${comp.id}/vulnerabilities`)).data });
    } catch (error) {
      setComponentVulns({ error });
    }
  };

  const openVendorForm = async (vendor: Row | null) => {
    setActionError(null);
    setVendorForm(vendor ?? {});
    if (!questionnaire) {
      try {
        setQuestionnaire((await api.get('/supplychain/vendors/questionnaire')).data);
      } catch (error) {
        setActionError({ what: 'load the vendor questionnaire', error });
      }
    }
  };

  // A card whose list failed to load, or that has nothing to average,
  // shows "not available" rather than 0.
  const totalComponents: number | null = loadErrors.components ? null : components.length;
  const criticalRisks: number | null = loadErrors.risks ? null : risks.filter(r => r.severity === 'critical').length;
  // Only vendors whose score was computed from stored answers count.
  const scoredVendors = vendors.filter((v) => v.assessment_status === 'assessed');
  const vendorScoreAvg: string | null = !loadErrors.vendors && scoredVendors.length > 0
    ? (scoredVendors.reduce((sum, v) => sum + Number(v.security_score), 0) / scoredVendors.length).toFixed(1)
    : null;
  const assessedSboms = sboms.filter((s) => s.compliance_status === 'compliant' || s.compliance_status === 'non_compliant');
  const sbomCompliancePct: number | null = !loadErrors.sboms && assessedSboms.length
    ? Math.round(
        (assessedSboms.filter((s) => s.compliance_status === 'compliant').length / assessedSboms.length) * 100,
      )
    : null;

  const uploadInputRef = useRef<HTMLInputElement | null>(null);
  const [uploadMessage, setUploadMessage] = useState<string | null>(null);

  // 422 invalid_sbom carries `errors`; 413 sbom_too_large.
  const handleSBOMUpload = async (file: File | null) => {
    if (!file) return;
    setUploadMessage(null);
    await runAction('upload', `upload ${file.name}`, async () => {
      const fd = new FormData();
      fd.append('file', file);
      const r = await api.post('/supplychain/sboms/upload', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setUploadMessage(
        `Uploaded ${r.data?.name || file.name}: ${r.data?.components_count ?? 0} component(s) stored `
        + `(${r.data?.direct_dependencies ?? 0} direct, ${r.data?.transitive_dependencies ?? 0} transitive); `
        + `NTIA status ${String(r.data?.compliance_status ?? 'not_assessed').replace(/_/g, ' ')}.`,
      );
    });
    if (uploadInputRef.current) uploadInputRef.current.value = '';
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
            onClick={() => { setActionError(null); setShowNewComponentModal(true); }}
            className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            New Component
          </button>
        </div>
        {actionError && !showNewComponentModal && !showGenerateSBOMModal && !editingSBOM && !vendorForm && (
          <div className="mb-4"><ActionErrorBanner what={actionError.what} error={actionError.error} /></div>
        )}

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Total Components</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{totalComponents ?? 'not available'}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">
              {scanStatusFilter ? `${scanStatusFilter.replace('_', ' ')} (filtered)` : 'tracked across SBOMs (first 100)'}
            </p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Critical Risks</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{criticalRisks ?? 'not available'}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">requiring action</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">Vendor Score Avg</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{vendorScoreAvg ?? 'not available'}</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">
              {scoredVendors.length} of {vendors.length} vendor(s) assessed from questionnaire answers
            </p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">SBOM Compliance</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{sbomCompliancePct !== null ? `${sbomCompliancePct}%` : NA}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">of {assessedSboms.length} assessed SBOM(s) meet the NTIA minimum elements</p>
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
                <LoadErrorBanner what="SBOMs" error={loadErrors.sboms} />
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
                    disabled={busy !== null}
                    className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg transition"
                  >
                    <Upload className="w-4 h-4" />
                    {busy === 'upload' ? 'Uploading…' : 'Upload SBOM (SPDX/CycloneDX)'}
                  </button>
                  <button
                    onClick={() => { setActionError(null); setShowGenerateSBOMModal(true); }}
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
                    No SBOMs yet. Upload an SPDX/CycloneDX JSON or generate one from stored components.
                  </div>
                )}
                {sboms.length >= 2 && (
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <div className="flex flex-wrap items-end gap-2">
                      <GitCompare className="w-5 h-5 text-purple-600" />
                      <select value={compareIds.a} onChange={(e) => setCompareIds({ ...compareIds, a: e.target.value })} aria-label="Baseline SBOM" className="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <option value="">Baseline SBOM...</option>
                        {sboms.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.application_version})</option>)}
                      </select>
                      <select value={compareIds.b} onChange={(e) => setCompareIds({ ...compareIds, b: e.target.value })} aria-label="Compared SBOM" className="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                        <option value="">Compare with...</option>
                        {sboms.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.application_version})</option>)}
                      </select>
                      <button
                        disabled={!compareIds.a || !compareIds.b || compareIds.a === compareIds.b || busy !== null}
                        onClick={() => runAction('compare', 'compare the SBOMs', async () => {
                          setCompareResult((await api.post('/supplychain/sboms/compare', { sbom_id_1: compareIds.a, sbom_id_2: compareIds.b })).data);
                        })}
                        className="px-4 py-2 text-sm bg-purple-600 text-white rounded-lg disabled:opacity-50"
                      >
                        Compare
                      </button>
                    </div>
                    {compareResult && (
                      <div className="text-sm space-y-1">
                        <p>
                          {compareResult.components_added?.length ?? 0} added, {compareResult.components_removed?.length ?? 0} removed,{' '}
                          {compareResult.components_updated?.length ?? 0} version change(s), {compareResult.unchanged} unchanged; vulnerability risk change {compareResult.risk_score_change}.
                        </p>
                        {(compareResult.components_added ?? []).length > 0 && (
                          <p><span className="font-medium text-green-700">Added:</span> {compareResult.components_added.map((c: Row) => `${c.name}@${c.version}`).join(', ')}</p>
                        )}
                        {(compareResult.components_removed ?? []).length > 0 && (
                          <p><span className="font-medium text-red-700">Removed:</span> {compareResult.components_removed.map((c: Row) => `${c.name}@${c.version}`).join(', ')}</p>
                        )}
                        {(compareResult.components_updated ?? []).length > 0 && (
                          <p><span className="font-medium text-blue-700">Updated:</span> {compareResult.components_updated.map((c: Row) => `${c.name} ${c.from_version} -> ${c.to_version}`).join(', ')}</p>
                        )}
                      </div>
                    )}
                  </div>
                )}
                <div className="grid grid-cols-1 gap-4">
                  {sboms.map((sbom) => {
                    return (
                    <div key={sbom.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <h3 className="font-semibold text-lg">{sbom.name}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">Format: {sbom.sbom_format}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(sbom.compliance_status || 'not_assessed')}`} title="NTIA minimum elements, derived from the stored components">
                          {String(sbom.compliance_status || 'not_assessed').replace(/_/g, ' ')}
                        </span>
                      </div>
                      <div className="grid grid-cols-5 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Version</p>
                          <p className="font-medium">{sbom.application_version}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Components</p>
                          <p className="font-medium">{sbom.components_count ?? 0}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Direct / Transitive</p>
                          <p className="font-medium">{sbom.direct_dependencies ?? 0} / {sbom.transitive_dependencies ?? 0}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Created</p>
                          <p className="font-medium">{shortDate(sbom.created_at)}</p>
                        </div>
                      </div>
                      {selectedSBOM?.id === sbom.id && (
                        <div className="mb-3 text-sm bg-gray-50 dark:bg-gray-900 rounded p-3 space-y-1">
                          {!sbomCompliance && <p className="text-gray-500">Loading NTIA assessment...</p>}
                          <LoadErrorBanner what="the SBOM compliance assessment" error={sbomCompliance?.error} />
                          {sbomCompliance?.data && (
                            <>
                              <p className="font-medium">
                                NTIA minimum elements: {String(sbomCompliance.data.status).replace(/_/g, ' ')} ({sbomCompliance.data.components_assessed} component(s) assessed)
                              </p>
                              <p className="text-xs text-gray-500">{sbomCompliance.data.basis}</p>
                              <ul className="text-xs grid grid-cols-2 gap-1">
                                {Object.entries((sbomCompliance.data.element_coverage ?? {}) as Record<string, number>).map(([k, v]) => (
                                  <li key={k}>{k.replace(/_/g, ' ')}: {v}% of components</li>
                                ))}
                              </ul>
                              {Object.entries((sbomCompliance.data.missing_components ?? {}) as Record<string, string[]>).map(([k, list]) => (
                                <p key={k} className="text-xs text-orange-700 dark:text-orange-300">Missing {k.replace(/_/g, ' ')}: {list.join(', ')}</p>
                              ))}
                            </>
                          )}
                        </div>
                      )}
                      <div className="flex gap-2">
                        <button
                          onClick={() => (selectedSBOM?.id === sbom.id ? setSelectedSBOM(null) : openSBOM(sbom))}
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
                              setActionError({ what: 'download the SBOM', error: err });
                            }
                          }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Download
                        </button>
                        <button
                          onClick={() => { setActionError(null); setEditingSBOM(sbom); }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Rename
                        </button>
                        <button
                          onClick={() => {
                            if (!window.confirm(`Delete SBOM "${sbom.name}"?`)) return;
                            runAction(`delete-${sbom.id}`, 'delete the SBOM', async () => { await api.delete(`/supplychain/sboms/${sbom.id}`); });
                          }}
                          className="px-3 py-2 text-sm border border-red-300 text-red-700 rounded hover:bg-red-50 transition"
                          title="Delete SBOM"
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

            {/* Components Tab */}
            {activeTab === 'components' && (
              <div className="space-y-6">
                <LoadErrorBanner what="software components" error={loadErrors.components} />
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
                  <select
                    value={scanStatusFilter}
                    onChange={(e) => setScanStatusFilter(e.target.value)}
                    aria-label="Lookup status"
                    className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"
                  >
                    <option value="">All components</option>
                    <option value="scanned">Looked up</option>
                    <option value="not_scanned">Not looked up</option>
                  </select>
                  <button
                    onClick={() => runAction('lookup', 'look components up in OSV / NVD', async () => {
                      setLookupResult((await api.post('/supplychain/components/lookup', { use_cache: true })).data);
                    })}
                    disabled={busy !== null}
                    title="Query OSV (and NVD when an API key is set) for every component, oldest lookup first"
                    className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50"
                  >
                    <RefreshCw className={clsx('w-4 h-4', busy === 'lookup' && 'animate-spin')} />
                    Look Up Vulnerabilities
                  </button>
                </div>

                <LoadErrorBanner what="vulnerability source status" error={loadErrors.sources} />
                {vulnSources && (
                  <div className="text-xs flex flex-wrap gap-4 text-gray-600 dark:text-gray-400">
                    {(['osv', 'nvd'] as const).map((p) => {
                      const s = vulnSources[p] as Row | undefined;
                      if (!s) return null;
                      return (
                        <span key={p}>
                          {p.toUpperCase()}: {String(s.status).replace(/_/g, ' ')}
                          {s.last_success_at ? `, last success ${shortDate(s.last_success_at)}` : ''}
                          {s.last_error ? `, last error: ${s.last_error}` : ''}
                          {s.reason ? ` (${s.reason})` : ''}
                        </span>
                      );
                    })}
                    {vulnSources.cache_entries && (
                      <span>cache: {Object.entries(vulnSources.cache_entries as Record<string, number>).map(([k, v]) => `${k} ${v}`).join(', ') || 'empty'}</span>
                    )}
                  </div>
                )}
                {lookupResult && (
                  <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 space-y-1">
                    <div className="flex justify-between">
                      <span>
                        Lookup: {lookupResult.components_checked} checked, {lookupResult.components_failed} failed,{' '}
                        {lookupResult.advisories_found} advisory match(es), {lookupResult.risks_new} new risk(s), {lookupResult.risks_updated} updated,{' '}
                        {lookupResult.cache_hits} cache hit(s){lookupResult.truncated ? ' (capped; run again for the rest)' : ''}.
                      </span>
                      <button onClick={() => setLookupResult(null)} className="text-xs underline">dismiss</button>
                    </div>
                    {Array.isArray(lookupResult.components_skipped) && lookupResult.components_skipped.length > 0 && (
                      <ul className="list-disc ml-5 text-xs">
                        {lookupResult.components_skipped.slice(0, 20).map((s: Row) => (
                          <li key={s.component_id}>{s.name}: {s.reason}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}

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
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Known Vulns</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Risk</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Score</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredComponents.map((comp) => {
                        const scanned = comp.vulnerability_scan_status === 'scanned';
                        const level = scanned ? riskScoreToLevel(comp.risk_score) : 'not scanned';
                        const license = comp.license_spdx_id || comp.license_type || '—';
                        return (
                        <React.Fragment key={comp.id}>
                        <tr className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-medium">{comp.name}</td>
                          <td className="px-6 py-4 text-sm font-mono">{comp.version}</td>
                          <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">{comp.package_type || '—'}</td>
                          <td className="px-6 py-4 text-sm">{license}</td>
                          <td className="px-6 py-4 text-sm font-semibold">
                            {scanned ? (comp.known_vulnerabilities_count ?? 0) : <span className="font-normal text-gray-500">not scanned</span>}
                            {comp.last_scanned && <div className="text-xs font-normal text-gray-500">{shortDate(comp.last_scanned)}</div>}
                          </td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(level)}`}>
                              {level}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm font-mono text-gray-600 dark:text-gray-400">{scanned ? Number(comp.risk_score ?? 0).toFixed(1) : NA}</td>
                          <td className="px-6 py-4 text-sm flex gap-2">
                            <button
                              onClick={() => (selectedComponent?.id === comp.id ? setSelectedComponent(null) : openComponent(comp))}
                              className="text-blue-600 dark:text-blue-400 hover:underline"
                              title="Advisories"
                            >
                              <Eye className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => runAction(`lookup-${comp.id}`, `look up ${comp.name}`, async () => {
                                setLookupResult((await api.post(`/supplychain/components/${comp.id}/lookup`, null, { params: { use_cache: false } })).data);
                              })}
                              disabled={busy !== null}
                              className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 disabled:opacity-50"
                              title="Look up in OSV / NVD now (bypasses the cache)"
                            >
                              <RefreshCw className={clsx('w-4 h-4', busy === `lookup-${comp.id}` && 'animate-spin')} />
                            </button>
                          </td>
                        </tr>
                        {selectedComponent?.id === comp.id && (
                          <tr className="bg-gray-50 dark:bg-gray-900">
                            <td colSpan={8} className="px-6 py-3 text-sm">
                              {!componentVulns && <p className="text-gray-500">Loading advisories...</p>}
                              <LoadErrorBanner what="component advisories" error={componentVulns?.error} />
                              {componentVulns?.data && (
                                <>
                                  <p className="text-xs text-gray-500 mb-1">
                                    Lookup status: {String(componentVulns.data.scan_status ?? 'not_scanned').replace(/_/g, ' ')}
                                    {comp.purl ? ` · purl ${comp.purl}` : ''}
                                  </p>
                                  {(componentVulns.data.advisories ?? []).length === 0 ? (
                                    <p className="text-gray-500">
                                      {componentVulns.data.scan_status === 'scanned' ? 'No advisory matched this component.' : 'Not looked up yet.'}
                                    </p>
                                  ) : (
                                    <ul className="space-y-1">
                                      {componentVulns.data.advisories.map((a: Row) => (
                                        <li key={a.risk_id ?? a.advisory_id} className="flex flex-wrap gap-2 items-center">
                                          <span className={`px-2 py-0.5 rounded text-xs ${getSeverityColor(a.severity)}`}>{a.severity}</span>
                                          <span className="font-mono">{a.advisory_id}</span>
                                          <span className="text-xs text-gray-500">{a.source} · {a.status}</span>
                                          {Array.isArray(a.cves) && a.cves.length > 0 && <span className="text-xs">{a.cves.join(', ')}</span>}
                                        </li>
                                      ))}
                                    </ul>
                                  )}
                                </>
                              )}
                            </td>
                          </tr>
                        )}
                        </React.Fragment>
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
                <LoadErrorBanner what="supply chain risks" error={loadErrors.risks} />
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
                          {risk.advisory_id && (
                            <p className="text-xs text-gray-500">Advisory {risk.advisory_id}{risk.source ? ` (${risk.source})` : ''}</p>
                          )}
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
                <LoadErrorBanner what="vendor assessments" error={loadErrors.vendors} />
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

                <div className="flex justify-end">
                  <button
                    onClick={() => openVendorForm(null)}
                    className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition"
                  >
                    <Plus className="w-4 h-4" />
                    New Vendor Assessment
                  </button>
                </div>
                {filteredVendors.length === 0 && (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
                    No vendor assessments yet.
                  </div>
                )}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {filteredVendors.map((vendor) => {
                    const assessed = vendor.assessment_status === 'assessed';
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
                            <span className="font-semibold">{assessed ? `${score.toFixed(1)}%` : 'not assessed'}</span>
                          </div>
                          {assessed && (
                            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                              <div
                                className={`h-2 rounded-full ${score >= 90 ? 'bg-green-600' : score >= 80 ? 'bg-yellow-600' : 'bg-orange-600'}`}
                                style={{ width: `${score}%` }}
                              />
                            </div>
                          )}
                          <p className="text-xs text-gray-500 mt-1">
                            {vendor.answered_questions ?? 0} of {vendor.total_questions ?? 0} questionnaire answer(s) stored
                          </p>
                        </div>
                        <div>
                          <p className="text-sm font-medium mb-2">Certifications <span className="font-normal text-xs text-gray-500">(as stated by the vendor)</span></p>
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
                        {selectedVendor?.id === vendor.id && (
                          <div className="text-xs bg-gray-50 dark:bg-gray-900 rounded p-2 space-y-1">
                            {Object.entries((vendor.questionnaire_responses ?? {}) as Record<string, unknown>).length === 0 ? (
                              <p className="text-gray-500">No answers stored.</p>
                            ) : (
                              Object.entries((vendor.questionnaire_responses ?? {}) as Record<string, unknown>).map(([k, v]) => (
                                <p key={k}><span className="font-mono">{k}</span>: {String(v)}</p>
                              ))
                            )}
                            {Array.isArray(vendor.third_party_subprocessors) && vendor.third_party_subprocessors.length > 0 && (
                              <p>Subprocessors: {vendor.third_party_subprocessors.join(', ')}</p>
                            )}
                            {vendor.notes && <p>Notes: {vendor.notes}</p>}
                          </div>
                        )}
                        <div className="flex gap-2">
                          <button
                            onClick={() => setSelectedVendor(selectedVendor?.id === vendor.id ? null : vendor)}
                            className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                          >
                            {selectedVendor?.id === vendor.id ? 'Hide Answers' : 'View Answers'}
                          </button>
                          <button
                            onClick={() => openVendorForm(vendor)}
                            className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                          >
                            Answer Questionnaire
                          </button>
                        </div>
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
              await runAction('component', 'add the component', async () => {
                await api.post('/supplychain/components', {
                  name: fd.get('name'),
                  version: fd.get('version'),
                  package_type: fd.get('package_type') || 'binary',
                  vendor: fd.get('vendor') || undefined,
                  purl: fd.get('purl') || undefined,
                  license: fd.get('license') || undefined,
                });
                setShowNewComponentModal(false);
              });
            }}>
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              <div>
                <label className="block text-sm font-medium mb-1">Component Name</label>
                <input name="name" required type="text" placeholder="e.g., log4j-core" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Version</label>
                <input name="version" required type="text" placeholder="e.g., 2.18.0" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Package Type</label>
                <select name="package_type" defaultValue="maven" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  {PACKAGE_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Supplier</label>
                <input name="vendor" type="text" placeholder="e.g., Apache Software Foundation" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Package URL (purl)</label>
                <input name="purl" type="text" placeholder="pkg:maven/org.apache.logging.log4j/log4j-core@2.18.0" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100 font-mono text-xs" />
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
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
              The document lists the components stored for this organisation (all of them, or the ones ticked below); nothing is synthesised.
            </p>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              const picked = fd.getAll('component_ids').map(String);
              await runAction('generate', 'generate the SBOM', async () => {
                await api.post('/supplychain/sboms/generate', {
                  name: fd.get('name'),
                  application_name: fd.get('application_name'),
                  application_version: fd.get('application_version') || '1.0',
                  sbom_format: fd.get('sbom_format') || 'cyclonedx_json',
                  spec_version: fd.get('spec_version') || '1.5',
                  component_ids: picked.length > 0 ? picked : undefined,
                });
                setShowGenerateSBOMModal(false);
              });
            }}>
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              {components.length > 0 && (
                <div className="max-h-32 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded p-2 text-xs space-y-0.5">
                  <p className="text-gray-500">Components (none ticked = all stored components)</p>
                  {components.map((c) => (
                    <label key={c.id} className="flex items-center gap-1">
                      <input type="checkbox" name="component_ids" value={c.id} /> {c.name}@{c.version}
                    </label>
                  ))}
                </div>
              )}
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
            <h2 className="text-xl font-bold mb-4">Rename SBOM</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              const target = editingSBOM;
              await runAction('rename', 'update the SBOM', async () => {
                // compliance_status is derived from the stored components;
                // the server refuses it (422 derived_field), so only the name is sent.
                await api.patch(`/supplychain/sboms/${target.id}`, { name: fd.get('name') });
                setEditingSBOM(null);
              });
            }}>
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              <div>
                <label className="block text-sm font-medium mb-1">Name</label>
                <input name="name" required type="text" defaultValue={editingSBOM.name || ''} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Compliance status is derived from the stored components (NTIA minimum elements) and cannot be set by hand.
                Version or format changes require regenerating the SBOM.
              </p>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setEditingSBOM(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Vendor Assessment / Questionnaire Modal */}
      {vendorForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setVendorForm(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[560px] max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-2">{vendorForm.id ? `Questionnaire: ${vendorForm.vendor_name}` : 'New Vendor Assessment'}</h2>
            <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
              The security score is computed by the server from these answers{questionnaire?.scoring ? ` (${questionnaire.scoring})` : ''}; it cannot be typed in.
            </p>
            <form className="space-y-3" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              const answers: Record<string, string> = {};
              for (const q of (questionnaire?.questions ?? []) as Row[]) {
                const a = String(fd.get(`q_${q.key}`) || '');
                if (a) answers[q.key] = a;
              }
              const certifications = String(fd.get('certifications') || '').split(',').map((s) => s.trim()).filter(Boolean);
              const subprocessors = String(fd.get('subprocessors') || '').split(',').map((s) => s.trim()).filter(Boolean);
              const body: Row = {
                questionnaire_responses: answers,
                certifications,
                third_party_subprocessors: subprocessors,
                notes: fd.get('notes') || undefined,
                risk_tier: fd.get('risk_tier') || undefined,
              };
              const editing = vendorForm;
              await runAction('vendor', editing.id ? 'save the questionnaire' : 'create the vendor assessment', async () => {
                if (editing.id) {
                  await api.patch(`/supplychain/vendors/${editing.id}`, body);
                } else {
                  await api.post('/supplychain/vendors', {
                    ...body,
                    vendor_name: fd.get('vendor_name'),
                    vendor_url: fd.get('vendor_url') || undefined,
                    assessment_type: 'initial',
                  });
                }
                setVendorForm(null);
              });
            }}>
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              {!vendorForm.id && (
                <>
                  <input name="vendor_name" required placeholder="Vendor name" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
                  <input name="vendor_url" placeholder="https://vendor.example (optional)" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
                </>
              )}
              <label className="block text-sm">Risk tier
                <select name="risk_tier" defaultValue={vendorForm.risk_tier || 'medium'} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                </select>
              </label>
              {!questionnaire && <p className="text-sm text-gray-500">Loading questionnaire...</p>}
              {((questionnaire?.questions ?? []) as Row[]).map((q) => (
                <div key={q.key} className="text-sm border-b border-gray-100 dark:border-gray-700 pb-2">
                  <p>{q.question} <span className="text-xs text-gray-400">(weight {q.weight})</span></p>
                  <select
                    name={`q_${q.key}`}
                    defaultValue={String((vendorForm.questionnaire_responses ?? {})[q.key] ?? '')}
                    className="mt-1 px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-sm"
                  >
                    <option value="">unanswered</option>
                    {((questionnaire?.answers ?? []) as string[]).map((a) => <option key={a} value={a}>{a}</option>)}
                  </select>
                </div>
              ))}
              <input name="certifications" defaultValue={parseCertifications(vendorForm.certifications).join(', ')} placeholder="Certifications stated by the vendor (comma separated)" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              <input name="subprocessors" defaultValue={(vendorForm.third_party_subprocessors ?? []).join(', ')} placeholder="Third-party subprocessors (comma separated)" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              <textarea name="notes" rows={2} defaultValue={vendorForm.notes ?? ''} placeholder="Notes" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              <div className="flex gap-2">
                <button type="button" onClick={() => setVendorForm(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
                <button type="submit" disabled={busy === 'vendor'} className="flex-1 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg disabled:opacity-50">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
