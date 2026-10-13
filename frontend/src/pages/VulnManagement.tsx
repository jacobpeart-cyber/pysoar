import React, { useState, useCallback } from 'react';
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
import { api } from '../lib/api';
import { vulnmgmtApi } from '../api/endpoints';
import LoadErrorBanner from '../components/LoadErrorBanner';
import { describeLoadError } from '../lib/loadError';

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

// Normalize backend snake_case fields into the camelCase shape this
// page expects. Previously every table (Vulnerabilities, Scan Profiles,
// Patch Operations, Exceptions) rendered undefined/N/A/Invalid Date
// because the frontend read `cveId`, `cvss`, `lastRun`, `vulnCount`,
// etc. which the backend does not emit.
// Field names follow src/schemas/vulnmgmt.py. The vulnerability catalog
// row carries no per-asset count or age, so those stay null and render
// "not available".
const NA = 'not available';

const normalizeVuln = (v: any) => ({
  ...v,
  cveId: v.cve_id ?? null,
  cvss: v.cvss_v3_score ?? null,
  epss: v.epss_score ?? null,
  patchAvailable: Boolean(v.patch_available),
  kev: Boolean(v.kev_listed),
  daysOpen: null as number | null,
  affectedAssets: null as number | null,
});

const normalizeProfile = (p: any) => ({
  ...p,
  schedule: p.schedule_cron ?? null,
  status: p.enabled ? 'active' : 'inactive',
  lastRun: p.last_scan_date ?? null,
  nextRun: p.next_scan_date ?? null,
});

// PatchOperationResponse: one row per vulnerability instance.
const normalizePatchOp = (op: any) => ({
  ...op,
  name: op.patch_name || op.patch_id || op.patch_type || 'Patch operation',
  startDate: op.deployment_date ?? null,
  verifiedDate: op.verification_date ?? null,
  status: op.deployment_status ?? null,
});

// VulnerabilityExceptionResponse has no status column; an exception past
// its expiry_date is reported as expired.
const normalizeException = (e: any) => ({
  ...e,
  instanceId: e.vulnerability_instance_id ?? null,
  reason: e.justification ?? null,
  expiryDate: e.expiry_date ?? null,
  approver: e.approved_by ?? null,
  status: e.expiry_date && new Date(e.expiry_date).getTime() < Date.now() ? 'expired' : 'active',
});

const fmtDate = (v: string | null | undefined, empty: string) =>
  v ? new Date(v).toLocaleString() : empty;

// Instance ids for one catalog vulnerability (patch plans, bulk actions and
// exceptions all operate on vulnerability_instances, not catalog rows).
const instanceIdsFor = async (vulnerabilityId: string): Promise<string[]> => {
  const res = await api.get('/vulnmgmt/instances', { params: { vulnerability_id: vulnerabilityId, size: 100 } });
  return (res.data?.items ?? []).map((i: any) => i.id);
};

export default function VulnManagement() {
  const [activeTab, setActiveTab] = useState('vulnerabilities');
  const [vulnerabilities, setVulnerabilities] = useState<any[]>([]);
  const [scanProfiles, setScanProfiles] = useState<any[]>([]);
  const [patchOps, setPatchOps] = useState<any[]>([]);
  const [exceptions, setExceptions] = useState<any[]>([]);
  const [dashboardMetrics, setDashboardMetrics] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadErrors, setLoadErrors] = useState<Record<'vulns' | 'patches' | 'profiles' | 'exceptions' | 'dashboard', unknown>>({
    vulns: null, patches: null, profiles: null, exceptions: null, dashboard: null,
  });
  const scanFileInput = React.useRef<HTMLInputElement>(null);
  const [importProfile, setImportProfile] = useState<any | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewVulnModal, setShowNewVulnModal] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<any | null>(null);
  const [editingVulnerability, setEditingVulnerability] = useState<any | null>(null);
  const [editingException, setEditingException] = useState<any | null>(null);
  const [editingScanProfile, setEditingScanProfile] = useState<any | null>(null);
  const [showFilterPanel, setShowFilterPanel] = useState(false);
  const [remediatingVuln, setRemediatingVuln] = useState<any | null>(null);

  const [showNewScanProfileModal, setShowNewScanProfileModal] = useState(false);
  const [showNewExceptionModal, setShowNewExceptionModal] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [vulnsRes, patchRes, profilesRes, exceptionsRes, dashRes] = await Promise.allSettled([
        vulnmgmtApi.getVulnerabilities(),
        vulnmgmtApi.getPatchOperations(),
        vulnmgmtApi.getScanProfiles(),
        vulnmgmtApi.getExceptions(),
        api.get('/vulnmgmt/dashboard').then(r => r.data),
      ]);
      const asList = (r: PromiseSettledResult<any>): any[] => {
        if (r.status !== 'fulfilled') return [];
        return Array.isArray(r.value) ? r.value : (r.value?.items ?? []);
      };
      const reason = (r: PromiseSettledResult<any>) => (r.status === 'rejected' ? (r.reason ?? new Error('request failed')) : null);
      setVulnerabilities(asList(vulnsRes).map(normalizeVuln));
      setScanProfiles(asList(profilesRes).map(normalizeProfile));
      setPatchOps(asList(patchRes).map(normalizePatchOp));
      setExceptions(asList(exceptionsRes).map(normalizeException));
      setDashboardMetrics(dashRes.status === 'fulfilled' ? dashRes.value : null);
      setLoadErrors({
        vulns: reason(vulnsRes),
        patches: reason(patchRes),
        profiles: reason(profilesRes),
        exceptions: reason(exceptionsRes),
        dashboard: reason(dashRes),
      });
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    loadData();
  }, []);

  // Summary cards read only the org-scoped /vulnmgmt/dashboard aggregate
  // (DashboardMetrics). No client-side count of the first page stands in.
  const criticalVulns: number | null = dashboardMetrics?.critical_vulnerabilities ?? null;
  const trackedVulns: number | null = dashboardMetrics?.total_vulnerabilities ?? null;
  const mttrDays: number | null = dashboardMetrics?.mttr_days ?? null;
  // With no tracked instances there is nothing to be compliant with.
  const slaCompliance: number | null = dashboardMetrics?.sla_compliance?.total
    ? dashboardMetrics.sla_compliance.compliance_percentage
    : null;

  const runScanImport = async (profile: any, file: File) => {
    try {
      const scanData = await file.text();
      // ScanImportRequest requires scan_format; the profile's scanner_type
      // names the parser (nessus / qualys / openvas, anything else is JSON).
      const res = await api.post('/vulnmgmt/vulnerabilities/import-scan', {
        scan_profile_id: profile.id,
        scan_format: profile.scanner_type || 'json',
        scan_data: scanData,
      });
      alert(`Scan import complete: ${res.data?.imported ?? 0} finding(s) read, ${res.data?.new ?? 0} new, ${res.data?.existing ?? 0} already known.`);
      loadData();
    } catch (error) {
      alert(`Scan import failed: ${describeLoadError(error)}`);
    }
  };

  const tabs = [
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { id: 'scan-profiles', label: 'Scan Profiles', icon: Activity },
    { id: 'patch-ops', label: 'Patch Operations', icon: CheckCircle },
    { id: 'exceptions', label: 'Exceptions', icon: Shield },
    { id: 'cisa-kev', label: 'CISA KEV', icon: AlertTriangle },
  ];

  const filteredVulns = vulnerabilities.filter(v =>
    (v.cveId ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (v.title ?? '').toLowerCase().includes(searchQuery.toLowerCase())
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

        <div className="mb-4">
          <LoadErrorBanner what="vulnerability dashboard metrics" error={loadErrors.dashboard} />
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Critical Vulns</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{criticalVulns ?? NA}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">requiring immediate action</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Tracked Vulnerabilities</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{trackedVulns ?? NA}</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">in the catalog</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">MTTR</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">
              {mttrDays === null ? NA : mttrDays.toFixed(1)}
            </p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">days mean time to remediate</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">SLA Compliance</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">
              {slaCompliance === null ? NA : `${slaCompliance.toFixed(1)}%`}
            </p>
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
                <LoadErrorBanner what="vulnerabilities" error={loadErrors.vulns} />
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">CVSS Score Distribution</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>9.0 - 10.0</span><span className="font-semibold text-red-600">{vulnerabilities.filter(v => (v.cvss ?? 0) >= 9).length}</span></div>
                      <div className="flex justify-between"><span>7.0 - 8.9</span><span className="font-semibold text-orange-600">{vulnerabilities.filter(v => (v.cvss ?? 0) >= 7 && (v.cvss ?? 0) < 9).length}</span></div>
                      <div className="flex justify-between"><span>4.0 - 6.9</span><span className="font-semibold text-yellow-600">{vulnerabilities.filter(v => (v.cvss ?? 0) >= 4 && (v.cvss ?? 0) < 7).length}</span></div>
                      <div className="flex justify-between"><span>0.0 - 3.9</span><span className="font-semibold text-green-600">{vulnerabilities.filter(v => v.cvss !== null && v.cvss < 4).length}</span></div>
                      <div className="flex justify-between"><span>Unscored</span><span className="font-semibold text-gray-500">{vulnerabilities.filter(v => v.cvss === null).length}</span></div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Severity Breakdown</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Critical</span><span className="font-semibold text-red-600">{vulnerabilities.filter(v => v.severity === 'critical').length}</span></div>
                      <div className="flex justify-between"><span>High</span><span className="font-semibold text-orange-600">{vulnerabilities.filter(v => v.severity === 'high').length}</span></div>
                      <div className="flex justify-between"><span>Medium</span><span className="font-semibold text-yellow-600">{vulnerabilities.filter(v => v.severity === 'medium').length}</span></div>
                      <div className="flex justify-between"><span>Low</span><span className="font-semibold text-green-600">{vulnerabilities.filter(v => v.severity === 'low').length}</span></div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Patch Status</h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>Patch Available</span><span className="font-semibold text-green-600">{vulnerabilities.filter(v => v.patchAvailable).length}</span></div>
                      <div className="flex justify-between"><span>No Patch</span><span className="font-semibold text-red-600">{vulnerabilities.filter(v => !v.patchAvailable).length}</span></div>
                      <div className="flex justify-between"><span>KEV Listed</span><span className="font-semibold text-red-600">{vulnerabilities.filter(v => v.kev).length}</span></div>
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
                              {(vuln.severity || 'unknown').toUpperCase()}
                            </span>
                          </td>
                          <td className="px-6 py-4 text-sm font-semibold">{vuln.cvss?.toFixed(1) ?? 'N/A'}</td>
                          <td className="px-6 py-4 text-sm">{vuln.epss === null ? NA : `${(vuln.epss * 100).toFixed(0)}%`}</td>
                          <td className="px-6 py-4">
                            {vuln.kev ? (
                              <AlertTriangle className="w-5 h-5 text-red-600" />
                            ) : (
                              <span className="text-gray-400">—</span>
                            )}
                          </td>
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
                <div className="flex justify-end">
                  <button
                    onClick={() => setShowNewScanProfileModal(true)}
                    className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition"
                  >
                    <Plus className="w-4 h-4" />
                    New Scan Profile
                  </button>
                </div>
                <LoadErrorBanner what="scan profiles" error={loadErrors.profiles} />
                {!loadErrors.profiles && scanProfiles.length === 0 && (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
                    No scan profiles defined.
                  </div>
                )}
                <div className="grid grid-cols-1 gap-4">
                  {scanProfiles.map((profile) => (
                    <div key={profile.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div>
                          <h3 className="font-semibold text-lg">{profile.name}</h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400">Scanner: {profile.scanner_type || NA} · Schedule: {profile.schedule || 'none'}</p>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(profile.status)}`}>
                          {profile.status}
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Last Scan</p>
                          <p className="font-medium">{fmtDate(profile.lastRun, 'Never')}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Next Scan</p>
                          <p className="font-medium">{fmtDate(profile.nextRun, 'Not scheduled')}</p>
                        </div>
                      </div>
                      <div className="flex gap-2 mt-4">
                        <button
                          onClick={() => {
                            // No scanner runs server-side: the backend imports a
                            // scanner export, so pick the file to import.
                            setImportProfile(profile);
                            scanFileInput.current?.click();
                          }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                          title="Import a scanner export file for this profile"
                        >
                          Import Results
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
                <LoadErrorBanner what="patch operations" error={loadErrors.patches} />
                <div className="grid grid-cols-1 gap-4">
                  {patchOps.map((op) => (
                    <div key={op.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                      <div className="flex justify-between items-start mb-4">
                        <div>
                          <h3 className="font-semibold text-lg">{op.name}</h3>
                          <div className="flex gap-4 mt-2 text-sm text-gray-600 dark:text-gray-400">
                            <span className="capitalize">{(op.patch_type || '').replace(/_/g, ' ')}</span>
                            <span>·</span>
                            <span className="font-mono">instance {op.vulnerability_instance_id}</span>
                          </div>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(op.status)}`}>
                          {op.status ?? NA}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-4 text-sm pt-2">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Deployed</p>
                          <p className="font-medium">{fmtDate(op.startDate, 'Not deployed')}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Verified</p>
                          <p className="font-medium">{fmtDate(op.verifiedDate, 'Not verified')}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Change Ticket</p>
                          <p className="font-medium">{op.change_ticket_id || 'None'}</p>
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
                <LoadErrorBanner what="exceptions" error={loadErrors.exceptions} />
                <div className="flex justify-end">
                  <button
                    onClick={() => setShowNewExceptionModal(true)}
                    className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition"
                  >
                    <Plus className="w-4 h-4" />
                    New Exception
                  </button>
                </div>
                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Instance</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Justification</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Approver</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Expires</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {exceptions.map((exc) => (
                        <tr key={exc.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                          <td className="px-6 py-4 text-sm font-mono font-medium">{exc.instanceId}</td>
                          <td className="px-6 py-4 text-sm">{exc.reason}</td>
                          <td className="px-6 py-4 text-sm">{exc.approver || 'None'}</td>
                          <td className="px-6 py-4 text-sm">{exc.expiryDate || 'No expiry'}</td>
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

                <LoadErrorBanner what="vulnerabilities" error={loadErrors.vulns} />
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
                              <p className="font-semibold">{vuln.cvss === null ? NA : vuln.cvss.toFixed(1)}</p>
                            </div>
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">EPSS Score</p>
                              <p className="font-semibold">{vuln.epss === null ? NA : `${(vuln.epss * 100).toFixed(0)}%`}</p>
                            </div>
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">Affected Assets</p>
                              <p className="font-semibold">{vuln.affectedAssets ?? NA}</p>
                            </div>
                            <div>
                              <p className="text-gray-600 dark:text-gray-400">Days Open</p>
                              <p className="font-semibold">{vuln.daysOpen ?? NA}</p>
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
              <div><span className="font-medium">CVSS:</span> {selectedVulnerability.cvss === null ? NA : selectedVulnerability.cvss.toFixed(1)}</div>
              <div><span className="font-medium">EPSS:</span> {selectedVulnerability.epss === null ? NA : `${(selectedVulnerability.epss * 100).toFixed(0)}%`}</div>
              <div><span className="font-medium">KEV:</span> {selectedVulnerability.kev ? 'Yes' : 'No'}</div>
              <div><span className="font-medium">Affected Assets:</span> {selectedVulnerability.affectedAssets ?? NA}</div>
              <div><span className="font-medium">Patch Available:</span> {selectedVulnerability.patchAvailable ? 'Yes' : 'No'}</div>
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
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.put(`/vulnmgmt/vulnerabilities/${editingVulnerability.id}`, {
                  title: fd.get('title'),
                  severity: fd.get('severity'),
                });
                setEditingVulnerability(null);
                loadData();
              } catch (err) { alert(`Update vulnerability failed: ${describeLoadError(err)}`); }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Title</label>
                <input name="title" type="text" defaultValue={editingVulnerability.title} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select name="severity" defaultValue={editingVulnerability.severity} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setEditingVulnerability(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Exception Modal */}
      {editingException && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Edit Exception: {editingException.instanceId}</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.put(`/vulnmgmt/exceptions/${editingException.id}`, {
                  justification: fd.get('justification'),
                  expiry_date: fd.get('expiry_date') || null,
                });
                setEditingException(null);
                loadData();
              } catch (err) { alert(`Update exception failed: ${describeLoadError(err)}`); }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Justification</label>
                <textarea name="justification" required minLength={10} defaultValue={editingException.reason} rows={3} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Expiry Date</label>
                <input name="expiry_date" type="date" defaultValue={editingException.expiryDate} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setEditingException(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Edit Scan Profile Modal */}
      {editingScanProfile && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Edit Scan Profile: {editingScanProfile.name}</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.put(`/vulnmgmt/scan-profiles/${editingScanProfile.id}`, {
                  name: fd.get('name'),
                  schedule_cron: fd.get('schedule') || null,
                });
                setEditingScanProfile(null);
                loadData();
              } catch (err) { alert(`Update scan profile failed: ${describeLoadError(err)}`); }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Name</label>
                <input name="name" type="text" defaultValue={editingScanProfile.name} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Schedule (cron)</label>
                <input name="schedule" type="text" defaultValue={editingScanProfile.schedule ?? ''} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setEditingScanProfile(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Save</button>
              </div>
            </form>
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
              <button onClick={async () => {
                try {
                  // create-plan takes vulnerability_instance_ids, so resolve
                  // this catalog vulnerability's instances first.
                  const instanceIds = await instanceIdsFor(remediatingVuln.id);
                  if (instanceIds.length === 0) {
                    alert('No affected instances are recorded for this vulnerability, so there is nothing to patch.');
                    return;
                  }
                  await api.post('/vulnmgmt/patch-operations/create-plan', {
                    vulnerability_instance_ids: instanceIds,
                  });
                  setRemediatingVuln(null);
                  loadData();
                } catch (e) {
                  alert(`Create patch plan failed: ${describeLoadError(e)}`);
                }
              }} className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Apply Patch</button>
              <button onClick={async () => {
                try {
                  const instanceIds = await instanceIdsFor(remediatingVuln.id);
                  if (instanceIds.length === 0) {
                    alert('No affected instances are recorded for this vulnerability, so there is nothing to mark mitigated.');
                    return;
                  }
                  await api.post('/vulnmgmt/instances/bulk-action', { instance_ids: instanceIds, action: 'update_status', value: 'mitigated' });
                  setRemediatingVuln(null);
                  loadData();
                } catch (e) {
                  alert(`Apply compensating control failed: ${describeLoadError(e)}`);
                }
              }} className="w-full px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition">Apply Compensating Control</button>
              <button onClick={() => setRemediatingVuln(null)} className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
            </div>
          </div>
        </div>
      )}

      {/* New Vulnerability Modal */}
      {showNewVulnModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setShowNewVulnModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Create Vulnerability Record</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.post('/vulnmgmt/vulnerabilities', {
                  cve_id: fd.get('cve_id'),
                  title: fd.get('title'),
                  severity: fd.get('severity') || 'medium',
                  cvss_v3_score: fd.get('cvss_score') ? parseFloat(fd.get('cvss_score') as string) : null,
                  description: fd.get('description') || '',
                });
                setShowNewVulnModal(false);
                loadData();
              } catch (err) { alert(`Create vulnerability failed: ${describeLoadError(err)}`); }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">CVE ID</label>
                <input name="cve_id" required type="text" placeholder="CVE-2025-XXXX" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Title</label>
                <input name="title" required type="text" placeholder="Vulnerability title" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select name="severity" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium" selected>Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">CVSS Score</label>
                <input name="cvss_score" type="number" placeholder="0.0" step="0.1" min="0" max="10" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea name="description" rows={2} placeholder="Vulnerability description" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  type="button"
                  onClick={() => setShowNewVulnModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition"
                >
                  Create
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* New Scan Profile Modal */}
      {showNewScanProfileModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setShowNewScanProfileModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Create Scan Profile</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await vulnmgmtApi.createScanProfile({
                  name: fd.get('name'),
                  scanner_type: fd.get('scanner_type'),
                  schedule_cron: fd.get('schedule') || null,
                  enabled: true,
                });
                setShowNewScanProfileModal(false);
                loadData();
              } catch (err) {
                alert(`Create scan profile failed: ${describeLoadError(err)}`);
              }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Name</label>
                <input name="name" required type="text" placeholder="Weekly authenticated scan" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Scanner (export format)</label>
                <select name="scanner_type" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="nessus">Nessus (.nessus XML)</option>
                  <option value="qualys">Qualys (CSV)</option>
                  <option value="openvas">OpenVAS (XML)</option>
                  <option value="json">Other (JSON findings)</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Schedule (cron)</label>
                <input name="schedule" type="text" placeholder="0 2 * * 0" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setShowNewScanProfileModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition">Create</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* New Exception Modal */}
      {showNewExceptionModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setShowNewExceptionModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Create Vulnerability Exception</h2>
            <form className="space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await vulnmgmtApi.createException({
                  vulnerability_instance_id: fd.get('vulnerability_instance_id'),
                  justification: fd.get('justification'),
                  exception_type: fd.get('exception_type') || 'risk_accepted',
                  approved_by: fd.get('approved_by') || null,
                  expiry_date: fd.get('expiry_date') || null,
                });
                setShowNewExceptionModal(false);
                loadData();
              } catch (err) {
                alert(`Create exception failed: ${describeLoadError(err)}`);
              }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Vulnerability Instance ID</label>
                <input name="vulnerability_instance_id" required type="text" placeholder="vulnerability instance UUID" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Exception Type</label>
                <select name="exception_type" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="risk_accepted">Risk Accepted</option>
                  <option value="false_positive">False Positive</option>
                  <option value="compensating_control">Compensating Control</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Justification</label>
                <textarea name="justification" required minLength={10} rows={3} placeholder="Business justification (at least 10 characters)" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Approved By</label>
                <input name="approved_by" type="text" placeholder="user id / name" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Expiry Date (ISO)</label>
                <input name="expiry_date" type="date" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => setShowNewExceptionModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition">Create</button>
              </div>
            </form>
          </div>
        </div>
      )}

      <input
        ref={scanFileInput}
        type="file"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = '';
          if (file && importProfile) runScanImport(importProfile, file);
        }}
      />
    </div>
  );
}
