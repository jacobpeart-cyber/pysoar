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
  RefreshCw,
  Upload,
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../lib/api';
import { vulnmgmtApi } from '../api/endpoints';
import type { Row } from '../lib/apiRow';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
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
// Field names follow src/schemas/vulnmgmt.py. Instance counts and age come
// from the stored instances of each catalogue row (null renders
// "not available").
const NA = 'not available';

const normalizeVuln = (v: Row) => ({
  ...v,
  cveId: v.cve_id ?? null,
  cvss: v.cvss_v3_score ?? null,
  epss: v.epss_score ?? null,
  patchAvailable: Boolean(v.patch_available),
  kev: Boolean(v.kev_listed),
  daysOpen: (v.days_open ?? null) as number | null,
  affectedAssets: (v.affected_instance_count ?? null) as number | null,
  openInstances: (v.open_instance_count ?? null) as number | null,
  kevDueDate: (v.kev_due_date ?? null) as string | null,
});

// Formats the import parser accepts (src/vulnmgmt/engine.py IMPORT_FORMATS).
const SCAN_FORMATS: { value: string; label: string }[] = [
  { value: 'auto', label: 'Detect from file' },
  { value: 'nessus', label: 'Nessus (.nessus XML / JSON / CSV)' },
  { value: 'tenable', label: 'Tenable.io export' },
  { value: 'openvas', label: 'OpenVAS / GVM (XML / CSV)' },
  { value: 'qualys', label: 'Qualys (CSV / JSON)' },
  { value: 'csv', label: 'Generic CSV' },
  { value: 'json', label: 'Generic JSON findings' },
];

const normalizeProfile = (p: Row) => ({
  ...p,
  schedule: p.schedule_cron ?? null,
  status: p.enabled ? 'active' : 'inactive',
  lastRun: p.last_scan_date ?? null,
  nextRun: p.next_scan_date ?? null,
});

// PatchOperationResponse: one row per vulnerability instance.
const normalizePatchOp = (op: Row) => ({
  ...op,
  name: op.patch_name || op.patch_id || op.patch_type || 'Patch operation',
  startDate: op.deployment_date ?? null,
  verifiedDate: op.verification_date ?? null,
  status: op.deployment_status ?? null,
});

// The server reports each exception's status (active / expired).
const normalizeException = (e: Row) => ({
  ...e,
  instanceId: e.vulnerability_instance_id ?? null,
  reason: e.justification ?? null,
  expiryDate: e.expiry_date ?? null,
  approver: e.approved_by ?? null,
  status: e.status ?? null,
});

const fmtDate = (v: string | null | undefined, empty: string) =>
  v ? new Date(v).toLocaleString() : empty;

// Instance ids for one catalog vulnerability (patch plans, bulk actions and
// exceptions all operate on vulnerability_instances, not catalog rows).
const instanceIdsFor = async (vulnerabilityId: string): Promise<string[]> => {
  const res = await api.get('/vulnmgmt/instances', { params: { vulnerability_id: vulnerabilityId, size: 100 } });
  return (res.data?.items ?? []).map((i: Row) => i.id);
};

export default function VulnManagement() {
  const [activeTab, setActiveTab] = useState('vulnerabilities');
  const [vulnerabilities, setVulnerabilities] = useState<Row[]>([]);
  const [scanProfiles, setScanProfiles] = useState<Row[]>([]);
  const [patchOps, setPatchOps] = useState<Row[]>([]);
  const [exceptions, setExceptions] = useState<Row[]>([]);
  const [dashboardMetrics, setDashboardMetrics] = useState<Row | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadErrors, setLoadErrors] = useState<Record<'vulns' | 'patches' | 'profiles' | 'exceptions' | 'dashboard', unknown>>({
    vulns: null, patches: null, profiles: null, exceptions: null, dashboard: null,
  });
  const scanFileInput = React.useRef<HTMLInputElement>(null);
  const [importProfile, setImportProfile] = useState<Row | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewVulnModal, setShowNewVulnModal] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState<Row | null>(null);
  const [editingVulnerability, setEditingVulnerability] = useState<Row | null>(null);
  const [editingException, setEditingException] = useState<Row | null>(null);
  const [editingScanProfile, setEditingScanProfile] = useState<Row | null>(null);
  const [severityFilter, setSeverityFilter] = useState('');
  const [remediatingVuln, setRemediatingVuln] = useState<Row | null>(null);

  const [showNewScanProfileModal, setShowNewScanProfileModal] = useState(false);
  const [showNewExceptionModal, setShowNewExceptionModal] = useState(false);
  const [importFormat, setImportFormat] = useState('auto');
  const [importResult, setImportResult] = useState<Row | null>(null);
  const [kevResult, setKevResult] = useState<Row | null>(null);
  const [refreshResult, setRefreshResult] = useState<Row | null>(null);
  const [planResult, setPlanResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [vulnsRes, patchRes, profilesRes, exceptionsRes, dashRes] = await Promise.allSettled([
        vulnmgmtApi.getVulnerabilities({ size: 100, severity: severityFilter || undefined }),
        vulnmgmtApi.getPatchOperations(),
        vulnmgmtApi.getScanProfiles(),
        vulnmgmtApi.getExceptions(),
        api.get('/vulnmgmt/dashboard').then(r => r.data),
      ]);
      const asList = (r: PromiseSettledResult<Row>): Row[] => {
        if (r.status !== 'fulfilled') return [];
        return Array.isArray(r.value) ? r.value : (r.value?.items ?? []);
      };
      const reason = (r: PromiseSettledResult<Row>) => (r.status === 'rejected' ? (r.reason ?? new Error('request failed')) : null);
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severityFilter]);

  // Summary cards read only the org-scoped /vulnmgmt/dashboard aggregate
  // (DashboardMetrics). No client-side count of the first page stands in.
  const criticalVulns: number | null = dashboardMetrics?.critical_vulnerabilities ?? null;
  const trackedVulns: number | null = dashboardMetrics?.total_vulnerabilities ?? null;
  const mttrDays: number | null = dashboardMetrics?.mean_time_to_remediate_days ?? dashboardMetrics?.mttr_days ?? null;
  const bySeverity: Record<string, number> | null = dashboardMetrics?.by_severity ?? null;
  const kevCompliancePct: number | null = dashboardMetrics?.kev_compliance?.compliance_percentage ?? null;
  // With no tracked instances there is nothing to be compliant with.
  const slaCompliance: number | null = dashboardMetrics?.sla_compliance?.total
    ? dashboardMetrics.sla_compliance.compliance_percentage
    : null;

  const runScanImport = async (profile: Row | null, file: File) => {
    setBusy('import');
    setActionError(null);
    setImportResult(null);
    try {
      const scanData = await file.text();
      // ScanImportRequest requires scan_format; a profile's scanner_type
      // names the parser, otherwise the format picked on this page.
      const res = await vulnmgmtApi.importScan({
        scan_profile_id: profile?.id ?? '',
        scan_format: profile?.scanner_type || importFormat,
        scan_data: scanData,
      });
      setImportResult({ ...res, file_name: file.name });
      loadData();
    } catch (error) {
      setActionError({ what: `import ${file.name}`, error });
    } finally {
      setBusy(null);
      setImportProfile(null);
    }
  };

  const runAction = async (key: string, what: string, fn: () => Promise<Row>, onDone: (r: Row) => void) => {
    setBusy(key);
    setActionError(null);
    try {
      onDone(await fn());
      loadData();
    } catch (error) {
      setActionError({ what, error });
    } finally {
      setBusy(null);
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
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => runAction('kev', 'sync the CISA KEV catalogue', () => vulnmgmtApi.syncKev(), (r) => setKevResult(r))}
              disabled={busy !== null}
              title="Fetch the CISA Known Exploited Vulnerabilities feed and flag the CVEs this organisation tracks"
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50"
            >
              <AlertTriangle className="w-4 h-4" />
              {busy === 'kev' ? 'Syncing KEV...' : 'Sync KEV'}
            </button>
            <button
              onClick={() => runAction('refresh', 'refresh risk and SLA scores', () => vulnmgmtApi.refreshScores(), (r) => setRefreshResult(r))}
              disabled={busy !== null}
              title="Recompute risk and SLA status on every stored instance"
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50"
            >
              <RefreshCw className={clsx('w-4 h-4', busy === 'refresh' && 'animate-spin')} />
              Refresh Scores
            </button>
            <button
              onClick={() => setShowNewVulnModal(true)}
              className="flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition"
            >
              <Plus className="w-4 h-4" />
              New Vulnerability
            </button>
          </div>
        </div>

        <div className="mb-4 space-y-3">
          <LoadErrorBanner what="vulnerability dashboard metrics" error={loadErrors.dashboard} />
          {actionError && !remediatingVuln && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
          {kevResult && (
            <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 flex justify-between gap-4">
              <span>
                KEV sync ({kevResult.source === 'cisa_feed' ? 'CISA feed' : kevResult.source}): {kevResult.catalog_entries} catalogue entries read,{' '}
                {kevResult.matched} tracked CVE(s) listed, {kevResult.newly_flagged} newly flagged, {kevResult.already_flagged} already flagged
                {typeof kevResult.exposure_vulnerabilities_flagged === 'number' && `, ${kevResult.exposure_vulnerabilities_flagged} exposure record(s) flagged`}.
                Nothing is created from the feed.
              </span>
              <button onClick={() => setKevResult(null)} className="text-xs underline">dismiss</button>
            </div>
          )}
          {refreshResult && (
            <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 flex justify-between gap-4">
              <span>
                Risk / SLA refreshed on {refreshResult.instances_refreshed} instance(s); {refreshResult.breached} breaching SLA
                {refreshResult.reopened_after_exception_expiry ? `; ${refreshResult.reopened_after_exception_expiry} reopened after exception expiry` : ''}
                {refreshResult.truncated ? ' (capped; the hourly task refreshes the rest)' : ''}.
              </span>
              <button onClick={() => setRefreshResult(null)} className="text-xs underline">dismiss</button>
            </div>
          )}
          {importResult && (
            <div className="text-sm bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded p-3 space-y-2">
              <div className="flex justify-between gap-4">
                <span className="font-medium">
                  Imported {importResult.file_name} ({importResult.scan_format}): {importResult.findings_read} finding(s) read
                </span>
                <button onClick={() => setImportResult(null)} className="text-xs underline">dismiss</button>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                <span>Instances created: {importResult.instances_created}</span>
                <span>Instances updated: {importResult.instances_updated}</span>
                <span>Instances reopened: {importResult.instances_reopened}</span>
                <span>Catalogue rows created: {importResult.vulnerabilities_created}</span>
                <span>Assets linked: {importResult.assets_linked}</span>
                <span>Assets created: {importResult.assets_created}</span>
                <span>SLA breached: {importResult.sla_breached}</span>
                <span>Skipped: {importResult.skipped_count}</span>
              </div>
              {Array.isArray(importResult.skipped) && importResult.skipped.length > 0 && (
                <div>
                  <p className="font-medium">Skipped findings by reason</p>
                  <ul className="list-disc ml-5">
                    {importResult.skipped.map((s: Row, i: number) => (
                      <li key={i}>
                        {s.reason}: {s.count}
                        {Array.isArray(s.examples) && s.examples.length > 0 && (
                          <span className="text-gray-600 dark:text-gray-400"> (e.g. {s.examples.map((x: unknown) => (typeof x === 'string' ? x : JSON.stringify(x))).join('; ')})</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {Array.isArray(importResult.parse_errors) && importResult.parse_errors.length > 0 && (
                <div>
                  <p className="font-medium">Parser warnings</p>
                  <ul className="list-disc ml-5">
                    {importResult.parse_errors.map((m: unknown, i: number) => <li key={i}>{typeof m === 'string' ? m : JSON.stringify(m)}</li>)}
                  </ul>
                </div>
              )}
              {importResult.automation_events_failed > 0 && (
                <p className="text-orange-700 dark:text-orange-300">{importResult.automation_events_failed} automation event(s) for new critical findings failed to fire.</p>
              )}
            </div>
          )}
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
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-4 text-sm">
          <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3">
            <p className="text-gray-600 dark:text-gray-400">Open findings</p>
            <p className="text-xl font-semibold">{dashboardMetrics?.open_findings ?? NA}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3">
            <p className="text-gray-600 dark:text-gray-400">Tracked instances</p>
            <p className="text-xl font-semibold">{dashboardMetrics?.total_instances ?? NA}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3">
            <p className="text-gray-600 dark:text-gray-400">Assets affected</p>
            <p className="text-xl font-semibold">{dashboardMetrics?.assets_affected ?? NA}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3">
            <p className="text-gray-600 dark:text-gray-400">Open KEV instances</p>
            <p className="text-xl font-semibold">{dashboardMetrics?.open_kev_instances ?? NA}</p>
          </div>
          <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3">
            <p className="text-gray-600 dark:text-gray-400">KEV (BOD 22-01) compliance</p>
            <p className="text-xl font-semibold">{kevCompliancePct === null ? NA : `${kevCompliancePct.toFixed(1)}%`}</p>
            {kevCompliancePct === null && <p className="text-xs text-gray-500">no KEV-listed instance tracked</p>}
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
                    <h3 className="font-semibold mb-3">CVSS Score Distribution <span className="text-xs font-normal text-gray-500">(catalogue rows on this page)</span></h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between"><span>9.0 - 10.0</span><span className="font-semibold text-red-600">{vulnerabilities.filter(v => (v.cvss ?? 0) >= 9).length}</span></div>
                      <div className="flex justify-between"><span>7.0 - 8.9</span><span className="font-semibold text-orange-600">{vulnerabilities.filter(v => (v.cvss ?? 0) >= 7 && (v.cvss ?? 0) < 9).length}</span></div>
                      <div className="flex justify-between"><span>4.0 - 6.9</span><span className="font-semibold text-yellow-600">{vulnerabilities.filter(v => (v.cvss ?? 0) >= 4 && (v.cvss ?? 0) < 7).length}</span></div>
                      <div className="flex justify-between"><span>0.0 - 3.9</span><span className="font-semibold text-green-600">{vulnerabilities.filter(v => v.cvss !== null && v.cvss < 4).length}</span></div>
                      <div className="flex justify-between"><span>Unscored</span><span className="font-semibold text-gray-500">{vulnerabilities.filter(v => v.cvss === null).length}</span></div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                    <h3 className="font-semibold mb-3">Open Instances by Severity</h3>
                    {bySeverity === null ? (
                      <p className="text-sm text-gray-500">{NA}</p>
                    ) : (
                      <div className="space-y-2 text-sm">
                        <div className="flex justify-between"><span>Critical</span><span className="font-semibold text-red-600">{bySeverity.critical ?? 0}</span></div>
                        <div className="flex justify-between"><span>High</span><span className="font-semibold text-orange-600">{bySeverity.high ?? 0}</span></div>
                        <div className="flex justify-between"><span>Medium</span><span className="font-semibold text-yellow-600">{bySeverity.medium ?? 0}</span></div>
                        <div className="flex justify-between"><span>Low</span><span className="font-semibold text-green-600">{bySeverity.low ?? 0}</span></div>
                      </div>
                    )}
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
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    aria-label="Filter by severity"
                    className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"
                  >
                    <option value="">All severities</option>
                    <option value="critical">Critical</option>
                    <option value="critical,high">Critical + High</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
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
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Open / Affected</th>
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
                            {vuln.openInstances ?? NA} / {vuln.affectedAssets ?? NA}
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
                <div className="flex flex-wrap items-end justify-between gap-4">
                  <div className="flex items-end gap-2">
                    <div>
                      <label className="block text-xs font-medium mb-1 text-gray-600 dark:text-gray-400">Scanner export format</label>
                      <select
                        value={importFormat}
                        onChange={(e) => setImportFormat(e.target.value)}
                        className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm"
                      >
                        {SCAN_FORMATS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
                      </select>
                    </div>
                    <button
                      onClick={() => { setImportProfile(null); scanFileInput.current?.click(); }}
                      disabled={busy !== null}
                      className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50"
                    >
                      <Upload className="w-4 h-4" />
                      {busy === 'import' ? 'Importing...' : 'Import Scanner Export'}
                    </button>
                  </div>
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
                <div className="text-sm bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded p-3">
                  Patch operations are record-keeping only: PySOAR does not deploy patches. Record the deployment and
                  verification here once your patching tool has done the work; a passed verification marks the instance patched.
                </div>
                {!loadErrors.patches && patchOps.length === 0 && (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
                    No patch operations recorded.
                  </div>
                )}
                <div className="grid grid-cols-1 gap-4">
                  {patchOps.map((op) => (
                    <div key={op.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                      <div className="flex justify-between items-start mb-4">
                        <div>
                          <h3 className="font-semibold text-lg">{op.name}</h3>
                          <div className="flex gap-4 mt-2 text-sm text-gray-600 dark:text-gray-400">
                            <span className="capitalize">{(op.patch_type || '').replace(/_/g, ' ')}</span>
                            <span>·</span>
                            <span className="font-mono">{op.cve_id || `instance ${op.vulnerability_instance_id}`}</span>
                            {op.asset_name && <><span>·</span><span>{op.asset_name}</span></>}
                            {op.instance_status && <><span>·</span><span>instance {op.instance_status}</span></>}
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
                        <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Type</th>
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
                          <td className="px-6 py-4 text-sm">
                            <div className="font-mono font-medium">{exc.cve_id || exc.instanceId}</div>
                            {exc.asset_name && <div className="text-xs text-gray-500">{exc.asset_name}</div>}
                          </td>
                          <td className="px-6 py-4 text-sm">{(exc.exception_type || NA).replace(/_/g, ' ')}</td>
                          <td className="px-6 py-4 text-sm">{exc.reason}</td>
                          <td className="px-6 py-4 text-sm">{exc.approver || 'None'}</td>
                          <td className="px-6 py-4 text-sm">{exc.expiryDate || 'No expiry'}</td>
                          <td className="px-6 py-4">
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(exc.status)}`}>
                              {exc.status ?? NA}
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
                    CISA Known Exploited Vulnerabilities among the CVEs this organisation tracks. Use Sync KEV to re-check the
                    catalogue against the CISA feed; BOD 22-01 due dates come from the feed.
                  </p>
                </div>

                <LoadErrorBanner what="vulnerabilities" error={loadErrors.vulns} />
                {!loadErrors.vulns && kevVulns.length === 0 && (
                  <div className="text-center text-gray-500 dark:text-gray-400 py-6 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
                    No KEV-listed vulnerability on this page. Run Sync KEV to flag tracked CVEs.
                  </div>
                )}
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
                          <p className="text-xs text-gray-500 mt-2">
                            KEV added: {vuln.kev_date_added ? new Date(vuln.kev_date_added).toLocaleDateString() : NA} · Due:{' '}
                            {vuln.kevDueDate ? new Date(vuln.kevDueDate).toLocaleDateString() : NA} · Open instances: {vuln.openInstances ?? NA}
                          </p>
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
              <div><span className="font-medium">Affected Instances:</span> {selectedVulnerability.affectedAssets ?? NA} ({selectedVulnerability.openInstances ?? NA} open)</div>
              <div><span className="font-medium">Days Open:</span> {selectedVulnerability.daysOpen ?? NA}</div>
              {selectedVulnerability.kev && (
                <div><span className="font-medium">KEV due date:</span> {selectedVulnerability.kevDueDate ? new Date(selectedVulnerability.kevDueDate).toLocaleDateString() : NA}</div>
              )}
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
              <p className="text-xs text-gray-500">
                A patch plan records one patch operation per open instance; nothing is deployed by PySOAR.
              </p>
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              {planResult && (
                <div className="text-sm bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded p-3">
                  Patch plan recorded: {planResult.created ?? (planResult.patch_operation_ids?.length ?? 0)} operation(s) created
                  {planResult.skipped ? `, ${Array.isArray(planResult.skipped) ? planResult.skipped.length : planResult.skipped} skipped` : ''}.
                  Deployment dispatched: {planResult.deployment_dispatched ? 'yes' : 'no (record-keeping only)'}.
                </div>
              )}
              <button onClick={async () => {
                setActionError(null);
                setPlanResult(null);
                try {
                  // create-plan takes vulnerability_instance_ids, so resolve
                  // this catalog vulnerability's instances first.
                  const instanceIds = await instanceIdsFor(remediatingVuln.id);
                  if (instanceIds.length === 0) {
                    setActionError({ what: 'record a patch plan', error: new Error('No affected instances are recorded for this vulnerability, so there is nothing to patch.') });
                    return;
                  }
                  const res = await api.post('/vulnmgmt/patch-operations/create-plan', {
                    vulnerability_instance_ids: instanceIds,
                  });
                  setPlanResult(res.data);
                  loadData();
                } catch (e) {
                  setActionError({ what: 'record a patch plan', error: e });
                }
              }} className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition">Record Patch Plan</button>
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
              <button onClick={() => { setRemediatingVuln(null); setPlanResult(null); setActionError(null); }} className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Close</button>
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
                  <option value="deferred">Deferred</option>
                  <option value="not_applicable">Not Applicable</option>
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
          if (file) runScanImport(importProfile, file);
        }}
      />
    </div>
  );
}
