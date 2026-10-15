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
import { api } from '../api/client';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import { describeLoadError } from '../lib/loadError';

const NA = 'not available';

const splitList = (v: string): string[] => v.split(',').map((k) => k.trim()).filter(Boolean);
const asStringList = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];

// POST /darkweb/monitors/{id}/trigger-scan (ScanStatusResponse)
interface ScanSourceEntry {
  label?: string;
  status?: string; // ok | not_configured | error | skipped
  checked?: number;
  matched?: number;
  error?: string;
  reason?: string;
  [k: string]: unknown;
}
interface ScanResult {
  scan_id: string;
  status: string; // completed | no_terms
  start_time: string;
  completion_time: string | null;
  findings: number; // matched
  new_findings: number; // created
  detail: string | null;
  terms_searched: string[];
  sources: Record<string, ScanSourceEntry>;
  skipped_duplicate: number;
  credential_leaks_created: number;
  critical_fired: number;
}

// GET /darkweb/dashboard (DarkWebDashboard), fields this page reads.
interface DarkWebDashboardData {
  scan_frequency: string;
  scan_interval_minutes: number | null;
  sources: Record<string, { label: string; configured: boolean; requires: string | null }>;
  source_platform_labels: Record<string, string>;
}

// POST /darkweb/credentials/bulk-remediate (CredentialRemediationReport)
interface RemediationReport {
  total_affected: number;
  recorded: number;
  execution: string;
  detail: string | null;
  remediation_date: string;
}

const FINDING_TYPE_LABELS: Record<string, string> = {
  threat_feed_match: 'Threat intel feed match',
};

const SCAN_STATUS_CLS: Record<string, string> = {
  ok: 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100',
  not_configured: 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100',
  error: 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100',
  skipped: 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100',
};

/** The backend's own explanation inside an HTTP error body ({detail: {detail}}). */
const backendDetail = (err: unknown): string | null => {
  const data = (err as { response?: { data?: { detail?: unknown } } })?.response?.data;
  const d = data?.detail;
  if (typeof d === 'string') return d;
  if (d && typeof d === 'object' && typeof (d as Record<string, unknown>).detail === 'string') {
    return (d as Record<string, string>).detail;
  }
  return null;
};
const httpStatus = (err: unknown): number | undefined =>
  (err as { response?: { status?: number } })?.response?.status;

function ScanResultPanel({ result }: { result: ScanResult }) {
  return (
    <div className="mt-3 border-t border-gray-200 dark:border-gray-700 pt-3 text-sm space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">Last scan: {result.status}</span>
        <span className="text-gray-600 dark:text-gray-400">
          {fmtDate(result.start_time)}{result.completion_time ? ` → ${fmtDate(result.completion_time)}` : ''}
        </span>
      </div>
      {result.detail && <p className="text-gray-700 dark:text-gray-300">{result.detail}</p>}
      {result.status !== 'no_terms' && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-2 text-xs">
          <div><p className="text-gray-500 dark:text-gray-400">Matched</p><p className="font-semibold">{result.findings}</p></div>
          <div><p className="text-gray-500 dark:text-gray-400">New findings created</p><p className="font-semibold">{result.new_findings}</p></div>
          <div><p className="text-gray-500 dark:text-gray-400">Skipped (duplicates)</p><p className="font-semibold">{result.skipped_duplicate}</p></div>
          <div><p className="text-gray-500 dark:text-gray-400">Credential leaks created</p><p className="font-semibold">{result.credential_leaks_created}</p></div>
          <div><p className="text-gray-500 dark:text-gray-400">Critical automations fired</p><p className="font-semibold">{result.critical_fired}</p></div>
        </div>
      )}
      {result.terms_searched.length > 0 && (
        <p className="text-xs text-gray-600 dark:text-gray-400">
          Terms searched: <span className="font-mono">{result.terms_searched.join(', ')}</span>
        </p>
      )}
      {Object.keys(result.sources).length > 0 && (
        <ul className="space-y-1 text-xs">
          {Object.entries(result.sources).map(([key, src]) => {
            const why = src.error ?? src.reason;
            return (
              <li key={key} className="flex flex-wrap items-start gap-2">
                <span className={clsx('px-2 py-0.5 rounded font-medium', SCAN_STATUS_CLS[src.status ?? ''] ?? SCAN_STATUS_CLS.not_configured)}>
                  {src.status ?? 'unknown'}
                </span>
                <span className="flex-1">
                  {src.label ?? key}
                  {typeof src.checked === 'number' ? ` · checked ${src.checked}` : ''}
                  {typeof src.matched === 'number' ? ` · matched ${src.matched}` : ''}
                  {why ? <span className="text-gray-600 dark:text-gray-400"> — {String(why)}</span> : null}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

/** affected_assets: {source, matched_terms, email|domain|url|...} */
function AffectedAssets({ assets }: { assets: unknown }) {
  if (Array.isArray(assets)) {
    if (assets.length === 0) return <span className="text-xs text-gray-500 dark:text-gray-400">None recorded</span>;
    return (
      <div className="flex flex-wrap gap-2">
        {assets.map((a, idx) => (
          <span key={idx} className="px-2 py-1 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100 rounded text-xs">{String(a)}</span>
        ))}
      </div>
    );
  }
  if (!assets || typeof assets !== 'object') {
    return <span className="text-xs text-gray-500 dark:text-gray-400">None recorded</span>;
  }
  const rec = assets as Record<string, unknown>;
  const matched = asStringList(rec.matched_terms);
  const rest = Object.entries(rec).filter(([k]) => k !== 'source' && k !== 'matched_terms');
  return (
    <div className="space-y-1 text-xs">
      {typeof rec.source === 'string' && (
        <p><span className="text-gray-600 dark:text-gray-400">Source:</span> {rec.source}</p>
      )}
      {matched.length > 0 && (
        <p>
          <span className="text-gray-600 dark:text-gray-400">Matched terms:</span>{' '}
          <span className="font-mono">{matched.join(', ')}</span>
        </p>
      )}
      {rest.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {rest.map(([k, v]) => (
            <span key={k} className="px-2 py-1 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100 rounded break-all">
              {k}: {Array.isArray(v) ? v.map(String).join(', ') : typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

const fmtDate = (v: unknown): string => {
  if (!v) return NA;
  const d = new Date(String(v));
  return Number.isFinite(d.getTime()) ? d.toLocaleString() : String(v);
};

// Monitor rows from GET /darkweb/monitors (DarkWebMonitorResponse).
const normMonitor = (m: any) => ({
  ...m,
  status: m.enabled === false ? 'paused' : 'active',
  keyword: Array.isArray(m.search_terms) ? m.search_terms.join(', ') : '',
  lastScan: m.last_check ?? null,
  findingsCount: m.findings_count ?? null,
  createdDate: m.created_at ?? null,
});

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
    case 'in_progress':
    case 'takedown_requested':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'identified':
    case 'open':
      return 'bg-orange-100 dark:bg-orange-900 text-orange-800 dark:text-orange-100';
    case 'failed':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'remediated':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

const OPEN_TAKEDOWN = ['identified', 'takedown_requested', 'in_progress'];

export default function DarkWebMonitor() {
  const [activeTab, setActiveTab] = useState('monitors');
  const [monitors, setMonitors] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [credentials, setCredentials] = useState<any[]>([]);
  const [threats, setThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  // Reference time for the "last 7 days" card, captured when data loads.
  const [loadedAt, setLoadedAt] = useState<number | null>(null);
  // Per-source load failures; each tab shows its own error instead of an
  // empty list, and summary cards say "not available".
  const [loadErrors, setLoadErrors] = useState<{
    monitors?: unknown;
    findings?: unknown;
    credentials?: unknown;
    threats?: unknown;
  }>({});
  const [searchQuery, setSearchQuery] = useState('');
  const [showNewMonitorModal, setShowNewMonitorModal] = useState(false);
  const [editingMonitor, setEditingMonitor] = useState<any | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [actionFinding, setActionFinding] = useState<any | null>(null);
  const [selectedCredential, setSelectedCredential] = useState<any | null>(null);
  const [newMonitorName, setNewMonitorName] = useState('');
  const [newMonitorKeywords, setNewMonitorKeywords] = useState('');
  const [newMonitorDomains, setNewMonitorDomains] = useState('');
  const [newMonitorEmails, setNewMonitorEmails] = useState('');
  const [createError, setCreateError] = useState<unknown>(null);
  const [editError, setEditError] = useState<unknown>(null);
  const [dashboard, setDashboard] = useState<DarkWebDashboardData | null>(null);
  const [dashboardError, setDashboardError] = useState<unknown>(null);
  const [scanType, setScanType] = useState<'full' | 'quick'>('full');
  const [scanningId, setScanningId] = useState<string | null>(null);
  const [scanResults, setScanResults] = useState<Record<string, ScanResult>>({});
  const [scanErrors, setScanErrors] = useState<Record<string, unknown>>({});
  const [takedownErrors, setTakedownErrors] = useState<Record<string, unknown>>({});
  const [selectedCredIds, setSelectedCredIds] = useState<string[]>([]);
  const [remediationAction, setRemediationAction] = useState('password_reset');
  const [remediating, setRemediating] = useState(false);
  const [remediationReport, setRemediationReport] = useState<RemediationReport | null>(null);
  const [remediationError, setRemediationError] = useState<unknown>(null);

  const platformLabel = (platform: string | null | undefined): string => {
    if (!platform) return NA;
    return dashboard?.source_platform_labels?.[platform] ?? platform;
  };

  const runScan = async (monitorId: string) => {
    setScanningId(monitorId);
    setScanErrors((prev) => ({ ...prev, [monitorId]: null }));
    try {
      const res = await api.post(`/darkweb/monitors/${monitorId}/trigger-scan`, { scan_type: scanType });
      const result = res.data as ScanResult;
      setScanResults((prev) => ({ ...prev, [monitorId]: result }));
      if (result.status === 'completed') {
        setMonitors((prev) => prev.map((m) => (m.id === monitorId ? { ...m, lastScan: result.completion_time ?? result.start_time } : m)));
      }
    } catch (err) {
      setScanErrors((prev) => ({ ...prev, [monitorId]: err }));
    } finally {
      setScanningId(null);
    }
  };

  const remediateSelected = async () => {
    if (selectedCredIds.length === 0) return;
    setRemediating(true);
    setRemediationError(null);
    setRemediationReport(null);
    try {
      const res = await api.post('/darkweb/credentials/bulk-remediate', {
        credential_ids: selectedCredIds,
        action: remediationAction,
      });
      const report = res.data as RemediationReport;
      setRemediationReport(report);
      setCredentials((prev) =>
        prev.map((c) =>
          selectedCredIds.includes(c.id) ? { ...c, status: 'remediated', remediation: remediationAction } : c,
        ),
      );
      setSelectedCredIds([]);
    } catch (err) {
      setRemediationError(err);
    } finally {
      setRemediating(false);
    }
  };

  React.useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      // size=100 so the user sees real findings beyond the default first
      // page (20). A failed source is recorded and shown, never coerced
      // into an empty list.
      const [alertsRes, credentialsRes, brandRes, monitorsRes, dashboardRes] = await Promise.allSettled([
        darkwebApi.getAlerts({ size: 100 }),
        darkwebApi.getCredentialLeaks({ size: 100 }),
        darkwebApi.getBrandMonitors(),
        darkwebApi.getMonitors(),
        api.get('/darkweb/dashboard'),
      ]);
      if (dashboardRes.status === 'fulfilled') {
        setDashboard(dashboardRes.value.data as DarkWebDashboardData);
        setDashboardError(null);
      } else {
        setDashboardError(dashboardRes.reason);
      }
      const asList = (d: any): any[] => (Array.isArray(d) ? d : (d?.items ?? []));
      // Findings: DarkWebFindingResponse
      const normFinding = (f: any) => ({
        ...f,
        discoveryDate: f.discovered_date ?? f.created_at ?? null,
        title: f.title ?? FINDING_TYPE_LABELS[f.finding_type] ?? f.finding_type ?? '—',
        kindLabel: FINDING_TYPE_LABELS[f.finding_type] ?? f.finding_type ?? null,
        platform: f.source_platform ?? null,
        affectedAssets: f.affected_assets ?? null,
      });
      // Credentials: CredentialLeakResponse has no severity field.
      const normCred = (c: any) => ({
        ...c,
        email: c.email ?? c.username ?? '—',
        source: c.breach_source ?? null,
        breachDate: c.breach_date ?? null,
        remediation: c.remediation_action ?? null,
        status: c.is_remediated ? 'remediated' : 'open',
      });
      // Brand threats: BrandThreatResponse; status is takedown_status
      // (identified | takedown_requested | in_progress | completed | failed).
      const normThreat = (t: any) => ({
        ...t,
        threat: t.malicious_domain ?? t.target_brand ?? t.target_domain ?? '—',
        status: t.takedown_status ?? null,
        discoveryDate: t.created_at ?? null,
      });
      const errors: typeof loadErrors = {};
      if (monitorsRes.status === 'fulfilled') setMonitors(asList(monitorsRes.value).map(normMonitor));
      else errors.monitors = monitorsRes.reason;
      if (alertsRes.status === 'fulfilled') setFindings(asList(alertsRes.value).map(normFinding));
      else errors.findings = alertsRes.reason;
      if (credentialsRes.status === 'fulfilled') setCredentials(asList(credentialsRes.value).map(normCred));
      else errors.credentials = credentialsRes.reason;
      if (brandRes.status === 'fulfilled') setThreats(asList(brandRes.value).map(normThreat));
      else errors.threats = brandRes.reason;
      setLoadErrors(errors);
      setLoadedAt(Date.now());
      setLoading(false);
    };
    loadData();
  }, []);

  const activeMonitors = loadErrors.monitors ? NA : monitors.filter(m => m.status === 'active').length;
  const newFindings = loadErrors.findings ? NA : findings.filter(f => {
    const when = f.discoveryDate;
    if (!when) return false;
    const t = new Date(when).getTime();
    return Number.isFinite(t) && loadedAt != null && t > loadedAt - 7 * 24 * 60 * 60 * 1000;
  }).length;
  const exposedCredentials = loadErrors.credentials ? NA : credentials.length;
  // Open brand threats: takedown not yet completed or failed
  // (src/darkweb/models.py TakedownStatus).
  const brandThreats = loadErrors.threats ? NA : threats.filter(t => OPEN_TAKEDOWN.includes(t.status)).length;

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

        {/* Scan schedule + sources (GET /darkweb/dashboard) */}
        <div className="mt-4 space-y-2">
          <LoadErrorBanner what="dark web scan sources" error={dashboardError} />
          {dashboard && (
            <div className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
              <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
                <h2 className="font-semibold">Scan sources</h2>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Scheduled sweep: {dashboard.scan_frequency || NA}
                  {dashboard.scan_interval_minutes != null ? ` (interval ${dashboard.scan_interval_minutes} min)` : ''}
                </p>
              </div>
              <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm">
                {Object.entries(dashboard.sources).map(([key, src]) => (
                  <li key={key} className="flex items-start gap-2">
                    <span
                      className={clsx(
                        'mt-0.5 px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap',
                        src.configured ? SCAN_STATUS_CLS.ok : SCAN_STATUS_CLS.not_configured,
                      )}
                    >
                      {src.configured ? 'configured' : 'not configured'}
                    </span>
                    <span>
                      {src.label}
                      {!src.configured && src.requires ? (
                        <span className="text-gray-600 dark:text-gray-400"> — requires {src.requires}</span>
                      ) : null}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-xs text-gray-500 dark:text-gray-400">
                Tor forums, Telegram, Discord and ransomware leak sites are not scanned; findings from them can only be recorded manually.
              </p>
            </div>
          )}
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
                <LoadErrorBanner what="monitors" error={loadErrors.monitors} />
                <div className="flex items-center gap-2 text-sm">
                  <label htmlFor="dw-scan-type" className="text-gray-600 dark:text-gray-400">Scan type</label>
                  <select
                    id="dw-scan-type"
                    value={scanType}
                    onChange={(e) => setScanType(e.target.value === 'quick' ? 'quick' : 'full')}
                    className="px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700"
                  >
                    <option value="full">Full (every source)</option>
                    <option value="quick">Quick (Have I Been Pwned sources only)</option>
                  </select>
                </div>
                <div className="grid grid-cols-1 gap-4">
                  {filteredMonitors.map((monitor) => (
                    <div key={monitor.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <h3 className="font-semibold text-lg">{monitor.name}</h3>
                          <div className="text-sm text-gray-600 dark:text-gray-400 mt-1 space-y-0.5">
                            <p>Search terms: <span className="font-mono">{asStringList(monitor.search_terms).join(', ') || 'none'}</span></p>
                            <p>Domains: <span className="font-mono">{asStringList(monitor.domains_watched).join(', ') || 'none'}</span></p>
                            <p>Emails: <span className="font-mono">{asStringList(monitor.emails_watched).join(', ') || 'none'}</span></p>
                          </div>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(monitor.status)}`}>
                          {monitor.status}
                        </span>
                      </div>
                      <div className="grid grid-cols-4 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Type</p>
                          <p className="font-medium">{monitor.monitor_type ?? NA}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Findings</p>
                          <p className="font-medium">{monitor.findingsCount ?? NA}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Created</p>
                          <p className="font-medium">{fmtDate(monitor.createdDate)}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Last Scan</p>
                          <p className="font-medium">{monitor.lastScan ? fmtDate(monitor.lastScan) : 'never'}</p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={() => runScan(monitor.id)}
                          disabled={scanningId !== null}
                          className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm bg-indigo-600 hover:bg-indigo-700 text-white rounded transition disabled:opacity-50"
                        >
                          <Zap className="w-4 h-4" />
                          {scanningId === monitor.id ? 'Scanning…' : `Scan now (${scanType})`}
                        </button>
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
                                alert(`Failed to delete monitor: ${describeLoadError(error)}`);
                              }
                            }
                          }}
                          className="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                      {scanErrors[monitor.id] ? (
                        <div className="mt-3">
                          <ActionErrorBanner what="scan this monitor" error={scanErrors[monitor.id]} />
                        </div>
                      ) : null}
                      {scanResults[monitor.id] && <ScanResultPanel result={scanResults[monitor.id]} />}
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

                <LoadErrorBanner what="findings" error={loadErrors.findings} />
                <div className="grid grid-cols-1 gap-4">
                  {filteredFindings.map((finding) => (
                    <div key={finding.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <AlertOctagon className="w-5 h-5 text-orange-600" />
                            <h3 className="font-semibold">{finding.title}</h3>
                            {finding.kindLabel && finding.kindLabel !== finding.title && (
                              <span className="px-2 py-0.5 rounded text-xs bg-gray-100 dark:bg-gray-700">{finding.kindLabel}</span>
                            )}
                            <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                              {finding.severity ? String(finding.severity).toUpperCase() : NA}
                            </span>
                          </div>
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">{finding.description}</p>
                          <div className="flex gap-4 text-sm">
                            <span className="text-gray-600 dark:text-gray-400">Source platform: {platformLabel(finding.platform)}</span>
                            <span className="text-gray-600 dark:text-gray-400">Discovered: {fmtDate(finding.discoveryDate)}</span>
                          </div>
                        </div>
                      </div>
                      <div className="border-t border-gray-200 dark:border-gray-700 pt-3 mt-3">
                        <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">Affected Assets:</p>
                        <AffectedAssets assets={finding.affectedAssets} />
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

                <LoadErrorBanner what="credential leaks" error={loadErrors.credentials} />
                <div className="flex flex-wrap items-center gap-2 text-sm">
                  <span className="text-gray-600 dark:text-gray-400">{selectedCredIds.length} selected</span>
                  <select
                    value={remediationAction}
                    onChange={(e) => setRemediationAction(e.target.value)}
                    className="px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700"
                  >
                    <option value="password_reset">Password reset</option>
                    <option value="account_disabled">Account disabled</option>
                    <option value="mfa_enforced">MFA enforced</option>
                  </select>
                  <button
                    onClick={remediateSelected}
                    disabled={remediating || selectedCredIds.length === 0}
                    className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded disabled:opacity-50"
                    title="Records the remediation decision on the selected leaks; nothing is executed in your identity provider"
                  >
                    {remediating ? 'Recording…' : 'Record remediation'}
                  </button>
                </div>
                <ActionErrorBanner what="record the remediation" error={remediationError} />
                {remediationReport && (
                  <div className="text-sm bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded p-3">
                    <p className="font-medium">
                      Recorded on {remediationReport.recorded} of {remediationReport.total_affected} leak(s) — execution: {remediationReport.execution === 'recorded_only' ? 'recorded only (nothing was executed)' : remediationReport.execution}
                    </p>
                    {remediationReport.detail && <p className="mt-1">{remediationReport.detail}</p>}
                  </div>
                )}
                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-700">
                        <th className="px-4 py-4 text-left">
                          <input
                            type="checkbox"
                            aria-label="Select all open leaks"
                            checked={filteredCredentials.some((c) => c.status === 'open') && filteredCredentials.filter((c) => c.status === 'open').every((c) => selectedCredIds.includes(c.id))}
                            onChange={(e) =>
                              setSelectedCredIds(e.target.checked ? filteredCredentials.filter((c) => c.status === 'open').map((c) => c.id) : [])
                            }
                          />
                        </th>
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
                          <td className="px-4 py-4">
                            <input
                              type="checkbox"
                              aria-label={`Select ${cred.email}`}
                              disabled={cred.status !== 'open'}
                              checked={selectedCredIds.includes(cred.id)}
                              onChange={(e) =>
                                setSelectedCredIds((prev) => (e.target.checked ? [...prev, cred.id] : prev.filter((id) => id !== cred.id)))
                              }
                            />
                          </td>
                          <td className="px-6 py-4 text-sm font-medium">{cred.email}</td>
                          <td className="px-6 py-4 text-sm">{cred.source ?? NA}</td>
                          <td className="px-6 py-4 text-sm">{cred.breachDate ?? NA}</td>
                          <td className="px-6 py-4">
                            {/* CredentialLeakResponse carries no severity */}
                            {cred.severity ? (
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(cred.severity)}`}>
                                {String(cred.severity).toUpperCase()}
                              </span>
                            ) : (
                              <span className="text-sm text-gray-500 dark:text-gray-400">{NA}</span>
                            )}
                          </td>
                          <td className="px-6 py-4 text-sm">{cred.remediation ?? NA}</td>
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

                <LoadErrorBanner what="brand threats" error={loadErrors.threats} />
                <div className="grid grid-cols-1 gap-4">
                  {filteredThreats.map((threat) => (
                    <div key={threat.id} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:shadow-lg transition">
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <AlertTriangle className="w-5 h-5 text-orange-600" />
                            <h3 className="font-semibold">{threat.threat}</h3>
                            {threat.threat_type && (
                              <span className="px-3 py-1 rounded-full text-xs font-medium bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100">
                                {threat.threat_type}
                              </span>
                            )}
                          </div>
                        </div>
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(threat.status)}`}>
                          {threat.status ?? NA}
                        </span>
                      </div>
                      <div className="grid grid-cols-3 gap-4 text-sm mb-4">
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Discovered</p>
                          <p className="font-medium">{fmtDate(threat.discoveryDate)}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Target</p>
                          <p className="font-medium">{threat.target_domain ?? threat.target_brand ?? NA}</p>
                        </div>
                        <div>
                          <p className="text-gray-600 dark:text-gray-400">Takedown Provider</p>
                          <p className="font-medium">{threat.takedown_provider ?? NA}</p>
                        </div>
                      </div>
                      <div className="flex gap-2">
                        <button
                          onClick={async () => {
                            if (threat.status === 'identified' || threat.status === 'failed') {
                              setTakedownErrors(prev => ({ ...prev, [threat.id]: null }));
                              try {
                                const res = await darkwebApi.requestTakedown(threat.id);
                                // Only a real backend answer changes the status.
                                if (res?.status) {
                                  setThreats(prev => prev.map(t => t.id === threat.id ? { ...t, status: res.status } : t));
                                }
                              } catch (error) {
                                setTakedownErrors(prev => ({ ...prev, [threat.id]: error }));
                              }
                            } else {
                              setSelectedFinding(threat);
                            }
                          }}
                          className="flex-1 px-3 py-2 text-sm bg-orange-600 hover:bg-orange-700 text-white rounded transition"
                        >
                          {threat.status === 'identified' || threat.status === 'failed' ? 'Initiate Takedown' : 'View Details'}
                        </button>
                        <button
                          onClick={async () => {
                            try {
                              await darkwebApi.exportReport('csv');
                            } catch (e) {
                              console.error('Export failed:', e);
                              alert(`Export failed: ${describeLoadError(e)}`);
                            }
                          }}
                          className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                        >
                          Full Report
                        </button>
                      </div>
                      {takedownErrors[threat.id] ? (
                        httpStatus(takedownErrors[threat.id]) === 501 ? (
                          <div role="status" className="mt-3 text-sm bg-gray-50 dark:bg-gray-900/40 border border-gray-200 dark:border-gray-700 rounded p-3">
                            <p className="font-medium">Takedown: Not available</p>
                            <p className="mt-1 text-gray-700 dark:text-gray-300">
                              {backendDetail(takedownErrors[threat.id]) ?? describeLoadError(takedownErrors[threat.id])}
                            </p>
                          </div>
                        ) : (
                          <div className="mt-3">
                            <ActionErrorBanner what="initiate a takedown" error={takedownErrors[threat.id]} />
                          </div>
                        )
                      ) : null}
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
              {selectedFinding.platform && <div><span className="font-medium">Platform:</span> {platformLabel(selectedFinding.platform)}</div>}
              {selectedFinding.affectedAssets && <div><span className="font-medium">Affected assets:</span> <AffectedAssets assets={selectedFinding.affectedAssets} /></div>}
              {selectedFinding.source && <div><span className="font-medium">Source:</span> {selectedFinding.source}</div>}
            </div>
            <button onClick={() => setSelectedFinding(null)} className="mt-6 w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Close</button>
          </div>
        </div>
      )}

      {/* Action Modal — buttons now call the real backend actions
          (escalate creates an Incident; notify dispatches Slack/Teams/
          PagerDuty/OpsGenie via send_incident_notifications). The PATCH
          fallback used to look like nothing happened because no
          incident was created and no message was sent. */}
      {actionFinding && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[500px] max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Take Action: {actionFinding.title}</h2>
            <div className="space-y-3">
              <button
                onClick={async () => {
                  try {
                    const res = await darkwebApi.escalateFinding(actionFinding.id);
                    const incidentId = res?.incident_id;
                    setFindings((prev) =>
                      prev.map((f) =>
                        f.id === actionFinding.id ? { ...f, status: 'escalated' } : f,
                      ),
                    );
                    alert(
                      res?.status === 'already_escalated'
                        ? `Already escalated. Incident ${incidentId}`
                        : `Incident ${incidentId} created. Severity: ${res?.incident_severity ?? 'medium'}`,
                    );
                  } catch (e: any) {
                    alert(`Escalate failed: ${e?.response?.data?.detail || e?.message || 'unknown error'}`);
                  }
                  setActionFinding(null);
                }}
                className="w-full px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition"
              >
                Escalate to Incident
              </button>
              <button
                onClick={async () => {
                  try {
                    const res = await darkwebApi.notifyStakeholders(actionFinding.id);
                    const sent = res?.delivery?.sent ?? [];
                    const failed = res?.delivery?.failed ?? [];
                    const skipped = res?.delivery?.skipped ?? [];
                    if (sent.length === 0) {
                      alert(
                        'No notification channels accepted the message. Configure Slack/Teams/PagerDuty in Settings → Integrations.\n\n'
                          + (failed.length ? `Failed: ${failed.join(', ')}\n` : '')
                          + (skipped.length ? `Skipped: ${skipped.join(', ')}` : ''),
                      );
                    } else {
                      setFindings((prev) =>
                        prev.map((f) =>
                          f.id === actionFinding.id ? { ...f, status: 'notified' } : f,
                        ),
                      );
                      alert(
                        `Sent to: ${sent.join(', ')}`
                          + (failed.length ? `\nFailed: ${failed.join(', ')}` : '')
                          + (skipped.length ? `\nSkipped: ${skipped.join(', ')}` : ''),
                      );
                    }
                  } catch (e: any) {
                    alert(`Notify failed: ${e?.response?.data?.detail || e?.message || 'unknown error'}`);
                  }
                  setActionFinding(null);
                }}
                className="w-full px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition"
              >
                Notify Stakeholders
              </button>
              <button
                onClick={async () => {
                  try {
                    await darkwebApi.updateFinding(actionFinding.id, { status: 'reviewed' });
                    setFindings((prev) =>
                      prev.map((f) =>
                        f.id === actionFinding.id ? { ...f, status: 'reviewed' } : f,
                      ),
                    );
                  } catch (e: any) {
                    alert(`Mark reviewed failed: ${e?.response?.data?.detail || e?.message}`);
                  }
                  setActionFinding(null);
                }}
                className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition"
              >
                Mark as Reviewed
              </button>
              <button
                onClick={() => setActionFinding(null)}
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
              >
                Cancel
              </button>
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
              <div><span className="font-medium">Source Breach:</span> {selectedCredential.source ?? NA}</div>
              <div><span className="font-medium">Breach Date:</span> {selectedCredential.breachDate ?? NA}</div>
              <div><span className="font-medium">Severity:</span> {selectedCredential.severity ?? NA}</div>
              <div><span className="font-medium">Remediation:</span> {selectedCredential.remediation ?? NA}</div>
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
              const name = String(formData.get('name') ?? '');
              const keyword = String(formData.get('keyword') ?? '');
              const domains = String(formData.get('domains') ?? '');
              const emails = String(formData.get('emails') ?? '');
              setEditError(null);
              try {
                const res = await api.patch(`/darkweb/monitors/${editingMonitor.id}`, {
                  name,
                  search_terms: splitList(keyword),
                  domains_watched: splitList(domains),
                  emails_watched: splitList(emails),
                });
                setMonitors(prev => prev.map(m => m.id === editingMonitor.id ? normMonitor({ ...m, ...res.data }) : m));
                setEditingMonitor(null);
              } catch (error) {
                setEditError(error);
              }
            }} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Monitor Name</label>
                <input type="text" name="name" defaultValue={editingMonitor.name} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Search terms</label>
                <textarea name="keyword" defaultValue={asStringList(editingMonitor.search_terms).join(', ')} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Domains watched</label>
                <textarea name="domains" defaultValue={asStringList(editingMonitor.domains_watched).join(', ')} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Emails watched</label>
                <textarea name="emails" defaultValue={asStringList(editingMonitor.emails_watched).join(', ')} rows={2} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <ActionErrorBanner what="update the monitor" error={editError} />
              <div className="flex gap-2 mt-6">
                <button type="button" onClick={() => { setEditingMonitor(null); setEditError(null); }} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
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
                <label className="block text-sm font-medium mb-1">Search terms</label>
                <textarea placeholder="Comma-separated, e.g. acme corp, acmecloud" rows={2} value={newMonitorKeywords} onChange={(e) => setNewMonitorKeywords(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Domains watched</label>
                <textarea placeholder="Comma-separated, e.g. acme.com" rows={2} value={newMonitorDomains} onChange={(e) => setNewMonitorDomains(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Emails watched</label>
                <textarea placeholder="Comma-separated; checked against Have I Been Pwned when HIBP_API_KEY is set" rows={2} value={newMonitorEmails} onChange={(e) => setNewMonitorEmails(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <ActionErrorBanner what="create the monitor" error={createError} />
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => { setShowNewMonitorModal(false); setCreateError(null); }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                >
                  Cancel
                </button>
                <button
                  onClick={async () => {
                    if (!newMonitorName.trim()) return;
                    setCreateError(null);
                    try {
                      // DarkWebMonitorCreate (src/schemas/darkweb.py): search_terms,
                      // domains_watched, emails_watched are lists; monitor_type
                      // is left to the backend default.
                      const res = await api.post('/darkweb/monitors', {
                        name: newMonitorName.trim(),
                        search_terms: splitList(newMonitorKeywords),
                        domains_watched: splitList(newMonitorDomains),
                        emails_watched: splitList(newMonitorEmails),
                      });
                      setMonitors(prev => [...prev, normMonitor(res.data)]);
                      setNewMonitorName('');
                      setNewMonitorKeywords('');
                      setNewMonitorDomains('');
                      setNewMonitorEmails('');
                      setShowNewMonitorModal(false);
                    } catch (error) {
                      setCreateError(error);
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
