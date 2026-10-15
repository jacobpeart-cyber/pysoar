import React, { useState } from 'react';
import {
  Shield,
  FileWarning,
  Eye,
  Lock,
  Search,
  Plus,
  Edit,
  Download,
  CheckCircle,
  XCircle,
  FileText,
  Activity,
  Play,
  Pause,
  Zap,
  RefreshCw,
  ScanLine,
} from 'lucide-react';
import clsx from 'clsx';
import { dlpApi } from '../api/endpoints';
import { api } from '../api/client';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';

const NA = 'not available';

// Built-in detectors the content scanner knows (src/dlp/scanner.py); any
// other data_patterns entry is treated as a regex.
const BUILTIN_PATTERNS = [
  'ssn', 'credit_card', 'email', 'phone', 'api_key', 'ipv4', 'ipv6', 'aws_key', 'private_key',
  'medical_diagnosis', 'medical_medication', 'medical_procedure',
];

// Channels that map to stored data the scanner reads. Other channels (email,
// web, usb, ...) have no data source in PySOAR and are not scanned.
const SCANNED_CHANNELS: { value: string; label: string }[] = [
  { value: 'logs', label: 'Ingested logs' },
  { value: 'evidence', label: 'Compliance evidence' },
  { value: 'tickets', label: 'Ticket comments' },
  { value: 'cases', label: 'Case / incident notes' },
];

const inputCls = 'w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100';

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
    case 'new':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'investigating':
    case 'in-progress':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'resolved':
    case 'closed':
    case 'active':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'inactive':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    case 'false_positive':
      return 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

const download = (name: string, content: string, type: string) => {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
};

// Split a patterns form into built-in names plus one regex per line.
const patternsFromForm = (fd: FormData): string[] => {
  const builtins = fd.getAll('builtin').map(String);
  const custom = String(fd.get('custom_patterns') || '')
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);
  return [...builtins, ...custom];
};

function PolicyPatternFields({ policy }: { policy?: Row | null }) {
  const current: string[] = Array.isArray(policy?.data_patterns) ? policy.data_patterns : [];
  const channels: string[] = Array.isArray(policy?.channels_monitored) ? policy.channels_monitored : [];
  const custom = current.filter((p) => !BUILTIN_PATTERNS.includes(p));
  return (
    <>
      <div>
        <label className="block text-sm font-medium mb-1">Detectors</label>
        <div className="grid grid-cols-2 gap-1 text-sm">
          {BUILTIN_PATTERNS.map((p) => (
            <label key={p} className="flex items-center gap-1">
              <input type="checkbox" name="builtin" value={p} defaultChecked={current.includes(p)} /> {p.replace(/_/g, ' ')}
            </label>
          ))}
        </div>
      </div>
      <div>
        <label className="block text-sm font-medium mb-1">Custom regexes (one per line)</label>
        <textarea name="custom_patterns" rows={2} defaultValue={custom.join('\n')} className={clsx(inputCls, 'font-mono text-xs')} placeholder="e.g. PRJ-[0-9]{6}" />
      </div>
      <div>
        <label className="block text-sm font-medium mb-1">Data to scan (none ticked = all)</label>
        <div className="grid grid-cols-2 gap-1 text-sm">
          {SCANNED_CHANNELS.map((c) => (
            <label key={c.value} className="flex items-center gap-1">
              <input type="checkbox" name="channel" value={c.value} defaultChecked={channels.includes(c.value)} /> {c.label}
            </label>
          ))}
        </div>
        <p className="text-xs text-gray-500 mt-1">Email, web and USB channels have no data source in PySOAR and are not scanned.</p>
      </div>
    </>
  );
}

export default function DLPDashboard() {
  const [activeTab, setActiveTab] = useState('policies');
  const [policies, setPolicies] = useState<Row[]>([]);
  const [incidents, setIncidents] = useState<Row[]>([]);
  const [classifications, setClassifications] = useState<Row[]>([]);
  const [findings, setFindings] = useState<Row[]>([]);
  const [scanStatus, setScanStatus] = useState<Row | null>(null);
  const [scanResult, setScanResult] = useState<Row | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadErrors, setLoadErrors] = useState<Record<string, unknown>>({});
  const [actionError, setActionError] = useState<{ what: string; error: unknown } | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [findingSource, setFindingSource] = useState('');
  const [showNewPolicyModal, setShowNewPolicyModal] = useState(false);
  const [selectedPolicy, setSelectedPolicy] = useState<Row | null>(null);
  const [editingPolicy, setEditingPolicy] = useState<Row | null>(null);
  const [testingPolicy, setTestingPolicy] = useState<Row | null>(null);
  const [testSampleText, setTestSampleText] = useState('');
  const [testResult, setTestResult] = useState<Row | null>(null);
  const [testError, setTestError] = useState<unknown>(null);
  const [selectedIncident, setSelectedIncident] = useState<Row | null>(null);
  const [incidentStatusUpdate, setIncidentStatusUpdate] = useState<string>('');
  const [incidentNotes, setIncidentNotes] = useState<string>('');
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const refreshPolicies = async () => {
    const policiesData = await dlpApi.getPolicies();
    setPolicies(Array.isArray(policiesData) ? (policiesData as Row[]) : []);
  };

  const loadFindings = async (source: string) => {
    try {
      const res = await api.get('/dlp/violations', {
        params: { size: 100, detected_by: 'content_scan', source_type: source || undefined },
      });
      setFindings(Array.isArray(res.data) ? res.data : (res.data?.items ?? []));
      setLoadErrors((prev) => ({ ...prev, findings: undefined }));
    } catch (err) {
      setLoadErrors((prev) => ({ ...prev, findings: err }));
    }
  };

  const loadData = async () => {
    setLoading(true);
    try {
      const results = await Promise.allSettled([
        dlpApi.getPolicies(),
        dlpApi.getIncidents(),
        dlpApi.getClassifications(),
        api.get('/dlp/scan/status').then((r) => r.data),
      ]);
      const keys = ['policies', 'incidents', 'classifications', 'scan'];
      const errs: Record<string, unknown> = {};
      results.forEach((r, i) => { if (r.status === 'rejected') errs[keys[i]] = r.reason; });
      setLoadErrors(errs);
      const value = (i: number) => (results[i].status === 'fulfilled' ? (results[i] as PromiseFulfilledResult<unknown>).value : null);
      const asRows = (v: unknown): Row[] => (Array.isArray(v) ? (v as Row[]) : ((v as Row | null)?.items ?? []));
      setPolicies(asRows(value(0)));
      setIncidents(asRows(value(1)));
      setClassifications(asRows(value(2)));
      setScanStatus((value(3) as Row | null) ?? null);
    } finally {
      setLoading(false);
    }
    loadFindings(findingSource);
  };

  React.useEffect(() => {
    loadData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const runAction = async (key: string, what: string, fn: () => Promise<string | void>) => {
    setActionBusy(key);
    setActionError(null);
    try {
      const msg = await fn();
      if (msg) setActionMessage(msg);
    } catch (error) {
      setActionError({ what, error });
    } finally {
      setActionBusy(null);
    }
  };

  const runScan = (rescan: boolean) => runAction('scan', 'run the DLP content scan', async () => {
    setScanResult(null);
    const res = await api.post('/dlp/scan/run', null, { params: { rescan } });
    setScanResult(res.data);
    await loadData();
  });

  const runTestPolicy = async () => {
    if (!testingPolicy) return;
    if (!testSampleText.trim()) return;
    setActionBusy(`test-${testingPolicy.id}`);
    setTestError(null);
    try {
      const response = await api.post(`/dlp/policies/${testingPolicy.id}/test`, { sample_text: testSampleText });
      setTestResult(response.data);
    } catch (err: unknown) {
      setTestError(err);
    } finally {
      setActionBusy(null);
    }
  };

  const activePolicies = policies.filter((p) => p.enabled !== false).length;
  const evaluatedPolicies = policies.filter((p) => p.evaluation_status === 'active').length;
  const openIncidents = incidents.filter((i) => i.status === 'open' || i.status === 'investigating').length;
  const openFindings = findings.filter((f) => f.status !== 'resolved' && f.status !== 'false_positive').length;

  const tabs = [
    { id: 'policies', label: 'Policies', icon: Shield },
    { id: 'scanning', label: 'Content Scanning', icon: ScanLine },
    { id: 'incidents', label: 'Incidents', icon: FileWarning },
    { id: 'classifications', label: 'Classifications', icon: Lock },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  const q = searchQuery.toLowerCase();
  const filteredPolicies = policies.filter((p) =>
    (p.name || '').toLowerCase().includes(q) || (p.description || '').toLowerCase().includes(q)
  );
  const filteredIncidents = incidents.filter((i) =>
    (i.incident_title || '').toLowerCase().includes(q) ||
    (i.description || '').toLowerCase().includes(q) ||
    (i.data_types_involved ?? []).join(' ').toLowerCase().includes(q)
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
              onClick={() => runScan(false)}
              disabled={actionBusy !== null}
              title="Evaluate the active policies over new stored rows now (admin); the sweep also runs every 15 minutes"
              className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50"
            >
              <RefreshCw className={clsx('w-4 h-4', actionBusy === 'scan' && 'animate-spin')} />
              Run Content Scan
            </button>
            <button
              onClick={() => { setActionError(null); setShowNewPolicyModal(true); }}
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
            <p className="text-sm font-medium text-indigo-600 dark:text-indigo-300">Enabled Policies</p>
            <p className="text-3xl font-bold text-indigo-900 dark:text-indigo-100 mt-2">{loadErrors.policies ? NA : activePolicies}</p>
            <p className="text-xs text-indigo-600 dark:text-indigo-300 mt-1">{evaluatedPolicies} evaluated by the content scanner</p>
          </div>
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Open Incidents</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{loadErrors.incidents ? NA : openIncidents}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">open or investigating</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Scanner Findings (listed)</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{loadErrors.findings ? NA : openFindings}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">open findings from stored data</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Data Classifications</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{loadErrors.classifications ? NA : classifications.length}</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">classification records</p>
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
      <div className="p-6 space-y-4">
        {actionError && !showNewPolicyModal && !editingPolicy && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
        {scanResult && (
          <div className="text-sm bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 rounded p-3 space-y-1">
            <div className="flex justify-between gap-4">
              <span>
                Content scan: {scanResult.rows_scanned ?? 0} row(s) scanned, {scanResult.findings_created ?? 0} finding(s) created;{' '}
                {scanResult.policies_active ?? 0} policy(ies) evaluated, {scanResult.policies_inactive ?? 0} inactive.
              </span>
              <button onClick={() => setScanResult(null)} className="text-xs underline">dismiss</button>
            </div>
            {Object.entries((scanResult.sources ?? {}) as Record<string, Row>).map(([k, s]) => (
              <p key={k} className="text-xs">{k}: {s.rows_scanned ?? 0} rows, {s.findings_created ?? 0} findings{s.error ? ` · error: ${s.error}` : ''}</p>
            ))}
            {(scanResult.inactive_policies ?? []).map((p: Row) => (
              <p key={p.policy_id} className="text-xs text-orange-700 dark:text-orange-300">Inactive: {p.name} ({p.reason})</p>
            ))}
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center h-64">
            <p className="text-gray-500 dark:text-gray-400">Loading DLP data...</p>
          </div>
        ) : (
          <>
            {/* Policies Tab */}
            {activeTab === 'policies' && (
              <div className="space-y-6">
                <LoadErrorBanner what="DLP policies" error={loadErrors.policies} />
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

                {!loadErrors.policies && filteredPolicies.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Shield className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No DLP policies found</p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-x-auto border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold">Policy Name</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Evaluation</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Severity</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Patterns</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Matches</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPolicies.map((policy) => (
                          <tr key={policy.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4">
                              <p className="text-sm font-medium">{policy.name}</p>
                              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{policy.description || 'No description'}</p>
                            </td>
                            <td className="px-6 py-4">
                              {policy.enabled !== false ? (
                                <span className="flex items-center gap-1 text-green-600 dark:text-green-400 text-sm"><CheckCircle className="w-4 h-4" />Enabled</span>
                              ) : (
                                <span className="flex items-center gap-1 text-gray-500 dark:text-gray-400 text-sm"><XCircle className="w-4 h-4" />Disabled</span>
                              )}
                            </td>
                            <td className="px-6 py-4 text-xs max-w-xs">
                              <span className={clsx('px-2 py-0.5 rounded-full', getStatusColor(policy.evaluation_status || 'inactive'))}>
                                {policy.evaluation_status || 'not evaluated'}
                              </span>
                              {policy.evaluation_reason && <div className="text-gray-500 mt-1">{policy.evaluation_reason}</div>}
                              {policy.last_evaluated_at && <div className="text-gray-400 mt-0.5">last {new Date(policy.last_evaluated_at).toLocaleString()}</div>}
                            </td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(policy.severity || 'medium')}`}>
                                {(policy.severity || 'medium').toUpperCase()}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-xs">
                              {Array.isArray(policy.data_patterns) && policy.data_patterns.length > 0
                                ? policy.data_patterns.join(', ')
                                : <span className="text-orange-600">none (matches nothing)</span>}
                            </td>
                            <td className="px-6 py-4 text-sm font-semibold">{policy.trigger_count ?? NA}</td>
                            <td className="px-6 py-4 text-sm">
                              <div className="flex gap-2 items-center">
                                <button onClick={() => setSelectedPolicy(policy)} title="View details" className="text-blue-600 dark:text-blue-400"><Eye className="w-4 h-4" /></button>
                                <button onClick={() => { setActionError(null); setEditingPolicy(policy); }} title="Edit policy" className="text-gray-600 dark:text-gray-400"><Edit className="w-4 h-4" /></button>
                                {policy.enabled !== false ? (
                                  <button
                                    onClick={() => runAction(`disable-${policy.id}`, 'disable the policy', async () => { await dlpApi.disablePolicy(policy.id); await refreshPolicies(); return 'Policy disabled'; })}
                                    disabled={actionBusy !== null}
                                    title="Disable policy"
                                    className="text-yellow-600 dark:text-yellow-400 disabled:opacity-50"
                                  >
                                    <Pause className="w-4 h-4" />
                                  </button>
                                ) : (
                                  <button
                                    onClick={() => runAction(`enable-${policy.id}`, 'enable the policy', async () => { await dlpApi.enablePolicy(policy.id); await refreshPolicies(); return 'Policy enabled'; })}
                                    disabled={actionBusy !== null}
                                    title="Enable policy"
                                    className="text-green-600 dark:text-green-400 disabled:opacity-50"
                                  >
                                    <Play className="w-4 h-4" />
                                  </button>
                                )}
                                <button
                                  onClick={() => { setTestingPolicy(policy); setTestSampleText(''); setTestResult(null); setTestError(null); }}
                                  title="Test this policy's patterns on sample text"
                                  className="text-indigo-600 dark:text-indigo-400"
                                >
                                  <Zap className="w-4 h-4" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* Content Scanning Tab */}
            {activeTab === 'scanning' && (
              <div className="space-y-6">
                <LoadErrorBanner what="the content scan status" error={loadErrors.scan} />
                {scanStatus && (
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 space-y-3">
                    <div className="flex flex-wrap justify-between gap-2">
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        Up to {scanStatus.max_rows_per_source_per_run} rows per source per run; first run looks back {scanStatus.initial_lookback_days} day(s).
                      </p>
                      <button
                        onClick={() => runScan(true)}
                        disabled={actionBusy !== null}
                        title="Rewind every source and scan the lookback window again (admin)"
                        className="px-3 py-1.5 text-xs border border-gray-300 dark:border-gray-600 rounded disabled:opacity-50"
                      >
                        Rescan From Start
                      </button>
                    </div>
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left border-b border-gray-200 dark:border-gray-700">
                          <th className="py-2">Source</th>
                          <th className="py-2">Policies covering</th>
                          <th className="py-2">Last run</th>
                          <th className="py-2">Rows scanned (total)</th>
                          <th className="py-2">Findings (total)</th>
                          <th className="py-2">Last error</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(scanStatus.sources ?? []).map((s: Row) => (
                          <tr key={s.source_type} className="border-b border-gray-100 dark:border-gray-700">
                            <td className="py-2">{s.label}</td>
                            <td className="py-2">{s.policies_covering}</td>
                            <td className="py-2 text-xs">{s.last_run_at ? `${new Date(s.last_run_at).toLocaleString()} (${s.last_run_rows} rows, ${s.last_run_findings} findings)` : 'never'}</td>
                            <td className="py-2">{s.rows_scanned_total}</td>
                            <td className="py-2">{s.findings_total}</td>
                            <td className="py-2 text-xs text-red-600">{s.last_error || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                <div className="flex items-center gap-2">
                  <h3 className="font-semibold">Scanner findings</h3>
                  <select
                    value={findingSource}
                    onChange={(e) => { setFindingSource(e.target.value); loadFindings(e.target.value); }}
                    aria-label="Source"
                    className="px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700"
                  >
                    <option value="">All sources</option>
                    {(scanStatus?.sources ?? []).map((s: Row) => <option key={s.source_type} value={s.source_type}>{s.label}</option>)}
                  </select>
                </div>
                <LoadErrorBanner what="scanner findings" error={loadErrors.findings} />
                {!loadErrors.findings && findings.length === 0 ? (
                  <p className="text-sm text-gray-500 text-center py-8 border border-dashed border-gray-300 dark:border-gray-700 rounded-lg">
                    No finding from the content scanner{findingSource ? ' for this source' : ''}.
                  </p>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-x-auto border border-gray-200 dark:border-gray-700">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left border-b border-gray-200 dark:border-gray-700">
                          <th className="px-4 py-2">Severity</th>
                          <th className="px-4 py-2">Data types</th>
                          <th className="px-4 py-2">Location</th>
                          <th className="px-4 py-2">Excerpt (redacted)</th>
                          <th className="px-4 py-2">Status</th>
                          <th className="px-4 py-2">Found</th>
                        </tr>
                      </thead>
                      <tbody>
                        {findings.map((f) => (
                          <tr key={f.id} className="border-b border-gray-100 dark:border-gray-700">
                            <td className="px-4 py-2"><span className={`px-2 py-0.5 rounded-full text-xs ${getSeverityColor(f.severity)}`}>{f.severity}</span></td>
                            <td className="px-4 py-2 text-xs">{(f.sensitive_data_types ?? []).join(', ') || '—'}</td>
                            <td className="px-4 py-2 text-xs">{f.location || `${f.source_type}:${f.source_id}`}</td>
                            <td className="px-4 py-2 text-xs font-mono max-w-xs truncate" title={f.redacted_excerpt ?? ''}>{f.redacted_excerpt || '—'}</td>
                            <td className="px-4 py-2"><span className={`px-2 py-0.5 rounded-full text-xs ${getStatusColor(f.status)}`}>{f.status}</span></td>
                            <td className="px-4 py-2 text-xs">{f.created_at ? new Date(f.created_at).toLocaleString() : '—'}</td>
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
                <LoadErrorBanner what="DLP incidents" error={loadErrors.incidents} />
                <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                  <h3 className="font-semibold mb-3">Incident Severity Breakdown <span className="text-xs font-normal text-gray-500">(listed incidents)</span></h3>
                  <div className="grid grid-cols-4 gap-2 text-sm">
                    {['critical', 'high', 'medium', 'low'].map((s) => (
                      <div key={s} className="flex justify-between"><span className="capitalize">{s}</span><span className="font-semibold">{incidents.filter((i) => i.severity === s).length}</span></div>
                    ))}
                  </div>
                </div>

                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search incidents by title, description or data type..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                  />
                </div>

                {!loadErrors.incidents && filteredIncidents.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <FileWarning className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No DLP incidents found</p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-x-auto border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold">Title</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Data types</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Severity</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Date</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredIncidents.map((incident) => (
                          <tr key={incident.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm">
                              <div className="font-medium">{incident.incident_title || incident.id}</div>
                              <div className="text-xs text-gray-500">{incident.description || ''}</div>
                            </td>
                            <td className="px-6 py-4 text-sm">{(incident.data_types_involved ?? []).join(', ') || '—'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(incident.severity || '')}`}>
                                {(incident.severity || 'unrated').toUpperCase()}
                              </span>
                            </td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(incident.status || '')}`}>
                                {incident.status || '—'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {incident.created_at ? new Date(incident.created_at).toLocaleDateString() : '—'}
                            </td>
                            <td className="px-6 py-4 text-sm">
                              <button onClick={() => { setSelectedIncident(incident); setIncidentNotes(incident.resolution_notes ?? ''); }} className="text-blue-600 dark:text-blue-400"><Eye className="w-4 h-4" /></button>
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
                <LoadErrorBanner what="data classifications" error={loadErrors.classifications} />
                {!loadErrors.classifications && classifications.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Lock className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No data classifications defined</p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {classifications.map((c, index) => (
                      <div key={String(c.id ?? index)} className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                        <div className="flex items-center gap-3 mb-2">
                          <Lock className="w-5 h-5 text-indigo-600 dark:text-indigo-400" />
                          <h3 className="font-semibold text-lg">{c.name ?? c.id ?? 'Unnamed'}</h3>
                          {(c.sensitivity ?? c.level) && <span className="ml-auto text-xs uppercase text-gray-500">{c.sensitivity ?? c.level}</span>}
                        </div>
                        {c.description && <p className="text-sm text-gray-600 dark:text-gray-400">{c.description}</p>}
                        <p className="text-xs text-gray-500 mt-2">Policies and incidents carry no classification link, so usage counts are not available.</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Reports Tab */}
            {activeTab === 'reports' && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <Activity className="w-6 h-6 text-indigo-600" />
                    <h3 className="font-semibold text-lg">Incidents (listed)</h3>
                  </div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between"><span>Total</span><span className="font-bold">{incidents.length}</span></div>
                    <div className="flex justify-between"><span>Open</span><span className="font-semibold text-red-600">{incidents.filter((i) => i.status === 'open').length}</span></div>
                    <div className="flex justify-between"><span>Resolved</span><span className="font-semibold text-green-600">{incidents.filter((i) => i.status === 'resolved' || i.status === 'closed').length}</span></div>
                  </div>
                </div>
                <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <Download className="w-6 h-6 text-green-600" />
                    <h3 className="font-semibold text-lg">Export</h3>
                  </div>
                  <div className="space-y-3">
                    <button
                      onClick={() => download('dlp-summary.json', JSON.stringify({ policies, incidents, findings, scan_status: scanStatus }, null, 2), 'application/json')}
                      className="w-full px-4 py-2 text-sm text-left border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                    >
                      DLP Summary (JSON)
                    </button>
                    <button
                      onClick={() => {
                        const esc = (v: unknown) => {
                          let s = String(v ?? '');
                          if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
                          return `"${s.replace(/"/g, '""')}"`;
                        };
                        const headers = ['ID', 'Title', 'Data types', 'Severity', 'Status', 'Created'];
                        const rows = incidents.map((i) => [i.id, i.incident_title, (i.data_types_involved ?? []).join(' '), i.severity, i.status, i.created_at].map(esc).join(','));
                        download('dlp-incidents.csv', [headers.join(','), ...rows].join('\n'), 'text/csv');
                      }}
                      className="w-full px-4 py-2 text-sm text-left border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                    >
                      Incident Details (CSV)
                    </button>
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
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[520px] max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">{selectedPolicy.name}</h2>
            <div className="space-y-2 text-sm">
              <p>{selectedPolicy.description || 'No description'}</p>
              <p>Patterns: {(selectedPolicy.data_patterns ?? []).join(', ') || 'none'}</p>
              <p>Data scanned: {(selectedPolicy.channels_monitored ?? []).join(', ') || 'all sources'}</p>
              <p>Evaluation: {selectedPolicy.evaluation_status || 'not evaluated'}{selectedPolicy.evaluation_reason ? ` (${selectedPolicy.evaluation_reason})` : ''}</p>
              <p>Matches: {selectedPolicy.trigger_count ?? NA} · last {selectedPolicy.last_triggered ? new Date(selectedPolicy.last_triggered).toLocaleString() : 'never'}</p>
            </div>
            <button onClick={() => setSelectedPolicy(null)} className="mt-6 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Close</button>
          </div>
        </div>
      )}

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setSelectedIncident(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[520px] max-h-screen overflow-y-auto space-y-3" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold">{selectedIncident.incident_title || 'Incident'}</h2>
            <p className="text-sm">{selectedIncident.description}</p>
            <p className="text-sm">Status: {selectedIncident.status} · Severity: {selectedIncident.severity}</p>
            {selectedIncident.resolution_notes && <p className="text-sm">Resolution notes: {selectedIncident.resolution_notes}</p>}
            {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
            <select value={incidentStatusUpdate} onChange={(e) => setIncidentStatusUpdate(e.target.value)} className={inputCls}>
              <option value="">— No status change —</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
              <option value="false_positive">False Positive</option>
            </select>
            <textarea value={incidentNotes} onChange={(e) => setIncidentNotes(e.target.value)} rows={2} className={inputCls} placeholder="Resolution notes" />
            <div className="flex gap-2 justify-end">
              <button onClick={() => { setSelectedIncident(null); setIncidentStatusUpdate(''); setIncidentNotes(''); }} className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Close</button>
              <button
                disabled={actionBusy !== null || (!incidentStatusUpdate && incidentNotes === (selectedIncident.resolution_notes ?? ''))}
                onClick={() => {
                  const target = selectedIncident;
                  runAction(`incident-${target.id}`, 'update the incident', async () => {
                    const payload: Record<string, string> = {};
                    if (incidentStatusUpdate) payload.status = incidentStatusUpdate;
                    if (incidentNotes) payload.resolution_notes = incidentNotes;
                    await dlpApi.updateIncident(target.id, payload);
                    const data = await dlpApi.getIncidents();
                    setIncidents(Array.isArray(data) ? (data as Row[]) : []);
                    setSelectedIncident(null);
                    setIncidentStatusUpdate('');
                    setIncidentNotes('');
                    return 'Incident updated';
                  });
                }}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg disabled:opacity-50"
              >
                Update Incident
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Policy Modal */}
      {editingPolicy && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setEditingPolicy(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[520px] max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Edit DLP Policy</h2>
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                const target = editingPolicy;
                runAction(`edit-${target.id}`, 'update the policy', async () => {
                  await api.patch(`/dlp/policies/${target.id}`, {
                    name: fd.get('name'),
                    description: fd.get('description') || undefined,
                    severity: fd.get('severity'),
                    enabled: fd.get('enabled') === 'on',
                    data_patterns: patternsFromForm(fd),
                    channels_monitored: fd.getAll('channel').map(String),
                  });
                  await refreshPolicies();
                  setEditingPolicy(null);
                  return 'Policy updated';
                });
              }}
            >
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              <input name="name" required defaultValue={editingPolicy.name} className={inputCls} />
              <textarea name="description" rows={2} defaultValue={editingPolicy.description ?? ''} className={inputCls} />
              <select name="severity" defaultValue={editingPolicy.severity || 'medium'} className={inputCls}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
              <PolicyPatternFields policy={editingPolicy} />
              <label className="flex items-center gap-2 text-sm"><input name="enabled" type="checkbox" defaultChecked={editingPolicy.enabled !== false} /> Enabled</label>
              <div className="flex gap-2">
                <button type="button" onClick={() => setEditingPolicy(null)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
                <button type="submit" disabled={actionBusy !== null} className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg disabled:opacity-50">Save</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Test Policy Modal */}
      {testingPolicy && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setTestingPolicy(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[560px] max-h-screen overflow-y-auto space-y-3" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold">Test Policy: {testingPolicy.name}</h2>
            <p className="text-xs text-gray-500">Evaluates this policy&apos;s own patterns ({(testingPolicy.data_patterns ?? []).join(', ') || 'none configured'}) on the sample; nothing is stored.</p>
            <textarea value={testSampleText} onChange={(e) => setTestSampleText(e.target.value)} rows={5} placeholder="Paste content to evaluate." className={clsx(inputCls, 'font-mono text-sm')} />
            <ActionErrorBanner what="test the policy" error={testError} />
            {testResult && (
              <div className="text-sm space-y-1 bg-gray-50 dark:bg-gray-900 rounded p-3">
                <p className="font-medium">
                  {testResult.sample_result?.has_violations ? `${testResult.violations_detected} match(es)` : 'No match'} · {testResult.sample_result?.patterns_evaluated ?? 0} pattern(s) evaluated
                </p>
                {(testResult.matched_patterns ?? []).length > 0 && <p>Matched: {testResult.matched_patterns.join(', ')}</p>}
                {testResult.redacted_excerpt && <p className="font-mono text-xs">{testResult.redacted_excerpt}</p>}
                <p className="text-xs text-gray-500">
                  Content scanning for this policy: {testResult.evaluation_status || 'not evaluated'}{testResult.evaluation_reason ? ` (${testResult.evaluation_reason})` : ''}
                </p>
              </div>
            )}
            <div className="flex gap-2 justify-end">
              <button onClick={() => setTestingPolicy(null)} className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Close</button>
              <button onClick={runTestPolicy} disabled={actionBusy !== null || !testSampleText.trim()} className="px-4 py-2 bg-indigo-600 text-white rounded-lg disabled:opacity-50">Run Test</button>
            </div>
          </div>
        </div>
      )}

      {/* New Policy Modal */}
      {showNewPolicyModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setShowNewPolicyModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[520px] max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Create DLP Policy</h2>
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                runAction('create', 'create the policy', async () => {
                  await api.post('/dlp/policies', {
                    name: String(fd.get('name') || '').trim(),
                    description: fd.get('description') || undefined,
                    severity: fd.get('severity') || 'medium',
                    enabled: true,
                    data_patterns: patternsFromForm(fd),
                    channels_monitored: fd.getAll('channel').map(String),
                  });
                  await refreshPolicies();
                  setShowNewPolicyModal(false);
                  return 'Policy created';
                });
              }}
            >
              {actionError && <ActionErrorBanner what={actionError.what} error={actionError.error} />}
              <input type="text" name="name" required placeholder="e.g., PII Protection Policy" className={inputCls} />
              <textarea name="description" placeholder="Describe the policy purpose..." rows={2} className={inputCls} />
              <select name="severity" defaultValue="medium" className={inputCls}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
              <PolicyPatternFields />
              <div className="flex gap-2">
                <button type="button" onClick={() => setShowNewPolicyModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg">Cancel</button>
                <button type="submit" disabled={actionBusy !== null} className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg disabled:opacity-50">Create</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Action Toast */}
      {actionMessage && (
        <div className="fixed bottom-4 right-4 bg-green-600 text-white px-4 py-2 rounded-lg shadow-lg flex items-center gap-2 z-50">
          <CheckCircle className="w-4 h-4" />
          <span className="text-sm">{actionMessage}</span>
          <button onClick={() => setActionMessage(null)} className="ml-2 text-white/80 hover:text-white" aria-label="Dismiss">
            <XCircle className="w-4 h-4" />
          </button>
        </div>
      )}
    </div>
  );
}
