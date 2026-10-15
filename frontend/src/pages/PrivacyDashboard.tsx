import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  UserCheck,
  FileText,
  Scale,
  Clock,
  AlertTriangle,
  Plus,
  X,
  Search,
  Shield,
  BookOpen,
} from 'lucide-react';
import { api } from '../lib/api';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import type { Row } from '../lib/apiRow';

const NA = 'not available';

function downloadBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

// One data subject request and its workflow: verify identity -> search the
// systems that hold personal data -> export (access / portability) or erase
// (erasure) -> close. Every step is a server call; refusals show the
// server's reason.
function DSRDetail({ dsr, sources, onClose, onChanged }: { dsr: Row; sources: Row[]; onClose: () => void; onChanged: (updated?: Row) => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<{ what: string; error: unknown } | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [method, setMethod] = useState('government_id');
  const [evidence, setEvidence] = useState('');
  const [pickedSources, setPickedSources] = useState<string[]>([]);
  const [nextStatus, setNextStatus] = useState('');
  const [denialReason, setDenialReason] = useState('');
  const [notes, setNotes] = useState('');
  const isExport = dsr.request_type === 'access' || dsr.request_type === 'portability';
  const isErasure = dsr.request_type === 'erasure';

  const step = async (key: string, what: string, fn: () => Promise<string | void>) => {
    setBusy(key);
    setError(null);
    setNotice(null);
    try {
      const msg = await fn();
      if (msg) setNotice(msg);
    } catch (err) {
      setError({ what, error: err });
    } finally {
      setBusy(null);
    }
  };

  const dataFound = (dsr.data_found?.sources ?? {}) as Record<string, Row>;
  const erasureSources = (dsr.erasure_log?.sources ?? {}) as Record<string, Row>;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white rounded-lg p-6 max-w-2xl w-full shadow-xl max-h-[90vh] overflow-y-auto space-y-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-lg font-bold text-gray-900">{dsr.request_type} request · {dsr.subject_name}</h2>
            <p className="text-sm text-gray-500">{dsr.subject_email} · {String(dsr.regulation || '').toUpperCase()}</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
        </div>
        <div className="grid grid-cols-2 gap-2 text-sm">
          <p>Status: <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusBadgeClass(dsr.status || '')}`}>{dsr.status}</span></p>
          <p>Deadline: {dsr.deadline ? String(dsr.deadline).slice(0, 10) : NA}
            {dsr.overdue ? <span className="text-red-600 font-medium"> (overdue)</span> : dsr.days_remaining != null ? ` (${dsr.days_remaining} day(s) left)` : ''}</p>
          <p>Identity: {dsr.identity_verified_at ? `verified ${String(dsr.identity_verified_at).slice(0, 10)} (${dsr.identity_verification_method})` : 'not verified'}</p>
          <p>Searched: {dsr.searched_at ? String(dsr.searched_at).slice(0, 16).replace('T', ' ') : 'not yet'}</p>
          {dsr.exported_at && <p className="col-span-2">Exported {String(dsr.exported_at).slice(0, 10)}: {dsr.export_record_count} record(s), sha256 <span className="font-mono text-xs">{dsr.export_sha256}</span></p>}
          {dsr.processing_notes && <p className="col-span-2">Notes: {dsr.processing_notes}</p>}
          {dsr.denial_reason && <p className="col-span-2 text-red-700">Denied: {dsr.denial_reason}</p>}
        </div>

        {error && <ActionErrorBanner what={error.what} error={error.error} />}
        {notice && <p className="text-sm bg-blue-50 border border-blue-200 rounded p-2">{notice}</p>}

        {dsr.status === 'received' && (
          <div className="border rounded p-3 space-y-2">
            <h3 className="text-sm font-semibold">1. Verify identity</h3>
            <div className="grid grid-cols-2 gap-2">
              <select value={method} onChange={(e) => setMethod(e.target.value)} className="border border-gray-300 rounded px-2 py-1 text-sm">
                <option value="government_id">Government ID</option>
                <option value="email_confirmation">E-mail confirmation</option>
                <option value="account_login">Authenticated account</option>
                <option value="knowledge_based">Knowledge-based questions</option>
                <option value="other">Other</option>
              </select>
              <input value={evidence} onChange={(e) => setEvidence(e.target.value)} placeholder="How it was verified (evidence reference)" className="border border-gray-300 rounded px-2 py-1 text-sm" />
            </div>
            <button
              disabled={busy !== null || evidence.trim().length < 3}
              onClick={() => step('verify', 'verify the identity', async () => {
                const res = await api.post(`/privacy/dsr/requests/${dsr.id}/verify-identity`, { verification_method: method, evidence });
                onChanged(res.data);
                return 'Identity verified.';
              })}
              className="px-3 py-1.5 text-sm bg-indigo-600 text-white rounded disabled:opacity-50"
            >
              Record Verification
            </button>
          </div>
        )}

        <div className="border rounded p-3 space-y-2">
          <h3 className="text-sm font-semibold">2. Search systems for the subject&apos;s data</h3>
          <div className="grid grid-cols-2 gap-1 text-xs">
            {sources.map((s) => (
              <label key={s.key} className="flex items-center gap-1" title={s.note ?? ''}>
                <input
                  type="checkbox"
                  checked={pickedSources.includes(s.key)}
                  onChange={(e) => setPickedSources((prev) => (e.target.checked ? [...prev, s.key] : prev.filter((k) => k !== s.key)))}
                />
                {s.label} <span className="text-gray-400">({s.erasure}{s.retain_reason ? `: ${s.retain_reason}` : ''})</span>
              </label>
            ))}
          </div>
          <p className="text-xs text-gray-500">None ticked = every source. Matching is on the subject&apos;s e-mail and identifier.</p>
          <button
            disabled={busy !== null}
            onClick={() => step('search', 'search the systems', async () => {
              const qs = new URLSearchParams();
              pickedSources.forEach((k) => qs.append('systems', k));
              // URLSearchParams keeps repeated keys (systems=a&systems=b), which the
              // FastAPI list query expects.
              const res = await api.post(`/privacy/dsr/requests/${dsr.id}/search-systems`, null, { params: qs });
              onChanged();
              return `${res.data?.total_records ?? 0} record(s) found across ${Object.keys(res.data?.sources ?? {}).length} source(s).`;
            })}
            className="px-3 py-1.5 text-sm border border-indigo-600 text-indigo-700 rounded disabled:opacity-50"
          >
            Search Systems
          </button>
          {Object.keys(dataFound).length > 0 && (
            <ul className="text-xs list-disc ml-5">
              {Object.entries(dataFound).map(([k, v]) => (
                <li key={k}>{v.label ?? k}: {v.records} record(s) · erasure: {v.erasure}</li>
              ))}
            </ul>
          )}
        </div>

        {isExport && (
          <div className="border rounded p-3 space-y-2">
            <h3 className="text-sm font-semibold">3. Export the subject&apos;s data</h3>
            <div className="flex gap-2">
              <button
                disabled={busy !== null}
                onClick={() => step('export-json', 'compile the export', async () => {
                  const res = await api.post(`/privacy/dsr/requests/${dsr.id}/compile-data`, null, { params: { format_type: 'json' } });
                  downloadBlob(new Blob([JSON.stringify(res.data?.package ?? res.data, null, 2)], { type: 'application/json' }), `dsr-${dsr.id}.json`);
                  onChanged();
                  return `Exported ${res.data?.record_count ?? 0} record(s); sha256 ${res.data?.sha256 ?? NA}.`;
                })}
                className="px-3 py-1.5 text-sm bg-indigo-600 text-white rounded disabled:opacity-50"
              >
                Download JSON
              </button>
              <button
                disabled={busy !== null}
                onClick={() => step('export-csv', 'compile the export', async () => {
                  const res = await api.post(`/privacy/dsr/requests/${dsr.id}/compile-data`, null, { params: { format_type: 'csv' }, responseType: 'blob' });
                  downloadBlob(res.data as Blob, `dsr-${dsr.id}.csv`);
                  onChanged();
                  const sha = res.headers?.['x-export-sha256'];
                  return `CSV exported${sha ? `; sha256 ${sha}` : ''}.`;
                })}
                className="px-3 py-1.5 text-sm border border-gray-300 rounded disabled:opacity-50"
              >
                Download CSV
              </button>
            </div>
          </div>
        )}

        {isErasure && (
          <div className="border border-red-200 rounded p-3 space-y-2">
            <h3 className="text-sm font-semibold text-red-700">3. Execute erasure (admin)</h3>
            <p className="text-xs text-gray-600">
              Anonymises, redacts or deletes the subject&apos;s rows per source; sources with a retention obligation are kept and listed with the reason.
            </p>
            <button
              disabled={busy !== null}
              onClick={() => {
                if (!window.confirm(`Erase the stored personal data of ${dsr.subject_email}? This cannot be undone.`)) return;
                step('erase', 'execute the erasure', async () => {
                  const res = await api.post(`/privacy/dsr/requests/${dsr.id}/execute-erasure`, { confirm: true });
                  onChanged(res.data);
                  return `Erasure ${res.data?.status}: ${res.data?.erasure_log?.records_processed ?? 0} record(s) processed, ${res.data?.erasure_log?.records_retained ?? 0} retained.`;
                });
              }}
              className="px-3 py-1.5 text-sm bg-red-600 text-white rounded disabled:opacity-50"
            >
              Execute Erasure
            </button>
            {Object.keys(erasureSources).length > 0 && (
              <ul className="text-xs list-disc ml-5">
                {Object.entries(erasureSources).map(([k, v]) => (
                  <li key={k}>{k}: {v.action} {v.records ?? 0}{v.remaining ? `, ${v.remaining} remaining` : ''}{v.reason ? ` (${v.reason})` : ''}{v.note ? ` · ${v.note}` : ''}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        <div className="border rounded p-3 space-y-2">
          <h3 className="text-sm font-semibold">Status</h3>
          <div className="grid grid-cols-2 gap-2">
            <select value={nextStatus} onChange={(e) => setNextStatus(e.target.value)} className="border border-gray-300 rounded px-2 py-1 text-sm">
              <option value="">— choose —</option>
              <option value="processing">processing</option>
              <option value="completed">completed</option>
              <option value="partially_complete">partially complete</option>
              <option value="denied">denied</option>
              <option value="appealed">appealed</option>
            </select>
            <input value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Processing notes (optional)" className="border border-gray-300 rounded px-2 py-1 text-sm" />
            {nextStatus === 'denied' && (
              <input value={denialReason} onChange={(e) => setDenialReason(e.target.value)} placeholder="Denial reason (required)" className="col-span-2 border border-gray-300 rounded px-2 py-1 text-sm" />
            )}
          </div>
          <p className="text-xs text-gray-500">The server enforces the workflow; erasure requests close only through Execute Erasure.</p>
          <button
            disabled={busy !== null || !nextStatus}
            onClick={() => step('status', `move the request to ${nextStatus}`, async () => {
              const res = await api.patch(`/privacy/dsr/requests/${dsr.id}`, {
                status: nextStatus,
                processing_notes: notes || undefined,
                denial_reason: nextStatus === 'denied' ? denialReason : undefined,
              });
              onChanged(res.data);
              return `Status set to ${res.data?.status ?? nextStatus}.`;
            })}
            className="px-3 py-1.5 text-sm border border-gray-300 rounded disabled:opacity-50"
          >
            Update Status
          </button>
        </div>
      </div>
    </div>
  );
}

// --- Helpers ---

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'completed':
    case 'approved':
    case 'resolved':
    case 'closed':
      return 'bg-green-100 text-green-800';
    case 'in_progress':
    case 'in_review':
    case 'processing':
    case 'partially_complete':
    case 'investigating':
    case 'contained':
      return 'bg-yellow-100 text-yellow-800';
    case 'denied':
    case 'rejected':
    case 'critical':
      return 'bg-red-100 text-red-800';
    case 'received':
    case 'draft':
    case 'reported':
      return 'bg-blue-100 text-blue-800';
    case 'identity_verified':
    case 'appealed':
      return 'bg-purple-100 text-purple-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
}

function riskBadgeClass(level: string): string {
  switch (level) {
    case 'critical':
      return 'bg-red-100 text-red-800';
    case 'high':
      return 'bg-orange-100 text-orange-800';
    case 'medium':
      return 'bg-yellow-100 text-yellow-800';
    case 'low':
      return 'bg-green-100 text-green-800';
    case 'negligible':
      return 'bg-gray-100 text-gray-600';
    case 'not_assessed':
      return 'bg-gray-50 text-gray-500 border border-dashed border-gray-300';
    default:
      return 'bg-gray-100 text-gray-800';
  }
}

function severityBadgeClass(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'bg-red-100 text-red-800';
    case 'high':
      return 'bg-orange-100 text-orange-800';
    case 'medium':
      return 'bg-yellow-100 text-yellow-800';
    case 'low':
      return 'bg-green-100 text-green-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
}

function extractItems(data: any): any[] {
  return data?.items || (Array.isArray(data) ? data : []);
}

// --- Component ---

export default function PrivacyDashboard() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'dsr' | 'pia' | 'consent' | 'ropa' | 'incidents'>('dsr');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [showCreateDSR, setShowCreateDSR] = useState(false);
  const [showCreatePIA, setShowCreatePIA] = useState(false);
  const [showCreateConsent, setShowCreateConsent] = useState(false);
  const [showCreateROPA, setShowCreateROPA] = useState(false);
  const [showCreateIncident, setShowCreateIncident] = useState(false);
  const [consentSubjectId, setConsentSubjectId] = useState('');
  const [openDsrId, setOpenDsrId] = useState<string | null>(null);
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [rowError, setRowError] = useState<{ what: string; error: unknown } | null>(null);
  const [incidentRegs, setIncidentRegs] = useState<string[]>([]);
  const [deadlines, setDeadlines] = useState<Record<string, Row>>({});

  // --- DSR Form State ---
  const [dsrForm, setDsrForm] = useState({
    request_type: 'access',
    regulation: 'gdpr',
    subject_name: '',
    subject_email: '',
    subject_identifier: '',
    description: '',
  });

  // --- PIA Form State ---
  // assessment_type must match backend PIAAssessmentType enum:
  //   'dpia' | 'pia' | 'tia' | 'legitimate_interest'
  const [piaForm, setPiaForm] = useState({
    name: '',
    project_name: '',
    assessment_type: 'pia',
    data_types_processed: '',
    processing_purposes: '',
    legal_basis: 'consent',
  });

  // --- Consent Form State ---
  const [consentForm, setConsentForm] = useState({
    subject_id: '',
    purpose: '',
    legal_basis: 'consent',
    consent_given: true,
    consent_mechanism: 'explicit_opt_in',
  });

  // --- ROPA Form State ---
  const [ropaForm, setRopaForm] = useState({
    name: '',
    purpose: '',
    legal_basis: 'consent',
    data_categories: '',
    data_subjects: '',
    recipients: '',
    retention_period_days: 365,
  });

  // --- Incident Form State ---
  const [incidentForm, setIncidentForm] = useState({
    title: '',
    description: '',
    incident_type: 'data_breach',
    severity: 'medium',
    data_types_affected: '',
    subjects_affected_count: 0,
  });

  // --- Queries ---

  const { data: statsData, error: statsError } = useQuery({
    queryKey: ['privacy-stats'],
    queryFn: async () => (await api.get('/privacy/dashboard/stats')).data,
  });

  const { data: dsrData, isLoading: dsrLoading, error: dsrError } = useQuery({
    queryKey: ['privacy-dsrs', overdueOnly],
    queryFn: async () => (await api.get('/privacy/dsr/requests', { params: { overdue: overdueOnly || undefined } })).data,
  });

  const { data: dsrSources } = useQuery<Row>({
    queryKey: ['privacy-dsr-sources'],
    queryFn: async () => (await api.get('/privacy/dsr/sources')).data,
  });

  const { data: deadlineAlerts, error: alertsError } = useQuery<Row[]>({
    queryKey: ['privacy-dsr-alerts'],
    queryFn: async () => (await api.get('/privacy/dsr/deadline-alerts')).data,
  });

  const { data: piaData, isLoading: piaLoading, error: piaError } = useQuery({
    queryKey: ['privacy-pias'],
    queryFn: async () => (await api.get('/privacy/pia/assessments')).data,
  });

  const { data: consentData, isLoading: consentLoading, error: consentError } = useQuery({
    queryKey: ['privacy-consent', consentSubjectId],
    queryFn: async () => {
      if (!consentSubjectId) return [];
      return (await api.get(`/privacy/consent/records/${consentSubjectId}`)).data;
    },
    enabled: activeTab === 'consent',
  });

  const { data: ropaData, isLoading: ropaLoading, error: ropaError } = useQuery({
    queryKey: ['privacy-ropa'],
    queryFn: async () => (await api.get('/privacy/ropa/processing-records')).data,
  });

  const { data: incidentData, isLoading: incidentLoading, error: incidentError } = useQuery({
    queryKey: ['privacy-incidents'],
    queryFn: async () => (await api.get('/privacy/incidents/reports')).data,
  });

  // --- Mutations ---

  const createDSR = useMutation({
    mutationFn: async (body: typeof dsrForm) => (await api.post('/privacy/dsr/requests', body)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-dsrs'] });
      queryClient.invalidateQueries({ queryKey: ['privacy-stats'] });
      setShowCreateDSR(false);
      setDsrForm({ request_type: 'access', regulation: 'gdpr', subject_name: '', subject_email: '', subject_identifier: '', description: '' });
    },
  });

  const createPIA = useMutation({
    mutationFn: async (body: any) => (await api.post('/privacy/pia/assessments', body)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-pias'] });
      setShowCreatePIA(false);
      setPiaForm({ name: '', project_name: '', assessment_type: 'pia', data_types_processed: '', processing_purposes: '', legal_basis: 'consent' });
    },
  });

  const createConsent = useMutation({
    mutationFn: async (body: typeof consentForm) => (await api.post('/privacy/consent/records', body)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-consent'] });
      setShowCreateConsent(false);
      setConsentForm({ subject_id: '', purpose: '', legal_basis: 'consent', consent_given: true, consent_mechanism: 'explicit_opt_in' });
    },
  });

  const createROPA = useMutation({
    mutationFn: async (body: any) => (await api.post('/privacy/ropa/processing-records', body)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-ropa'] });
      setShowCreateROPA(false);
      setRopaForm({ name: '', purpose: '', legal_basis: 'consent', data_categories: '', data_subjects: '', recipients: '', retention_period_days: 365 });
    },
  });

  const createIncident = useMutation({
    mutationFn: async (body: any) => (await api.post('/privacy/incidents/report', body)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-incidents'] });
      queryClient.invalidateQueries({ queryKey: ['privacy-stats'] });
      setShowCreateIncident(false);
      setIncidentForm({ title: '', description: '', incident_type: 'data_breach', severity: 'medium', data_types_affected: '', subjects_affected_count: 0 });
    },
  });

  // --- Derived Data ---

  const dsrs = extractItems(dsrData);
  const pias = extractItems(piaData);
  const consents = consentData?.items || (Array.isArray(consentData) ? consentData : []);
  const ropas = extractItems(ropaData);
  const incidents = extractItems(incidentData);

  const filteredDSRs = useMemo(() => {
    let items = dsrs;
    if (filterStatus !== 'all') items = items.filter((d: any) => d?.status === filterStatus);
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      items = items.filter((d: any) =>
        (d?.subject_name || '').toLowerCase().includes(term) ||
        (d?.subject_email || '').toLowerCase().includes(term) ||
        (d?.request_type || '').toLowerCase().includes(term)
      );
    }
    return items;
  }, [dsrs, filterStatus, searchTerm]);

  const filteredPIAs = useMemo(() => {
    if (!searchTerm) return pias;
    const term = searchTerm.toLowerCase();
    return pias.filter((p: any) =>
      (p?.name || '').toLowerCase().includes(term) ||
      (p?.project_name || '').toLowerCase().includes(term)
    );
  }, [pias, searchTerm]);

  const filteredIncidents = useMemo(() => {
    if (!searchTerm) return incidents;
    const term = searchTerm.toLowerCase();
    return incidents.filter((i: any) =>
      (i?.title || '').toLowerCase().includes(term) ||
      (i?.incident_type || '').toLowerCase().includes(term)
    );
  }, [incidents, searchTerm]);

  const openDsr = dsrs.find((d: Row) => d?.id === openDsrId) ?? null;
  const refreshPrivacy = () => {
    queryClient.invalidateQueries({ queryKey: ['privacy-dsrs'] });
    queryClient.invalidateQueries({ queryKey: ['privacy-stats'] });
    queryClient.invalidateQueries({ queryKey: ['privacy-dsr-alerts'] });
  };
  const rowAction = async (what: string, fn: () => Promise<void>) => {
    setRowError(null);
    try {
      await fn();
    } catch (error) {
      setRowError({ what, error });
    }
  };

  const tabs = [
    { id: 'dsr' as const, label: 'DSR Requests', icon: UserCheck },
    { id: 'pia' as const, label: 'PIAs', icon: FileText },
    { id: 'consent' as const, label: 'Consent Records', icon: Scale },
    { id: 'ropa' as const, label: 'Processing Records (ROPA)', icon: BookOpen },
    { id: 'incidents' as const, label: 'Privacy Incidents', icon: AlertTriangle },
  ];

  return (
    <div className="min-h-screen bg-gray-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-3">
            <Shield className="w-8 h-8 text-indigo-600" />
            Privacy Dashboard
          </h1>
          <p className="text-gray-500 mt-1">Data Subject Rights, PIAs, Consent, ROPA & Incident Management</p>
        </div>

        <div className="mb-4 space-y-2">
          <LoadErrorBanner what="privacy statistics" error={statsError} />
          <LoadErrorBanner what="DSR deadline alerts" error={alertsError} />
          {rowError && <ActionErrorBanner what={rowError.what} error={rowError.error} />}
          {(deadlineAlerts ?? []).length > 0 && (
            <div className="text-sm bg-red-50 border border-red-200 text-red-800 rounded p-3">
              <p className="font-medium">Open DSRs near or past their deadline</p>
              <ul className="list-disc ml-5">
                {(deadlineAlerts ?? []).map((a) => (
                  <li key={a.dsr_id}>
                    <button className="underline" onClick={() => { setActiveTab('dsr'); setOpenDsrId(a.dsr_id); }}>{a.subject}</button>: {a.status}
                    {a.days_overdue != null ? ` (${a.days_overdue} day(s) overdue)` : a.days_remaining != null ? ` (${a.days_remaining} day(s) left)` : ''}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg border border-gray-200 p-5">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm text-gray-500">Total DSRs</p>
                <p className="text-2xl font-bold text-gray-900 mt-1">{statsData?.total_dsrs ?? NA}</p>
                <p className="text-xs text-gray-400">{statsData?.closed_dsrs ?? NA} closed · {statsData?.overdue_dsrs ?? NA} overdue</p>
              </div>
              <UserCheck className="w-6 h-6 text-indigo-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-5">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm text-gray-500">Open DSRs</p>
                <p className="text-2xl font-bold text-yellow-600 mt-1">{statsData?.pending_dsrs ?? NA}</p>
              </div>
              <Clock className="w-6 h-6 text-yellow-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-5">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm text-gray-500">DSR Compliance Rate</p>
                <p className="text-2xl font-bold text-green-600 mt-1">
                  {statsData?.dsr_compliance_rate != null ? `${statsData.dsr_compliance_rate}%` : NA}
                </p>
                <p className="text-xs text-gray-400">
                  {statsData?.dsr_compliance_rate != null ? 'closed DSRs closed by their deadline' : 'no DSR has been closed yet'}
                </p>
              </div>
              <Scale className="w-6 h-6 text-green-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-5">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm text-gray-500">Active PIAs</p>
                <p className="text-2xl font-bold text-purple-600 mt-1">{statsData?.active_pias ?? NA}</p>
              </div>
              <FileText className="w-6 h-6 text-purple-500" />
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="mb-6 border-b border-gray-200">
          <div className="flex gap-6 overflow-x-auto">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => { setActiveTab(tab.id); setSearchTerm(''); setFilterStatus('all'); }}
                  className={`pb-3 px-2 text-sm font-medium flex items-center gap-2 border-b-2 whitespace-nowrap transition-colors ${
                    activeTab === tab.id
                      ? 'border-indigo-600 text-indigo-600'
                      : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {tab.label}
                </button>
              );
            })}
          </div>
        </div>

        {/* Search Bar */}
        <div className="mb-4 flex items-center gap-4">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
        </div>

        {/* DSR Tab */}
        {activeTab === 'dsr' && (
          <div>
            <div className="mb-4 flex justify-between items-center">
              <select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              >
                <option value="all">All Statuses</option>
                <option value="received">Received</option>
                <option value="identity_verified">Identity Verified</option>
                <option value="processing">Processing</option>
                <option value="partially_complete">Partially Complete</option>
                <option value="completed">Completed</option>
                <option value="denied">Denied</option>
                <option value="appealed">Appealed</option>
              </select>
              <label className="flex items-center gap-1 text-sm text-gray-600">
                <input type="checkbox" checked={overdueOnly} onChange={(e) => setOverdueOnly(e.target.checked)} /> Overdue only
              </label>
              <button
                onClick={() => setShowCreateDSR(true)}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm flex items-center gap-2"
              >
                <Plus className="w-4 h-4" /> New DSR
              </button>
            </div>
            <LoadErrorBanner what="DSR requests" error={dsrError} />
            {dsrLoading ? (
              <p className="text-gray-500 py-8 text-center">Loading...</p>
            ) : (
              <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">ID</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Type</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Regulation</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Subject</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Deadline</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredDSRs.map((row: any) => (
                      <tr key={row?.id} className="border-t border-gray-100 hover:bg-gray-50 cursor-pointer" onClick={() => setOpenDsrId(row?.id)}>
                        <td className="px-4 py-3 text-sm font-mono text-indigo-600 underline">{row?.id || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-900">{row?.request_type || ''}</td>
                        <td className="px-4 py-3 text-sm">
                          <span className="bg-gray-100 text-gray-700 px-2 py-0.5 rounded text-xs uppercase">
                            {row?.regulation || ''}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-700">
                          <div>{row?.subject_name || ''}</div>
                          <div className="text-xs text-gray-400">{row?.subject_email || ''}</div>
                        </td>
                        <td className="px-4 py-3 text-sm">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusBadgeClass(row?.status || '')}`}>
                            {row?.status || ''}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600">
                          {row?.deadline ? String(row.deadline).slice(0, 10) : NA}
                          {row?.overdue ? <div className="text-xs text-red-600">overdue</div> : row?.days_remaining != null ? <div className="text-xs text-gray-400">{row.days_remaining} day(s) left</div> : null}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-500">{row?.created_at?.slice(0, 10) || ''}</td>
                      </tr>
                    ))}
                    {filteredDSRs.length === 0 && (
                      <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-400">No DSR requests found.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* PIA Tab */}
        {activeTab === 'pia' && (
          <div>
            <div className="mb-4 flex justify-end">
              <button
                onClick={() => setShowCreatePIA(true)}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm flex items-center gap-2"
              >
                <Plus className="w-4 h-4" /> New PIA
              </button>
            </div>
            <LoadErrorBanner what="PIA assessments" error={piaError} />
            {piaLoading ? (
              <p className="text-gray-500 py-8 text-center">Loading...</p>
            ) : (
              <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Name</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Project</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Type</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Risk Level</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredPIAs.map((pia: any) => (
                      <tr key={pia?.id} className="border-t border-gray-100 hover:bg-gray-50">
                        <td className="px-4 py-3 text-sm font-medium text-gray-900">{pia?.name || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-700">{pia?.project_name || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-600">{pia?.assessment_type || ''}</td>
                        <td className="px-4 py-3 text-sm">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusBadgeClass(pia?.status || '')}`}>
                            {pia?.status || ''}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm">
                          <select
                            value={pia?.risk_level || 'not_assessed'}
                            aria-label="Risk level"
                            onChange={(e) => {
                              const value = e.target.value;
                              rowAction('update the PIA risk level', async () => {
                                await api.patch(`/privacy/pia/assessments/${pia.id}`, { risk_level: value });
                                queryClient.invalidateQueries({ queryKey: ['privacy-pias'] });
                              });
                            }}
                            className={`px-2 py-0.5 rounded text-xs font-medium ${riskBadgeClass(pia?.risk_level || '')}`}
                          >
                            {['not_assessed', 'negligible', 'low', 'medium', 'high', 'critical'].map((l) => (
                              <option key={l} value={l}>{l.replace('_', ' ')}</option>
                            ))}
                          </select>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-500">{pia?.updated_at?.slice(0, 10) || ''}</td>
                      </tr>
                    ))}
                    {filteredPIAs.length === 0 && (
                      <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">No PIA assessments found.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Consent Tab */}
        {activeTab === 'consent' && (
          <div>
            <div className="mb-4 flex items-center gap-4">
              <div className="flex-1 max-w-sm">
                <label className="block text-xs text-gray-500 mb-1">Subject ID (required to load records)</label>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="Enter subject ID..."
                    value={consentSubjectId}
                    onChange={(e) => setConsentSubjectId(e.target.value)}
                    className="flex-1 border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
              </div>
              <button
                onClick={() => setShowCreateConsent(true)}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm flex items-center gap-2 self-end"
              >
                <Plus className="w-4 h-4" /> New Consent
              </button>
            </div>
            <LoadErrorBanner what="consent records" error={consentError} />
            {consentLoading ? (
              <p className="text-gray-500 py-8 text-center">Loading...</p>
            ) : !consentSubjectId ? (
              <p className="text-gray-400 py-8 text-center">Enter a subject ID above to view consent records.</p>
            ) : (
              <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">ID</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Purpose</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Legal Basis</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Consent Given</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Consent Date</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Withdrawal Date</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Mechanism</th>
                    </tr>
                  </thead>
                  <tbody>
                    {consents.map((rec: any) => (
                      <tr key={rec?.id} className="border-t border-gray-100 hover:bg-gray-50">
                        <td className="px-4 py-3 text-sm font-mono text-indigo-600">{rec?.id || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-900">{rec?.purpose || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-600">{rec?.legal_basis || ''}</td>
                        <td className="px-4 py-3 text-sm">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${rec?.consent_given ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                            {rec?.consent_given ? 'Yes' : 'No'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-500">{rec?.consent_date?.slice(0, 10) || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-500">{rec?.withdrawal_date?.slice(0, 10) || '-'}</td>
                        <td className="px-4 py-3 text-sm text-gray-600">{rec?.consent_mechanism || ''}</td>
                      </tr>
                    ))}
                    {consents.length === 0 && (
                      <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-400">No consent records found for this subject.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ROPA Tab */}
        {activeTab === 'ropa' && (
          <div>
            <div className="mb-4 flex justify-end">
              <button
                onClick={() => setShowCreateROPA(true)}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm flex items-center gap-2"
              >
                <Plus className="w-4 h-4" /> New Processing Record
              </button>
            </div>
            <LoadErrorBanner what="processing records" error={ropaError} />
            {ropaLoading ? (
              <p className="text-gray-500 py-8 text-center">Loading...</p>
            ) : (
              <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Name</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Purpose</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Legal Basis</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Data Categories</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Retention (days)</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ropas.map((rec: any) => (
                      <tr key={rec?.id} className="border-t border-gray-100 hover:bg-gray-50">
                        <td className="px-4 py-3 text-sm font-medium text-gray-900">{rec?.name || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-700">{rec?.purpose || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-600">{rec?.legal_basis || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-600">
                          {Array.isArray(rec?.data_categories) ? rec.data_categories.join(', ') : (rec?.data_categories || '')}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600">{rec?.retention_period_days ?? NA}</td>
                        <td className="px-4 py-3 text-sm text-gray-500">
                          {rec?.created_at?.slice(0, 10) || ''}
                          <div className="text-xs">reviewed {rec?.last_reviewed ? String(rec.last_reviewed).slice(0, 10) : 'never'}</div>
                          <button
                            className="text-xs text-indigo-600 underline"
                            onClick={() => rowAction('mark the record reviewed', async () => {
                              await api.patch(`/privacy/ropa/processing-records/${rec.id}`, { last_reviewed: new Date().toISOString() });
                              queryClient.invalidateQueries({ queryKey: ['privacy-ropa'] });
                            })}
                          >
                            Mark reviewed today (admin)
                          </button>
                        </td>
                      </tr>
                    ))}
                    {ropas.length === 0 && (
                      <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">No processing records found.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Incidents Tab */}
        {activeTab === 'incidents' && (
          <div>
            <div className="mb-4 flex justify-end">
              <button
                onClick={() => setShowCreateIncident(true)}
                className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm flex items-center gap-2"
              >
                <Plus className="w-4 h-4" /> Report Incident
              </button>
            </div>
            <LoadErrorBanner what="privacy incidents" error={incidentError} />
            {incidentLoading ? (
              <p className="text-gray-500 py-8 text-center">Loading...</p>
            ) : (
              <div className="bg-white border border-gray-200 rounded-lg overflow-hidden">
                <table className="w-full">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Title</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Type</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Severity</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Notification</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Subjects Affected</th>
                      <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Created</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIncidents.map((inc: any) => (
                      <tr key={inc?.id} className="border-t border-gray-100 hover:bg-gray-50">
                        <td className="px-4 py-3 text-sm font-medium text-gray-900">{inc?.title || ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-600">{inc?.incident_type || ''}</td>
                        <td className="px-4 py-3 text-sm">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${severityBadgeClass(inc?.severity || '')}`}>
                            {inc?.severity || ''}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm">
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusBadgeClass(inc?.status || '')}`}>
                            {inc?.status || ''}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-sm">
                          {inc?.notification_required ? (
                            <span className="text-red-600 font-medium">Required{inc?.notification_deadline ? ` by ${inc.notification_deadline}` : ''}</span>
                          ) : (
                            <span className="text-gray-400">Not required</span>
                          )}
                          <div className="text-xs text-gray-500">
                            Regulations: {(inc?.regulations_implicated ?? []).join(', ') || 'none recorded'}
                          </div>
                          <button
                            className="text-xs text-indigo-600 underline"
                            onClick={() => rowAction('compute notification deadlines', async () => {
                              const res = await api.post(`/privacy/incidents/reports/${inc.id}/notification-deadlines`);
                              setDeadlines((prev) => ({ ...prev, [inc.id]: res.data }));
                            })}
                          >
                            Notification deadlines
                          </button>
                          {deadlines[inc?.id] && (
                            <div className="text-xs text-gray-600">
                              {deadlines[inc.id].status === 'not_assessed'
                                ? `Not assessed: ${deadlines[inc.id].detail ?? 'no regulation recorded'}`
                                : Object.entries(deadlines[inc.id] as Record<string, unknown>)
                                    .filter(([, v]) => typeof v === 'string' && /^\d{4}-/.test(v))
                                    .map(([k, v]) => `${k}: ${String(v).slice(0, 16).replace('T', ' ')}`)
                                    .join(' · ') || JSON.stringify(deadlines[inc.id])}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3 text-sm text-gray-600">{inc?.subjects_affected_count ?? '-'}</td>
                        <td className="px-4 py-3 text-sm text-gray-500">{inc?.created_at?.slice(0, 10) || ''}</td>
                      </tr>
                    ))}
                    {filteredIncidents.length === 0 && (
                      <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-400">No privacy incidents found.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* --- Create DSR Modal --- */}
        {showCreateDSR && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowCreateDSR(false)}>
            <div className="bg-white rounded-lg p-6 max-w-lg w-full shadow-xl" onClick={(e) => e.stopPropagation()}>
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-lg font-bold text-gray-900">New Data Subject Request</h2>
                <button onClick={() => setShowCreateDSR(false)} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
              </div>
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Request Type</label>
                    <select value={dsrForm.request_type} onChange={(e) => setDsrForm({ ...dsrForm, request_type: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm">
                      <option value="access">Access</option>
                      <option value="erasure">Erasure</option>
                      <option value="rectification">Rectification</option>
                      <option value="restriction">Restriction</option>
                      <option value="portability">Portability</option>
                      <option value="objection">Objection</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Regulation</label>
                    <select value={dsrForm.regulation} onChange={(e) => setDsrForm({ ...dsrForm, regulation: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm">
                      <option value="gdpr">GDPR</option>
                      <option value="ccpa">CCPA</option>
                      <option value="lgpd">LGPD</option>
                      <option value="pipa">PIPA</option>
                      <option value="pdpa">PDPA</option>
                      <option value="hipaa">HIPAA</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Subject Name</label>
                  <input type="text" value={dsrForm.subject_name} onChange={(e) => setDsrForm({ ...dsrForm, subject_name: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="Full name" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Subject Email</label>
                  <input type="email" value={dsrForm.subject_email} onChange={(e) => setDsrForm({ ...dsrForm, subject_email: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="email@example.com" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Subject Identifier</label>
                  <input type="text" value={dsrForm.subject_identifier} onChange={(e) => setDsrForm({ ...dsrForm, subject_identifier: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="User ID, account number, etc." />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Description</label>
                  <textarea value={dsrForm.description} onChange={(e) => setDsrForm({ ...dsrForm, description: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" rows={3} placeholder="Details about the request..." />
                </div>
              </div>
              <div className="flex gap-3 mt-5">
                <button onClick={() => setShowCreateDSR(false)} className="flex-1 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm hover:bg-gray-50">Cancel</button>
                <button
                  onClick={() => createDSR.mutate(dsrForm)}
                  disabled={createDSR.isPending || !dsrForm.subject_name || !dsrForm.subject_email}
                  className="flex-1 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-300 text-white px-4 py-2 rounded-lg text-sm"
                >
                  {createDSR.isPending ? 'Creating...' : 'Create DSR'}
                </button>
              </div>
              <div className="mt-2"><ActionErrorBanner what="create the DSR" error={createDSR.error} /></div>
            </div>
          </div>
        )}

        {/* --- Create PIA Modal --- */}
        {showCreatePIA && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowCreatePIA(false)}>
            <div className="bg-white rounded-lg p-6 max-w-lg w-full shadow-xl" onClick={(e) => e.stopPropagation()}>
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-lg font-bold text-gray-900">New Privacy Impact Assessment</h2>
                <button onClick={() => setShowCreatePIA(false)} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Assessment Name</label>
                  <input type="text" value={piaForm.name} onChange={(e) => setPiaForm({ ...piaForm, name: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="PIA name" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Project Name</label>
                  <input type="text" value={piaForm.project_name} onChange={(e) => setPiaForm({ ...piaForm, project_name: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="Project name" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Assessment Type</label>
                    <select value={piaForm.assessment_type} onChange={(e) => setPiaForm({ ...piaForm, assessment_type: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm">
                      <option value="pia">PIA (Privacy Impact Assessment)</option>
                      <option value="dpia">DPIA (Data Protection Impact Assessment)</option>
                      <option value="tia">TIA (Transfer Impact Assessment)</option>
                      <option value="legitimate_interest">Legitimate Interest Assessment</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Legal Basis</label>
                    <select value={piaForm.legal_basis} onChange={(e) => setPiaForm({ ...piaForm, legal_basis: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm">
                      <option value="consent">Consent</option>
                      <option value="contract">Contract</option>
                      <option value="legal_obligation">Legal Obligation</option>
                      <option value="legitimate_interest">Legitimate Interest</option>
                      <option value="public_interest">Public Interest</option>
                      <option value="vital_interest">Vital Interest</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Data Types Processed</label>
                  <input type="text" value={piaForm.data_types_processed} onChange={(e) => setPiaForm({ ...piaForm, data_types_processed: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="Comma-separated list" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Processing Purposes</label>
                  <input type="text" value={piaForm.processing_purposes} onChange={(e) => setPiaForm({ ...piaForm, processing_purposes: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="Comma-separated list" />
                </div>
              </div>
              <div className="flex gap-3 mt-5">
                <button onClick={() => setShowCreatePIA(false)} className="flex-1 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm hover:bg-gray-50">Cancel</button>
                <button
                  onClick={() => createPIA.mutate({
                    ...piaForm,
                    data_types_processed: piaForm.data_types_processed.split(',').map((s) => s.trim()).filter(Boolean),
                    processing_purposes: piaForm.processing_purposes.split(',').map((s) => s.trim()).filter(Boolean),
                  })}
                  disabled={createPIA.isPending || !piaForm.name || !piaForm.project_name}
                  className="flex-1 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-300 text-white px-4 py-2 rounded-lg text-sm"
                >
                  {createPIA.isPending ? 'Creating...' : 'Create PIA'}
                </button>
              </div>
              <div className="mt-2"><ActionErrorBanner what="create the PIA" error={createPIA.error} /></div>
            </div>
          </div>
        )}

        {/* --- Create Consent Modal --- */}
        {showCreateConsent && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowCreateConsent(false)}>
            <div className="bg-white rounded-lg p-6 max-w-lg w-full shadow-xl" onClick={(e) => e.stopPropagation()}>
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-lg font-bold text-gray-900">New Consent Record</h2>
                <button onClick={() => setShowCreateConsent(false)} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Subject ID</label>
                  <input type="text" value={consentForm.subject_id} onChange={(e) => setConsentForm({ ...consentForm, subject_id: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Purpose</label>
                  <input type="text" value={consentForm.purpose} onChange={(e) => setConsentForm({ ...consentForm, purpose: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="e.g., marketing, analytics" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Legal Basis</label>
                    <select value={consentForm.legal_basis} onChange={(e) => setConsentForm({ ...consentForm, legal_basis: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm">
                      <option value="consent">Consent</option>
                      <option value="contract">Contract</option>
                      <option value="legitimate_interest">Legitimate Interest</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Mechanism</label>
                    <input type="text" value={consentForm.consent_mechanism} onChange={(e) => setConsentForm({ ...consentForm, consent_mechanism: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="web_form, email, etc." />
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <input type="checkbox" checked={consentForm.consent_given} onChange={(e) => setConsentForm({ ...consentForm, consent_given: e.target.checked })} className="rounded" />
                  <label className="text-sm text-gray-700">Consent Given</label>
                </div>
              </div>
              <div className="flex gap-3 mt-5">
                <button onClick={() => setShowCreateConsent(false)} className="flex-1 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm hover:bg-gray-50">Cancel</button>
                <button
                  onClick={() => createConsent.mutate(consentForm)}
                  disabled={createConsent.isPending || !consentForm.subject_id || !consentForm.purpose}
                  className="flex-1 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-300 text-white px-4 py-2 rounded-lg text-sm"
                >
                  {createConsent.isPending ? 'Creating...' : 'Create Consent'}
                </button>
              </div>
              <div className="mt-2"><ActionErrorBanner what="create the consent record" error={createConsent.error} /></div>
            </div>
          </div>
        )}

        {/* --- Create ROPA Modal --- */}
        {showCreateROPA && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowCreateROPA(false)}>
            <div className="bg-white rounded-lg p-6 max-w-lg w-full shadow-xl" onClick={(e) => e.stopPropagation()}>
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-lg font-bold text-gray-900">New Processing Record</h2>
                <button onClick={() => setShowCreateROPA(false)} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
                  <input type="text" value={ropaForm.name} onChange={(e) => setRopaForm({ ...ropaForm, name: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Purpose</label>
                  <input type="text" value={ropaForm.purpose} onChange={(e) => setRopaForm({ ...ropaForm, purpose: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Legal Basis</label>
                    <select value={ropaForm.legal_basis} onChange={(e) => setRopaForm({ ...ropaForm, legal_basis: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm">
                      <option value="consent">Consent</option>
                      <option value="contract">Contract</option>
                      <option value="legal_obligation">Legal Obligation</option>
                      <option value="legitimate_interest">Legitimate Interest</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Retention (days)</label>
                    <input type="number" value={ropaForm.retention_period_days} onChange={(e) => setRopaForm({ ...ropaForm, retention_period_days: parseInt(e.target.value) || 0 })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Data Categories (comma-separated)</label>
                  <input type="text" value={ropaForm.data_categories} onChange={(e) => setRopaForm({ ...ropaForm, data_categories: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Data Subjects (comma-separated)</label>
                  <input type="text" value={ropaForm.data_subjects} onChange={(e) => setRopaForm({ ...ropaForm, data_subjects: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Recipients (comma-separated)</label>
                  <input type="text" value={ropaForm.recipients} onChange={(e) => setRopaForm({ ...ropaForm, recipients: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                </div>
              </div>
              <div className="flex gap-3 mt-5">
                <button onClick={() => setShowCreateROPA(false)} className="flex-1 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm hover:bg-gray-50">Cancel</button>
                <button
                  onClick={() => {
                    // Backend DataProcessingRecordCreate expects:
                    //   data_categories / data_subjects / recipients : Optional[List[str]]
                    //   retention_period_days : Optional[int]
                    // Split free-text comma fields into lists; coerce retention to int.
                    const dataCategories = ropaForm.data_categories.split(',').map((s) => s.trim()).filter(Boolean);
                    const dataSubjects = ropaForm.data_subjects.split(',').map((s) => s.trim()).filter(Boolean);
                    const recipients = ropaForm.recipients.split(',').map((s) => s.trim()).filter(Boolean);
                    const retentionDays = Number.isFinite(ropaForm.retention_period_days)
                      ? Math.max(0, Math.trunc(ropaForm.retention_period_days))
                      : null;
                    createROPA.mutate({
                      name: ropaForm.name,
                      purpose: ropaForm.purpose,
                      legal_basis: ropaForm.legal_basis,
                      data_categories: dataCategories.length > 0 ? dataCategories : undefined,
                      data_subjects: dataSubjects.length > 0 ? dataSubjects : undefined,
                      recipients: recipients.length > 0 ? recipients : undefined,
                      retention_period_days: retentionDays !== null ? retentionDays : undefined,
                    });
                  }}
                  disabled={createROPA.isPending || !ropaForm.name || !ropaForm.purpose}
                  className="flex-1 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-300 text-white px-4 py-2 rounded-lg text-sm"
                >
                  {createROPA.isPending ? 'Creating...' : 'Create Record'}
                </button>
              </div>
              <div className="mt-2"><ActionErrorBanner what="create the processing record" error={createROPA.error} /></div>
            </div>
          </div>
        )}

        {/* --- Create Incident Modal --- */}
        {showCreateIncident && (
          <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setShowCreateIncident(false)}>
            <div className="bg-white rounded-lg p-6 max-w-lg w-full shadow-xl" onClick={(e) => e.stopPropagation()}>
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-lg font-bold text-gray-900">Report Privacy Incident</h2>
                <button onClick={() => setShowCreateIncident(false)} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Title</label>
                  <input type="text" value={incidentForm.title} onChange={(e) => setIncidentForm({ ...incidentForm, title: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Description</label>
                  <textarea value={incidentForm.description} onChange={(e) => setIncidentForm({ ...incidentForm, description: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" rows={3} />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Incident Type</label>
                    <input type="text" value={incidentForm.incident_type} onChange={(e) => setIncidentForm({ ...incidentForm, incident_type: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="data_breach, unauthorized_access, etc." />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-gray-600 mb-1">Severity</label>
                    <select value={incidentForm.severity} onChange={(e) => setIncidentForm({ ...incidentForm, severity: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm">
                      <option value="critical">Critical</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Data Types Affected (comma-separated)</label>
                  <input type="text" value={incidentForm.data_types_affected} onChange={(e) => setIncidentForm({ ...incidentForm, data_types_affected: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Subjects Affected Count</label>
                  <input type="number" value={incidentForm.subjects_affected_count} onChange={(e) => setIncidentForm({ ...incidentForm, subjects_affected_count: parseInt(e.target.value) || 0 })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Regulations implicated (sets notification deadlines)</label>
                  <div className="flex gap-4 text-sm">
                    {['gdpr', 'ccpa', 'hipaa'].map((r) => (
                      <label key={r} className="flex items-center gap-1">
                        <input type="checkbox" checked={incidentRegs.includes(r)} onChange={(e) => setIncidentRegs((prev) => (e.target.checked ? [...prev, r] : prev.filter((x) => x !== r)))} />
                        {r.toUpperCase()}
                      </label>
                    ))}
                  </div>
                </div>
              </div>
              <div className="flex gap-3 mt-5">
                <button onClick={() => setShowCreateIncident(false)} className="flex-1 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm hover:bg-gray-50">Cancel</button>
                <button
                  onClick={() => createIncident.mutate({
                    ...incidentForm,
                    data_types_affected: incidentForm.data_types_affected.split(',').map((s) => s.trim()).filter(Boolean),
                    regulations_implicated: incidentRegs,
                  })}
                  disabled={createIncident.isPending || !incidentForm.title || !incidentForm.description}
                  className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-red-300 text-white px-4 py-2 rounded-lg text-sm"
                >
                  {createIncident.isPending ? 'Reporting...' : 'Report Incident'}
                </button>
              </div>
              <div className="mt-2"><ActionErrorBanner what="report the incident" error={createIncident.error} /></div>
            </div>
          </div>
        )}

        {openDsr && (
          <DSRDetail
            dsr={openDsr}
            sources={(dsrSources?.sources ?? []) as Row[]}
            onClose={() => setOpenDsrId(null)}
            onChanged={() => refreshPrivacy()}
          />
        )}
      </div>
    </div>
  );
}
