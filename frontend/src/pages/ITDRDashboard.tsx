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
  AlertCircle,
  AlertTriangle,
  CheckCircle,
  Clock,
  Shield,
} from 'lucide-react';
import clsx from 'clsx';
import { itdrApi } from '../api/endpoints';
import { api } from '../lib/api';

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

type ITDRRecordKind = 'threat' | 'exposure' | 'anomaly' | 'access';

interface ITDRDetailModalProps {
  threat: any | null;
  exposure: any | null;
  anomaly: any | null;
  access: any | null;
  mode: 'view' | 'edit';
  onClose: () => void;
  onSaved: (kind: ITDRRecordKind, updated: any) => void;
}

function ITDRDetailModal({ threat, exposure, anomaly, access, mode, onClose, onSaved }: ITDRDetailModalProps) {
  const record = threat || exposure || anomaly || access;
  const kind: ITDRRecordKind = threat ? 'threat' : exposure ? 'exposure' : anomaly ? 'anomaly' : 'access';

  const [form, setForm] = useState<any>(() => ({
    // threat fields
    severity: record?.severity ?? '',
    status: record?.status ?? '',
    confidence_score: record?.confidence_score ?? 0,
    analyst_notes: record?.analyst_notes ?? '',
    // exposure fields
    is_remediated: Boolean(record?.is_remediated),
    remediation_action: record?.remediation_action ?? '',
    // anomaly fields
    is_reviewed: Boolean(record?.is_reviewed),
    reviewer_notes: record?.reviewer_notes ?? '',
    // privileged-access fields
    justification: record?.justification ?? '',
    was_revoked: Boolean(record?.was_revoked),
    revocation_reason: record?.revocation_reason ?? '',
  }));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEdit = mode === 'edit';

  const handleSave = async () => {
    if (!record?.id) return;
    setSaving(true);
    setError(null);
    try {
      let payload: Record<string, any> = {};
      let updated: any;
      if (kind === 'threat') {
        payload = {
          severity: form.severity,
          status: form.status,
          confidence_score: Number(form.confidence_score) || 0,
        };
        updated = await itdrApi.updateThreat(record.id, payload);
      } else if (kind === 'exposure') {
        payload = {
          is_remediated: Boolean(form.is_remediated),
          remediation_action: form.remediation_action || null,
        };
        updated = await itdrApi.updateExposure(record.id, payload);
      } else if (kind === 'anomaly') {
        payload = {
          is_reviewed: Boolean(form.is_reviewed),
          reviewer_notes: form.reviewer_notes || null,
        };
        updated = await itdrApi.updateAnomaly(record.id, payload);
      } else if (kind === 'access') {
        payload = {
          justification: form.justification || null,
          was_revoked: Boolean(form.was_revoked),
          revocation_reason: form.revocation_reason || null,
        };
        updated = await itdrApi.updatePrivilegedAccess(record.id, payload);
      }
      onSaved(kind, updated);
    } catch (e: any) {
      setError(e?.response?.data?.detail || e?.message || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const title =
    kind === 'threat' ? (isEdit ? 'Edit Threat' : 'Threat Details')
    : kind === 'exposure' ? (isEdit ? 'Edit Credential Exposure' : 'Credential Exposure Details')
    : kind === 'anomaly' ? (isEdit ? 'Edit Access Anomaly' : 'Access Anomaly Details')
    : (isEdit ? 'Edit Privileged Access' : 'Privileged Access Details');

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[36rem] max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-xl font-bold mb-4">{title}</h2>

        {!isEdit && (
          <pre className="text-xs bg-gray-100 dark:bg-gray-900 rounded p-4 overflow-auto max-h-96">
            {JSON.stringify(record, null, 2)}
          </pre>
        )}

        {isEdit && kind === 'threat' && (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium mb-1">Severity</label>
              <select value={form.severity} onChange={(e) => setForm((f: any) => ({ ...f, severity: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                <option value="critical">critical</option>
                <option value="high">high</option>
                <option value="medium">medium</option>
                <option value="low">low</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Status</label>
              <select value={form.status} onChange={(e) => setForm((f: any) => ({ ...f, status: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                <option value="pending">pending</option>
                <option value="investigating">investigating</option>
                <option value="resolved">resolved</option>
                <option value="dismissed">dismissed</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Confidence Score (0-100)</label>
              <input type="number" min={0} max={100} value={form.confidence_score} onChange={(e) => setForm((f: any) => ({ ...f, confidence_score: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
            </div>
          </div>
        )}

        {isEdit && kind === 'exposure' && (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <input id="is_remediated" type="checkbox" checked={form.is_remediated} onChange={(e) => setForm((f: any) => ({ ...f, is_remediated: e.target.checked }))} />
              <label htmlFor="is_remediated" className="text-sm font-medium">Mark as remediated</label>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Remediation Action</label>
              <select value={form.remediation_action || ''} onChange={(e) => setForm((f: any) => ({ ...f, remediation_action: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                <option value="">(none)</option>
                <option value="password_reset">password_reset</option>
                <option value="token_revoke">token_revoke</option>
                <option value="key_rotation">key_rotation</option>
              </select>
            </div>
          </div>
        )}

        {isEdit && kind === 'anomaly' && (
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <input id="is_reviewed" type="checkbox" checked={form.is_reviewed} onChange={(e) => setForm((f: any) => ({ ...f, is_reviewed: e.target.checked }))} />
              <label htmlFor="is_reviewed" className="text-sm font-medium">Mark as reviewed</label>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Reviewer Notes</label>
              <textarea value={form.reviewer_notes || ''} onChange={(e) => setForm((f: any) => ({ ...f, reviewer_notes: e.target.value }))} rows={4} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
            </div>
          </div>
        )}

        {isEdit && kind === 'access' && (
          <div className="space-y-3">
            <div>
              <label className="block text-sm font-medium mb-1">Justification</label>
              <textarea value={form.justification || ''} onChange={(e) => setForm((f: any) => ({ ...f, justification: e.target.value }))} rows={3} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
            </div>
            <div className="flex items-center gap-2">
              <input id="was_revoked" type="checkbox" checked={form.was_revoked} onChange={(e) => setForm((f: any) => ({ ...f, was_revoked: e.target.checked }))} />
              <label htmlFor="was_revoked" className="text-sm font-medium">Was revoked</label>
            </div>
            <div>
              <label className="block text-sm font-medium mb-1">Revocation Reason</label>
              <input type="text" value={form.revocation_reason || ''} onChange={(e) => setForm((f: any) => ({ ...f, revocation_reason: e.target.value }))} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
            </div>
          </div>
        )}

        {error && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}

        <div className="mt-5 flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
            {isEdit ? 'Cancel' : 'Close'}
          </button>
          {isEdit && (
            <button onClick={handleSave} disabled={saving} className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition">
              {saving ? 'Saving...' : 'Save'}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

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
  const [dashboardMetrics, setDashboardMetrics] = useState<any | null>(null);
  const [scanInProgress, setScanInProgress] = useState(false);
  const [exposureCheckInProgress, setExposureCheckInProgress] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState<any | null>(null);
  const [selectedExposure, setSelectedExposure] = useState<any | null>(null);
  const [selectedAnomaly, setSelectedAnomaly] = useState<any | null>(null);
  const [selectedAccess, setSelectedAccess] = useState<any | null>(null);
  const [detailMode, setDetailMode] = useState<'view' | 'edit'>('view');
  const [showFilterPanel, setShowFilterPanel] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('all');

  const loadData = React.useCallback(async () => {
    setLoading(true);
    try {
      const [threatsData, exposuresData, anomaliesData, accessData, identitiesData, metricsData] = await Promise.all([
        itdrApi.getIdentityThreats().catch(() => null),
        itdrApi.getCredentialExposures().catch(() => null),
        itdrApi.getAccessAnomalies().catch(() => null),
        itdrApi.getPrivilegedAccess().catch(() => null),
        itdrApi.getIdentities({ size: 500 } as any).catch(() => null),
        api.get('/itdr/dashboard/metrics').then(r => r.data).catch(() => null),
      ]);
      setIdentityThreats(threatsData?.items ?? []);
      setCredentialExposures(exposuresData?.items ?? []);
      setAccessAnomalies(anomaliesData?.items ?? []);
      setPrivilegedAccess(accessData?.items ?? []);
      setIdentities(identitiesData?.items ?? []);
      setDashboardMetrics(metricsData);
    } catch (error) {
      console.error('Error loading ITDR data:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    loadData();
  }, [loadData]);

  // Real scan dispatch — previously the ITDR page had no way to
  // trigger /threats/scan from the UI, so the "Active Threats" card
  // was just whatever rows happened to already exist. Now the header
  // button kicks off the real three-heuristic scan and refreshes.
  const handleRunScan = async () => {
    try {
      setScanInProgress(true);
      const res = await api.post('/itdr/threats/scan', {});
      await loadData();
      // Backend returns `threats_created` (not `threats_found`). The
      // count reflects NEW threats opened this run — already-open
      // threats of the same type on the same identity are deduped.
      const newCount = res.data?.threats_created ?? 0;
      const scanned = res.data?.identities_scanned ?? 0;
      alert(`Identity threat scan complete — ${newCount} new threat(s) created across ${scanned} identities.`);
    } catch (err: any) {
      alert(`Scan failed: ${err?.response?.data?.detail || err?.message || 'unknown error'}`);
    } finally {
      setScanInProgress(false);
    }
  };

  const handleCheckExposures = async () => {
    // The /credential-exposures/check endpoint requires an
    // identity_id query param. Iterate every identity in scope and
    // aggregate the hit counts so the button is genuinely org-wide.
    try {
      setExposureCheckInProgress(true);
      let totalHits = 0;
      let ids = 0;
      for (const profile of identities) {
        try {
          const r = await api.post(`/itdr/credential-exposures/check?identity_id=${encodeURIComponent(profile.id)}`);
          totalHits += r.data?.exposures_found ?? 0;
          ids += 1;
        } catch {
          /* ignore per-identity failures — sweep continues */
        }
      }
      await loadData();
      alert(`Credential exposure check complete — ${totalHits} exposure(s) across ${ids} identities.`);
    } catch (err: any) {
      alert(`Exposure check failed: ${err?.response?.data?.detail || err?.message || 'unknown error'}`);
    } finally {
      setExposureCheckInProgress(false);
    }
  };

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
    const threat = identityThreats.find(t => t.id === threatId);
    if (threat) { setSelectedThreat(threat); setDetailMode('view'); }
  };

  const handleEditThreat = (threatId: string) => {
    const threat = identityThreats.find(t => t.id === threatId);
    if (threat) { setSelectedThreat(threat); setDetailMode('edit'); }
  };

  const handleViewExposure = (exposureId: string) => {
    const exposure = credentialExposures.find(c => c.id === exposureId);
    if (exposure) { setSelectedExposure(exposure); setDetailMode('view'); }
  };

  const handleEditExposure = (exposureId: string) => {
    const exposure = credentialExposures.find(c => c.id === exposureId);
    if (exposure) { setSelectedExposure(exposure); setDetailMode('edit'); }
  };

  const handleViewAnomaly = (anomalyId: string) => {
    const anomaly = accessAnomalies.find(a => a.id === anomalyId);
    if (anomaly) { setSelectedAnomaly(anomaly); setDetailMode('view'); }
  };

  const handleEditAnomaly = (anomalyId: string) => {
    const anomaly = accessAnomalies.find(a => a.id === anomalyId);
    if (anomaly) { setSelectedAnomaly(anomaly); setDetailMode('edit'); }
  };

  const handleViewAccess = (accessId: string) => {
    const access = privilegedAccess.find(p => p.id === accessId);
    if (access) { setSelectedAccess(access); setDetailMode('view'); }
  };

  const handleEditAccess = (accessId: string) => {
    const access = privilegedAccess.find(p => p.id === accessId);
    if (access) { setSelectedAccess(access); setDetailMode('edit'); }
  };

  // A threat is "active" while it's still open — that's `detected`
  // (fresh from scan) OR `investigating` (analyst has picked it up).
  // Anything else (contained, remediated, false_positive) has been
  // closed and should not count toward the Active Threats card.
  const activeThreats = identityThreats.filter(
    t => t.status === 'detected' || t.status === 'investigating'
  ).length;
  const exposedCredentials = credentialExposures.filter(c => !c.is_remediated).length;
  const highRiskIdentities = identityThreats.filter(t => (t.confidence_score ?? 0) >= 80).length;

  // Compute MFA coverage from identities data
  const mfaCoverage = identities.length > 0
    ? Math.round((identities.filter((i: any) => i.mfa_enabled).length / (identities.length || 1)) * 100)
    : 0;

  const tabs = [
    { id: 'identity-threats', label: 'Identity Threats', icon: UserX },
    { id: 'credential-exposure', label: 'Credential Exposure', icon: Key },
    { id: 'access-anomalies', label: 'Access Anomalies', icon: ShieldAlert },
    { id: 'privileged-access', label: 'Privileged Access', icon: Lock },
  ];

  const filteredThreats = identityThreats.filter(t => {
    const matchesSearch = (t.threat_type ?? '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (t.identity_id ?? '').toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || t.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

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
          <div className="flex items-center gap-2">
            <button
              onClick={handleRunScan}
              disabled={scanInProgress}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
              title="Run identity threat scan (dormant admins, privileged-without-MFA, stale credentials)"
            >
              <Shield className="w-4 h-4" />
              {scanInProgress ? 'Scanning…' : 'Run Threat Scan'}
            </button>
            <button
              onClick={handleCheckExposures}
              disabled={exposureCheckInProgress}
              className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
              title="Check every identity against leaked-credential datasets"
            >
              <AlertCircle className="w-4 h-4" />
              {exposureCheckInProgress ? 'Checking…' : 'Check Exposures'}
            </button>
            <button
              onClick={() => setShowNewThreatModal(true)}
              className="flex items-center gap-2 bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg transition"
            >
              <Plus className="w-4 h-4" />
              New Threat
            </button>
          </div>
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
                    onClick={() => setShowFilterPanel(prev => !prev)}
                    className={clsx(
                      'flex items-center gap-2 px-4 py-2 border rounded-lg transition',
                      showFilterPanel
                        ? 'border-orange-500 bg-orange-50 dark:bg-orange-900/20 text-orange-600'
                        : 'border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700'
                    )}
                  >
                    <Filter className="w-4 h-4" />
                    Filter
                  </button>
                </div>

                {showFilterPanel && (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 flex gap-4">
                    <div>
                      <label className="block text-sm font-medium mb-1">Severity</label>
                      <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm">
                        <option value="all">All</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                      </select>
                    </div>
                  </div>
                )}

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
                            <td className="px-6 py-4 text-sm">{credential.created_at ? new Date(credential.created_at || "").toLocaleDateString() : 'N/A'}</td>
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
                              <button
                                onClick={() => handleEditExposure(credential.id)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                                title="Edit exposure"
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
                              {anomaly.created_at ? new Date(anomaly.created_at || "").toLocaleString() : 'N/A'}
                            </p>
                          </div>
                          <div className="flex gap-2 ml-4">
                            <button
                              onClick={() => handleViewAnomaly(anomaly.id)}
                              className="text-blue-600 dark:text-blue-400 hover:underline"
                              title="View details"
                            >
                              <Eye className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleEditAnomaly(anomaly.id)}
                              className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                              title="Edit anomaly"
                            >
                              <Edit className="w-4 h-4" />
                            </button>
                          </div>
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
                            <td className="px-6 py-4 text-sm">{access.created_at ? new Date(access.created_at || "").toLocaleDateString() : 'N/A'}</td>
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

      {/* Detail/Edit Modal */}
      {(selectedThreat || selectedExposure || selectedAnomaly || selectedAccess) && (
        <ITDRDetailModal
          threat={selectedThreat}
          exposure={selectedExposure}
          anomaly={selectedAnomaly}
          access={selectedAccess}
          mode={detailMode}
          onClose={() => { setSelectedThreat(null); setSelectedExposure(null); setSelectedAnomaly(null); setSelectedAccess(null); }}
          onSaved={(kind, updated) => {
            if (kind === 'threat') setIdentityThreats(prev => prev.map(x => x.id === updated.id ? updated : x));
            if (kind === 'exposure') setCredentialExposures(prev => prev.map(x => x.id === updated.id ? updated : x));
            if (kind === 'anomaly') setAccessAnomalies(prev => prev.map(x => x.id === updated.id ? updated : x));
            if (kind === 'access') setPrivilegedAccess(prev => prev.map(x => x.id === updated.id ? updated : x));
            setSelectedThreat(null); setSelectedExposure(null); setSelectedAnomaly(null); setSelectedAccess(null);
          }}
        />
      )}

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
