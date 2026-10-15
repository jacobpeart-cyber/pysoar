import React, { useState } from 'react';
import {
  UserX,
  Key,
  ShieldAlert,
  Lock,
  Plus,
  Edit,
  Eye,
  Search,
  Filter,
  AlertCircle,
  AlertTriangle,
  Clock,
  Shield,
  Users,
  Zap,
} from 'lucide-react';
import clsx from 'clsx';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import ActionErrorBanner from '../components/ActionErrorBanner';
import { itdrApi } from '../api/endpoints';
import { api } from '../lib/api';
import LoadErrorBanner from '../components/LoadErrorBanner';
import { describeLoadError } from '../lib/loadError';
import { useRoleGate, ANALYST_ONLY_REASON } from '../lib/roles';

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
  const [identities, setIdentities] = useState<ITDRIdentity[]>([]);
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
  // Per-list load failures, keyed by list. A failed list renders an error
  // banner instead of an empty table.
  const [loadErrors, setLoadErrors] = useState<Record<'threats' | 'exposures' | 'anomalies' | 'access' | 'identities', unknown>>({
    threats: null, exposures: null, anomalies: null, access: null, identities: null,
  });
  const [respondThreat, setRespondThreat] = useState<{ id: string; threat_type?: string; source_ip?: string | null } | null>(null);
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
      // itdrApi list helpers already unwrap `{items, ...}` into the items
      // array (extractData), so reading `.items` again always gave [].
      const asList = (data: any): any[] => (Array.isArray(data) ? data : (data?.items ?? []));
      const [threatsRes, exposuresRes, anomaliesRes, accessRes, identitiesRes] = await Promise.allSettled([
        itdrApi.getIdentityThreats(),
        itdrApi.getCredentialExposures(),
        itdrApi.getAccessAnomalies(),
        itdrApi.getPrivilegedAccess(),
        itdrApi.getIdentities({ size: 100 }),
      ]);
      const value = (r: PromiseSettledResult<any>) => (r.status === 'fulfilled' ? asList(r.value) : []);
      const reason = (r: PromiseSettledResult<any>) => (r.status === 'rejected' ? (r.reason ?? new Error('request failed')) : null);
      setIdentityThreats(value(threatsRes));
      setCredentialExposures(value(exposuresRes));
      setAccessAnomalies(value(anomaliesRes));
      setPrivilegedAccess(value(accessRes));
      setIdentities(value(identitiesRes));
      setLoadErrors({
        threats: reason(threatsRes),
        exposures: reason(exposuresRes),
        anomalies: reason(anomaliesRes),
        access: reason(accessRes),
        identities: reason(identitiesRes),
      });
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    loadData();
  }, [loadData]);

  const queryClient = useQueryClient();
  // Server-computed metrics (GET /itdr/dashboard/metrics): counts over every
  // row of the organisation, not just the page of rows loaded here.
  const { data: metrics, error: metricsError } = useQuery({
    queryKey: ['itdr-metrics'],
    queryFn: async () => (await api.get<ITDRMetrics>('/itdr/dashboard/metrics')).data,
  });
  const refreshAll = React.useCallback(() => {
    queryClient.invalidateQueries({ queryKey: ['itdr-metrics'] });
    queryClient.invalidateQueries({ queryKey: ['itdr-identity-sources'] });
    loadData();
  }, [queryClient, loadData]);

  // POST /itdr/threats/scan: dormant admins, privileged-without-MFA, stale credentials.
  const scanMutation = useMutation({
    mutationFn: async () =>
      (await api.post<{ identities_scanned: number; threats_created: number; completed_at: string }>('/itdr/threats/scan', {})).data,
    onSuccess: refreshAll,
  });

  // One org-wide call (POST /itdr/credential-exposures/check-all) replaces
  // the old per-identity loop over /credential-exposures/check.
  const exposureMutation = useMutation({
    mutationFn: async () =>
      (await api.post<{ leaks_checked: number; exposures_created: number; identities_affected: number; capped: boolean }>(
        '/itdr/credential-exposures/check-all',
      )).data,
    onSuccess: refreshAll,
  });

  const handleCreateThreat = async () => {
    if (!newThreatForm.threat_type || !newThreatForm.identity_id) return;
    setSubmitting(true);
    try {
      const created = await itdrApi.createThreat(newThreatForm);
      setIdentityThreats((prev) => [created, ...prev]);
      setShowNewThreatModal(false);
      setNewThreatForm({ threat_type: '', identity_id: '', severity: 'critical', confidence_score: 80 });
    } catch (error) {
      alert(`Create threat failed: ${describeLoadError(error)}`);
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

  const tabs = [
    { id: 'identity-threats', label: 'Identity Threats', icon: UserX },
    { id: 'credential-exposure', label: 'Credential Exposure', icon: Key },
    { id: 'access-anomalies', label: 'Access Anomalies', icon: ShieldAlert },
    { id: 'privileged-access', label: 'Privileged Access', icon: Lock },
    { id: 'identities', label: 'Identities & Sources', icon: Users },
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
              onClick={() => scanMutation.mutate()}
              disabled={scanMutation.isPending}
              className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
              title="Run identity threat scan (dormant admins, privileged-without-MFA, stale credentials)"
            >
              <Shield className="w-4 h-4" />
              {scanMutation.isPending ? 'Scanning…' : 'Run Threat Scan'}
            </button>
            <button
              onClick={() => exposureMutation.mutate()}
              disabled={exposureMutation.isPending}
              className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
              title="Match every identity against this organisation's dark-web credential leak records"
            >
              <AlertCircle className="w-4 h-4" />
              {exposureMutation.isPending ? 'Checking…' : 'Check all credential exposures'}
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

        <div className="space-y-2 mb-4">
          <ActionErrorBanner what="run the identity threat scan" error={scanMutation.error} />
          <ActionErrorBanner what="check credential exposures" error={exposureMutation.error} />
          {scanMutation.data && (
            <p className="text-sm text-green-700 dark:text-green-300">
              Identity threat scan complete: {scanMutation.data.threats_created} new threat(s) across {scanMutation.data.identities_scanned} identities.
            </p>
          )}
          {exposureMutation.data && (
            <p className="text-sm text-green-700 dark:text-green-300">
              Credential exposure check: {exposureMutation.data.leaks_checked} leak record(s) checked, {exposureMutation.data.exposures_created} new
              exposure(s) on {exposureMutation.data.identities_affected} identities{exposureMutation.data.capped ? ' (per-run cap reached; the hourly run continues)' : ''}.
            </p>
          )}
        </div>

        {/* Summary Cards (GET /itdr/dashboard/metrics) */}
        <LoadErrorBanner what="ITDR metrics" error={metricsError} />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-2">
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Active Threats</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{metrics ? metrics.active_threats_total : 'not available'}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">
              {metrics ? `${metrics.critical_threats_active} critical · ${metrics.high_threats_active} high` : 'requiring investigation'}
            </p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Exposed Credentials</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{metrics ? metrics.credential_exposures_active : 'not available'}</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">pending remediation</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Privileged Identities</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{metrics ? metrics.privileged_identities : 'not available'}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">
              {metrics ? `${metrics.identities_at_risk} at risk (score >= 50) of ${metrics.total_identities}` : 'admin / privileged / elevated'}
            </p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-green-600 dark:text-green-300">MFA Coverage</p>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">
              {metrics && metrics.mfa_coverage_percent !== null ? `${metrics.mfa_coverage_percent}%` : 'Not available'}
            </p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">
              {metrics
                ? metrics.mfa_coverage_percent === null
                  ? 'no identities to measure'
                  : `${metrics.identities_with_mfa} of ${metrics.total_identities} enrolled`
                : 'enrolled users'}
            </p>
          </div>
        </div>
        {metrics && (
          <div className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-gray-600 dark:text-gray-400">
            <span className="flex items-center gap-1"><Clock className="w-3 h-3" />
              Last scan: {metrics.last_scan_timestamp ? new Date(metrics.last_scan_timestamp).toLocaleString() : 'No scan yet'}
            </span>
            <span className="flex items-center gap-1"><Zap className="w-3 h-3" />
              Last directory sync: {metrics.last_directory_sync_at ? new Date(metrics.last_directory_sync_at).toLocaleString() : 'Never'}
            </span>
            <span>
              Identity integrations: {metrics.identity_integrations.length === 0
                ? 'none installed'
                : metrics.identity_integrations.map((i) => `${i.display_name || i.integration_id} (${i.provider})`).join(', ')}
            </span>
            <span>
              By source: {Object.keys(metrics.identities_by_source).length === 0
                ? 'no identities'
                : Object.entries(metrics.identities_by_source).map(([k, v]) => `${k} ${v}`).join(' · ')}
            </span>
            <span>Anomalies pending review: {metrics.anomalies_pending_review}</span>
            <span>Dormant: {metrics.dormant_accounts}</span>
            <span>Active JIT grants: {metrics.jit_access_active}</span>
          </div>
        )}
        {metrics && metrics.jobs.length > 0 && (
          <details className="mt-3">
            <summary className="text-xs text-gray-600 dark:text-gray-400 cursor-pointer">ITDR job runs ({metrics.jobs.length})</summary>
            <div className="mt-2"><JobsList jobs={metrics.jobs} /></div>
          </details>
        )}
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

                {loadErrors.threats ? (
                  <LoadErrorBanner what="identity threats" error={loadErrors.threats} />
                ) : filteredThreats.length === 0 ? (
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
                              <button
                                onClick={() => setRespondThreat(threat)}
                                className="text-orange-600 dark:text-orange-400 hover:underline text-xs font-medium"
                                title="Respond (admin; destructive actions are proposed for approval)"
                              >
                                Respond
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

                {loadErrors.exposures ? (
                  <LoadErrorBanner what="credential exposures" error={loadErrors.exposures} />
                ) : filteredCredentials.length === 0 ? (
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

                {loadErrors.anomalies ? (
                  <LoadErrorBanner what="access anomalies" error={loadErrors.anomalies} />
                ) : filteredAnomalies.length === 0 ? (
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

                {loadErrors.access ? (
                  <LoadErrorBanner what="privileged access events" error={loadErrors.access} />
                ) : filteredPrivileged.length === 0 ? (
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

            {activeTab === 'identities' && (
              <IdentitiesTab identities={identities} loadError={loadErrors.identities} onChanged={refreshAll} />
            )}
          </>
        )}
      </div>

      {respondThreat && (
        <ThreatRespondModal
          threat={respondThreat}
          onClose={() => setRespondThreat(null)}
          onDone={() => {
            queryClient.invalidateQueries({ queryKey: ['itdr-metrics'] });
            loadData();
          }}
        />
      )}

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

// ---------------------------------------------------------------------------
// Wave 3: identity sources, directory sync / CSV import, identity-provider
// actions, auth analysis and the guarded respond path (src/api/v1/endpoints/itdr.py).
// ---------------------------------------------------------------------------

// run_statuses() rows (src/itdr/runs.py)
interface ITDRJob {
  job: string;
  status: string;
  last_run_at?: string | null;
  last_run_rows: number;
  rows_processed_total: number;
  last_error?: string | null;
  last_run_summary: Record<string, unknown>;
}

interface IdentityIntegrationRef {
  integration_id: string;
  provider: string;
  display_name?: string | null;
  health_status?: string | null;
}

// ITDRDashboardMetrics (src/schemas/itdr.py)
interface ITDRMetrics {
  total_identities: number;
  identities_at_risk: number;
  critical_threats_active: number;
  high_threats_active: number;
  credential_exposures_active: number;
  anomalies_pending_review: number;
  service_accounts_over_privileged: number;
  dormant_accounts: number;
  jit_access_active: number;
  last_scan_timestamp: string | null;
  overall_risk_score: number;
  active_threats_total: number;
  privileged_identities: number;
  identities_with_mfa: number;
  mfa_coverage_percent: number | null;
  identities_by_source: Record<string, number>;
  last_directory_sync_at: string | null;
  identity_integrations: IdentityIntegrationRef[];
  jobs: ITDRJob[];
}

// GET /itdr/identity-sources
interface IdentitySources {
  integrations: IdentityIntegrationRef[];
  supported_providers: string[];
  identities_by_source: Record<string, number>;
  jobs: ITDRJob[];
  csv_import: {
    required: string[];
    columns: Record<string, string[]>;
    max_rows: number;
    max_bytes: number;
    list_separator: string;
  };
}

// POST /itdr/identities/sync (src/itdr/tasks.py sync_org_directories)
interface SyncIntegrationResult {
  integration_id: string;
  status: string;
  provider?: string;
  fetched?: number;
  created?: number;
  updated?: number;
  skipped?: number;
  mfa_unchecked?: number;
  capped?: boolean;
  warnings?: unknown[];
  error?: string;
}
interface SyncResult {
  organization_id: string;
  integrations: SyncIntegrationResult[];
}

// IdentityImportResult (src/schemas/itdr.py)
interface ImportResult {
  dry_run: boolean;
  rows_read: number;
  valid_rows: number;
  invalid_rows: number;
  created: number;
  updated: number;
  columns: Record<string, string>;
  errors: { line?: number; error?: string }[];
}

// run_identity_action() (src/itdr/directory.py)
interface IdentityActionResult {
  action: string;
  identity_id: string;
  username: string;
  provider: string | null;
  integration_id: string | null;
  status: string;
  detail: string;
  missing_dependency: string | null;
  error: string | null;
  steps: unknown[];
}

interface AuthBaseline {
  hour_counts?: Record<string, number>;
  source_counts?: Record<string, number>;
  success_total?: number;
  failure_days?: Record<string, number>;
  updated_at?: string;
  method?: string;
}

// IdentityProfileResponse (src/schemas/itdr.py)
interface ITDRIdentity {
  id: string;
  user_id: string;
  username: string;
  email: string;
  display_name?: string | null;
  identity_provider: string;
  privilege_level: string;
  is_service_account: boolean;
  is_dormant: boolean;
  mfa_enabled: boolean;
  risk_score: number;
  last_authentication?: string | null;
  account_status?: string | null;
  source?: string | null;
  source_integration_id?: string | null;
  last_synced_at?: string | null;
  auth_baseline?: AuthBaseline | null;
}

// respond payload identity_provider block
interface IdentityProviderBlock {
  status: string | null;
  tool?: string;
  provider?: string;
  integration_id?: string;
  action?: string;
  proposal_id?: string;
  missing_dependency?: string;
  detail?: string | null;
  audit_log_id?: string;
}

interface RespondResult {
  threat_id: string;
  action: string;
  proposed: boolean;
  executed: boolean;
  status: string;
  threat_status: string;
  results: ({ tool: string } & Record<string, unknown>)[];
  identity_provider?: IdentityProviderBlock;
  proposals?: Record<string, unknown>[];
}

const IDP_ACTIONS: { id: string; label: string }[] = [
  { id: 'disable_account', label: 'Disable account' },
  { id: 'enable_account', label: 'Enable account' },
  { id: 'force_password_reset', label: 'Force password reset' },
  { id: 'revoke_sessions', label: 'Revoke sessions' },
];

// RESPONSE_TOOLS keys (src/api/v1/endpoints/itdr.py)
const RESPOND_ACTIONS: { id: string; label: string; needs?: 'ip' | 'hostname' }[] = [
  { id: 'contain', label: 'Mark contained (no tool)' },
  { id: 'disable_account', label: 'Disable account' },
  { id: 'force_password_reset', label: 'Force password reset' },
  { id: 'block_ip', label: 'Block IP', needs: 'ip' },
  { id: 'isolate_host', label: 'Isolate host', needs: 'hostname' },
  { id: 'quarantine', label: 'Quarantine (account + host)', needs: 'hostname' },
  { id: 'open_incident', label: 'Open incident' },
];

const fmtTime = (v?: string | null) => (v ? new Date(v).toLocaleString() : null);
const humanize = (k: string) => k.replace(/_/g, ' ');
const showValue = (v: unknown): string => {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
};

const JOB_LABELS: Record<string, string> = {
  itdr_scan: 'Identity threat scan',
  itdr_auth: 'Auth-event analysis',
};
const jobLabel = (job: string) =>
  JOB_LABELS[job] ?? (job.startsWith('itdr_sync:') ? `Directory sync (${job.slice('itdr_sync:'.length)})` : job);

function JobsList({ jobs }: { jobs: ITDRJob[] }) {
  if (jobs.length === 0) {
    return <p className="text-sm text-gray-500 dark:text-gray-400">No ITDR job has run for this organisation yet.</p>;
  }
  return (
    <ul className="space-y-2">
      {jobs.map((j) => (
        <li key={j.job} className="text-sm border border-gray-200 dark:border-gray-700 rounded p-2">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{jobLabel(j.job)}</span>
            <span className={clsx('px-2 py-0.5 rounded text-xs', j.status === 'failed'
              ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100'
              : j.status === 'partial' ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100'
              : j.status === 'never_run' ? 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-200'
              : 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100')}>{j.status}</span>
            <span className="text-xs text-gray-500 dark:text-gray-400">
              {fmtTime(j.last_run_at) ? `last run ${fmtTime(j.last_run_at)}` : 'never run'} · {j.last_run_rows} rows last run · {j.rows_processed_total} total
            </span>
          </div>
          {j.last_error && <p className="text-xs text-red-600 dark:text-red-400 mt-1">Error: {j.last_error}</p>}
          {Object.keys(j.last_run_summary ?? {}).length > 0 && (
            <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">
              {Object.entries(j.last_run_summary).map(([k, v]) => `${humanize(k)}: ${showValue(v)}`).join(' · ')}
            </p>
          )}
        </li>
      ))}
    </ul>
  );
}

function IdentityProviderChip({ block }: { block: IdentityProviderBlock }) {
  if (block.status === 'proposed') {
    return (
      <div className="rounded border border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20 p-3 text-sm space-y-1">
        <span className="inline-block px-2 py-0.5 rounded-full text-xs font-medium bg-blue-600 text-white">Proposed — awaiting approval</span>
        <p>
          {block.provider ?? 'identity provider'} · {block.action ?? '—'}
          {block.proposal_id && <> · proposal <span className="font-mono">{block.proposal_id}</span></>}
        </p>
        {block.detail && <p className="text-gray-600 dark:text-gray-300">{block.detail}</p>}
        <Link to="/agentic?tab=approvals" className="text-blue-700 dark:text-blue-300 underline">Open the approvals queue</Link>
      </div>
    );
  }
  if (block.status === 'awaiting_integration') {
    return (
      <div className="rounded border border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-900/20 p-3 text-sm space-y-1">
        <span className="inline-block px-2 py-0.5 rounded-full text-xs font-medium bg-yellow-500 text-white">Awaiting integration</span>
        {(block.provider || block.integration_id || block.action) && (
          <p>
            {[block.provider && `provider ${block.provider}`, block.integration_id && `integration ${block.integration_id}`, block.action && `action ${block.action}`]
              .filter(Boolean).join(' · ')}
          </p>
        )}
        {block.missing_dependency && <p>Missing: {block.missing_dependency}</p>}
        {block.detail && <p className="text-gray-600 dark:text-gray-300">{block.detail}</p>}
      </div>
    );
  }
  return (
    <div className="rounded border border-gray-200 dark:border-gray-700 p-3 text-sm space-y-1">
      <span className="inline-block px-2 py-0.5 rounded-full text-xs font-medium bg-gray-200 dark:bg-gray-700">
        Identity provider: {block.status ?? 'unknown'}
      </span>
      <p>{[block.provider, block.action, block.integration_id].filter(Boolean).join(' · ')}</p>
      {block.detail && <p className="text-gray-600 dark:text-gray-300">{block.detail}</p>}
    </div>
  );
}

function ThreatRespondModal({
  threat,
  onClose,
  onDone,
}: {
  threat: { id: string; threat_type?: string; source_ip?: string | null };
  onClose: () => void;
  onDone: () => void;
}) {
  const [action, setAction] = useState('disable_account');
  const [ip, setIp] = useState(threat.source_ip ?? '');
  const [hostname, setHostname] = useState('');
  const [propose, setPropose] = useState(true);
  const needs = RESPOND_ACTIONS.find((a) => a.id === action)?.needs;
  const mutation = useMutation({
    mutationFn: async () => {
      const details: Record<string, unknown> = { propose_actions: propose };
      if (ip.trim()) details.ip = ip.trim();
      if (hostname.trim()) details.hostname = hostname.trim();
      const res = await api.post<RespondResult>(`/itdr/threats/${threat.id}/respond`, {
        threat_id: threat.id,
        action_type: action,
        action_details: details,
      });
      return res.data;
    },
    onSuccess: () => onDone(),
  });
  const result = mutation.data;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[36rem] max-h-[85vh] overflow-y-auto space-y-4" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-xl font-bold">Respond to {threat.threat_type ?? 'threat'}</h2>
        <p className="text-xs text-gray-500 dark:text-gray-400">
          Runs through the guarded agent runtime (admin only). Destructive actions are proposed for approval, never executed inline.
        </p>
        <div>
          <label className="block text-sm font-medium mb-1">Action</label>
          <select value={action} onChange={(e) => setAction(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
            {RESPOND_ACTIONS.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
          </select>
        </div>
        {needs === 'ip' && (
          <div>
            <label className="block text-sm font-medium mb-1">IP address</label>
            <input value={ip} onChange={(e) => setIp(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
          </div>
        )}
        {needs === 'hostname' && (
          <div>
            <label className="block text-sm font-medium mb-1">Hostname</label>
            <input value={hostname} onChange={(e) => setHostname(e.target.value)} className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
          </div>
        )}
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={propose} onChange={(e) => setPropose(e.target.checked)} />
          Propose destructive actions for approval (unchecked: they are refused)
        </label>

        <ActionErrorBanner what="respond to this threat" error={mutation.error} />

        {result && (
          <div className="space-y-2 text-sm">
            <p>
              Result: <span className="font-semibold">{result.status}</span> · threat status {result.threat_status}
            </p>
            {result.results.length > 0 && (
              <ul className="list-disc ml-5">
                {result.results.map((r, i) => (
                  <li key={i}>
                    {r.tool}: {r.proposed ? 'proposed for approval' : showValue(r.status ?? r.result ?? 'executed')}
                  </li>
                ))}
              </ul>
            )}
            {result.identity_provider && <IdentityProviderChip block={result.identity_provider} />}
            {result.proposed && !result.identity_provider && (
              <Link to="/agentic?tab=approvals" className="text-blue-700 dark:text-blue-300 underline">Open the approvals queue</Link>
            )}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700">Close</button>
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending || (needs === 'hostname' && !hostname.trim()) || (needs === 'ip' && !ip.trim())}
            className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg disabled:opacity-50"
          >
            {mutation.isPending ? 'Submitting…' : 'Respond'}
          </button>
        </div>
      </div>
    </div>
  );
}

function IdentityActionCell({ identity, onDone }: { identity: ITDRIdentity; onDone: () => void }) {
  const [action, setAction] = useState('');
  const mutation = useMutation({
    mutationFn: async (a: string) =>
      (await api.post<IdentityActionResult>(`/itdr/identities/${identity.id}/actions/${a}`, { reason: '' })).data,
    onSuccess: () => onDone(),
  });
  const r = mutation.data;
  return (
    <div className="space-y-1 min-w-[14rem]">
      <div className="flex gap-1">
        <select value={action} onChange={(e) => setAction(e.target.value)} className="px-2 py-1 text-xs border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700">
          <option value="">Directory action…</option>
          {IDP_ACTIONS.map((a) => <option key={a.id} value={a.id}>{a.label}</option>)}
        </select>
        <button
          disabled={!action || mutation.isPending}
          onClick={() => {
            if (window.confirm(`${IDP_ACTIONS.find((a) => a.id === action)?.label} for ${identity.username} in its identity provider?`)) {
              mutation.mutate(action);
            }
          }}
          className="px-2 py-1 text-xs rounded bg-red-600 text-white disabled:opacity-50"
        >
          {mutation.isPending ? '…' : 'Run'}
        </button>
      </div>
      <ActionErrorBanner what={`run ${humanize(mutation.variables ?? 'the action')} on ${identity.username}`} error={mutation.error} />
      {r && (
        <div className={clsx('text-xs rounded p-2', r.status === 'executed'
          ? 'bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-200'
          : 'bg-yellow-50 dark:bg-yellow-900/20 text-yellow-800 dark:text-yellow-200')}>
          <p className="font-medium">{r.status === 'executed' ? 'Executed' : r.status === 'awaiting_integration' ? 'Awaiting integration' : r.status}{r.provider ? ` (${r.provider})` : ''}</p>
          {r.detail && <p>{r.detail}</p>}
          {r.missing_dependency && <p>Missing: {r.missing_dependency}</p>}
          {r.error && <p>Error: {r.error}</p>}
        </div>
      )}
    </div>
  );
}

function IdentitySourcesPanel({ onChanged }: { onChanged: () => void }) {
  const queryClient = useQueryClient();
  const { data: sources, error: sourcesError } = useQuery({
    queryKey: ['itdr-identity-sources'],
    queryFn: async () => (await api.get<IdentitySources>('/itdr/identity-sources')).data,
  });
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['itdr-identity-sources'] });
    queryClient.invalidateQueries({ queryKey: ['itdr-metrics'] });
    onChanged();
  };
  const sync = useMutation({
    mutationFn: async () => (await api.post<SyncResult>('/itdr/identities/sync')).data,
    onSuccess: refresh,
  });
  const auth = useMutation({
    mutationFn: async () => (await api.post<Record<string, unknown>>('/itdr/auth-analysis/run')).data,
    onSuccess: refresh,
  });
  const [file, setFile] = useState<File | null>(null);
  const [dryRun, setDryRun] = useState(true);
  const importMut = useMutation({
    mutationFn: async ({ f, dry }: { f: File; dry: boolean }) => {
      const form = new FormData();
      form.append('file', f);
      return (await api.post<ImportResult>('/itdr/identities/import', form, { params: { dry_run: dry } })).data;
    },
    onSuccess: (res) => {
      if (!res.dry_run) refresh();
    },
  });
  const imported = importMut.data;

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 space-y-4">
      <h3 className="font-semibold">Identity sources</h3>
      <LoadErrorBanner what="identity sources" error={sourcesError} />
      {sources && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div className="space-y-2">
            <p className="font-medium">Directory integrations</p>
            {sources.integrations.length === 0 ? (
              <p className="text-gray-500 dark:text-gray-400">
                No active identity-provider integration. Supported: {sources.supported_providers.join(', ')}. Install one under
                Integrations, or import a CSV export below (the Active Directory path; there is no LDAP connector).
              </p>
            ) : (
              <ul className="list-disc ml-5">
                {sources.integrations.map((i) => (
                  <li key={i.integration_id}>
                    {i.display_name || i.integration_id} ({i.provider}){i.health_status ? ` · health ${i.health_status}` : ''}
                  </li>
                ))}
              </ul>
            )}
            <p className="font-medium pt-2">Identities by source</p>
            {Object.keys(sources.identities_by_source).length === 0 ? (
              <p className="text-gray-500 dark:text-gray-400">No identities yet.</p>
            ) : (
              <p>{Object.entries(sources.identities_by_source).map(([k, v]) => `${k}: ${v}`).join(' · ')}</p>
            )}
          </div>
          <div>
            <p className="font-medium mb-1">Jobs</p>
            <JobsList jobs={sources.jobs} />
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        <button onClick={() => sync.mutate()} disabled={sync.isPending} className="px-3 py-2 text-sm rounded-lg bg-blue-600 text-white disabled:opacity-50">
          {sync.isPending ? 'Syncing…' : 'Sync identities'}
        </button>
        <button onClick={() => auth.mutate()} disabled={auth.isPending} className="px-3 py-2 text-sm rounded-lg bg-indigo-600 text-white disabled:opacity-50">
          {auth.isPending ? 'Analysing…' : 'Run auth analysis'}
        </button>
      </div>
      <ActionErrorBanner what="sync identities" error={sync.error} />
      <ActionErrorBanner what="run the auth-event analysis" error={auth.error} />
      {sync.data && (
        <ul className="text-sm space-y-1">
          {sync.data.integrations.map((i) => (
            <li key={i.integration_id} className={i.status === 'failed' ? 'text-red-600 dark:text-red-400' : ''}>
              {i.provider ?? i.integration_id}: {i.status}
              {i.status === 'failed'
                ? ` — ${i.error ?? 'no detail'}`
                : ` — fetched ${i.fetched ?? 0}, created ${i.created ?? 0}, updated ${i.updated ?? 0}, skipped ${i.skipped ?? 0}${i.mfa_unchecked ? `, MFA not checked for ${i.mfa_unchecked}` : ''}${i.capped ? ' (per-run cap reached)' : ''}`}
              {Array.isArray(i.warnings) && i.warnings.length > 0 && (
                <span className="block text-xs text-yellow-700 dark:text-yellow-300">Warnings: {i.warnings.map(showValue).join('; ')}</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {auth.data && (
        <p className="text-sm">
          Auth analysis: {Object.entries(auth.data).filter(([k]) => k !== 'organization_id').map(([k, v]) => `${humanize(k)} ${showValue(v)}`).join(' · ')}
        </p>
      )}

      <div className="border-t border-gray-200 dark:border-gray-700 pt-3 space-y-2">
        <p className="font-medium text-sm">Import CSV (Active Directory or any directory export)</p>
        {sources && (
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Required: {sources.csv_import.required.join(', ')}. Up to {sources.csv_import.max_rows} rows / {sources.csv_import.max_bytes} bytes.
            List columns separated by {sources.csv_import.list_separator}. Accepted headers:{' '}
            {Object.entries(sources.csv_import.columns).map(([k, v]) => `${k} (${v.join('/')})`).join('; ')}
          </p>
        )}
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <input type="file" accept=".csv,text/csv" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          <label className="flex items-center gap-1">
            <input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} />
            Dry run (validate only)
          </label>
          <button
            disabled={!file || importMut.isPending}
            onClick={() => file && importMut.mutate({ f: file, dry: dryRun })}
            className="px-3 py-2 rounded-lg bg-gray-800 dark:bg-gray-600 text-white disabled:opacity-50"
          >
            {importMut.isPending ? 'Importing…' : dryRun ? 'Validate CSV' : 'Import CSV'}
          </button>
        </div>
        <ActionErrorBanner what="import the CSV" error={importMut.error} />
        {imported && (
          <div className="text-sm rounded border border-gray-200 dark:border-gray-700 p-2 space-y-1">
            <p className="font-medium">{imported.dry_run ? 'Dry run — nothing written' : 'Imported'}</p>
            <p>
              Rows read {imported.rows_read} · valid {imported.valid_rows} · invalid {imported.invalid_rows}
              {!imported.dry_run && ` · created ${imported.created} · updated ${imported.updated}`}
            </p>
            {Object.keys(imported.columns).length > 0 && (
              <p className="text-xs text-gray-500 dark:text-gray-400">
                Columns: {Object.entries(imported.columns).map(([k, v]) => `${k} ← ${v}`).join(', ')}
              </p>
            )}
            {imported.errors.length > 0 && (
              <ul className="list-disc ml-5 text-xs text-red-600 dark:text-red-400">
                {imported.errors.map((e, i) => <li key={i}>{e.line !== undefined ? `Line ${e.line}: ` : ''}{e.error ?? showValue(e)}</li>)}
              </ul>
            )}
          </div>
        )}
      </div>
      <AddIdentityForm onCreated={refresh} />
    </div>
  );
}

// POST /itdr/identities: one identity entered by hand, for accounts no
// directory integration or CSV export covers. Risk starts at the server's
// default and is computed by the ITDR analysis, not entered here.
function AddIdentityForm({ onCreated }: { onCreated: () => void }) {
  const gate = useRoleGate();
  const empty = {
    user_id: '', username: '', email: '', display_name: '', identity_provider: 'active_directory',
    privilege_level: 'standard', is_service_account: false, mfa_enabled: false, groups: '',
  };
  const [form, setForm] = useState(empty);
  const create = useMutation({
    mutationFn: async () =>
      (await api.post<ITDRIdentity>('/itdr/identities', {
        user_id: form.user_id.trim(),
        username: form.username.trim(),
        email: form.email.trim(),
        display_name: form.display_name.trim() || null,
        identity_provider: form.identity_provider,
        privilege_level: form.privilege_level,
        is_service_account: form.is_service_account,
        mfa_enabled: form.mfa_enabled,
        group_memberships: form.groups.split(',').map((g) => g.trim()).filter(Boolean),
      })).data,
    onSuccess: () => {
      setForm(empty);
      onCreated();
    },
  });
  const cls = 'px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-sm';
  const ready = form.user_id.trim() && form.username.trim() && form.email.trim().length >= 5;
  return (
    <form
      className="border-t border-gray-200 dark:border-gray-700 pt-3 space-y-2"
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate();
      }}
    >
      <p className="font-medium text-sm">Add one identity by hand</p>
      <p className="text-xs text-gray-500 dark:text-gray-400">
        For an account no directory sync or CSV covers. MFA enrolment is what you state here; nothing verifies it against
        the identity provider.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <input value={form.user_id} onChange={(e) => setForm({ ...form, user_id: e.target.value })} placeholder="Directory user id *" className={cls} disabled={!gate.isAnalyst} />
        <input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} placeholder="Username *" className={cls} disabled={!gate.isAnalyst} />
        <input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} placeholder="Email *" className={cls} disabled={!gate.isAnalyst} />
        <input value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} placeholder="Display name" className={cls} disabled={!gate.isAnalyst} />
        <select value={form.identity_provider} onChange={(e) => setForm({ ...form, identity_provider: e.target.value })} className={cls} disabled={!gate.isAnalyst}>
          {['active_directory', 'azure_ad', 'okta', 'ping', 'custom_saml', 'ldap'].map((p) => <option key={p} value={p}>{humanize(p)}</option>)}
        </select>
        <select value={form.privilege_level} onChange={(e) => setForm({ ...form, privilege_level: e.target.value })} className={cls} disabled={!gate.isAnalyst}>
          {['standard', 'elevated', 'admin', 'service_account', 'privileged_access'].map((p) => <option key={p} value={p}>{humanize(p)}</option>)}
        </select>
        <input value={form.groups} onChange={(e) => setForm({ ...form, groups: e.target.value })} placeholder="Groups (comma separated)" className={cls} disabled={!gate.isAnalyst} />
        <label className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={form.is_service_account} onChange={(e) => setForm({ ...form, is_service_account: e.target.checked })} disabled={!gate.isAnalyst} />
          Service account
        </label>
        <label className="flex items-center gap-1 text-sm">
          <input type="checkbox" checked={form.mfa_enabled} onChange={(e) => setForm({ ...form, mfa_enabled: e.target.checked })} disabled={!gate.isAnalyst} />
          MFA enrolled (stated)
        </label>
      </div>
      <button
        type="submit"
        disabled={!gate.isAnalyst || !ready || create.isPending}
        title={gate.isAnalyst ? undefined : ANALYST_ONLY_REASON}
        className="px-3 py-2 text-sm rounded-lg bg-blue-600 text-white disabled:opacity-50"
      >
        {create.isPending ? 'Adding…' : 'Add identity'}
      </button>
      {!gate.isAnalyst && <p className="text-xs text-gray-500">{ANALYST_ONLY_REASON}</p>}
      <ActionErrorBanner what="add the identity" error={create.error} />
      {create.data && (
        <p className="text-xs text-green-700 dark:text-green-400">
          Added {create.data.username} ({String(create.data.id).slice(0, 8)}).
        </p>
      )}
    </form>
  );
}

function AuthBaselineSummary({ baseline }: { baseline?: AuthBaseline | null }) {
  if (!baseline) return <span className="text-gray-400" title="No authentication events analysed for this identity yet">—</span>;
  const sources = Object.keys(baseline.source_counts ?? {}).length;
  const hours = Object.keys(baseline.hour_counts ?? {}).length;
  return (
    <span title={baseline.method ?? ''}>
      {baseline.success_total ?? 0} sign-ins · {hours} hours · {sources} sources
      {baseline.updated_at && <span className="block text-xs text-gray-500 dark:text-gray-400">updated {fmtTime(baseline.updated_at)}</span>}
    </span>
  );
}

function IdentitiesTab({
  identities,
  loadError,
  onChanged,
}: {
  identities: ITDRIdentity[];
  loadError: unknown;
  onChanged: () => void;
}) {
  return (
    <div className="space-y-6">
      <IdentitySourcesPanel onChanged={onChanged} />
      {loadError ? (
        <LoadErrorBanner what="identities" error={loadError} />
      ) : identities.length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">No identities yet. Sync a directory integration or import a CSV.</p>
      ) : (
        <div className="bg-white dark:bg-gray-800 rounded-lg overflow-x-auto border border-gray-200 dark:border-gray-700">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700 text-left">
                <th className="px-4 py-3">Identity</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Account</th>
                <th className="px-4 py-3">Privilege</th>
                <th className="px-4 py-3">MFA</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Last synced</th>
                <th className="px-4 py-3">Sign-in baseline</th>
                <th className="px-4 py-3">Directory action</th>
              </tr>
            </thead>
            <tbody>
              {identities.map((i) => (
                <tr key={i.id} className="border-b border-gray-200 dark:border-gray-700 align-top">
                  <td className="px-4 py-3">
                    <p className="font-medium">{i.display_name || i.username}</p>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{i.email}</p>
                  </td>
                  <td className="px-4 py-3">
                    {i.source ?? 'manual'}
                    {i.source_integration_id && <span className="block text-xs text-gray-500 dark:text-gray-400 font-mono">{i.source_integration_id}</span>}
                  </td>
                  <td className="px-4 py-3">{i.account_status ?? <span className="text-gray-400" title="The source did not report an account status">—</span>}</td>
                  <td className="px-4 py-3">{i.privilege_level}{i.is_service_account ? ' (service)' : ''}{i.is_dormant ? ' · dormant' : ''}</td>
                  <td className="px-4 py-3">{i.mfa_enabled ? 'Enrolled' : 'Not enrolled'}</td>
                  <td className="px-4 py-3">{i.risk_score}</td>
                  <td className="px-4 py-3">{fmtTime(i.last_synced_at) ?? <span className="text-gray-400" title="Never synced from a directory">—</span>}</td>
                  <td className="px-4 py-3"><AuthBaselineSummary baseline={i.auth_baseline} /></td>
                  <td className="px-4 py-3"><IdentityActionCell identity={i} onDone={onChanged} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
