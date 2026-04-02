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
  const [piaForm, setPiaForm] = useState({
    name: '',
    project_name: '',
    assessment_type: 'full',
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
    consent_mechanism: 'web_form',
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

  const { data: statsData } = useQuery({
    queryKey: ['privacy-stats'],
    queryFn: async () => (await api.get('/privacy/dashboard/stats')).data,
  });

  const { data: dsrData, isLoading: dsrLoading } = useQuery({
    queryKey: ['privacy-dsrs'],
    queryFn: async () => (await api.get('/privacy/dsr/requests')).data,
  });

  const { data: piaData, isLoading: piaLoading } = useQuery({
    queryKey: ['privacy-pias'],
    queryFn: async () => (await api.get('/privacy/pia/assessments')).data,
  });

  const { data: consentData, isLoading: consentLoading } = useQuery({
    queryKey: ['privacy-consent', consentSubjectId],
    queryFn: async () => {
      if (!consentSubjectId) return [];
      return (await api.get(`/privacy/consent/records/${consentSubjectId}`)).data;
    },
    enabled: activeTab === 'consent',
  });

  const { data: ropaData, isLoading: ropaLoading } = useQuery({
    queryKey: ['privacy-ropa'],
    queryFn: async () => (await api.get('/privacy/ropa/processing-records')).data,
  });

  const { data: incidentData, isLoading: incidentLoading } = useQuery({
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
      setPiaForm({ name: '', project_name: '', assessment_type: 'full', data_types_processed: '', processing_purposes: '', legal_basis: 'consent' });
    },
  });

  const createConsent = useMutation({
    mutationFn: async (body: typeof consentForm) => (await api.post('/privacy/consent/records', body)).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['privacy-consent'] });
      setShowCreateConsent(false);
      setConsentForm({ subject_id: '', purpose: '', legal_basis: 'consent', consent_given: true, consent_mechanism: 'web_form' });
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

        {/* Stats Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-white rounded-lg border border-gray-200 p-5">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm text-gray-500">Total DSRs</p>
                <p className="text-2xl font-bold text-gray-900 mt-1">{statsData?.total_dsrs ?? dsrs.length}</p>
              </div>
              <UserCheck className="w-6 h-6 text-indigo-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-5">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm text-gray-500">Pending DSRs</p>
                <p className="text-2xl font-bold text-yellow-600 mt-1">{statsData?.pending_dsrs ?? '-'}</p>
              </div>
              <Clock className="w-6 h-6 text-yellow-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-5">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm text-gray-500">DSR Compliance Rate</p>
                <p className="text-2xl font-bold text-green-600 mt-1">
                  {statsData?.dsr_compliance_rate != null ? `${statsData.dsr_compliance_rate}%` : '-'}
                </p>
              </div>
              <Scale className="w-6 h-6 text-green-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 p-5">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-sm text-gray-500">Active PIAs</p>
                <p className="text-2xl font-bold text-purple-600 mt-1">{statsData?.active_pias ?? pias.length}</p>
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
              <button
                onClick={() => setShowCreateDSR(true)}
                className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm flex items-center gap-2"
              >
                <Plus className="w-4 h-4" /> New DSR
              </button>
            </div>
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
                      <tr key={row?.id} className="border-t border-gray-100 hover:bg-gray-50">
                        <td className="px-4 py-3 text-sm font-mono text-indigo-600">{row?.id || ''}</td>
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
                        <td className="px-4 py-3 text-sm text-gray-600">{row?.deadline || ''}</td>
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
                          <span className={`px-2 py-0.5 rounded text-xs font-medium ${riskBadgeClass(pia?.risk_level || '')}`}>
                            {pia?.risk_level || ''}
                          </span>
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
                        <td className="px-4 py-3 text-sm text-gray-600">{rec?.retention_period_days ?? ''}</td>
                        <td className="px-4 py-3 text-sm text-gray-500">{rec?.created_at?.slice(0, 10) || ''}</td>
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
              {createDSR.isError && <p className="text-red-500 text-xs mt-2">Failed to create DSR. Please try again.</p>}
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
                    <input type="text" value={piaForm.assessment_type} onChange={(e) => setPiaForm({ ...piaForm, assessment_type: e.target.value })} className="w-full border border-gray-300 rounded px-3 py-2 text-sm" placeholder="full, targeted, etc." />
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
              {createPIA.isError && <p className="text-red-500 text-xs mt-2">Failed to create PIA. Please try again.</p>}
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
              {createConsent.isError && <p className="text-red-500 text-xs mt-2">Failed to create consent record.</p>}
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
                  onClick={() => createROPA.mutate({
                    ...ropaForm,
                    data_categories: ropaForm.data_categories.split(',').map((s) => s.trim()).filter(Boolean),
                    data_subjects: ropaForm.data_subjects.split(',').map((s) => s.trim()).filter(Boolean),
                    recipients: ropaForm.recipients.split(',').map((s) => s.trim()).filter(Boolean),
                  })}
                  disabled={createROPA.isPending || !ropaForm.name || !ropaForm.purpose}
                  className="flex-1 bg-indigo-600 hover:bg-indigo-700 disabled:bg-indigo-300 text-white px-4 py-2 rounded-lg text-sm"
                >
                  {createROPA.isPending ? 'Creating...' : 'Create Record'}
                </button>
              </div>
              {createROPA.isError && <p className="text-red-500 text-xs mt-2">Failed to create processing record.</p>}
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
              </div>
              <div className="flex gap-3 mt-5">
                <button onClick={() => setShowCreateIncident(false)} className="flex-1 border border-gray-300 text-gray-700 px-4 py-2 rounded-lg text-sm hover:bg-gray-50">Cancel</button>
                <button
                  onClick={() => createIncident.mutate({
                    ...incidentForm,
                    data_types_affected: incidentForm.data_types_affected.split(',').map((s) => s.trim()).filter(Boolean),
                  })}
                  disabled={createIncident.isPending || !incidentForm.title || !incidentForm.description}
                  className="flex-1 bg-red-600 hover:bg-red-700 disabled:bg-red-300 text-white px-4 py-2 rounded-lg text-sm"
                >
                  {createIncident.isPending ? 'Reporting...' : 'Report Incident'}
                </button>
              </div>
              {createIncident.isError && <p className="text-red-500 text-xs mt-2">Failed to report incident.</p>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
