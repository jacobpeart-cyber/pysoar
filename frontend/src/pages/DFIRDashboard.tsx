import React, { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  FileSearch,
  Clock,
  Scale,
  Database,
  Plus,
  Edit,
  CheckCircle,
  AlertCircle,
  Search,
  Filter,
  Download,
  Eye,
  Loader2,
  Server,
  RefreshCw,
  ShieldCheck,
  FileText,
} from 'lucide-react';
import clsx from 'clsx';
import { dfirApi } from '../api/endpoints';
import { api } from '../api/client';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import { describeLoadError } from '../lib/loadError';

const NA = 'not available';

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
    case 'open':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'in-progress':
    case 'in_progress':
      return 'bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-100';
    case 'closed':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

/** Safely uppercase a value, returning '' for nullish inputs */
const safeUpper = (val: any): string => (val ? String(val).toUpperCase() : '');

/** Safely call toLocaleString, returning fallback for nullish inputs */
const safeLocale = (val: any, fallback = 'N/A'): string => {
  if (val == null) return fallback;
  try {
    return new Date(val || "").toLocaleString();
  } catch {
    return String(val);
  }
};

/** Format bytes into human-readable size */
const formatBytes = (bytes: any): string => {
  if (bytes == null) return 'N/A';
  const n = Number(bytes);
  if (isNaN(n)) return 'N/A';
  if (n === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(n) / Math.log(1024));
  return `${(n / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
};

/** Extract items array from a potentially paginated API response */
const extractItems = (data: any): any[] => {
  if (Array.isArray(data)) return data;
  if (data?.items && Array.isArray(data.items)) return data.items;
  return [];
};

// ---------------------------------------------------------------------------
// Wave 3 contract types (src/schemas/dfir.py)
// ---------------------------------------------------------------------------

interface EvidenceRow {
  id: string;
  evidence_type?: string;
  source_device?: string;
  storage_location?: string;
  storage_kind?: 'local' | 'remote' | 'none';
  collection_status?: string | null;
  collection_command_id?: string | null;
  collection_agent_id?: string | null;
  collection_error?: string | null;
}

interface CollectResponse {
  status: string;
  detail: string;
  evidence: EvidenceRow | null;
  command_id: string | null;
  agent_id: string | null;
  agent_hostname: string | null;
}

interface EvidenceVerification {
  algorithm: string;
  reference: string;
  computed_hash: string | null;
  stored_hash: string | null;
  file_matches_stored_hash: boolean | null;
  claimed_hash_matches: boolean | null;
  is_valid: boolean;
}

interface ReconstructResponse {
  case_id: string;
  created: number;
  already_present: number;
  from_custody: number;
  from_artifacts: number;
  truncated: boolean;
}

interface IocExtractionResult {
  iocs_extracted: number;
  artifacts_scanned: number;
  evidence_files_scanned: number;
  evidence_files_truncated: number;
  evidence_skipped: { evidence_id: string; reason: string }[];
  scan_artifacts_written: number;
}

const REMOTE_LOCATION_RE = /^(https:\/\/|s3:\/\/)/;

const inputCls =
  'w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100';

interface HttpErrorLike {
  response?: { status?: number; data?: unknown };
}

/** HTTP status of a failed axios request, or undefined. */
const httpStatus = (err: unknown): number | undefined =>
  (err as HttpErrorLike | null)?.response?.status;

/** The `error` code of a `{detail: {error, detail}}` body, or undefined. */
const errorCode = (err: unknown): string | undefined => {
  const data = (err as HttpErrorLike | null)?.response?.data as { detail?: unknown } | undefined;
  const d = data?.detail;
  if (d && typeof d === 'object' && 'error' in d) return String((d as { error: unknown }).error);
  return undefined;
};

/** For a 501, the backend's reason text; otherwise null. */
const notImplementedReason = (err: unknown): string | null => {
  if (httpStatus(err) !== 501) return null;
  const data = (err as HttpErrorLike).response?.data as { detail?: unknown } | undefined;
  const d = data?.detail;
  if (typeof d === 'string') return d;
  if (d && typeof d === 'object' && 'detail' in d) return String((d as { detail: unknown }).detail);
  return 'the server reported this feature as not implemented';
};

/** A blob-typed request's error body is a Blob; parse it so the banners can read it. */
const parseBlobError = async (err: unknown): Promise<unknown> => {
  const resp = (err as HttpErrorLike | null)?.response;
  if (resp && resp.data instanceof Blob) {
    try {
      resp.data = JSON.parse(await resp.data.text());
    } catch {
      /* body was not JSON; leave the status line to speak for itself */
    }
  }
  return err;
};

const saveBlob = (blob: Blob, filename: string) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

const collectionStatusColor = (s: string | null | undefined): string => {
  switch (s) {
    case 'collected':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'collected_on_host':
      return 'bg-teal-100 dark:bg-teal-900 text-teal-800 dark:text-teal-100';
    case 'pending':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'awaiting_approval':
      return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
    case 'failed':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

const STORAGE_KIND_LABEL: Record<string, string> = {
  local: 'Held by PySOAR',
  remote: 'Remote object',
  none: 'No bytes stored',
};

export default function DFIRDashboard() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState('cases');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCase, setSelectedCase] = useState<any>(null);
  const [showNewCaseModal, setShowNewCaseModal] = useState(false);
  const [showFilterPanel, setShowFilterPanel] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [viewDetailItem, setViewDetailItem] = useState<any>(null);
  const [viewDetailType, setViewDetailType] = useState<string>('');

  // New Case form state
  const [newCaseTitle, setNewCaseTitle] = useState('');
  const [newCaseNumber, setNewCaseNumber] = useState('');
  const [newCaseDescription, setNewCaseDescription] = useState('');
  const [newCaseSeverity, setNewCaseSeverity] = useState('medium');
  const [newCaseType, setNewCaseType] = useState('incident_response');
  const [newCaseError, setNewCaseError] = useState('');

  // Edit Case modal state
  const [showEditCaseModal, setShowEditCaseModal] = useState(false);
  const [editCaseItem, setEditCaseItem] = useState<any>(null);
  const [editCaseTitle, setEditCaseTitle] = useState('');
  const [editCaseDescription, setEditCaseDescription] = useState('');
  const [editCaseSeverity, setEditCaseSeverity] = useState('medium');
  const [editCaseStatus, setEditCaseStatus] = useState('open');
  const [editCaseError, setEditCaseError] = useState('');

  // Edit Legal Hold modal state
  const [showEditHoldModal, setShowEditHoldModal] = useState(false);
  const [editHoldItem, setEditHoldItem] = useState<any>(null);
  const [editHoldType, setEditHoldType] = useState('');
  const [editHoldStatus, setEditHoldStatus] = useState('');
  const [editHoldCustodians, setEditHoldCustodians] = useState('');
  const [editHoldError, setEditHoldError] = useState('');

  // New Evidence modal state
  const [showNewEvidenceModal, setShowNewEvidenceModal] = useState(false);
  const [newEvidenceError, setNewEvidenceError] = useState<unknown>(null);
  const [newEvidenceMode, setNewEvidenceMode] = useState<'upload' | 'remote'>('upload');
  const [showCollectModal, setShowCollectModal] = useState(false);
  const [verifyItem, setVerifyItem] = useState<EvidenceRow | null>(null);
  const [downloadError, setDownloadError] = useState<unknown>(null);
  const [caseReportError, setCaseReportError] = useState<unknown>(null);

  // New Legal Hold modal state
  const [showNewHoldModal, setShowNewHoldModal] = useState(false);
  const [newHoldError, setNewHoldError] = useState('');

  // Data queries
  const { data: casesData, isLoading: casesLoading, error: casesError } = useQuery({
    queryKey: ['dfir-cases'],
    queryFn: () => dfirApi.getCases(),
  });

  // Shared axios client: carries the bearer token (the old raw fetch sent
  // none, always 401'd and silently fell back to first-page counts).
  const { data: dashboardData, isLoading: dashboardLoading, error: dashboardError } = useQuery({
    queryKey: ['dfir-dashboard'],
    queryFn: async () => {
      const response = await api.get('/dfir/dashboard/metrics');
      return response.data;
    },
  });

  // Evidence, timeline, legal holds depend on having a selected case
  const activeCaseId = selectedCase?.id;

  const { data: evidenceData, isLoading: evidenceLoading, error: evidenceError } = useQuery({
    queryKey: ['dfir-evidence', activeCaseId],
    queryFn: () => dfirApi.getEvidence(activeCaseId as string),
    enabled: !!activeCaseId,
  });

  const { data: timelineData, isLoading: timelineLoading, error: timelineError } = useQuery({
    queryKey: ['dfir-timeline', activeCaseId],
    queryFn: () => dfirApi.getTimeline(activeCaseId as string),
    enabled: !!activeCaseId,
  });

  const { data: legalHoldsData, isLoading: holdsLoading, error: holdsError } = useQuery({
    queryKey: ['dfir-legal-holds', activeCaseId],
    queryFn: async () => {
      const response = await api.get(`/dfir/cases/${activeCaseId}/legal-holds`);
      return response.data;
    },
    enabled: !!activeCaseId,
  });

  // Extract items from paginated responses
  const cases = extractItems(casesData);
  const evidence = extractItems(evidenceData);
  const timeline = extractItems(timelineData);
  const legalHolds = extractItems(legalHoldsData);

  // Create case mutation
  const createCaseMutation = useMutation({
    mutationFn: (data: { case_number: string; title: string; description: string; severity: string; case_type: string }) =>
      dfirApi.createCase(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dfir-cases'] });
      queryClient.invalidateQueries({ queryKey: ['dfir-dashboard'] });
      setShowNewCaseModal(false);
      resetNewCaseForm();
    },
    onError: (err: any) => {
      setNewCaseError(`Failed to create case: ${describeLoadError(err)}`);
    },
  });

  // Edit case mutation
  const editCaseMutation = useMutation({
    mutationFn: (data: { caseId: string; title: string; description: string; severity: string; status: string }) =>
      dfirApi.updateCase(data.caseId, { title: data.title, description: data.description, severity: data.severity, status: data.status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dfir-cases'] });
      queryClient.invalidateQueries({ queryKey: ['dfir-dashboard'] });
      setShowEditCaseModal(false);
      setEditCaseItem(null);
      setEditCaseError('');
    },
    onError: (err: any) => {
      setEditCaseError(`Failed to update case: ${describeLoadError(err)}`);
    },
  });

  // Edit legal hold mutation
  const editHoldMutation = useMutation({
    mutationFn: (data: { holdId: string; hold_type: string; status: string; custodians: string[] }) =>
      dfirApi.updateLegalHold(data.holdId, { hold_type: data.hold_type, status: data.status, custodians: data.custodians }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dfir-legal-holds'] });
      queryClient.invalidateQueries({ queryKey: ['dfir-dashboard'] });
      setShowEditHoldModal(false);
      setEditHoldItem(null);
      setEditHoldError('');
    },
    onError: (err: any) => {
      setEditHoldError(`Failed to update legal hold: ${describeLoadError(err)}`);
    },
  });

  const resetNewCaseForm = () => {
    setNewCaseTitle('');
    setNewCaseNumber('');
    setNewCaseDescription('');
    setNewCaseSeverity('medium');
    setNewCaseType('incident_response');
    setNewCaseError('');
  };

  const handleCreateCase = () => {
    if (!newCaseTitle.trim()) {
      setNewCaseError('Case title is required');
      return;
    }
    if (!newCaseNumber.trim()) {
      setNewCaseError('Case number is required');
      return;
    }
    setNewCaseError('');
    createCaseMutation.mutate({
      case_number: newCaseNumber,
      title: newCaseTitle,
      description: newCaseDescription,
      severity: newCaseSeverity,
      case_type: newCaseType,
    });
  };

  const loading = casesLoading || dashboardLoading;
  const error = casesError;

  // Org-wide counts come only from GET /dfir/dashboard/metrics. No
  // fallback to the first page of cases or the selected case's evidence,
  // which used to be presented as global totals.
  const activeCases = dashboardData?.active_cases ?? NA;
  const totalCases = dashboardData?.total_cases ?? NA;
  const evidenceCount = dashboardData?.total_evidence_items ?? NA;
  const activeHoldsCount = dashboardData?.legal_holds_active ?? NA;
  const criticalCases = dashboardData?.critical_cases ?? NA;
  const highCases = dashboardData?.high_cases ?? NA;
  const collectionsPending = dashboardData?.collections_pending ?? NA;
  // DFIRDashboardResponse has no resolution-time metric, so the old
  // "Avg Resolution" card (always "not available") is gone.

  const filteredCases = cases.filter((c: any) => {
    const matchesSearch =
      !searchQuery ||
      (c?.title || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (c?.case_number || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (c?.lead_investigator_id || '').toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = severityFilter === 'all' || c?.severity === severityFilter;
    const matchesStatus = statusFilter === 'all' || c?.status === statusFilter;
    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const filteredEvidence = evidence.filter((e: any) =>
    !searchQuery ||
    (e?.evidence_type || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (e?.source_device || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Action handlers
  const handleViewCase = useCallback((caseItem: any) => {
    setSelectedCase(caseItem);
    setViewDetailItem(caseItem);
    setViewDetailType('case');
  }, []);

  const handleEditCase = useCallback((caseItem: any) => {
    setSelectedCase(caseItem);
    setEditCaseItem(caseItem);
    setEditCaseTitle(caseItem.title || '');
    setEditCaseDescription(caseItem.description || '');
    setEditCaseSeverity(caseItem.severity || 'medium');
    setEditCaseStatus(caseItem.status || 'open');
    setEditCaseError('');
    setShowEditCaseModal(true);
  }, []);

  const handleViewEvidence = useCallback((item: any) => {
    setViewDetailItem(item);
    setViewDetailType('evidence');
  }, []);

  const handleDownloadEvidence = useCallback(async (item: EvidenceRow) => {
    setDownloadError(null);
    try {
      const response = await api.get(`/dfir/evidence/${item.id}/download`, {
        responseType: 'blob',
      });
      const blob = response.data as Blob;
      const cd = response.headers?.['content-disposition'];
      let filename = `evidence-${item.id}`;
      if (cd && typeof cd === 'string') {
        const m = cd.match(/filename="?([^"]+)"?/);
        if (m) filename = m[1];
      } else if (item.storage_location) {
        const base = String(item.storage_location).split(/[\\/]/).pop();
        if (base) filename = base;
      }
      saveBlob(blob, filename);
    } catch (err) {
      // 403 evidence_path_outside_tenant_root / 404 missing file land here.
      setDownloadError(await parseBlobError(err));
    }
  }, []);

  const caseReportMutation = useMutation({
    mutationFn: async (caseId: string) => (await api.get(`/dfir/cases/${caseId}/report`)).data,
    onMutate: () => setCaseReportError(null),
    onError: (err: unknown) => setCaseReportError(err),
  });

  const handleViewHold = useCallback((hold: any) => {
    setViewDetailItem(hold);
    setViewDetailType('legal-hold');
  }, []);

  const handleEditHold = useCallback((hold: any) => {
    setEditHoldItem(hold);
    setEditHoldType(hold.hold_type || '');
    setEditHoldStatus(hold.status || '');
    setEditHoldCustodians(Array.isArray(hold.custodians) ? hold.custodians.join(', ') : (hold.custodians || ''));
    setEditHoldError('');
    setShowEditHoldModal(true);
  }, []);

  const tabs = [
    { id: 'cases', label: 'Cases', icon: Shield },
    { id: 'evidence', label: 'Evidence', icon: FileSearch },
    { id: 'timeline', label: 'Timeline', icon: Clock },
    { id: 'artifacts', label: 'Artifacts', icon: Database },
    { id: 'legal-holds', label: 'Legal Holds', icon: Scale },
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-red-600" />
            <h1 className="text-3xl font-bold">DFIR Dashboard</h1>
          </div>
          <button
            onClick={() => { resetNewCaseForm(); setShowNewCaseModal(true); }}
            className="flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition"
          >
            <Plus className="w-4 h-4" />
            New Case
          </button>
        </div>

        {/* Summary Cards */}
        <div className="mb-4">
          <LoadErrorBanner what="DFIR dashboard metrics" error={dashboardError} />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Active Cases</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{activeCases}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">of {totalCases} total</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Critical / High Cases</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">
              {criticalCases} / {highCases}
            </p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">by case severity</p>
          </div>
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Evidence Items</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{evidenceCount}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">
              {collectionsPending} agent collection{collectionsPending === 1 ? '' : 's'} pending or awaiting approval
            </p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Legal Holds Active</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{activeHoldsCount}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">in effect</p>
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
            <Loader2 className="w-8 h-8 animate-spin text-gray-400" />
            <p className="ml-3 text-gray-500 dark:text-gray-400">Loading DFIR data...</p>
          </div>
        ) : error ? (
          <LoadErrorBanner what="forensic cases" error={error} />
        ) : (
          <>
            {/* Cases Tab */}
            {activeTab === 'cases' && (
              <div className="space-y-6">
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search cases..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                  <button
                    onClick={() => setShowFilterPanel(!showFilterPanel)}
                    className={clsx(
                      'flex items-center gap-2 px-4 py-2 border rounded-lg transition',
                      showFilterPanel
                        ? 'border-red-500 bg-red-50 dark:bg-red-900/20 text-red-600'
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
                    <div>
                      <label className="block text-sm font-medium mb-1">Status</label>
                      <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm">
                        <option value="all">All</option>
                        <option value="open">Open</option>
                        <option value="in_progress">In Progress</option>
                        <option value="closed">Closed</option>
                      </select>
                    </div>
                  </div>
                )}

                {filteredCases.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Shield className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">No cases found</p>
                    <button
                      onClick={() => { resetNewCaseForm(); setShowNewCaseModal(true); }}
                      className="mt-3 text-red-600 hover:underline text-sm"
                    >
                      Create your first case
                    </button>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Case Name</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Severity</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Lead</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Evidence</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Legal Hold</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredCases.map((caseItem: any) => (
                          <tr key={caseItem.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-medium">{caseItem.title || 'Untitled'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getSeverityColor(caseItem.severity || '')}`}>
                                {safeUpper(caseItem.severity)}
                              </span>
                            </td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(caseItem.status || '')}`}>
                                {caseItem.status || 'unknown'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm">{caseItem.lead_investigator_id || 'Unassigned'}</td>
                            {/* ForensicCaseResponse.evidence_count: counted from evidence rows */}
                            <td className="px-6 py-4 text-sm">{caseItem.evidence_count ?? NA}</td>
                            <td className="px-6 py-4">
                              {caseItem.legal_hold_active ? (
                                <CheckCircle className="w-5 h-5 text-green-600" />
                              ) : (
                                <AlertCircle className="w-5 h-5 text-gray-400" />
                              )}
                            </td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => handleViewCase(caseItem)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                                title="View case"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => handleEditCase(caseItem)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                                title="Edit case"
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

            {/* Evidence Tab */}
            {activeTab === 'evidence' && (
              <div className="space-y-6">
                {!activeCaseId && (
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 text-sm text-yellow-800 dark:text-yellow-200">
                    Select a case from the Cases tab to view its evidence.
                  </div>
                )}
                {activeCaseId && (
                  <div className="flex justify-end gap-2">
                    <button
                      onClick={() => setShowCollectModal(true)}
                      className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg transition"
                    >
                      <Server className="w-4 h-4" />
                      Collect from Endpoint
                    </button>
                    <button
                      onClick={() => { setNewEvidenceError(null); setShowNewEvidenceModal(true); }}
                      className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition"
                    >
                      <Plus className="w-4 h-4" />
                      Add Evidence
                    </button>
                  </div>
                )}
                <ActionErrorBanner what="download the evidence" error={downloadError} />
                <div className="flex gap-4">
                  <div className="flex-1 relative">
                    <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      placeholder="Search evidence..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                    />
                  </div>
                </div>

                <LoadErrorBanner what="evidence" error={evidenceError} />
                {evidenceError ? null : evidenceLoading ? (
                  <div className="flex items-center justify-center h-32">
                    <Loader2 className="w-6 h-6 animate-spin text-gray-400" />
                    <p className="ml-2 text-gray-500">Loading evidence...</p>
                  </div>
                ) : filteredEvidence.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <FileSearch className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">
                      {activeCaseId ? 'No evidence items found for this case' : 'Select a case to view evidence'}
                    </p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Source</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Type</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Collection</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Storage</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Size</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Hash</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Verified</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">CoC</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredEvidence.map((item: any) => (
                          <tr key={item.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-medium">{item.source_device || NA}</td>
                            <td className="px-6 py-4 text-sm">{item.evidence_type || NA}</td>
                            <td className="px-6 py-4 text-sm">
                              {item.collection_status ? (
                                <div className="space-y-1">
                                  <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${collectionStatusColor(item.collection_status)}`}>
                                    {item.collection_status}
                                  </span>
                                  {item.collection_command_id && (
                                    <p className="text-xs text-gray-500 dark:text-gray-400 font-mono" title="agent command id">
                                      cmd {String(item.collection_command_id).slice(0, 8)}
                                    </p>
                                  )}
                                  {item.collection_agent_id && (
                                    <p className="text-xs text-gray-500 dark:text-gray-400 font-mono" title="endpoint agent id">
                                      agent {String(item.collection_agent_id).slice(0, 8)}
                                    </p>
                                  )}
                                  {item.collection_error && (
                                    <p className="text-xs text-red-600 dark:text-red-400 max-w-xs break-words">{item.collection_error}</p>
                                  )}
                                </div>
                              ) : (
                                <span className="text-xs text-gray-500 dark:text-gray-400" title="uploaded or registered, not collected by an agent">
                                  manual
                                </span>
                              )}
                            </td>
                            <td className="px-6 py-4 text-xs" title={item.storage_location || ''}>
                              {item.storage_kind ? (STORAGE_KIND_LABEL[item.storage_kind] ?? item.storage_kind) : NA}
                            </td>
                            <td className="px-6 py-4 text-sm">{formatBytes(item.file_size_bytes)}</td>
                            <td className="px-6 py-4 text-xs font-mono text-gray-600 dark:text-gray-400" title={item.original_hash_sha256 || item.original_hash_md5 || ''}>
                              {(item.original_hash_sha256 || item.original_hash_md5 || 'N/A').substring(0, 16)}{(item.original_hash_sha256 || item.original_hash_md5) ? '...' : ''}
                            </td>
                            <td className="px-6 py-4">
                              {item.is_verified ? (
                                <CheckCircle className="w-5 h-5 text-green-600" />
                              ) : (
                                <AlertCircle className="w-5 h-5 text-orange-600" />
                              )}
                            </td>
                            <td className="px-6 py-4">
                              {item.chain_of_custody_log && Object.keys(item.chain_of_custody_log).length > 0 ? (
                                <CheckCircle className="w-5 h-5 text-green-600" />
                              ) : (
                                <AlertCircle className="w-5 h-5 text-red-600" />
                              )}
                            </td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => handleDownloadEvidence(item)}
                                disabled={item.storage_kind === 'none'}
                                className="text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-30 disabled:cursor-not-allowed"
                                title={item.storage_kind === 'none' ? 'No bytes stored for this item' : 'Download evidence'}
                              >
                                <Download className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => setVerifyItem(item)}
                                className="text-green-700 dark:text-green-400 hover:underline"
                                title="Verify integrity"
                              >
                                <ShieldCheck className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => handleViewEvidence(item)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                                title="View evidence details"
                              >
                                <Eye className="w-4 h-4" />
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

            {/* Timeline Tab */}
            {activeTab === 'timeline' && (
              <div className="space-y-6">
                {!activeCaseId && (
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 text-sm text-yellow-800 dark:text-yellow-200">
                    Select a case from the Cases tab to view its timeline.
                  </div>
                )}
                {activeCaseId && <TimelineActions caseId={activeCaseId} />}
                <LoadErrorBanner what="the timeline" error={timelineError} />
                {timelineError ? null : timelineLoading ? (
                  <div className="flex items-center justify-center h-32">
                    <Loader2 className="w-6 h-6 animate-spin text-gray-400" />
                    <p className="ml-2 text-gray-500">Loading timeline...</p>
                  </div>
                ) : timeline.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Clock className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">
                      {activeCaseId ? 'No timeline events for this case' : 'Select a case to view timeline'}
                    </p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="font-semibold text-lg mb-6">Timeline of Events</h3>
                    <div className="space-y-4">
                      {timeline.map((event: any, index: number) => (
                        <div key={event.id || index} className="flex gap-4">
                          <div className="flex flex-col items-center">
                            <div className={clsx(
                              'w-4 h-4 rounded-full mt-2',
                              event.is_pivotal ? 'bg-red-600' : 'bg-gray-400 dark:bg-gray-600'
                            )} />
                            {index < timeline.length - 1 && (
                              <div className="w-0.5 h-12 bg-gray-300 dark:bg-gray-600 my-2" />
                            )}
                          </div>
                          <div className="pb-4">
                            <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
                              {safeLocale(event.event_timestamp)}
                            </p>
                            <p className="font-medium mt-1">{event.description || 'No description'}</p>
                            <div className="flex gap-2 mt-2">
                              {event.severity_score != null && (
                                <span className={`px-2 py-1 rounded text-xs ${
                                  event.severity_score >= 8 ? getSeverityColor('critical') :
                                  event.severity_score >= 6 ? getSeverityColor('high') :
                                  event.severity_score >= 4 ? getSeverityColor('medium') :
                                  getSeverityColor('low')
                                }`}>
                                  Score: {event.severity_score}
                                </span>
                              )}
                              {event.is_pivotal && (
                                <span className="px-2 py-1 rounded text-xs bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100">
                                  Pivot Point
                                </span>
                              )}
                              {event.mitre_technique_id && (
                                <span className="px-2 py-1 rounded text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100">
                                  {event.mitre_technique_id}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Artifacts Tab — now backed by /dfir/cases/{id}/artifacts.
                Previously this tab rendered a hardcoded checklist of
                "MRU Lists / Chrome History / Prefetch Files" with green
                checkmarks regardless of whether the case had any
                ForensicArtifact rows — pure UI theater. */}
            {activeTab === 'artifacts' && (
              <ArtifactsTab caseId={activeCaseId} />
            )}

            {/* Legal Holds Tab */}
            {activeTab === 'legal-holds' && (
              <div className="space-y-6">
                {!activeCaseId && (
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 text-sm text-yellow-800 dark:text-yellow-200">
                    Select a case from the Cases tab to view its legal holds.
                  </div>
                )}
                {activeCaseId && (
                  <div className="flex justify-end">
                    <button
                      onClick={() => { setNewHoldError(''); setShowNewHoldModal(true); }}
                      className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg transition"
                    >
                      <Plus className="w-4 h-4" />
                      New Legal Hold
                    </button>
                  </div>
                )}
                <LoadErrorBanner what="legal holds" error={holdsError} />
                {holdsError ? null : holdsLoading ? (
                  <div className="flex items-center justify-center h-32">
                    <Loader2 className="w-6 h-6 animate-spin text-gray-400" />
                    <p className="ml-2 text-gray-500">Loading legal holds...</p>
                  </div>
                ) : legalHolds.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-48 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
                    <Scale className="w-12 h-12 text-gray-300 dark:text-gray-600 mb-3" />
                    <p className="text-gray-500 dark:text-gray-400">
                      {activeCaseId ? 'No legal holds for this case' : 'Select a case to view legal holds'}
                    </p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Hold Type</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Status</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Custodians</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Created</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Updated</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {legalHolds.map((hold: any) => (
                          <tr key={hold.id} className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                            <td className="px-6 py-4 text-sm font-medium">{hold.hold_type || 'N/A'}</td>
                            <td className="px-6 py-4">
                              <span className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(hold.status || '')}`}>
                                {hold.status || 'unknown'}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm">
                              {Array.isArray(hold.custodians)
                                ? hold.custodians.join(', ')
                                : hold.custodians || 'N/A'}
                            </td>
                            <td className="px-6 py-4 text-sm">{safeLocale(hold.created_at)}</td>
                            <td className="px-6 py-4 text-sm">{safeLocale(hold.updated_at)}</td>
                            <td className="px-6 py-4 text-sm flex gap-2">
                              <button
                                onClick={() => handleViewHold(hold)}
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                                title="View legal hold"
                              >
                                <Eye className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => handleEditHold(hold)}
                                className="text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100"
                                title="Edit legal hold"
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

      {/* View Detail Modal */}
      {viewDetailItem && viewDetailType && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => { setViewDetailItem(null); setViewDetailType(''); setCaseReportError(null); }}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[32rem] max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">
              {viewDetailType === 'case' && 'Case Details'}
              {viewDetailType === 'evidence' && 'Evidence Details'}
              {viewDetailType === 'legal-hold' && 'Legal Hold Details'}
            </h2>
            <pre className="text-xs bg-gray-100 dark:bg-gray-900 rounded p-4 overflow-auto max-h-96">
              {JSON.stringify(viewDetailItem, null, 2)}
            </pre>
            {viewDetailType === 'case' && (
              <div className="mt-4 space-y-2">
                <button
                  onClick={() => caseReportMutation.mutate(viewDetailItem.id)}
                  disabled={caseReportMutation.isPending}
                  className="flex items-center gap-2 px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50"
                >
                  <FileText className="w-4 h-4" />
                  {caseReportMutation.isPending ? 'Requesting report…' : 'Generate case report'}
                </button>
                {notImplementedReason(caseReportError) ? (
                  <NotAvailable reason={notImplementedReason(caseReportError) as string} />
                ) : (
                  <ActionErrorBanner what="generate the case report" error={caseReportError} />
                )}
              </div>
            )}
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => { setViewDetailItem(null); setViewDetailType(''); setCaseReportError(null); }}
                className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* New Case Modal */}
      {showNewCaseModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Create New Case</h2>
            {newCaseError && (
              <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">
                {newCaseError}
              </div>
            )}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Case Number</label>
                <input
                  type="text"
                  placeholder="e.g., DFIR-2026-001"
                  value={newCaseNumber}
                  onChange={(e) => setNewCaseNumber(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Case Title</label>
                <input
                  type="text"
                  placeholder="Enter case title"
                  value={newCaseTitle}
                  onChange={(e) => setNewCaseTitle(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea
                  placeholder="Case description"
                  value={newCaseDescription}
                  onChange={(e) => setNewCaseDescription(e.target.value)}
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Case Type</label>
                <select
                  value={newCaseType}
                  onChange={(e) => setNewCaseType(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="incident_response">Incident Response</option>
                  <option value="malware_analysis">Malware Analysis</option>
                  <option value="insider_threat">Insider Threat</option>
                  <option value="data_breach">Data Breach</option>
                  <option value="fraud">Fraud</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select
                  value={newCaseSeverity}
                  onChange={(e) => setNewCaseSeverity(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => setShowNewCaseModal(false)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  disabled={createCaseMutation.isPending}
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateCase}
                  disabled={createCaseMutation.isPending}
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {createCaseMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                  Create
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Edit Case Modal */}
      {showEditCaseModal && editCaseItem && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Edit Case</h2>
            {editCaseError && (
              <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">
                {editCaseError}
              </div>
            )}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Case Title</label>
                <input
                  type="text"
                  value={editCaseTitle}
                  onChange={(e) => setEditCaseTitle(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea
                  value={editCaseDescription}
                  onChange={(e) => setEditCaseDescription(e.target.value)}
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Status</label>
                <select
                  value={editCaseStatus}
                  onChange={(e) => setEditCaseStatus(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="open">Open</option>
                  <option value="in_progress">In Progress</option>
                  <option value="closed">Closed</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Severity</label>
                <select
                  value={editCaseSeverity}
                  onChange={(e) => setEditCaseSeverity(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => { setShowEditCaseModal(false); setEditCaseItem(null); }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  disabled={editCaseMutation.isPending}
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    if (!editCaseTitle.trim()) {
                      setEditCaseError('Case title is required');
                      return;
                    }
                    editCaseMutation.mutate({
                      caseId: editCaseItem.id,
                      title: editCaseTitle,
                      description: editCaseDescription,
                      severity: editCaseSeverity,
                      status: editCaseStatus,
                    });
                  }}
                  disabled={editCaseMutation.isPending}
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {editCaseMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                  Save
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Edit Legal Hold Modal */}
      {showEditHoldModal && editHoldItem && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96 max-h-screen overflow-y-auto">
            <h2 className="text-xl font-bold mb-4">Edit Legal Hold</h2>
            {editHoldError && (
              <div className="mb-4 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-300">
                {editHoldError}
              </div>
            )}
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1">Hold Type</label>
                <select
                  value={editHoldType}
                  onChange={(e) => setEditHoldType(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="litigation">Litigation</option>
                  <option value="regulatory">Regulatory</option>
                  <option value="investigation">Investigation</option>
                  <option value="preservation">Preservation</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Status</label>
                <select
                  value={editHoldStatus}
                  onChange={(e) => setEditHoldStatus(e.target.value)}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                >
                  <option value="active">Active</option>
                  <option value="released">Released</option>
                  <option value="expired">Expired</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Custodians (comma-separated)</label>
                <input
                  type="text"
                  value={editHoldCustodians}
                  onChange={(e) => setEditHoldCustodians(e.target.value)}
                  placeholder="e.g., John Doe, Jane Smith"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <div className="flex gap-2 mt-6">
                <button
                  onClick={() => { setShowEditHoldModal(false); setEditHoldItem(null); }}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                  disabled={editHoldMutation.isPending}
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    const custodiansList = editHoldCustodians
                      .split(',')
                      .map((c) => c.trim())
                      .filter((c) => c.length > 0);
                    editHoldMutation.mutate({
                      holdId: editHoldItem.id,
                      hold_type: editHoldType,
                      status: editHoldStatus,
                      custodians: custodiansList,
                    });
                  }}
                  disabled={editHoldMutation.isPending}
                  className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition disabled:opacity-50 flex items-center justify-center gap-2"
                >
                  {editHoldMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                  Save
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Evidence Modal: upload bytes (hashed server-side) or register a remote object */}
      {showNewEvidenceModal && activeCaseId && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setShowNewEvidenceModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[28rem] max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">Add Evidence</h2>
            <div className="flex gap-2 mb-4 text-sm">
              <button
                type="button"
                onClick={() => { setNewEvidenceMode('upload'); setNewEvidenceError(null); }}
                className={clsx('flex-1 px-3 py-1.5 rounded-lg border', newEvidenceMode === 'upload' ? 'border-blue-600 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300' : 'border-gray-300 dark:border-gray-600')}
              >
                Upload file
              </button>
              <button
                type="button"
                onClick={() => { setNewEvidenceMode('remote'); setNewEvidenceError(null); }}
                className={clsx('flex-1 px-3 py-1.5 rounded-lg border', newEvidenceMode === 'remote' ? 'border-blue-600 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300' : 'border-gray-300 dark:border-gray-600')}
              >
                Register remote object
              </button>
            </div>
            <form className="space-y-3" onSubmit={async (e) => {
              e.preventDefault();
              setNewEvidenceError(null);
              const fd = new FormData(e.currentTarget);
              try {
                if (newEvidenceMode === 'upload') {
                  const file = fd.get('file');
                  if (!(file instanceof File) || file.size === 0) {
                    setNewEvidenceError(new Error('Choose a non-empty file to upload'));
                    return;
                  }
                  const body = new FormData();
                  body.append('file', file);
                  for (const k of ['evidence_type', 'source_device', 'source_ip', 'handling_notes']) {
                    const v = fd.get(k);
                    if (typeof v === 'string' && v.trim()) body.append(k, v.trim());
                  }
                  // The client defaults to JSON (axios would serialise the FormData);
                  // multipart makes axios hand the body to the browser, which adds the boundary.
                  await api.post(`/dfir/cases/${activeCaseId}/evidence/upload`, body, {
                    headers: { 'Content-Type': 'multipart/form-data' },
                  });
                } else {
                  const location = String(fd.get('storage_location') || '').trim();
                  // The backend accepts only https:// or s3:// here (400 invalid_storage_location).
                  if (location && !REMOTE_LOCATION_RE.test(location)) {
                    setNewEvidenceError(new Error('Storage location must be an https:// or s3:// object URL'));
                    return;
                  }
                  const size = String(fd.get('file_size_bytes') || '').trim();
                  await api.post('/dfir/evidence', {
                    case_id: activeCaseId,
                    evidence_type: fd.get('evidence_type') || 'file',
                    source_device: String(fd.get('source_device') || '').trim(),
                    source_ip: fd.get('source_ip') || null,
                    acquisition_method: fd.get('acquisition_method') || 'remote_object',
                    original_hash_sha256: fd.get('original_hash_sha256') || null,
                    original_hash_md5: fd.get('original_hash_md5') || null,
                    storage_location: location,
                    file_size_bytes: size ? parseInt(size, 10) : null,
                    handling_notes: fd.get('handling_notes') || null,
                  });
                }
                setShowNewEvidenceModal(false);
                queryClient.invalidateQueries({ queryKey: ['dfir-evidence'] });
                queryClient.invalidateQueries({ queryKey: ['dfir-cases'] });
                queryClient.invalidateQueries({ queryKey: ['dfir-dashboard'] });
              } catch (err: unknown) {
                setNewEvidenceError(err);
              }
            }}>
              {newEvidenceMode === 'upload' && (
                <div>
                  <label className="block text-sm font-medium mb-1">File</label>
                  <input name="file" type="file" required className="w-full text-sm" />
                </div>
              )}
              <div>
                <label className="block text-sm font-medium mb-1">Evidence Type</label>
                <select name="evidence_type" className={inputCls}>
                  <option value="file">file</option>
                  <option value="disk_image">disk_image</option>
                  <option value="memory_dump">memory_dump</option>
                  <option value="network_pcap">network_pcap</option>
                  <option value="log_file">log_file</option>
                  <option value="email">email</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Source Device{newEvidenceMode === 'remote' ? '' : ' (optional)'}</label>
                <input name="source_device" type="text" required={newEvidenceMode === 'remote'} placeholder="workstation-042" className={inputCls} />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Source IP</label>
                <input name="source_ip" type="text" placeholder="10.0.0.42" className={inputCls} />
              </div>
              {newEvidenceMode === 'remote' && (
                <>
                  <div>
                    <label className="block text-sm font-medium mb-1">Storage Location</label>
                    <input
                      name="storage_location"
                      type="text"
                      placeholder="https://… or s3://bucket/key"
                      pattern="(https://|s3://).+"
                      title="An https:// or s3:// object URL"
                      className={inputCls}
                    />
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      Only https:// or s3:// object URLs. Local files go through the upload tab.
                    </p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Acquisition Method</label>
                    <input name="acquisition_method" type="text" defaultValue="remote_object" className={inputCls} />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">SHA-256 Hash</label>
                    <input name="original_hash_sha256" type="text" placeholder="64 hex characters" className={`${inputCls} font-mono text-xs`} />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">MD5 Hash (optional)</label>
                    <input name="original_hash_md5" type="text" placeholder="32 hex characters" className={`${inputCls} font-mono text-xs`} />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">File Size (bytes)</label>
                    <input name="file_size_bytes" type="number" min="0" className={inputCls} />
                  </div>
                </>
              )}
              <div>
                <label className="block text-sm font-medium mb-1">Handling Notes</label>
                <textarea name="handling_notes" rows={2} className={inputCls} />
              </div>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                {newEvidenceMode === 'upload'
                  ? 'The file is stored in this tenant\'s evidence directory; SHA-256, MD5 and SHA-512 are computed by the server as it is written.'
                  : 'Registers a remote object and its recorded hashes. PySOAR does not hold the bytes, so verification compares a hash you supply with the recorded one.'}
              </p>
              <ActionErrorBanner what="add the evidence" error={newEvidenceError} />
              <div className="flex gap-2 mt-5">
                <button type="button" onClick={() => setShowNewEvidenceModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition">
                  {newEvidenceMode === 'upload' ? 'Upload' : 'Register'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showCollectModal && activeCaseId && (
        <CollectEvidenceModal caseId={activeCaseId} onClose={() => setShowCollectModal(false)} />
      )}

      {verifyItem && <VerifyEvidenceModal item={verifyItem} onClose={() => setVerifyItem(null)} />}

      {/* New Legal Hold Modal */}
      {showNewHoldModal && activeCaseId && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => setShowNewHoldModal(false)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[28rem] max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">New Legal Hold</h2>
            <form className="space-y-3" onSubmit={async (e) => {
              e.preventDefault();
              setNewHoldError('');
              const fd = new FormData(e.currentTarget);
              const custodiansStr = (fd.get('custodians') as string) || '';
              const custodians = custodiansStr
                .split(',')
                .map((c) => c.trim())
                .filter((c) => c.length > 0);
              try {
                // LegalHoldCreate (src/schemas/dfir.py) requires
                // `data_sources`; scope/reason/status are not fields and
                // were silently dropped (and the request 422'd).
                const dataSources = ((fd.get('data_sources') as string) || '')
                  .split(',')
                  .map((d) => d.trim())
                  .filter((d) => d.length > 0);
                await api.post(`/dfir/cases/${activeCaseId}/legal-holds`, {
                  case_id: activeCaseId,
                  hold_type: fd.get('hold_type') || 'preservation',
                  custodians,
                  data_sources: dataSources,
                });
                setShowNewHoldModal(false);
                queryClient.invalidateQueries({ queryKey: ['dfir-legal-holds'] });
              } catch (err: unknown) {
                setNewHoldError(`Failed to create legal hold: ${describeLoadError(err)}`);
              }
            }}>
              <div>
                <label className="block text-sm font-medium mb-1">Hold Type</label>
                <select name="hold_type" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700">
                  <option value="preservation">preservation</option>
                  <option value="litigation">litigation</option>
                  <option value="regulatory">regulatory</option>
                  <option value="internal_investigation">internal_investigation</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Custodians (comma separated)</label>
                <input name="custodians" required type="text" placeholder="alice@acme.com, bob@acme.com" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Data Sources (comma separated)</label>
                <input name="data_sources" required type="text" placeholder="mailbox, sharepoint, laptop-042" className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700" />
              </div>
              {newHoldError && <p className="text-sm text-red-600 dark:text-red-400">{newHoldError}</p>}
              <div className="flex gap-2 mt-5">
                <button type="button" onClick={() => setShowNewHoldModal(false)} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">Cancel</button>
                <button type="submit" className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition">Create</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}


//** A 501 from the backend: the feature does not exist, with the server's reason. */
function NotAvailable({ reason }: { reason: string }) {
  return (
    <div className="text-sm bg-gray-50 dark:bg-gray-900/40 border border-gray-300 dark:border-gray-600 rounded p-3 text-gray-700 dark:text-gray-300">
      <p className="font-medium">Not available</p>
      <p className="text-xs mt-1">{reason}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Collect from endpoint: POST /dfir/cases/{id}/evidence/collect
// ---------------------------------------------------------------------------

const COLLECTION_TYPES = [
  { value: 'process_list', label: 'Process list' },
  { value: 'network_connections', label: 'Network connections' },
  { value: 'file', label: 'File' },
  { value: 'memory_dump', label: 'Memory dump (needs a second approver)' },
] as const;

function CollectEvidenceModal({ caseId, onClose }: { caseId: string; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [hostname, setHostname] = useState('');
  const [collectionType, setCollectionType] = useState<string>('process_list');
  const [path, setPath] = useState('');
  const [pid, setPid] = useState('');
  const [maxBytes, setMaxBytes] = useState('');
  const [notes, setNotes] = useState('');
  const [formError, setFormError] = useState('');

  const collect = useMutation({
    mutationFn: async () => {
      const body: Record<string, unknown> = { hostname: hostname.trim(), collection_type: collectionType };
      if (collectionType === 'file') {
        body.path = path.trim();
        if (maxBytes.trim()) body.max_bytes = parseInt(maxBytes, 10);
      }
      if (collectionType === 'memory_dump') body.pid = parseInt(pid, 10);
      if (notes.trim()) body.notes = notes.trim();
      const res = await api.post<CollectResponse>(`/dfir/cases/${caseId}/evidence/collect`, body);
      return { httpStatus: res.status, data: res.data };
    },
    onSuccess: (out) => {
      if (out.data.evidence) {
        queryClient.invalidateQueries({ queryKey: ['dfir-evidence'] });
        queryClient.invalidateQueries({ queryKey: ['dfir-cases'] });
        queryClient.invalidateQueries({ queryKey: ['dfir-dashboard'] });
      }
    },
  });

  const submit = () => {
    setFormError('');
    if (!hostname.trim()) return setFormError('Hostname is required');
    if (collectionType === 'file' && !path.trim()) return setFormError('Path is required for a file collection');
    if (collectionType === 'memory_dump' && !(parseInt(pid, 10) > 0)) return setFormError('A positive process id is required for a memory dump');
    collect.mutate();
  };

  const result = collect.data?.data;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[30rem] max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-xl font-bold mb-1">Collect from Endpoint</h2>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
          Issues a collection command to the endpoint agent enrolled for this host. The evidence row follows the command.
        </p>
        <div className="space-y-3">
          <div>
            <label className="block text-sm font-medium mb-1">Hostname</label>
            <input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="workstation-042" className={inputCls} />
          </div>
          <div>
            <label className="block text-sm font-medium mb-1">Collection type</label>
            <select value={collectionType} onChange={(e) => setCollectionType(e.target.value)} className={inputCls}>
              {COLLECTION_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
          </div>
          {collectionType === 'file' && (
            <>
              <div>
                <label className="block text-sm font-medium mb-1">Path on the host</label>
                <input value={path} onChange={(e) => setPath(e.target.value)} placeholder="/var/log/auth.log or C:\Windows\..." className={`${inputCls} font-mono text-xs`} />
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">Max bytes (optional, server default 1 MiB, limit 25 MiB)</label>
                <input type="number" min="1" value={maxBytes} onChange={(e) => setMaxBytes(e.target.value)} className={inputCls} />
              </div>
            </>
          )}
          {collectionType === 'memory_dump' && (
            <div>
              <label className="block text-sm font-medium mb-1">Process id</label>
              <input type="number" min="1" value={pid} onChange={(e) => setPid(e.target.value)} className={inputCls} />
            </div>
          )}
          <div>
            <label className="block text-sm font-medium mb-1">Notes</label>
            <textarea rows={2} value={notes} onChange={(e) => setNotes(e.target.value)} className={inputCls} />
          </div>

          {formError && <p className="text-sm text-red-600 dark:text-red-400">{formError}</p>}
          <ActionErrorBanner what="request the collection" error={collect.error} />

          {result && result.status === 'awaiting_agent' && (
            <div className="text-sm bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-300 dark:border-yellow-700 rounded p-3 text-yellow-800 dark:text-yellow-200">
              <p className="font-medium">Awaiting agent: no endpoint agent covers {hostname.trim()}. Nothing was created.</p>
              <p className="text-xs mt-1">{result.detail}</p>
              {result.agent_hostname && (
                <p className="text-xs mt-1">Agent found: {result.agent_hostname}{result.agent_id ? ` (${result.agent_id})` : ''}</p>
              )}
            </div>
          )}
          {result && result.status !== 'awaiting_agent' && (
            <div className="text-sm bg-blue-50 dark:bg-blue-900/20 border border-blue-300 dark:border-blue-700 rounded p-3 text-blue-800 dark:text-blue-200 space-y-1">
              <p className="font-medium">
                {result.status === 'awaiting_approval' ? 'Awaiting approval' : 'Pending'} (HTTP {collect.data?.httpStatus})
              </p>
              <p className="text-xs">{result.detail}</p>
              {result.command_id && <p className="text-xs font-mono">command {result.command_id}</p>}
              {result.agent_hostname && <p className="text-xs">agent {result.agent_hostname}</p>}
              {result.evidence && <p className="text-xs font-mono">evidence {result.evidence.id}</p>}
            </div>
          )}

          <div className="flex gap-2 mt-4">
            <button onClick={onClose} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
              {result ? 'Close' : 'Cancel'}
            </button>
            <button
              onClick={submit}
              disabled={collect.isPending}
              className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {collect.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Collect
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Verify integrity: POST /dfir/evidence/{id}/verify
// ---------------------------------------------------------------------------

const triState = (v: boolean | null) =>
  v === true ? (
    <span className="text-green-700 dark:text-green-400 font-medium">match</span>
  ) : v === false ? (
    <span className="text-red-700 dark:text-red-400 font-bold">MISMATCH</span>
  ) : (
    <span className="text-gray-500 dark:text-gray-400" title="nothing to compare on this side">not compared</span>
  );

function VerifyEvidenceModal({ item, onClose }: { item: EvidenceRow; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [algorithm, setAlgorithm] = useState<'sha256' | 'md5'>('sha256');
  const [claimed, setClaimed] = useState('');

  const verify = useMutation({
    mutationFn: async () => {
      const body: Record<string, string> = { hash_algorithm: algorithm };
      if (claimed.trim()) body.evidence_hash = claimed.trim();
      const res = await api.post<{ verification: EvidenceVerification | null }>(`/dfir/evidence/${item.id}/verify`, body);
      return res.data.verification;
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: ['dfir-evidence'] });
    },
  });

  const v = verify.data;
  const nothingToCompare = errorCode(verify.error) === 'nothing_to_compare';

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={onClose}>
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[34rem] max-h-screen overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <h2 className="text-xl font-bold mb-1">Verify Evidence Integrity</h2>
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
          {item.source_device || item.id} · {item.storage_kind ? STORAGE_KIND_LABEL[item.storage_kind] ?? item.storage_kind : NA}.{' '}
          {item.storage_kind === 'local'
            ? 'The stored bytes are re-hashed and compared with the hash recorded at collection.'
            : 'PySOAR does not hold these bytes; supply a hash to compare with the recorded one.'}
        </p>
        <div className="space-y-3">
          <div className="flex gap-3">
            <div className="w-32">
              <label className="block text-sm font-medium mb-1">Algorithm</label>
              <select value={algorithm} onChange={(e) => setAlgorithm(e.target.value as 'sha256' | 'md5')} className={inputCls}>
                <option value="sha256">sha256</option>
                <option value="md5">md5</option>
              </select>
            </div>
            <div className="flex-1">
              <label className="block text-sm font-medium mb-1">Hash to compare (optional)</label>
              <input
                value={claimed}
                onChange={(e) => setClaimed(e.target.value)}
                placeholder={algorithm === 'sha256' ? '64 hex characters' : '32 hex characters'}
                className={`${inputCls} font-mono text-xs`}
              />
            </div>
          </div>

          {nothingToCompare && (
            <p className="text-sm text-yellow-800 dark:text-yellow-200 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-300 dark:border-yellow-700 rounded p-2">
              Nothing to compare: enter the hash of your copy of the object above and verify again.
            </p>
          )}
          <ActionErrorBanner what="verify the evidence" error={verify.error} />

          {v && (
            <div
              className={clsx(
                'rounded border p-3 text-sm space-y-1',
                v.is_valid
                  ? 'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700'
                  : 'bg-red-50 dark:bg-red-900/30 border-red-400 dark:border-red-700',
              )}
            >
              <p className={clsx('font-bold', v.is_valid ? 'text-green-800 dark:text-green-200' : 'text-red-800 dark:text-red-200')}>
                {v.is_valid ? 'Integrity verified' : 'Integrity NOT verified'}
              </p>
              <p className="text-xs">
                Algorithm {v.algorithm} · reference:{' '}
                {v.reference === 'file' ? 'stored file re-hashed' : v.reference === 'stored_hash' ? 'recorded hash (no local file)' : v.reference || NA}
              </p>
              <p className="text-xs font-mono break-all">computed: {v.computed_hash ?? '— (no local bytes hashed)'}</p>
              <p className="text-xs font-mono break-all">recorded: {v.stored_hash ?? '— (no hash recorded)'}</p>
              <p className="text-xs">File vs recorded hash: {triState(v.file_matches_stored_hash)}</p>
              <p className="text-xs">Supplied hash vs reference: {triState(v.claimed_hash_matches)}</p>
              {!v.is_valid && item.storage_kind === 'local' && v.computed_hash == null && (
                <p className="text-xs text-red-700 dark:text-red-300">The stored evidence file is missing.</p>
              )}
            </div>
          )}

          <div className="flex gap-2 mt-4">
            <button onClick={onClose} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition">
              Close
            </button>
            <button
              onClick={() => verify.mutate()}
              disabled={verify.isPending}
              className="flex-1 px-4 py-2 bg-green-700 hover:bg-green-800 text-white rounded-lg transition disabled:opacity-50 flex items-center justify-center gap-2"
            >
              {verify.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Verify
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Timeline: reconstruct + export
// ---------------------------------------------------------------------------

function TimelineActions({ caseId }: { caseId: string }) {
  const queryClient = useQueryClient();
  const reconstruct = useMutation({
    mutationFn: async () => (await api.post<ReconstructResponse>(`/dfir/cases/${caseId}/timeline/reconstruct`)).data,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['dfir-timeline', caseId] }),
  });
  const exportTimeline = useMutation({
    mutationFn: async (format: 'json' | 'csv') => {
      try {
        const res = await api.post(`/dfir/cases/${caseId}/timeline/export`, null, {
          params: { format },
          responseType: 'blob',
        });
        saveBlob(res.data as Blob, `timeline-${caseId}.${format}`);
      } catch (err) {
        throw await parseBlobError(err);
      }
    },
  });
  const r = reconstruct.data;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2 justify-end">
        <button
          onClick={() => reconstruct.mutate()}
          disabled={reconstruct.isPending}
          className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
          title="Derive events from chain-of-custody entries and stored artifact timestamps"
        >
          <RefreshCw className={clsx('w-4 h-4', reconstruct.isPending && 'animate-spin')} />
          Reconstruct
        </button>
        <button
          onClick={() => exportTimeline.mutate('json')}
          disabled={exportTimeline.isPending}
          className="flex items-center gap-2 border border-gray-300 dark:border-gray-600 px-4 py-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50"
        >
          <Download className="w-4 h-4" /> Export JSON
        </button>
        <button
          onClick={() => exportTimeline.mutate('csv')}
          disabled={exportTimeline.isPending}
          className="flex items-center gap-2 border border-gray-300 dark:border-gray-600 px-4 py-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50"
        >
          <Download className="w-4 h-4" /> Export CSV
        </button>
      </div>
      <ActionErrorBanner what="reconstruct the timeline" error={reconstruct.error} />
      <ActionErrorBanner what="export the timeline" error={exportTimeline.error} />
      {r && (
        <div className="text-sm bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded p-3 text-purple-900 dark:text-purple-100">
          Reconstruction added {r.created} event{r.created === 1 ? '' : 's'} ({r.from_custody} from chain of custody,{' '}
          {r.from_artifacts} from artifacts); {r.already_present} already present.
          {r.truncated && (
            <span className="block mt-1 text-orange-700 dark:text-orange-300">
              Truncated: the derivation hit its limit, so not every source entry was turned into an event.
            </span>
          )}
        </div>
      )}
    </div>
  );
}

// Real Artifacts tab — fetches ForensicArtifact rows for the active
// case from /dfir/cases/{id}/artifacts and exposes "Extract IOCs".
interface ArtifactRow {
  id: string;
  evidence_id?: string;
  artifact_type?: string;
  artifact_data?: Record<string, unknown>;
  risk_score?: number;
  ioc_count?: number;
  created_at?: string;
}

const ARTIFACT_TYPE_LABEL: Record<string, string> = {
  evidence_ioc_scan: 'Evidence IOC scan',
};

function ArtifactsTab({ caseId }: { caseId: string | null }) {
  const queryClient = useQueryClient();
  const { data, isLoading, isError, error: artifactsError } = useQuery<{ items?: ArtifactRow[] } | ArtifactRow[]>({
    queryKey: ['dfir-artifacts', caseId],
    queryFn: async () => {
      const res = await api.get(`/dfir/cases/${caseId}/artifacts`, { params: { size: 100 } });
      return res.data;
    },
    enabled: !!caseId,
  });

  const extractMutation = useMutation({
    mutationFn: async () => (await api.post<IocExtractionResult>(`/dfir/cases/${caseId}/artifacts/extract-iocs`, {})).data,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['dfir-artifacts', caseId] });
    },
  });

  const analyzeMutation = useMutation({
    mutationFn: async (a: ArtifactRow) =>
      (await api.post('/dfir/artifacts/analyze', { artifact_type: a.artifact_type ?? '', artifact_data: a.artifact_data ?? {} })).data,
  });

  if (!caseId) {
    return (
      <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 text-sm text-yellow-800 dark:text-yellow-200">
        Select a case from the Cases tab to view its artifacts.
      </div>
    );
  }

  const items: ArtifactRow[] = Array.isArray(data) ? data : (data?.items ?? []);
  const x = extractMutation.data;
  const analyzeNa = notImplementedReason(analyzeMutation.error);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">Case Artifacts ({items.length})</h3>
        <button
          onClick={() => extractMutation.mutate()}
          disabled={extractMutation.isPending}
          className="flex items-center gap-2 bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
          title="Scan stored artifacts and the evidence bytes held by PySOAR for IOCs"
        >
          <FileSearch className="w-4 h-4" />
          {extractMutation.isPending ? 'Extracting…' : 'Extract IOCs'}
        </button>
      </div>
      <ActionErrorBanner what="extract IOCs" error={extractMutation.error} />
      {x && (
        <div className="text-sm bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded p-3 text-purple-900 dark:text-purple-100 space-y-1">
          <p className="font-medium">
            {x.iocs_extracted} IOC{x.iocs_extracted === 1 ? '' : 's'} extracted from {x.artifacts_scanned} artifact
            {x.artifacts_scanned === 1 ? '' : 's'} and {x.evidence_files_scanned} evidence file
            {x.evidence_files_scanned === 1 ? '' : 's'}; {x.scan_artifacts_written} scan artifact
            {x.scan_artifacts_written === 1 ? '' : 's'} written.
          </p>
          {x.evidence_files_truncated > 0 && (
            <p className="text-xs text-orange-700 dark:text-orange-300">
              {x.evidence_files_truncated} evidence file{x.evidence_files_truncated === 1 ? ' was' : 's were'} larger than the scan limit; only the first part was scanned.
            </p>
          )}
          {x.evidence_skipped.length > 0 && (
            <div className="text-xs">
              <p>Evidence not scanned:</p>
              <ul className="list-disc ml-5">
                {x.evidence_skipped.map((s) => (
                  <li key={s.evidence_id}>
                    <span className="font-mono">{s.evidence_id.slice(0, 8)}</span>: {s.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
      {analyzeNa ? (
        <NotAvailable reason={`Artifact analysis: ${analyzeNa}`} />
      ) : (
        <ActionErrorBanner what="analyze the artifact" error={analyzeMutation.error} />
      )}
      {isLoading && (
        <div className="flex items-center gap-2 text-gray-500 dark:text-gray-400">
          <Loader2 className="w-4 h-4 animate-spin" /> Loading artifacts…
        </div>
      )}
      <LoadErrorBanner what="artifacts" error={artifactsError} />
      {!isLoading && !isError && items.length === 0 && (
        <div className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6 text-center text-gray-600 dark:text-gray-400">
          No artifacts registered on this case yet.
        </div>
      )}
      {!isLoading && items.length > 0 && (
        <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-gray-50 dark:bg-gray-700 text-xs font-medium uppercase text-gray-600 dark:text-gray-300">
              <tr>
                <th className="px-4 py-2 text-left">Artifact</th>
                <th className="px-4 py-2 text-left">Type</th>
                <th className="px-4 py-2 text-left">Evidence</th>
                <th className="px-4 py-2 text-left">Risk Score</th>
                <th className="px-4 py-2 text-left">IOCs</th>
                <th className="px-4 py-2 text-left">Created</th>
                <th className="px-4 py-2 text-left">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
              {items.map((a) => (
                <tr key={a.id} className="text-sm">
                  <td className="px-4 py-2 font-mono text-xs">{a.id.slice(0, 8)}</td>
                  <td className="px-4 py-2">
                    {a.artifact_type ? ARTIFACT_TYPE_LABEL[a.artifact_type] ?? a.artifact_type : NA}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs">{a.evidence_id ? a.evidence_id.slice(0, 8) : NA}</td>
                  <td className="px-4 py-2">{typeof a.risk_score === 'number' ? a.risk_score.toFixed(1) : NA}</td>
                  <td className="px-4 py-2" title="indicators persisted by the last IOC extraction">
                    {typeof a.ioc_count === 'number' ? a.ioc_count : NA}
                  </td>
                  <td className="px-4 py-2 text-gray-500 dark:text-gray-400">
                    {a.created_at ? new Date(a.created_at).toLocaleString() : NA}
                  </td>
                  <td className="px-4 py-2">
                    <button
                      onClick={() => analyzeMutation.mutate(a)}
                      disabled={analyzeMutation.isPending}
                      className="text-xs text-blue-600 dark:text-blue-400 hover:underline disabled:opacity-50"
                    >
                      Analyze
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
