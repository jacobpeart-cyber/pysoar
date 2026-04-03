import React, { useState, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Shield,
  FileSearch,
  Clock,
  Scale,
  Database,
  ChevronDown,
  Plus,
  Edit,
  Trash2,
  CheckCircle,
  AlertCircle,
  Search,
  Filter,
  Download,
  Eye,
  Loader2,
} from 'lucide-react';
import clsx from 'clsx';
import { dfirApi } from '../api/endpoints';

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

  // Data queries
  const { data: casesData, isLoading: casesLoading, error: casesError } = useQuery({
    queryKey: ['dfir-cases'],
    queryFn: () => dfirApi.getCases(),
  });

  const { data: dashboardData, isLoading: dashboardLoading } = useQuery({
    queryKey: ['dfir-dashboard'],
    queryFn: async () => {
      const response = await fetch('/api/v1/dfir/dashboard/metrics');
      if (!response.ok) return null;
      return response.json();
    },
  });

  // Evidence, timeline, legal holds depend on having a selected case
  const activeCaseId = selectedCase?.id;

  const { data: evidenceData, isLoading: evidenceLoading, error: evidenceError } = useQuery({
    queryKey: ['dfir-evidence', activeCaseId],
    queryFn: () => activeCaseId ? dfirApi.getEvidence(activeCaseId) : Promise.resolve({ items: [] }),
    enabled: !!activeCaseId,
  });

  const { data: timelineData, isLoading: timelineLoading, error: timelineError } = useQuery({
    queryKey: ['dfir-timeline', activeCaseId],
    queryFn: () => activeCaseId ? dfirApi.getTimeline(activeCaseId) : Promise.resolve({ items: [] }),
    enabled: !!activeCaseId,
  });

  const { data: legalHoldsData, isLoading: holdsLoading, error: holdsError } = useQuery({
    queryKey: ['dfir-legal-holds', activeCaseId],
    queryFn: async () => {
      if (!activeCaseId) return { items: [] };
      const response = await fetch(`/api/v1/dfir/cases/${activeCaseId}/legal-holds`);
      if (!response.ok) return { items: [] };
      return response.json();
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
      setNewCaseError(err?.response?.data?.detail || err?.message || 'Failed to create case');
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

  // Compute stats from dashboard API or fallback to local data
  const activeCases = dashboardData?.active_cases ?? cases.filter((c: any) => c?.status === 'open' || c?.status === 'in_progress').length;
  const totalCases = dashboardData?.total_cases ?? cases.length;
  const evidenceCount = dashboardData?.total_evidence_items ?? evidence.length;
  const activeHoldsCount = dashboardData?.legal_holds_active ?? legalHolds.filter((h: any) => h?.status === 'active').length;

  // Compute average resolution time from closed cases
  const computeAvgResolution = (): string => {
    if (dashboardData?.avg_resolution_days != null) {
      return `${Number(dashboardData.avg_resolution_days).toFixed(1)} days`;
    }
    const closedCases = cases.filter((c: any) => c?.status === 'closed' && c?.created_at && c?.updated_at);
    if (closedCases.length === 0) return 'N/A';
    const totalMs = closedCases.reduce((sum: number, c: any) => {
      return sum + (new Date(c.updated_at || "").getTime() - new Date(c.created_at || "").getTime());
    }, 0);
    const avgDays = totalMs / closedCases.length / (1000 * 60 * 60 * 24);
    return `${avgDays.toFixed(1)} days`;
  };
  const avgResolutionTime = computeAvgResolution();

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
    // Navigate to edit or open edit modal - placeholder for now
    console.log('Edit case:', caseItem.id);
  }, []);

  const handleViewEvidence = useCallback((item: any) => {
    setViewDetailItem(item);
    setViewDetailType('evidence');
  }, []);

  const handleDownloadEvidence = useCallback((item: any) => {
    if (item?.storage_location) {
      window.open(item.storage_location, '_blank');
    } else {
      console.log('Download evidence:', item.id);
    }
  }, []);

  const handleViewHold = useCallback((hold: any) => {
    setViewDetailItem(hold);
    setViewDetailType('legal-hold');
  }, []);

  const handleEditHold = useCallback((hold: any) => {
    console.log('Edit legal hold:', hold.id);
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
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-red-600 dark:text-red-300">Active Cases</p>
            <p className="text-3xl font-bold text-red-900 dark:text-red-100 mt-2">{activeCases}</p>
            <p className="text-xs text-red-600 dark:text-red-300 mt-1">of {totalCases} total</p>
          </div>
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Evidence Items</p>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{evidenceCount}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">collected</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Legal Holds Active</p>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{activeHoldsCount}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">in effect</p>
          </div>
          <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 p-4 rounded-lg">
            <p className="text-sm font-medium text-orange-600 dark:text-orange-300">Avg Resolution</p>
            <p className="text-3xl font-bold text-orange-900 dark:text-orange-100 mt-2">{avgResolutionTime}</p>
            <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">time to close</p>
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
          <div className="flex items-center justify-center h-64">
            <AlertCircle className="w-8 h-8 text-red-500" />
            <p className="ml-3 text-red-500">Failed to load data. Please try again.</p>
          </div>
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
                            <td className="px-6 py-4 text-sm">{caseItem.evidence_count || 0}</td>
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

                {evidenceLoading ? (
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
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Source / Type</th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">Type</th>
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
                            <td className="px-6 py-4 text-sm font-medium">{item.evidence_type || item.source_device || 'Unknown'}</td>
                            <td className="px-6 py-4 text-sm">{item.evidence_type || 'N/A'}</td>
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
                                className="text-blue-600 dark:text-blue-400 hover:underline"
                                title="Download evidence"
                              >
                                <Download className="w-4 h-4" />
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
                {timelineLoading ? (
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

            {/* Artifacts Tab */}
            {activeTab === 'artifacts' && (
              <div className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="font-semibold mb-4">Registry Artifacts</h3>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> MRU Lists</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> TypedURLs</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Installed Programs</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> USB History</li>
                    </ul>
                  </div>
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="font-semibold mb-4">File System Artifacts</h3>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Recycle Bin</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Prefetch Files</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Shadow Copies</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Thumbnail Cache</li>
                    </ul>
                  </div>
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="font-semibold mb-4">Browser Artifacts</h3>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Chrome History</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Firefox Cookies</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> IE Cache</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Downloaded Files</li>
                    </ul>
                  </div>
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
                    <h3 className="font-semibold mb-4">Event Log Analysis</h3>
                    <ul className="space-y-2 text-sm">
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Process Creation (4688)</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Logon Events (4624)</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Lateral Movement (4672)</li>
                      <li className="flex items-center gap-2"><CheckCircle className="w-4 h-4 text-green-600" /> Privilege Escalation (4673)</li>
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {/* Legal Holds Tab */}
            {activeTab === 'legal-holds' && (
              <div className="space-y-6">
                {!activeCaseId && (
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 text-sm text-yellow-800 dark:text-yellow-200">
                    Select a case from the Cases tab to view its legal holds.
                  </div>
                )}
                {holdsLoading ? (
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
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50" onClick={() => { setViewDetailItem(null); setViewDetailType(''); }}>
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[32rem] max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-xl font-bold mb-4">
              {viewDetailType === 'case' && 'Case Details'}
              {viewDetailType === 'evidence' && 'Evidence Details'}
              {viewDetailType === 'legal-hold' && 'Legal Hold Details'}
            </h2>
            <pre className="text-xs bg-gray-100 dark:bg-gray-900 rounded p-4 overflow-auto max-h-96">
              {JSON.stringify(viewDetailItem, null, 2)}
            </pre>
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => { setViewDetailItem(null); setViewDetailType(''); }}
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
    </div>
  );
}
