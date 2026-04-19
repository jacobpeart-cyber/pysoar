import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Search,
  Plus,
  Pause,
  Play,
  Trash2,
  Eye,
  Copy,
  Download,
  Filter,
  CheckCircle,
  AlertCircle,
  Clock,
  Zap,
  BookOpen,
  Lightbulb,
  ChevronDown,
  X,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
  info: 'bg-gray-100 text-gray-700 border-gray-200',
};

// Safely parse a field that might be a JSON string or already an array
const safeArray = (val: any): any[] => {
  if (Array.isArray(val)) return val;
  if (typeof val === 'string') {
    try { const p = JSON.parse(val); return Array.isArray(p) ? p : []; } catch { return []; }
  }
  return [];
};

const statusColors: Record<string, string> = {
  active: 'text-green-600 bg-green-50 border border-green-200',
  paused: 'text-yellow-600 bg-yellow-50 border border-yellow-200',
  completed: 'text-blue-600 bg-blue-50 border border-blue-200',
  cancelled: 'text-gray-600 bg-gray-50 border border-gray-200',
  pending: 'text-purple-600 bg-purple-50 border border-purple-200',
  running: 'text-green-600 bg-green-50 border border-green-200',
  failed: 'text-red-600 bg-red-50 border border-red-200',
  new: 'text-blue-600 bg-blue-50',
  investigating: 'text-yellow-600 bg-yellow-50',
  confirmed: 'text-green-600 bg-green-50',
  false_positive: 'text-purple-600 bg-purple-50',
  DRAFT: 'text-gray-600 bg-gray-50 border border-gray-200',
  ACTIVE: 'text-green-600 bg-green-50 border border-green-200',
  COMPLETED: 'text-blue-600 bg-blue-50 border border-blue-200',
  ARCHIVED: 'text-gray-600 bg-gray-50 border border-gray-200',
  PENDING: 'text-purple-600 bg-purple-50 border border-purple-200',
  RUNNING: 'text-green-600 bg-green-50 border border-green-200',
  PAUSED: 'text-yellow-600 bg-yellow-50 border border-yellow-200',
  FAILED: 'text-red-600 bg-red-50 border border-red-200',
  CANCELLED: 'text-gray-600 bg-gray-50 border border-gray-200',
};

function formatDuration(seconds: number | null | undefined): string {
  if (!seconds) return '-';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function ThreatHunting() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'hunts' | 'hypotheses' | 'findings' | 'notebooks' | 'templates'>(
    'hunts'
  );
  const [selectedHunt, setSelectedHunt] = useState<any>(null);
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [huntFilter, setHuntFilter] = useState('');
  const [findingSeverityFilter, setFindingSeverityFilter] = useState('');
  const [findingStatusFilter, setFindingStatusFilter] = useState('');
  const [mitreFilterTab, setMitreFilterTab] = useState('');
  const [priorityFilterTab, setPriorityFilterTab] = useState('');
  const [hypothesisStatusFilter, setHypothesisStatusFilter] = useState('');

  // Modal states
  const [showNewHuntModal, setShowNewHuntModal] = useState(false);
  const [showNewHypothesisModal, setShowNewHypothesisModal] = useState(false);
  const [newHuntHypothesisId, setNewHuntHypothesisId] = useState('');
  const [newHypothesisTitle, setNewHypothesisTitle] = useState('');
  const [newHypothesisDescription, setNewHypothesisDescription] = useState('');
  const [newHypothesisPriority, setNewHypothesisPriority] = useState(3);
  const [selectedNotebook, setSelectedNotebook] = useState<any>(null);
  const [showCreateNotebookModal, setShowCreateNotebookModal] = useState(false);
  const [newNotebookTitle, setNewNotebookTitle] = useState('');
  const [newNotebookDescription, setNewNotebookDescription] = useState('');
  const [newNotebookSessionId, setNewNotebookSessionId] = useState('');
  const [editingHypothesis, setEditingHypothesis] = useState<any>(null);
  const [editHypothesisTitle, setEditHypothesisTitle] = useState('');
  const [editHypothesisDescription, setEditHypothesisDescription] = useState('');
  const [editHypothesisPriority, setEditHypothesisPriority] = useState(3);

  // Error banner for mutation failures
  const [actionError, setActionError] = useState<string | null>(null);
  const showError = (err: any) => {
    const msg =
      err?.response?.data?.detail ||
      (typeof err?.response?.data === 'string' ? err.response.data : null) ||
      err?.message ||
      'Action failed';
    setActionError(typeof msg === 'string' ? msg : JSON.stringify(msg));
  };

  // Fetch hunting stats
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['hunting-stats'],
    queryFn: async () => {
      try {
        const response = await api.get('/hunting/stats');
        return response.data;
      } catch { return null; }
    },
    retry: 1,
  });

  // Fetch hunt sessions
  const { data: huntsData, isLoading: huntsLoading } = useQuery({
    queryKey: ['hunting-sessions', huntFilter],
    queryFn: async () => {
      try {
        const response = await api.get('/hunting/sessions', {
          params: huntFilter ? { status: huntFilter } : {},
        });
        return response.data;
      } catch { return { items: [] }; }
    },
    enabled: activeTab === 'hunts',
    retry: 1,
  });

  // Fetch hypotheses
  const { data: hypothesesData, isLoading: hypothesesLoading } = useQuery({
    queryKey: ['hunting-hypotheses', mitreFilterTab, priorityFilterTab, hypothesisStatusFilter],
    queryFn: async () => {
      try {
        const response = await api.get('/hunting/hypotheses', {
          params: {
            ...(mitreFilterTab && { search: mitreFilterTab }),
            ...(priorityFilterTab && { priority: priorityFilterTab }),
            ...(hypothesisStatusFilter && { status: hypothesisStatusFilter }),
          },
        });
        return response.data;
      } catch { return { items: [] }; }
    },
    enabled: activeTab === 'hypotheses' || showNewHuntModal,
    retry: 1,
  });

  // Fetch findings
  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ['hunting-findings', findingSeverityFilter, findingStatusFilter],
    queryFn: async () => {
      try {
        const response = await api.get('/hunting/findings', {
          params: {
            ...(findingSeverityFilter && { severity: findingSeverityFilter }),
            ...(findingStatusFilter && { classification: findingStatusFilter }),
          },
        });
        return response.data;
      } catch { return { items: [] }; }
    },
    enabled: activeTab === 'findings',
    retry: 1,
  });

  // Fetch notebooks
  const { data: notebooksData, isLoading: notebooksLoading } = useQuery({
    queryKey: ['hunting-notebooks'],
    queryFn: async () => {
      try {
        const response = await api.get('/hunting/notebooks');
        return response.data;
      } catch { return []; }
    },
    enabled: activeTab === 'notebooks',
    retry: 1,
  });

  // Fetch templates
  const { data: templatesData, isLoading: templatesLoading } = useQuery({
    queryKey: ['hunting-templates'],
    queryFn: async () => {
      try {
        const response = await api.get('/hunting/templates');
        return response.data;
      } catch { return []; }
    },
    enabled: activeTab === 'templates',
    retry: 1,
  });

  // Pause/Resume hunt mutation
  const toggleHuntMutation = useMutation({
    mutationFn: async ({ huntId, action }: { huntId: string; action: string }) => {
      const response = await api.post(`/hunting/sessions/${huntId}/${action}`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['hunting-stats'] });
    },
    onError: (err: any) => showError(err),
  });

  // Cancel hunt mutation
  const cancelHuntMutation = useMutation({
    mutationFn: async (huntId: string) => {
      const response = await api.post(`/hunting/sessions/${huntId}/cancel`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['hunting-stats'] });
    },
    onError: (err: any) => showError(err),
  });

  // Create hunt session mutation
  const createHuntMutation = useMutation({
    mutationFn: async (hypothesisId: string) => {
      const response = await api.post('/hunting/sessions', { hypothesis_id: hypothesisId });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['hunting-stats'] });
      setShowNewHuntModal(false);
      setNewHuntHypothesisId('');
    },
    onError: (err: any) => showError(err),
  });

  // Create hypothesis mutation
  const createHypothesisMutation = useMutation({
    mutationFn: async (data: { title: string; description: string; priority: number }) => {
      const response = await api.post('/hunting/hypotheses', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-hypotheses'] });
      queryClient.invalidateQueries({ queryKey: ['hunting-stats'] });
      setShowNewHypothesisModal(false);
      setNewHypothesisTitle('');
      setNewHypothesisDescription('');
      setNewHypothesisPriority(3);
    },
    onError: (err: any) => showError(err),
  });

  // Instantiate template mutation
  const instantiateTemplateMutation = useMutation({
    mutationFn: async (templateId: string) => {
      const response = await api.post(`/hunting/templates/${templateId}/instantiate`, {});
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-hypotheses'] });
      queryClient.invalidateQueries({ queryKey: ['hunting-stats'] });
      setActiveTab('hypotheses');
    },
    onError: (err: any) => showError(err),
  });

  // Escalate finding mutation
  const escalateFindingMutation = useMutation({
    mutationFn: async (findingId: string) => {
      const response = await api.post(`/hunting/findings/${findingId}/escalate`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-findings'] });
    },
    onError: (err: any) => showError(err),
  });

  // Update hypothesis mutation
  const updateHypothesisMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: { title: string; description: string; priority: number } }) => {
      const response = await api.put(`/hunting/hypotheses/${id}`, data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-hypotheses'] });
      setEditingHypothesis(null);
    },
    onError: (err: any) => showError(err),
  });

  // Delete hypothesis mutation
  const deleteHypothesisMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/hunting/hypotheses/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-hypotheses'] });
    },
    onError: (err: any) => showError(err),
  });

  // Activate hypothesis mutation
  const activateHypothesisMutation = useMutation({
    mutationFn: async (id: string) => {
      const r = await api.post(`/hunting/hypotheses/${id}/activate`);
      return r.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-hypotheses'] });
    },
    onError: (err: any) => showError(err),
  });

  // Create notebook mutation
  const createNotebookMutation = useMutation({
    mutationFn: async (data: { title: string; description: string; session_id: string }) => {
      const response = await api.post('/hunting/notebooks', data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-notebooks'] });
      setShowCreateNotebookModal(false);
      setNewNotebookTitle('');
      setNewNotebookDescription('');
      setNewNotebookSessionId('');
    },
    onError: (err: any) => showError(err),
  });

  // Duplicate notebook mutation
  const duplicateNotebookMutation = useMutation({
    mutationFn: async (notebook: any) => {
      const response = await api.post('/hunting/notebooks', {
        title: `${notebook.title} (Copy)`,
        session_id: notebook.session_id,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['hunting-notebooks'] });
    },
    onError: (err: any) => showError(err),
  });

  const tabs = [
    { id: 'hunts', label: 'Hunts', icon: Zap },
    { id: 'hypotheses', label: 'Hypotheses', icon: Lightbulb },
    { id: 'findings', label: 'Findings', icon: CheckCircle },
    { id: 'notebooks', label: 'Notebooks', icon: BookOpen },
    { id: 'templates', label: 'Templates', icon: Search },
  ];

  const hunts = huntsData?.items || (Array.isArray(huntsData) ? huntsData : []);
  const hypotheses = hypothesesData?.items || (Array.isArray(hypothesesData) ? hypothesesData : []);
  const findings = findingsData?.items || (Array.isArray(findingsData) ? findingsData : []);
  const notebooks = notebooksData?.items || (Array.isArray(notebooksData) ? notebooksData : []);
  const templates = Array.isArray(templatesData) ? templatesData : (templatesData?.items || []);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Threat Hunting</h1>
          <p className="text-gray-500 mt-1">Proactive threat detection and investigation</p>
        </div>
      </div>

      {/* Error banner */}
      {actionError && (
        <div className="flex items-start justify-between p-4 rounded-lg border border-red-200 bg-red-50 text-red-800">
          <div className="flex items-start space-x-2">
            <AlertCircle className="w-5 h-5 mt-0.5 flex-shrink-0" />
            <div className="text-sm">
              <div className="font-semibold">Action failed</div>
              <div className="mt-0.5 break-words">{actionError}</div>
            </div>
          </div>
          <button
            onClick={() => setActionError(null)}
            className="text-red-600 hover:text-red-800 ml-4"
            aria-label="Dismiss error"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="bg-white rounded-lg border border-gray-200">
        <div className="flex border-b border-gray-200">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={clsx(
                  'flex items-center space-x-2 px-6 py-4 font-medium border-b-2 transition-colors',
                  activeTab === tab.id
                    ? 'border-blue-600 text-blue-600'
                    : 'border-transparent text-gray-600 hover:text-gray-900'
                )}
              >
                <Icon className="w-5 h-5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Hunts Tab */}
      {activeTab === 'hunts' && (
        <div className="space-y-6">
          {/* Stats */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <StatsCard
              title="Active Hunts"
              value={statsLoading ? '-' : stats?.active_hunts || 0}
              icon={Zap}
              color="blue"
            />
            <StatsCard
              title="Hypotheses"
              value={statsLoading ? '-' : stats?.total_hypotheses || 0}
              icon={Lightbulb}
              color="yellow"
            />
            <StatsCard
              title="Findings"
              value={statsLoading ? '-' : stats?.total_findings || 0}
              icon={CheckCircle}
              color="green"
            />
            <StatsCard
              title="Completed Hunts"
              value={statsLoading ? '-' : stats?.completed_hunts || 0}
              icon={AlertCircle}
              color="red"
            />
          </div>

          {/* Filters and Create */}
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-500" />
            <button
              onClick={() => setHuntFilter('')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                huntFilter === '' ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              All
            </button>
            <button
              onClick={() => setHuntFilter('RUNNING')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                huntFilter === 'RUNNING' ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Active
            </button>
            <button
              onClick={() => setHuntFilter('PAUSED')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                huntFilter === 'PAUSED' ? 'bg-yellow-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Paused
            </button>
            <button
              onClick={() => setHuntFilter('COMPLETED')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                huntFilter === 'COMPLETED' ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Completed
            </button>

            <div className="flex-1" />

            <button
              onClick={() => setShowNewHuntModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              <Plus className="w-5 h-5" />
              New Hunt
            </button>
          </div>

          {/* Hunts Table */}
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {huntsLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : hunts.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                <Search className="w-12 h-12 mb-4 text-gray-300" />
                <p>No hunts found</p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Hunt ID
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Hypothesis
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Findings
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Started
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Duration
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {hunts.map((hunt: any, index: number) => (
                    <tr key={hunt.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 text-sm font-medium text-gray-900 font-mono">
                        {hunt.id?.slice(0, 8)}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 font-mono">
                        {hunt.hypothesis_id?.slice(0, 8) || '-'}
                      </td>
                      <td className="px-6 py-4">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full capitalize', statusColors[hunt.status])}>
                          {hunt.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">{hunt.findings_count || 0}</td>
                      <td className="px-6 py-4 text-sm text-gray-600">
                        {hunt.started_at ? new Date(hunt.started_at || "").toLocaleDateString() : '-'}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">{formatDuration(hunt.duration_seconds)}</td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => setSelectedHunt(hunt)}
                            className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                          >
                            View
                          </button>
                          {(hunt.status === 'RUNNING' || hunt.status === 'active') ? (
                            <button
                              onClick={() =>
                                toggleHuntMutation.mutate({
                                  huntId: hunt.id,
                                  action: 'pause',
                                })
                              }
                              className="text-yellow-600 hover:text-yellow-800 p-1"
                              title="Pause"
                            >
                              <Pause className="w-4 h-4" />
                            </button>
                          ) : (hunt.status === 'PAUSED' || hunt.status === 'paused') ? (
                            <button
                              onClick={() =>
                                toggleHuntMutation.mutate({
                                  huntId: hunt.id,
                                  action: 'resume',
                                })
                              }
                              className="text-green-600 hover:text-green-800 p-1"
                              title="Resume"
                            >
                              <Play className="w-4 h-4" />
                            </button>
                          ) : null}
                          {!['COMPLETED', 'FAILED', 'CANCELLED', 'completed', 'cancelled'].includes(hunt.status) && (
                            <button
                              onClick={() => cancelHuntMutation.mutate(hunt.id)}
                              className="text-red-600 hover:text-red-800 p-1"
                              title="Cancel"
                            >
                              <X className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Hunt Details Modal */}
          {selectedHunt && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
                  <h2 className="text-lg font-semibold text-gray-900">
                    Hunt <span className="font-mono">{selectedHunt.id?.slice(0, 8)}</span>
                  </h2>
                  <button
                    onClick={() => setSelectedHunt(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Status</label>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full capitalize inline-block',
                          statusColors[selectedHunt.status]
                        )}
                      >
                        {selectedHunt.status}
                      </span>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Findings</label>
                      <p className="text-gray-900 font-medium">{selectedHunt.findings_count || 0}</p>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Hypothesis ID</label>
                    <p className="text-gray-900 font-mono">{selectedHunt.hypothesis_id || '-'}</p>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Events Analyzed</label>
                      <p className="text-gray-900 font-medium">{selectedHunt.events_analyzed || 0}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Queries Executed</label>
                      <p className="text-gray-900 font-medium">{selectedHunt.queries_executed || selectedHunt.query_count || 0}</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Duration</label>
                      <p className="text-gray-900">{formatDuration(selectedHunt.duration_seconds)}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Created By</label>
                      <p className="text-gray-900">{selectedHunt.created_by || '-'}</p>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Started At</label>
                      <p className="text-gray-900 text-sm">
                        {selectedHunt.started_at ? new Date(selectedHunt.started_at || "").toLocaleString() : '-'}
                      </p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Completed At</label>
                      <p className="text-gray-900 text-sm">
                        {selectedHunt.completed_at ? new Date(selectedHunt.completed_at || "").toLocaleString() : '-'}
                      </p>
                    </div>
                  </div>
                  {selectedHunt.error_message && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Error</label>
                      <p className="text-red-600 text-sm">{selectedHunt.error_message}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* New Hunt Modal */}
          {showNewHuntModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">Create New Hunt Session</h2>
                  <button
                    onClick={() => setShowNewHuntModal(false)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Select Hypothesis</label>
                    <select
                      value={newHuntHypothesisId}
                      onChange={(e) => setNewHuntHypothesisId(e.target.value)}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="">-- Select a hypothesis --</option>
                      {hypotheses.map((h: any) => (
                        <option key={h.id} value={h.id}>
                          {h.title} ({h.status})
                        </option>
                      ))}
                    </select>
                    {hypotheses.length === 0 && (
                      <p className="text-xs text-gray-500 mt-1">No hypotheses available. Create one first.</p>
                    )}
                  </div>
                  <div className="flex justify-end gap-2">
                    <button
                      onClick={() => setShowNewHuntModal(false)}
                      className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm font-medium"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => {
                        if (newHuntHypothesisId) {
                          createHuntMutation.mutate(newHuntHypothesisId);
                        }
                      }}
                      disabled={!newHuntHypothesisId || createHuntMutation.isPending}
                      className={clsx(
                        'px-4 py-2 rounded-lg text-sm font-medium text-white',
                        !newHuntHypothesisId || createHuntMutation.isPending
                          ? 'bg-blue-400 cursor-not-allowed'
                          : 'bg-blue-600 hover:bg-blue-700'
                      )}
                    >
                      {createHuntMutation.isPending ? 'Creating...' : 'Create Hunt'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Hypotheses Tab */}
      {activeTab === 'hypotheses' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="flex items-center gap-2 flex-wrap">
            <Filter className="w-5 h-5 text-gray-500" />
            <button
              onClick={() => {
                setMitreFilterTab('');
                setPriorityFilterTab('');
                setHypothesisStatusFilter('');
              }}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                !mitreFilterTab && !priorityFilterTab && !hypothesisStatusFilter
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              All
            </button>

            <div className="h-6 border-r border-gray-300" />

            <span className="text-xs text-gray-500 font-medium">MITRE:</span>
            {['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation'].map((mitre) => (
              <button
                key={mitre}
                onClick={() => setMitreFilterTab(mitreFilterTab === mitre ? '' : mitre)}
                className={clsx(
                  'px-2 py-1 rounded text-xs font-medium transition-colors',
                  mitreFilterTab === mitre ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                )}
              >
                {mitre}
              </button>
            ))}

            <div className="h-6 border-r border-gray-300" />

            <span className="text-xs text-gray-500 font-medium">Priority:</span>
            {([{ label: 'High', value: '1' }, { label: 'Medium', value: '3' }, { label: 'Low', value: '4' }]).map((priority) => (
              <button
                key={priority.value}
                onClick={() => setPriorityFilterTab(priorityFilterTab === priority.value ? '' : priority.value)}
                className={clsx(
                  'px-2 py-1 rounded text-xs font-medium transition-colors',
                  priorityFilterTab === priority.value ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                )}
              >
                {priority.label}
              </button>
            ))}

            <div className="flex-1" />

            <button
              onClick={() => setShowNewHypothesisModal(true)}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              <Plus className="w-5 h-5" />
              Create Hypothesis
            </button>
          </div>

          {/* Hypotheses Grid */}
          {hypothesesLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : hypotheses.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-gray-500">
              <Lightbulb className="w-12 h-12 mb-4 text-gray-300" />
              <p>No hypotheses found</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {hypotheses.map((hypothesis: any) => (
                <div key={hypothesis.id} className="bg-white rounded-lg border border-gray-200 p-6">
                  <div className="flex items-start justify-between mb-3">
                    <h3 className="font-semibold text-gray-900 flex-1">{hypothesis.title}</h3>
                    <span
                      className={clsx(
                        'px-2 py-1 text-xs font-medium rounded-full whitespace-nowrap ml-2',
                        hypothesis.priority <= 2
                          ? 'bg-red-100 text-red-700'
                          : hypothesis.priority === 3
                            ? 'bg-yellow-100 text-yellow-700'
                            : 'bg-blue-100 text-blue-700'
                      )}
                    >
                      P{hypothesis.priority}
                    </span>
                  </div>

                  <p className="text-sm text-gray-600 mb-4 line-clamp-2">{hypothesis.description}</p>

                  {(() => { const mt = safeArray(hypothesis.mitre_techniques); return mt.length > 0 ? (
                    <div className="mb-3">
                      <p className="text-xs text-gray-500 font-medium mb-2">MITRE Techniques:</p>
                      <div className="flex flex-wrap gap-1">
                        {mt.slice(0, 3).map((tech: string, i: number) => (
                          <span key={i} className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                            {String(tech)}
                          </span>
                        ))}
                        {mt.length > 3 && (
                          <span className="px-2 py-1 text-xs text-gray-600">
                            +{mt.length - 3}
                          </span>
                        )}
                      </div>
                    </div>
                  ) : null; })()}

                  <div className="flex items-center justify-between mb-4 text-xs text-gray-500">
                    <span>{safeArray(hypothesis.data_sources).join(', ') || 'No sources'}</span>
                    <span
                      className={clsx(
                        'px-2 py-1 rounded-full',
                        statusColors[hypothesis.status] || 'bg-gray-100 text-gray-700'
                      )}
                    >
                      {hypothesis.status}
                    </span>
                  </div>

                  <div className="flex gap-2 mb-2">
                    <button
                      onClick={() => {
                        setEditingHypothesis(hypothesis);
                        setEditHypothesisTitle(hypothesis.title);
                        setEditHypothesisDescription(hypothesis.description || '');
                        setEditHypothesisPriority(hypothesis.priority || 3);
                      }}
                      className="flex-1 px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm font-medium"
                    >
                      Edit
                    </button>
                    {hypothesis.status === 'DRAFT' && (
                      <button
                        onClick={() => activateHypothesisMutation.mutate(hypothesis.id)}
                        className="flex-1 px-3 py-2 bg-green-50 text-green-600 rounded-lg hover:bg-green-100 text-sm font-medium"
                      >
                        Activate
                      </button>
                    )}
                    <button
                      onClick={() => {
                        if (confirm('Are you sure you want to delete this hypothesis?')) {
                          deleteHypothesisMutation.mutate(hypothesis.id);
                        }
                      }}
                      className="px-3 py-2 border border-red-300 text-red-600 rounded-lg hover:bg-red-50"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                  <button
                    onClick={() => {
                      setNewHuntHypothesisId(hypothesis.id);
                      setShowNewHuntModal(true);
                      setActiveTab('hunts');
                    }}
                    className="w-full px-3 py-2 bg-blue-50 text-blue-600 rounded-lg hover:bg-blue-100 text-sm font-medium"
                  >
                    Start Hunt
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* New Hypothesis Modal */}
          {showNewHypothesisModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">Create New Hypothesis</h2>
                  <button
                    onClick={() => setShowNewHypothesisModal(false)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Title</label>
                    <input
                      type="text"
                      value={newHypothesisTitle}
                      onChange={(e) => setNewHypothesisTitle(e.target.value)}
                      placeholder="Enter hypothesis title"
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                    <textarea
                      value={newHypothesisDescription}
                      onChange={(e) => setNewHypothesisDescription(e.target.value)}
                      placeholder="Describe the hypothesis"
                      rows={3}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Priority (1=highest, 5=lowest)</label>
                    <select
                      value={newHypothesisPriority}
                      onChange={(e) => setNewHypothesisPriority(Number(e.target.value))}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value={1}>1 - Critical</option>
                      <option value={2}>2 - High</option>
                      <option value={3}>3 - Medium</option>
                      <option value={4}>4 - Low</option>
                      <option value={5}>5 - Info</option>
                    </select>
                  </div>
                  <div className="flex justify-end gap-2">
                    <button
                      onClick={() => setShowNewHypothesisModal(false)}
                      className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm font-medium"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => {
                        if (newHypothesisTitle && newHypothesisDescription) {
                          createHypothesisMutation.mutate({
                            title: newHypothesisTitle,
                            description: newHypothesisDescription,
                            priority: newHypothesisPriority,
                          });
                        }
                      }}
                      disabled={!newHypothesisTitle || !newHypothesisDescription || createHypothesisMutation.isPending}
                      className={clsx(
                        'px-4 py-2 rounded-lg text-sm font-medium text-white',
                        !newHypothesisTitle || !newHypothesisDescription || createHypothesisMutation.isPending
                          ? 'bg-blue-400 cursor-not-allowed'
                          : 'bg-blue-600 hover:bg-blue-700'
                      )}
                    >
                      {createHypothesisMutation.isPending ? 'Creating...' : 'Create Hypothesis'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Edit Hypothesis Modal */}
          {editingHypothesis && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">Edit Hypothesis</h2>
                  <button
                    onClick={() => setEditingHypothesis(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Title</label>
                    <input
                      type="text"
                      value={editHypothesisTitle}
                      onChange={(e) => setEditHypothesisTitle(e.target.value)}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                    <textarea
                      value={editHypothesisDescription}
                      onChange={(e) => setEditHypothesisDescription(e.target.value)}
                      rows={3}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Priority (1=highest, 5=lowest)</label>
                    <select
                      value={editHypothesisPriority}
                      onChange={(e) => setEditHypothesisPriority(Number(e.target.value))}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value={1}>1 - Critical</option>
                      <option value={2}>2 - High</option>
                      <option value={3}>3 - Medium</option>
                      <option value={4}>4 - Low</option>
                      <option value={5}>5 - Info</option>
                    </select>
                  </div>
                  <div className="flex justify-end gap-2">
                    <button
                      onClick={() => setEditingHypothesis(null)}
                      className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm font-medium"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => {
                        if (editHypothesisTitle && editHypothesisDescription) {
                          updateHypothesisMutation.mutate({
                            id: editingHypothesis.id,
                            data: {
                              title: editHypothesisTitle,
                              description: editHypothesisDescription,
                              priority: editHypothesisPriority,
                            },
                          });
                        }
                      }}
                      disabled={!editHypothesisTitle || !editHypothesisDescription || updateHypothesisMutation.isPending}
                      className={clsx(
                        'px-4 py-2 rounded-lg text-sm font-medium text-white',
                        !editHypothesisTitle || !editHypothesisDescription || updateHypothesisMutation.isPending
                          ? 'bg-blue-400 cursor-not-allowed'
                          : 'bg-blue-600 hover:bg-blue-700'
                      )}
                    >
                      {updateHypothesisMutation.isPending ? 'Saving...' : 'Save Changes'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Findings Tab */}
      {activeTab === 'findings' && (
        <div className="space-y-6">
          {/* Filters */}
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-500" />
            <button
              onClick={() => {
                setFindingSeverityFilter('');
                setFindingStatusFilter('');
              }}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                !findingSeverityFilter && !findingStatusFilter
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              All
            </button>

            <span className="text-xs text-gray-500 font-medium">Severity:</span>
            {['critical', 'high', 'medium', 'low'].map((severity) => (
              <button
                key={severity}
                onClick={() => setFindingSeverityFilter(findingSeverityFilter === severity ? '' : severity)}
                className={clsx(
                  'px-2 py-1 rounded text-xs font-medium transition-colors capitalize',
                  findingSeverityFilter === severity
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                )}
              >
                {severity}
              </button>
            ))}

            <div className="h-6 border-r border-gray-300" />

            <span className="text-xs text-gray-500 font-medium">Classification:</span>
            {['true_positive', 'false_positive', 'testing'].map((classification) => (
              <button
                key={classification}
                onClick={() => setFindingStatusFilter(findingStatusFilter === classification ? '' : classification)}
                className={clsx(
                  'px-2 py-1 rounded text-xs font-medium transition-colors',
                  findingStatusFilter === classification
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                )}
              >
                {classification.replace(/_/g, ' ')}
              </button>
            ))}
          </div>

          {/* Findings Table */}
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            {findingsLoading ? (
              <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
              </div>
            ) : findings.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-64 text-gray-500">
                <CheckCircle className="w-12 h-12 mb-4 text-gray-300" />
                <p>No findings found</p>
              </div>
            ) : (
              <table className="w-full">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Time
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Title
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Session
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Severity
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Description
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Evidence
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Classification
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {findings.map((finding: any) => (
                    <tr key={finding.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 text-sm text-gray-500">
                        {finding.created_at ? new Date(finding.created_at || "").toLocaleString() : '-'}
                      </td>
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">{finding.title}</td>
                      <td className="px-6 py-4 text-sm text-gray-600 font-mono">
                        {finding.session_id?.slice(0, 8) || '-'}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={clsx(
                            'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                            severityColors[finding.severity] || severityColors.info
                          )}
                        >
                          {finding.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600 max-w-xs truncate">{finding.description}</td>
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">
                        {Array.isArray(finding.evidence) ? finding.evidence.length : 0}
                      </td>
                      <td className="px-6 py-4">
                        <span
                          className={clsx(
                            'px-2 py-1 text-xs font-medium rounded-full capitalize',
                            finding.classification === 'true_positive'
                              ? 'text-green-600 bg-green-50'
                              : finding.classification === 'false_positive'
                                ? 'text-purple-600 bg-purple-50'
                                : 'text-gray-600 bg-gray-50'
                          )}
                        >
                          {finding.classification ? finding.classification.replace(/_/g, ' ') : 'unclassified'}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => setSelectedFinding(finding)}
                            className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                          >
                            View
                          </button>
                          {!finding.escalated_to_case && (
                            <button
                              onClick={() => escalateFindingMutation.mutate(finding.id)}
                              className="text-red-600 hover:text-red-800 text-sm font-medium"
                            >
                              Escalate
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>

          {/* Finding Details Modal */}
          {selectedFinding && (() => {
            // Pre-parse all fields safely outside JSX to avoid render crashes
            const sfTitle = selectedFinding.title || 'Untitled Finding';
            const sfClassification = selectedFinding.classification || '';
            const sfSeverity = selectedFinding.severity || 'info';
            const sfSessionId = selectedFinding.session_id || '-';
            const sfDescription = selectedFinding.description || 'No description available';
            const sfEscalated = !!selectedFinding.escalated_to_case;
            const sfCaseId = selectedFinding.case_id || '';

            const safeParseArray = (val: any): any[] => {
              try {
                if (Array.isArray(val)) return val;
                if (typeof val === 'string' && val.trim()) {
                  const parsed = JSON.parse(val);
                  return Array.isArray(parsed) ? parsed : [];
                }
                return [];
              } catch {
                return [];
              }
            };

            const evidence = safeParseArray(selectedFinding.evidence);
            const assets = safeParseArray(selectedFinding.affected_assets);
            const iocs = safeParseArray(selectedFinding.iocs_found);
            const techniques = safeParseArray(selectedFinding.mitre_techniques);

            return (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setSelectedFinding(null)}>
              <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
                  <h2 className="text-lg font-semibold text-gray-900">Finding: {sfTitle}</h2>
                  <button
                    onClick={() => setSelectedFinding(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Classification</label>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full capitalize',
                          sfClassification === 'true_positive'
                            ? 'text-green-600 bg-green-50'
                            : sfClassification === 'false_positive'
                              ? 'text-purple-600 bg-purple-50'
                              : 'text-gray-600 bg-gray-50'
                        )}
                      >
                        {sfClassification ? sfClassification.replace(/_/g, ' ') : 'unclassified'}
                      </span>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Severity</label>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                          severityColors[sfSeverity] || severityColors.info
                        )}
                      >
                        {sfSeverity}
                      </span>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Session ID</label>
                    <p className="text-gray-900 font-mono text-sm">{sfSessionId}</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Description</label>
                    <p className="text-gray-900">{sfDescription}</p>
                  </div>
                  {evidence.length > 0 && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Evidence</label>
                      <ul className="list-disc list-inside text-sm text-gray-900">
                        {evidence.map((e: any, i: number) => (
                          <li key={i}>{typeof e === 'object' && e !== null ? JSON.stringify(e) : String(e ?? '')}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {assets.length > 0 && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Affected Assets</label>
                      <div className="flex flex-wrap gap-1">
                        {assets.map((a: any, i: number) => (
                          <span key={i} className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">{String(a ?? '')}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {iocs.length > 0 && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">IOCs Found</label>
                      <div className="flex flex-wrap gap-1">
                        {iocs.map((ioc: any, i: number) => (
                          <span key={i} className="px-2 py-1 text-xs bg-red-50 text-red-700 rounded font-mono">{String(ioc ?? '')}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {techniques.length > 0 && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">MITRE Techniques</label>
                      <div className="flex flex-wrap gap-1">
                        {techniques.map((t: any, i: number) => (
                          <span key={i} className="px-2 py-1 text-xs bg-blue-50 text-blue-700 rounded">{String(t ?? '')}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {selectedFinding.analyst_notes && (
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Analyst Notes</label>
                      <p className="text-gray-900 text-sm whitespace-pre-wrap">{selectedFinding.analyst_notes}</p>
                    </div>
                  )}
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Escalated</label>
                    <p className="text-gray-900 font-medium">
                      {sfEscalated ? `Yes (Case: ${sfCaseId.slice(0, 8) || 'N/A'})` : 'No'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
            );
          })()}
        </div>
      )}

      {/* Notebooks Tab */}
      {activeTab === 'notebooks' && (
        <div className="space-y-6">
          <button
            onClick={() => setShowCreateNotebookModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
          >
            <Plus className="w-5 h-5" />
            Create Notebook
          </button>

          {notebooksLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : notebooks.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-gray-500">
              <BookOpen className="w-12 h-12 mb-4 text-gray-300" />
              <p>No notebooks yet</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {notebooks.map((notebook: any) => (
                <div key={notebook.id} className="bg-white rounded-lg border border-gray-200 p-6">
                  <h3 className="font-semibold text-gray-900 mb-2">{notebook.title}</h3>
                  <p className="text-sm text-gray-600 mb-4 line-clamp-2">
                    Session: <span className="font-mono">{notebook.session_id?.slice(0, 8) || '-'}</span>
                  </p>

                  <div className="space-y-2 text-xs text-gray-500 mb-4">
                    <div className="flex items-center justify-between">
                      <span>Version: {notebook.version || 1}</span>
                      <span>{notebook.is_published ? 'Published' : 'Draft'}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Updated: {new Date(notebook.updated_at || "").toLocaleDateString()}</span>
                      <span>{notebook.content?.length || 0} cells</span>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => setSelectedNotebook(notebook)}
                      className="flex-1 px-3 py-2 bg-blue-50 text-blue-600 rounded-lg hover:bg-blue-100 text-sm font-medium flex items-center justify-center gap-1"
                    >
                      <Eye className="w-4 h-4" />
                      Open
                    </button>
                    <button
                      onClick={() => duplicateNotebookMutation.mutate(notebook)}
                      className="flex-1 px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm font-medium flex items-center justify-center gap-1"
                    >
                      <Copy className="w-4 h-4" />
                      Duplicate
                    </button>
                    <button
                      onClick={async () => {
                        try {
                          const response = await api.get(`/hunting/notebooks/${notebook.id}/export`);
                          const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `notebook-${notebook.id.slice(0, 8)}.json`;
                          a.click();
                          URL.revokeObjectURL(url);
                        } catch (err: any) {
                          console.error('Export failed:', err);
                          showError(err);
                        }
                      }}
                      className="px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Create Notebook Modal */}
          {showCreateNotebookModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
                  <h2 className="text-lg font-semibold text-gray-900">Create New Notebook</h2>
                  <button
                    onClick={() => setShowCreateNotebookModal(false)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Title</label>
                    <input
                      type="text"
                      value={newNotebookTitle}
                      onChange={(e) => setNewNotebookTitle(e.target.value)}
                      placeholder="Notebook title"
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
                    <textarea
                      value={newNotebookDescription}
                      onChange={(e) => setNewNotebookDescription(e.target.value)}
                      placeholder="Notebook description"
                      rows={3}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">Hunt Session</label>
                    <select
                      value={newNotebookSessionId}
                      onChange={(e) => setNewNotebookSessionId(e.target.value)}
                      className="w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:ring-blue-500 focus:border-blue-500"
                    >
                      <option value="">-- Select a session --</option>
                      {hunts.map((h: any) => (
                        <option key={h.id} value={h.id}>{h.id?.slice(0, 8)} — {h.status}</option>
                      ))}
                    </select>
                  </div>
                  <div className="flex justify-end gap-2">
                    <button
                      onClick={() => setShowCreateNotebookModal(false)}
                      className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm font-medium"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => {
                        if (newNotebookTitle && newNotebookSessionId) {
                          createNotebookMutation.mutate({
                            title: newNotebookTitle,
                            description: newNotebookDescription,
                            session_id: newNotebookSessionId,
                          });
                        }
                      }}
                      disabled={!newNotebookTitle || !newNotebookSessionId || createNotebookMutation.isPending}
                      className={clsx(
                        'px-4 py-2 rounded-lg text-sm font-medium text-white',
                        !newNotebookTitle || !newNotebookSessionId || createNotebookMutation.isPending
                          ? 'bg-blue-400 cursor-not-allowed'
                          : 'bg-blue-600 hover:bg-blue-700'
                      )}
                    >
                      {createNotebookMutation.isPending ? 'Creating...' : 'Create Notebook'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Notebook Detail Modal */}
          {selectedNotebook && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
                  <h2 className="text-lg font-semibold text-gray-900">{selectedNotebook.title}</h2>
                  <button
                    onClick={() => setSelectedNotebook(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Session ID</label>
                      <p className="text-gray-900 font-mono text-sm">{selectedNotebook.session_id || '-'}</p>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Version</label>
                      <p className="text-gray-900">{selectedNotebook.version || 1}</p>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Status</label>
                    <p className="text-gray-900">{selectedNotebook.is_published ? 'Published' : 'Draft'}</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Content ({selectedNotebook.content?.length || 0} cells)</label>
                    <pre className="bg-gray-50 rounded-lg p-4 text-sm text-gray-800 overflow-x-auto max-h-64 overflow-y-auto">
                      {JSON.stringify(selectedNotebook.content, null, 2) || '[]'}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Templates Tab */}
      {activeTab === 'templates' && (
        <div className="space-y-6">
          {templatesLoading ? (
            <div className="flex items-center justify-center h-64">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
          ) : templates.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-64 text-gray-500">
              <Search className="w-12 h-12 mb-4 text-gray-300" />
              <p>No templates available</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {templates.map((template: any) => (
                <div key={template.id} className="bg-white rounded-lg border border-gray-200 p-6">
                  <div className="flex items-start justify-between mb-2">
                    <h3 className="font-semibold text-gray-900">{template.name}</h3>
                    <span
                      className={clsx(
                        'px-2 py-1 text-xs font-medium rounded-full whitespace-nowrap ml-2',
                        template.difficulty === 'advanced'
                          ? 'bg-red-100 text-red-700'
                          : template.difficulty === 'intermediate'
                            ? 'bg-yellow-100 text-yellow-700'
                            : 'bg-green-100 text-green-700'
                      )}
                    >
                      {template.difficulty}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 mb-4 line-clamp-2">{template.description}</p>

                  {(() => { const mt = safeArray(template.mitre_techniques); return mt.length > 0 ? (
                    <div className="mb-3">
                      <p className="text-xs text-gray-500 font-medium mb-2">MITRE Techniques:</p>
                      <div className="flex flex-wrap gap-1">
                        {mt.slice(0, 3).map((tech: string, i: number) => (
                          <span key={i} className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                            {String(tech)}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null; })()}

                  <div className="space-y-2 text-xs text-gray-500 mb-4">
                    <div>Category: {template.category}</div>
                    <div>Type: {template.hunt_type}</div>
                    <div>Est. Duration: {template.estimated_duration_minutes}m</div>
                  </div>

                  <button
                    onClick={() => instantiateTemplateMutation.mutate(template.id)}
                    disabled={instantiateTemplateMutation.isPending}
                    className={clsx(
                      'w-full px-3 py-2 rounded-lg text-sm font-medium text-white',
                      instantiateTemplateMutation.isPending
                        ? 'bg-blue-400 cursor-not-allowed'
                        : 'bg-blue-600 hover:bg-blue-700'
                    )}
                  >
                    {instantiateTemplateMutation.isPending ? 'Creating...' : 'Use Template'}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function StatsCard({ title, value, icon: Icon, color }: any) {
  const colorClasses = {
    blue: 'text-blue-600',
    yellow: 'text-yellow-600',
    green: 'text-green-600',
    red: 'text-red-600',
  };

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-gray-600">{title}</p>
          <p className="text-2xl font-bold text-gray-900 mt-1">{value}</p>
        </div>
        <Icon className={`w-8 h-8 ${colorClasses[color as keyof typeof colorClasses] || 'text-blue-600'} opacity-10`} />
      </div>
    </div>
  );
}
