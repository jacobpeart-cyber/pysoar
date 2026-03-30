import { useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
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

const statusColors: Record<string, string> = {
  active: 'text-green-600 bg-green-50 border border-green-200',
  paused: 'text-yellow-600 bg-yellow-50 border border-yellow-200',
  completed: 'text-blue-600 bg-blue-50 border border-blue-200',
  cancelled: 'text-gray-600 bg-gray-50 border border-gray-200',
  new: 'text-blue-600 bg-blue-50',
  investigating: 'text-yellow-600 bg-yellow-50',
  confirmed: 'text-green-600 bg-green-50',
  false_positive: 'text-purple-600 bg-purple-50',
};

export default function ThreatHunting() {
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

  // Fetch hunting stats
  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['hunting-stats'],
    queryFn: async () => {
      const response = await api.get('/hunting/stats');
      return response.data;
    },
  });

  // Fetch hunt sessions
  const { data: huntsData, isLoading: huntsLoading } = useQuery({
    queryKey: ['hunting-sessions', huntFilter],
    queryFn: async () => {
      const response = await api.get('/hunting/sessions', {
        params: huntFilter ? { status: huntFilter } : {},
      });
      return response.data;
    },
    enabled: activeTab === 'hunts',
  });

  // Fetch hypotheses
  const { data: hypothesesData, isLoading: hypothesesLoading } = useQuery({
    queryKey: ['hunting-hypotheses', mitreFilterTab, priorityFilterTab, hypothesisStatusFilter],
    queryFn: async () => {
      const response = await api.get('/hunting/hypotheses', {
        params: {
          ...(mitreFilterTab && { mitre_tactic: mitreFilterTab }),
          ...(priorityFilterTab && { priority: priorityFilterTab }),
          ...(hypothesisStatusFilter && { status: hypothesisStatusFilter }),
        },
      });
      return response.data;
    },
    enabled: activeTab === 'hypotheses',
  });

  // Fetch findings
  const { data: findingsData, isLoading: findingsLoading } = useQuery({
    queryKey: ['hunting-findings', findingSeverityFilter, findingStatusFilter],
    queryFn: async () => {
      const response = await api.get('/hunting/findings', {
        params: {
          ...(findingSeverityFilter && { severity: findingSeverityFilter }),
          ...(findingStatusFilter && { status: findingStatusFilter }),
        },
      });
      return response.data;
    },
    enabled: activeTab === 'findings',
  });

  // Fetch notebooks
  const { data: notebooksData, isLoading: notebooksLoading } = useQuery({
    queryKey: ['hunting-notebooks'],
    queryFn: async () => {
      const response = await api.get('/hunting/notebooks');
      return response.data;
    },
    enabled: activeTab === 'notebooks',
  });

  // Fetch templates
  const { data: templatesData, isLoading: templatesLoading } = useQuery({
    queryKey: ['hunting-templates'],
    queryFn: async () => {
      const response = await api.get('/hunting/templates');
      return response.data;
    },
    enabled: activeTab === 'templates',
  });

  // Pause/Resume hunt mutation
  const toggleHuntMutation = useMutation({
    mutationFn: async ({ huntId, action }: { huntId: string; action: string }) => {
      const response = await api.post(`/hunting/sessions/${huntId}/${action}`);
      return response.data;
    },
  });

  // Cancel hunt mutation
  const cancelHuntMutation = useMutation({
    mutationFn: async (huntId: string) => {
      const response = await api.post(`/hunting/sessions/${huntId}/cancel`);
      return response.data;
    },
  });

  // Escalate finding mutation
  const escalateFindingMutation = useMutation({
    mutationFn: async (findingId: string) => {
      const response = await api.post(`/hunting/findings/${findingId}/escalate`);
      return response.data;
    },
  });

  const tabs = [
    { id: 'hunts', label: 'Hunts', icon: Zap },
    { id: 'hypotheses', label: 'Hypotheses', icon: Lightbulb },
    { id: 'findings', label: 'Findings', icon: CheckCircle },
    { id: 'notebooks', label: 'Notebooks', icon: BookOpen },
    { id: 'templates', label: 'Templates', icon: Search },
  ];

  const hunts = huntsData?.items || [];
  const hypotheses = hypothesesData?.items || [];
  const findings = findingsData?.items || [];
  const notebooks = notebooksData?.items || [];
  const templates = templatesData?.items || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Threat Hunting</h1>
          <p className="text-gray-500 mt-1">Proactive threat detection and investigation</p>
        </div>
      </div>

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
              value={statsLoading ? '-' : stats?.hypotheses_tracked || 0}
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
              title="Confirmed Threats"
              value={statsLoading ? '-' : stats?.confirmed_threats || 0}
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
              onClick={() => setHuntFilter('active')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                huntFilter === 'active' ? 'bg-green-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Active
            </button>
            <button
              onClick={() => setHuntFilter('paused')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                huntFilter === 'paused' ? 'bg-yellow-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Paused
            </button>
            <button
              onClick={() => setHuntFilter('completed')}
              className={clsx(
                'px-3 py-1 rounded-full text-sm font-medium transition-colors',
                huntFilter === 'completed' ? 'bg-blue-500 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
              )}
            >
              Completed
            </button>

            <div className="flex-1" />

            <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
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
                      Hunt Name
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
                  {hunts.map((hunt: any) => (
                    <tr key={hunt.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">{hunt.name}</td>
                      <td className="px-6 py-4 text-sm text-gray-600">{hunt.hypothesis}</td>
                      <td className="px-6 py-4">
                        <span className={clsx('px-2 py-1 text-xs font-medium rounded-full capitalize', statusColors[hunt.status])}>
                          {hunt.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">{hunt.findings_count || 0}</td>
                      <td className="px-6 py-4 text-sm text-gray-600">
                        {new Date(hunt.started_at).toLocaleDateString()}
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-600">{hunt.duration || '-'}</td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => setSelectedHunt(hunt)}
                            className="text-blue-600 hover:text-blue-800 text-sm font-medium"
                          >
                            View
                          </button>
                          {hunt.status === 'active' ? (
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
                          ) : hunt.status === 'paused' ? (
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
                          {hunt.status !== 'completed' && hunt.status !== 'cancelled' && (
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
                  <h2 className="text-lg font-semibold text-gray-900">{selectedHunt.name}</h2>
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
                    <label className="block text-sm font-medium text-gray-500 mb-1">Hypothesis</label>
                    <p className="text-gray-900">{selectedHunt.hypothesis}</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Description</label>
                    <p className="text-gray-900 text-sm">{selectedHunt.description || '-'}</p>
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
            {['High', 'Medium', 'Low'].map((priority) => (
              <button
                key={priority}
                onClick={() => setPriorityFilterTab(priorityFilterTab === priority ? '' : priority)}
                className={clsx(
                  'px-2 py-1 rounded text-xs font-medium transition-colors',
                  priorityFilterTab === priority ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                )}
              >
                {priority}
              </button>
            ))}

            <div className="flex-1" />

            <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
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
                        hypothesis.priority === 'high'
                          ? 'bg-red-100 text-red-700'
                          : hypothesis.priority === 'medium'
                            ? 'bg-yellow-100 text-yellow-700'
                            : 'bg-blue-100 text-blue-700'
                      )}
                    >
                      {hypothesis.priority}
                    </span>
                  </div>

                  <p className="text-sm text-gray-600 mb-4 line-clamp-2">{hypothesis.description}</p>

                  {hypothesis.mitre_techniques && hypothesis.mitre_techniques.length > 0 && (
                    <div className="mb-3">
                      <p className="text-xs text-gray-500 font-medium mb-2">MITRE Techniques:</p>
                      <div className="flex flex-wrap gap-1">
                        {hypothesis.mitre_techniques.slice(0, 3).map((tech: string) => (
                          <span key={tech} className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                            {tech}
                          </span>
                        ))}
                        {hypothesis.mitre_techniques.length > 3 && (
                          <span className="px-2 py-1 text-xs text-gray-600">
                            +{hypothesis.mitre_techniques.length - 3}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  <div className="flex items-center justify-between mb-4 text-xs text-gray-500">
                    <span>{hypothesis.data_sources?.join(', ') || 'No sources'}</span>
                    <span
                      className={clsx(
                        'px-2 py-1 rounded-full',
                        hypothesis.status === 'active'
                          ? 'bg-green-100 text-green-700'
                          : 'bg-gray-100 text-gray-700'
                      )}
                    >
                      {hypothesis.status}
                    </span>
                  </div>

                  <button className="w-full px-3 py-2 bg-blue-50 text-blue-600 rounded-lg hover:bg-blue-100 text-sm font-medium">
                    Start Hunt
                  </button>
                </div>
              ))}
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

            <span className="text-xs text-gray-500 font-medium">Status:</span>
            {['new', 'investigating', 'confirmed', 'false_positive'].map((status) => (
              <button
                key={status}
                onClick={() => setFindingStatusFilter(findingStatusFilter === status ? '' : status)}
                className={clsx(
                  'px-2 py-1 rounded text-xs font-medium transition-colors',
                  findingStatusFilter === status
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                )}
              >
                {status.replace('_', ' ')}
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
                      Hunt
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Type
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
                      Status
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
                        {new Date(finding.timestamp).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">{finding.hunt_name}</td>
                      <td className="px-6 py-4 text-sm text-gray-600">{finding.finding_type}</td>
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
                      <td className="px-6 py-4 text-sm font-medium text-gray-900">{finding.evidence_count || 0}</td>
                      <td className="px-6 py-4">
                        <span
                          className={clsx(
                            'px-2 py-1 text-xs font-medium rounded-full capitalize',
                            statusColors[finding.status]
                          )}
                        >
                          {finding.status.replace('_', ' ')}
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
                          {finding.status === 'confirmed' && (
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
          {selectedFinding && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
              <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto">
                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
                  <h2 className="text-lg font-semibold text-gray-900">Finding Details</h2>
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
                      <label className="block text-sm font-medium text-gray-500 mb-1">Status</label>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full capitalize',
                          statusColors[selectedFinding.status]
                        )}
                      >
                        {selectedFinding.status.replace('_', ' ')}
                      </span>
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-500 mb-1">Severity</label>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full border capitalize',
                          severityColors[selectedFinding.severity]
                        )}
                      >
                        {selectedFinding.severity}
                      </span>
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Description</label>
                    <p className="text-gray-900">{selectedFinding.description}</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 mb-1">Evidence Count</label>
                    <p className="text-gray-900 font-medium">{selectedFinding.evidence_count || 0}</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Notebooks Tab */}
      {activeTab === 'notebooks' && (
        <div className="space-y-6">
          <button className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
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
                  <p className="text-sm text-gray-600 mb-4 line-clamp-2">{notebook.description}</p>

                  <div className="space-y-2 text-xs text-gray-500 mb-4">
                    <div className="flex items-center justify-between">
                      <span>Created by: {notebook.created_by}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Last modified: {new Date(notebook.last_modified).toLocaleDateString()}</span>
                      <span>{notebook.cell_count} cells</span>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button className="flex-1 px-3 py-2 bg-blue-50 text-blue-600 rounded-lg hover:bg-blue-100 text-sm font-medium flex items-center justify-center gap-1">
                      <Eye className="w-4 h-4" />
                      Open
                    </button>
                    <button className="flex-1 px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm font-medium flex items-center justify-center gap-1">
                      <Copy className="w-4 h-4" />
                      Duplicate
                    </button>
                    <button className="px-3 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50">
                      <Download className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
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
                  <h3 className="font-semibold text-gray-900 mb-2">{template.name}</h3>
                  <p className="text-sm text-gray-600 mb-4 line-clamp-2">{template.description}</p>

                  {template.mitre_techniques && template.mitre_techniques.length > 0 && (
                    <div className="mb-3">
                      <p className="text-xs text-gray-500 font-medium mb-2">MITRE Techniques:</p>
                      <div className="flex flex-wrap gap-1">
                        {template.mitre_techniques.slice(0, 3).map((tech: string) => (
                          <span key={tech} className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded">
                            {tech}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="space-y-2 text-xs text-gray-500 mb-4">
                    <div>Data sources: {template.data_sources?.join(', ') || 'None'}</div>
                    <div>Frequency: {template.recommended_frequency}</div>
                  </div>

                  <button className="w-full px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm font-medium">
                    Start Hunt from Template
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
