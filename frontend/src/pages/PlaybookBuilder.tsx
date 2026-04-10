import React, { useState, useEffect, useCallback } from 'react';
import {
  Workflow,
  Play,
  Pause,
  CheckCircle,
  Plus,
  Edit,
  Copy,
  Trash2,
  Clock,
  BarChart3,
  GitBranch,
  Search,
  Filter,
  AlertCircle,
  XCircle,
  Loader2,
  FileText,
  Zap,
  Shield,
  Globe,
  Mail,
  Terminal,
  X,
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../api/client';

const getStatusColor = (status: string) => {
  switch (status) {
    case 'active':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'draft':
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
    case 'running':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'completed':
      return 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100';
    case 'failed':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
    case 'paused':
      return 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100';
    default:
      return 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  }
};

const getCategoryIcon = (category: string) => {
  switch (category) {
    case 'incident-response':
      return AlertCircle;
    case 'threat-hunting':
      return Shield;
    case 'enrichment':
      return Globe;
    case 'notification':
      return Mail;
    case 'remediation':
      return Terminal;
    case 'compliance':
      return FileText;
    default:
      return Zap;
  }
};

interface Playbook {
  id: string;
  name: string;
  description: string;
  nodes?: any[];
  edges?: any[];
  status: string;
  category?: string;
  trigger_type?: string;
  trigger_config?: any;
  version?: number;
  updated_at: string;
  created_by: string;
  execution_count: number;
}

interface Template {
  id: string;
  name: string;
  description: string;
  category: string;
  nodeCount: number;
  popularity: number;
  tags: string[];
}

interface Execution {
  id: string;
  playbookName: string;
  playbookId: string;
  status: string;
  startedAt: string;
  duration: string;
  triggeredBy: string;
  nodesExecuted: number;
  totalNodes: number;
}

export default function PlaybookBuilder() {
  const [activeTab, setActiveTab] = useState('playbooks');
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [selectedExecution, setSelectedExecution] = useState<Execution | null>(null);
  const [previewTemplate, setPreviewTemplate] = useState<Template | null>(null);
  const [showFilter, setShowFilter] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: string; text: string } | null>(null);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [playbooksRes, templatesRes] = await Promise.all([
          api.get('/playbook-builder').catch(() => ({ data: { items: [] } })),
          api.get('/playbook-builder/templates').catch(() => ({ data: { items: [] } })),
        ]);
        const pbItems = playbooksRes.data?.items || playbooksRes.data;
        setPlaybooks(Array.isArray(pbItems) ? pbItems : []);
        const tplItems = templatesRes.data?.items || templatesRes.data;
        setTemplates(Array.isArray(tplItems) ? tplItems : []);
        setExecutions([]);
      } catch (error) {
        setNotification({ type: 'error', text: 'Failed to load playbook data' });
        setPlaybooks([]);
        setTemplates([]);
        setExecutions([]);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const totalPlaybooks = playbooks.length;
  const activePlaybooks = playbooks.filter((p) => p.status === 'active').length;
  const templatesAvailable = templates.length;
  const recentExecutions = executions.length;

  const tabs = [
    { id: 'playbooks', label: 'Playbooks', icon: Workflow },
    { id: 'templates', label: 'Templates', icon: FileText },
    { id: 'executions', label: 'Executions', icon: Play },
  ];

  const filteredPlaybooks = playbooks.filter(
    (p) =>
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.description.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredTemplates = templates.filter(
    (t) =>
      t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.category.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const filteredExecutions = executions.filter((e) =>
    e.playbookName.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
      {/* Header */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 p-6">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <Workflow className="w-8 h-8 text-indigo-600" />
            <div>
              <h1 className="text-3xl font-bold">Visual Playbook Builder</h1>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                Design, automate, and orchestrate security workflows
              </p>
            </div>
          </div>
          <button
            disabled={actionLoading === 'create'}
            onClick={() => {
              const name = window.prompt('Playbook name:');
              if (!name?.trim()) return;
              (async () => {
                setActionLoading('create');
                try {
                  const res = await api.post('/playbook-builder', { name: name.trim(), description: '', status: 'draft' });
                  setPlaybooks((prev) => [...prev, res.data]);
                  setNotification({ type: 'success', text: 'Playbook created' });
                } catch (err) {
                  setNotification({ type: 'error', text: 'Failed to create playbook' });
                } finally {
                  setActionLoading(null);
                }
              })();
            }}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
          >
            {actionLoading === 'create' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            New Playbook
          </button>
        </div>

        {/* Stat Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-gradient-to-br from-indigo-50 to-indigo-100 dark:from-indigo-900 dark:to-indigo-800 p-4 rounded-lg shadow">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-indigo-600 dark:text-indigo-300">Total Playbooks</p>
              <Workflow className="w-5 h-5 text-indigo-500 dark:text-indigo-400" />
            </div>
            <p className="text-3xl font-bold text-indigo-900 dark:text-indigo-100 mt-2">{totalPlaybooks}</p>
            <p className="text-xs text-indigo-600 dark:text-indigo-300 mt-1">across all workflows</p>
          </div>
          <div className="bg-gradient-to-br from-green-50 to-green-100 dark:from-green-900 dark:to-green-800 p-4 rounded-lg shadow">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-green-600 dark:text-green-300">Active</p>
              <CheckCircle className="w-5 h-5 text-green-500 dark:text-green-400" />
            </div>
            <p className="text-3xl font-bold text-green-900 dark:text-green-100 mt-2">{activePlaybooks}</p>
            <p className="text-xs text-green-600 dark:text-green-300 mt-1">currently deployed</p>
          </div>
          <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 p-4 rounded-lg shadow">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-purple-600 dark:text-purple-300">Templates Available</p>
              <FileText className="w-5 h-5 text-purple-500 dark:text-purple-400" />
            </div>
            <p className="text-3xl font-bold text-purple-900 dark:text-purple-100 mt-2">{templatesAvailable}</p>
            <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">ready to customize</p>
          </div>
          <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 p-4 rounded-lg shadow">
            <div className="flex items-center justify-between">
              <p className="text-sm font-medium text-blue-600 dark:text-blue-300">Recent Executions</p>
              <BarChart3 className="w-5 h-5 text-blue-500 dark:text-blue-400" />
            </div>
            <p className="text-3xl font-bold text-blue-900 dark:text-blue-100 mt-2">{recentExecutions}</p>
            <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">in the last 24 hours</p>
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
      <div className="p-6">
        {loading ? (
          <div className="flex flex-col items-center justify-center h-64 gap-3">
            <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
            <p className="text-gray-500 dark:text-gray-400">Loading playbook data...</p>
          </div>
        ) : (
          <>
            {/* Search bar */}
            <div className="flex gap-4 mb-6">
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder={
                    activeTab === 'playbooks'
                      ? 'Search playbooks...'
                      : activeTab === 'templates'
                        ? 'Search templates...'
                        : 'Search executions...'
                  }
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                />
              </div>
              <button
                onClick={() => setShowFilter((prev) => !prev)}
                className="flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
              >
                <Filter className="w-4 h-4" />
                Filter
              </button>
            </div>

            {/* Playbooks Tab */}
            {activeTab === 'playbooks' && (
              <div className="space-y-6">
                {filteredPlaybooks.length === 0 ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <Workflow className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                    <h3 className="text-xl font-semibold text-gray-700 dark:text-gray-300 mb-2">
                      No playbooks yet
                    </h3>
                    <p className="text-gray-500 dark:text-gray-400 mb-6">
                      Create your first visual playbook to automate security workflows.
                    </p>
                    <button
                      disabled={actionLoading === 'create-first'}
                      onClick={async () => {
                        const pbName = window.prompt('Playbook name:');
                        if (!pbName?.trim()) return;
                        setActionLoading('create-first');
                        try {
                          const res = await api.post('/playbook-builder', { name: pbName.trim(), description: '', status: 'draft' });
                          setPlaybooks((prev) => [...prev, res.data]);
                          setNotification({ type: 'success', text: 'Playbook created' });
                        } catch (err) {
                          setNotification({ type: 'error', text: 'Failed to create playbook' });
                        } finally {
                          setActionLoading(null);
                        }
                      }}
                      className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 rounded-lg transition disabled:opacity-50"
                    >
                      {actionLoading === 'create-first' ? <Loader2 className="w-5 h-5 animate-spin" /> : <Plus className="w-5 h-5" />}
                      Create Your First Playbook
                    </button>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 shadow">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-750">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Name
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Nodes
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Status
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Last Modified
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Author
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Runs
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Actions
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPlaybooks.map((playbook) => (
                          <tr
                            key={playbook.id}
                            className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition"
                          >
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-3">
                                <GitBranch className="w-5 h-5 text-indigo-500" />
                                <div>
                                  <p className="text-sm font-semibold">{playbook.name}</p>
                                  <p className="text-xs text-gray-500 dark:text-gray-400">
                                    {playbook.description}
                                  </p>
                                </div>
                              </div>
                            </td>
                            <td className="px-6 py-4 text-sm">
                              <span className="inline-flex items-center gap-1">
                                <Workflow className="w-3.5 h-3.5 text-gray-400" />
                                {playbook.nodes?.length ?? 0}
                              </span>
                            </td>
                            <td className="px-6 py-4">
                              <span
                                className={clsx(
                                  'px-3 py-1 rounded-full text-xs font-medium',
                                  getStatusColor(playbook.status)
                                )}
                              >
                                {(playbook.status || '').charAt(0).toUpperCase() + playbook.status.slice(1)}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              <span className="inline-flex items-center gap-1">
                                <Clock className="w-3.5 h-3.5" />
                                {new Date(playbook.updated_at || "").toLocaleDateString()}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {playbook.created_by}
                            </td>
                            <td className="px-6 py-4 text-sm font-medium">{playbook.execution_count ?? 0}</td>
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={() => setSelectedPlaybook(playbook)}
                                  className="p-1.5 text-gray-500 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition"
                                  title="Edit"
                                >
                                  <Edit className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={async () => {
                                    try {
                                      const newStatus = playbook.status === 'active' ? 'paused' : 'active';
                                      await api.put(`/playbook-builder/${playbook.id}`, { status: newStatus });
                                      setPlaybooks((prev) =>
                                        prev.map((p) => (p.id === playbook.id ? { ...p, status: newStatus } : p))
                                      );
                                    } catch (err) {
                                      setNotification({ type: 'error', text: 'Failed to update playbook status' });
                                    }
                                  }}
                                  className="p-1.5 text-gray-500 hover:text-green-600 dark:hover:text-green-400 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition"
                                  title={playbook.status === 'active' ? 'Pause' : 'Run'}
                                >
                                  {playbook.status === 'active' ? (
                                    <Pause className="w-4 h-4" />
                                  ) : (
                                    <Play className="w-4 h-4" />
                                  )}
                                </button>
                                <button
                                  onClick={async () => {
                                    try {
                                      const res = await api.post(`/playbook-builder/${playbook.id}/clone`, { new_name: `${playbook.name} (Copy)` });
                                      setPlaybooks((prev) => [...prev, res.data]);
                                      setNotification({ type: 'success', text: 'Playbook duplicated' });
                                    } catch (err) {
                                      setNotification({ type: 'error', text: 'Failed to duplicate playbook' });
                                    }
                                  }}
                                  className="p-1.5 text-gray-500 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition"
                                  title="Duplicate"
                                >
                                  <Copy className="w-4 h-4" />
                                </button>
                                <button
                                  onClick={async () => {
                                    if (!confirm(`Delete playbook "${playbook.name}"?`)) return;
                                    try {
                                      await api.delete(`/playbook-builder/${playbook.id}`);
                                      setPlaybooks((prev) => prev.filter((p) => p.id !== playbook.id));
                                      setNotification({ type: 'success', text: 'Playbook deleted' });
                                    } catch (err) {
                                      setNotification({ type: 'error', text: 'Failed to delete playbook' });
                                    }
                                  }}
                                  className="p-1.5 text-gray-500 hover:text-red-600 dark:hover:text-red-400 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition"
                                  title="Delete"
                                >
                                  <Trash2 className="w-4 h-4" />
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

            {/* Templates Tab */}
            {activeTab === 'templates' && (
              <div className="space-y-6">
                {filteredTemplates.length === 0 ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <FileText className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                    <h3 className="text-xl font-semibold text-gray-700 dark:text-gray-300 mb-2">
                      No templates available
                    </h3>
                    <p className="text-gray-500 dark:text-gray-400">
                      Templates will appear here once they are published to the library.
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {filteredTemplates.map((template) => {
                      const CategoryIcon = getCategoryIcon(template.category);
                      return (
                        <div
                          key={template.id}
                          className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6 shadow hover:shadow-lg transition group"
                        >
                          <div className="flex items-start justify-between mb-4">
                            <div className="p-2 bg-indigo-50 dark:bg-indigo-900 rounded-lg">
                              <CategoryIcon className="w-6 h-6 text-indigo-600 dark:text-indigo-400" />
                            </div>
                            <span className="text-xs font-medium text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
                              {(template.category || '').replace('-', ' ')}
                            </span>
                          </div>
                          <h3 className="font-semibold text-lg mb-2 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition">
                            {template.name}
                          </h3>
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-4 line-clamp-2">
                            {template.description}
                          </p>
                          <div className="flex items-center justify-between text-sm text-gray-500 dark:text-gray-400 mb-4">
                            <span className="inline-flex items-center gap-1">
                              <Workflow className="w-3.5 h-3.5" />
                              {template.nodeCount} nodes
                            </span>
                            <span className="inline-flex items-center gap-1">
                              <BarChart3 className="w-3.5 h-3.5" />
                              {template.popularity} uses
                            </span>
                          </div>
                          {template.tags && template.tags.length > 0 && (
                            <div className="flex flex-wrap gap-1.5 mb-4">
                              {template.tags.map((tag) => (
                                <span
                                  key={tag}
                                  className="text-xs bg-indigo-50 dark:bg-indigo-900 text-indigo-700 dark:text-indigo-300 px-2 py-0.5 rounded"
                                >
                                  {tag}
                                </span>
                              ))}
                            </div>
                          )}
                          <div className="flex gap-2">
                            <button
                              disabled={actionLoading === `template-${template.id}`}
                              onClick={async () => {
                                setActionLoading(`template-${template.id}`);
                                try {
                                  const res = await api.post(`/playbook-builder/templates/${template.id}/create`, { playbook_name: template.name });
                                  setPlaybooks((prev) => [...prev, res.data]);
                                  setActiveTab('playbooks');
                                  setNotification({ type: 'success', text: 'Playbook created from template' });
                                } catch (err) {
                                  setNotification({ type: 'error', text: 'Failed to create playbook from template' });
                                } finally {
                                  setActionLoading(null);
                                }
                              }}
                              className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition disabled:opacity-50"
                            >
                              {actionLoading === `template-${template.id}` ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                              Use Template
                            </button>
                            <button
                              onClick={() => setPreviewTemplate(template)}
                              className="px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition"
                            >
                              Preview
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            )}

            {/* Executions Tab */}
            {activeTab === 'executions' && (
              <div className="space-y-6">
                {/* Execution summary cards */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 shadow">
                    <h3 className="font-semibold mb-3 text-sm text-gray-600 dark:text-gray-400">
                      Status Breakdown
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="inline-flex items-center gap-2">
                          <span className="w-2 h-2 bg-blue-500 rounded-full" />
                          Running
                        </span>
                        <span className="font-semibold">
                          {executions.filter((e) => e.status === 'running').length}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="inline-flex items-center gap-2">
                          <span className="w-2 h-2 bg-green-500 rounded-full" />
                          Completed
                        </span>
                        <span className="font-semibold">
                          {executions.filter((e) => e.status === 'completed').length}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="inline-flex items-center gap-2">
                          <span className="w-2 h-2 bg-red-500 rounded-full" />
                          Failed
                        </span>
                        <span className="font-semibold">
                          {executions.filter((e) => e.status === 'failed').length}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 shadow">
                    <h3 className="font-semibold mb-3 text-sm text-gray-600 dark:text-gray-400">
                      Average Duration
                    </h3>
                    <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                      {executions.length > 0 ? '2m 34s' : '--'}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">across all runs</p>
                  </div>
                  <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 shadow">
                    <h3 className="font-semibold mb-3 text-sm text-gray-600 dark:text-gray-400">
                      Success Rate
                    </h3>
                    <p className="text-2xl font-bold text-gray-900 dark:text-gray-100">
                      {executions.length > 0
                        ? `${Math.round(
                            (executions.filter((e) => e.status === 'completed').length /
                              executions.length) *
                              100
                          )}%`
                        : '--'}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">completion rate</p>
                  </div>
                </div>

                {filteredExecutions.length === 0 ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <Play className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                    <h3 className="text-xl font-semibold text-gray-700 dark:text-gray-300 mb-2">
                      No executions yet
                    </h3>
                    <p className="text-gray-500 dark:text-gray-400">
                      Run a playbook to see execution history and results here.
                    </p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden border border-gray-200 dark:border-gray-700 shadow">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-750">
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Playbook
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Status
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Progress
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Started
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Duration
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Triggered By
                          </th>
                          <th className="px-6 py-4 text-left text-sm font-semibold text-gray-900 dark:text-gray-100">
                            Actions
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredExecutions.map((execution) => (
                          <tr
                            key={execution.id}
                            className="border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 transition"
                          >
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-2">
                                <GitBranch className="w-4 h-4 text-indigo-500" />
                                <span className="text-sm font-medium">{execution.playbookName}</span>
                              </div>
                            </td>
                            <td className="px-6 py-4">
                              <span
                                className={clsx(
                                  'px-3 py-1 rounded-full text-xs font-medium inline-flex items-center gap-1.5',
                                  getStatusColor(execution.status)
                                )}
                              >
                                {execution.status === 'running' && (
                                  <Loader2 className="w-3 h-3 animate-spin" />
                                )}
                                {execution.status === 'completed' && (
                                  <CheckCircle className="w-3 h-3" />
                                )}
                                {execution.status === 'failed' && <XCircle className="w-3 h-3" />}
                                {(execution.status || '').charAt(0).toUpperCase() + execution.status.slice(1)}
                              </span>
                            </td>
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-2">
                                <div className="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-1.5">
                                  <div
                                    className={clsx('h-1.5 rounded-full transition-all', {
                                      'bg-blue-500': execution.status === 'running',
                                      'bg-green-500': execution.status === 'completed',
                                      'bg-red-500': execution.status === 'failed',
                                    })}
                                    style={{
                                      width: `${
                                        execution.totalNodes > 0
                                          ? Math.round(
                                              (execution.nodesExecuted / execution.totalNodes) * 100
                                            )
                                          : 0
                                      }%`,
                                    }}
                                  />
                                </div>
                                <span className="text-xs text-gray-500 dark:text-gray-400">
                                  {execution.nodesExecuted}/{execution.totalNodes}
                                </span>
                              </div>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              <span className="inline-flex items-center gap-1">
                                <Clock className="w-3.5 h-3.5" />
                                {new Date(execution.startedAt || "").toLocaleString()}
                              </span>
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {execution.duration}
                            </td>
                            <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                              {execution.triggeredBy}
                            </td>
                            <td className="px-6 py-4">
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={() => setSelectedExecution(execution)}
                                  className="p-1.5 text-gray-500 hover:text-indigo-600 dark:hover:text-indigo-400 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition"
                                  title="View Details"
                                >
                                  <BarChart3 className="w-4 h-4" />
                                </button>
                                {execution.status === 'running' && (
                                  <span
                                    className="p-1.5 text-gray-400 cursor-not-allowed rounded"
                                    title="Pause not available"
                                  >
                                    <Pause className="w-4 h-4" />
                                  </span>
                                )}
                                {execution.status !== 'running' && (
                                  <button
                                    onClick={async () => {
                                      try {
                                        const res = await api.post(`/playbook-builder/${execution.playbookId}/execute`, {});
                                        setExecutions((prev) => [...prev, res.data]);
                                        setNotification({ type: 'success', text: 'Playbook execution started' });
                                      } catch (err) {
                                        setNotification({ type: 'error', text: 'Failed to re-run playbook' });
                                      }
                                    }}
                                    className="p-1.5 text-gray-500 hover:text-green-600 dark:hover:text-green-400 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition"
                                    title="Re-run"
                                  >
                                    <Play className="w-4 h-4" />
                                  </button>
                                )}
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
          </>
        )}
      </div>

      {/* Edit Playbook Modal */}
      {selectedPlaybook && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setSelectedPlaybook(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Edit Playbook</h2>
              <button onClick={() => setSelectedPlaybook(null)} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
            </div>
            <form className="p-6 space-y-4" onSubmit={async (e) => {
              e.preventDefault();
              const fd = new FormData(e.currentTarget);
              try {
                await api.put(`/playbook-builder/${selectedPlaybook.id}`, {
                  name: fd.get('name'),
                  description: fd.get('description'),
                  category: fd.get('category'),
                  trigger_type: fd.get('trigger_type'),
                  status: fd.get('status'),
                });
                setPlaybooks((prev) => prev.map((p) => p.id === selectedPlaybook.id ? {
                  ...p,
                  name: fd.get('name') as string,
                  description: fd.get('description') as string,
                  category: fd.get('category') as string,
                  trigger_type: fd.get('trigger_type') as string,
                  status: fd.get('status') as string,
                } : p));
                setSelectedPlaybook(null);
                setNotification({ type: 'success', text: 'Playbook updated' });
              } catch (err) {
                setNotification({ type: 'error', text: 'Failed to update playbook' });
              }
            }}>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                <input name="name" type="text" defaultValue={selectedPlaybook.name} required
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
                <textarea name="description" rows={3} defaultValue={selectedPlaybook.description || ''}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100" />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Category</label>
                  <select name="category" defaultValue={selectedPlaybook.category || 'incident-response'}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                    <option value="incident-response">Incident Response</option>
                    <option value="threat-hunting">Threat Hunting</option>
                    <option value="compliance">Compliance</option>
                    <option value="enrichment">Enrichment</option>
                    <option value="remediation">Remediation</option>
                    <option value="notification">Notification</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Trigger Type</label>
                  <select name="trigger_type" defaultValue={selectedPlaybook.trigger_type || 'manual'}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                    <option value="manual">Manual</option>
                    <option value="alert">Alert-based</option>
                    <option value="scheduled">Scheduled</option>
                    <option value="webhook">Webhook</option>
                    <option value="event">Event-driven</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Status</label>
                <select name="status" defaultValue={selectedPlaybook.status || 'draft'}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100">
                  <option value="draft">Draft</option>
                  <option value="active">Active</option>
                  <option value="paused">Paused</option>
                  <option value="archived">Archived</option>
                </select>
              </div>

              {/* Nodes summary */}
              {selectedPlaybook.nodes && selectedPlaybook.nodes.length > 0 && (
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Workflow Nodes ({selectedPlaybook.nodes.length})</label>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {selectedPlaybook.nodes.map((node: any, i: number) => (
                      <div key={node.id || i} className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-700 rounded text-sm">
                        <span className="w-6 h-6 flex items-center justify-center bg-indigo-100 dark:bg-indigo-900 text-indigo-600 dark:text-indigo-400 rounded text-xs font-bold">{i + 1}</span>
                        <span className="font-medium text-gray-800 dark:text-gray-200">{node.label || node.name || node.node_type}</span>
                        <span className="text-xs text-gray-500">{node.node_type}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex gap-3 pt-4 border-t border-gray-200 dark:border-gray-700">
                <button type="button" onClick={() => setSelectedPlaybook(null)}
                  className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition">
                  Cancel
                </button>
                <button type="submit"
                  className="flex-1 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition">
                  Save Changes
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
