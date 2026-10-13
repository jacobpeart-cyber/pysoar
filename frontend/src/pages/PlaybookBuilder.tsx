import React, { useState, useEffect, useCallback, useRef } from 'react';
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
  AlertTriangle,
  ListChecks,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import clsx from 'clsx';
import { api } from '../api/client';
import FormModal from '../components/FormModal';
import LoadErrorBanner from '../components/LoadErrorBanner';
import ActionErrorBanner from '../components/ActionErrorBanner';
import { describeLoadError } from '../lib/loadError';

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
    case 'partial':
    case 'awaiting_integration':
    case 'manual_required':
    case 'not_implemented':
      return 'bg-amber-100 dark:bg-amber-900 text-amber-800 dark:text-amber-100';
    case 'queued_for_approval':
      return 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100';
    case 'forbidden_privileged_node':
      return 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100';
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
  edgeCount: number;
  nodes: any[];
}

/** Map a backend template row (node_count / edge_count) onto the card's shape. */
function toTemplate(row: any): Template {
  const nodes = Array.isArray(row?.nodes) ? row.nodes : [];
  return {
    id: row?.id ?? '',
    name: row?.name ?? '',
    description: row?.description ?? '',
    category: row?.category ?? '',
    nodeCount: typeof row?.node_count === 'number' ? row.node_count : nodes.length,
    edgeCount: typeof row?.edge_count === 'number' ? row.edge_count : Array.isArray(row?.edges) ? row.edges.length : 0,
    nodes,
  };
}

interface Execution {
  id: string;
  playbookName: string;
  playbookId: string;
  status: string;
  startedAt: string;
  duration: string;
  durationMs: number | null;
  triggeredBy: string;
  nodesExecuted: number;
  totalNodes: number;
}

/** Map a backend execution row (snake_case) onto the table's shape. */
function toExecution(row: any): Execution {
  const ms = typeof row?.duration_ms === 'number' ? row.duration_ms : null;
  return {
    id: row?.id,
    playbookName: row?.playbook_name ?? row?.playbook_id ?? '',
    playbookId: row?.playbook_id,
    status: row?.status ?? '',
    startedAt: row?.started_at ?? row?.created_at ?? '',
    duration: ms === null ? 'not available' : ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`,
    durationMs: ms,
    triggeredBy: row?.triggered_by ?? 'not available',
    nodesExecuted: typeof row?.nodes_executed === 'number' ? row.nodes_executed : 0,
    totalNodes: typeof row?.total_nodes === 'number' ? row.total_nodes : 0,
  };
}

interface BuilderNode {
  id: string;
  node_id: string;
  node_type: string;
  display_name: string;
  description?: string;
  position_x: number;
  position_y: number;
  config?: any;
  timeout_seconds: number;
  retry_count: number;
  on_error: string;
}

interface BuilderEdge {
  id: string;
  source_node_id: string;
  target_node_id: string;
  edge_type: string;
  label?: string;
  condition_expression?: string;
  priority: number;
}

/** Run statuses after which a visual execution no longer changes. */
const TERMINAL_RUN_STATUSES = new Set(['completed', 'partial', 'failed', 'cancelled']);

const NODE_STATUS_LABELS: Record<string, string> = {
  completed: 'Completed',
  failed: 'Failed',
  running: 'Running',
  pending: 'Pending',
  skipped: 'Skipped',
  awaiting_integration: 'Awaiting integration',
  manual_required: 'Manual action required',
  queued_for_approval: 'Queued for approval',
  not_implemented: 'Not implemented',
  forbidden_privileged_node: 'Forbidden: needs admin',
};

const PARTIAL_EXPLANATION =
  'Partial: the run finished without errors, but at least one node did not complete. It is waiting ' +
  'on an integration, queued for approval or needs a manual action. Only nodes marked Completed ' +
  'actually happened.';

function formatMs(ms: unknown): string {
  if (typeof ms !== 'number') return 'not available';
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

function formatWhen(value: unknown): string {
  if (!value || typeof value !== 'string') return 'not available';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

interface RunState {
  playbookId: string;
  playbookName: string;
  executionId: string | null;
  starting: boolean;
  startError: unknown;
  pollError: unknown;
  status: any | null;
}

function BuilderRunModal({
  run,
  onClose,
  onRetryPoll,
}: {
  run: RunState;
  onClose: () => void;
  onRetryPoll: () => void;
}) {
  const st = run.status;
  const status: string = st?.status || (run.executionId ? 'pending' : '');
  const terminal = TERMINAL_RUN_STATUSES.has(status);
  const nodeSummary: Record<string, number> = st?.node_summary || {};
  const nodeExecutions: any[] = Array.isArray(st?.node_executions) ? st.node_executions : [];
  const path: string[] = Array.isArray(st?.execution_path) ? st.execution_path : [];
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={onClose}>
      <div
        className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-2xl mx-4 max-h-[85vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Run: {run.playbookName}</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-6 space-y-4">
          {run.starting && (
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Loader2 className="w-4 h-4 animate-spin" /> Starting execution...
            </div>
          )}
          <ActionErrorBanner what="start the run" error={run.startError} />
          {run.executionId && (
            <>
              <div className="rounded-lg bg-gray-50 dark:bg-gray-900 p-4 space-y-2 text-sm">
                <div className="flex items-center gap-2">
                  <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', getStatusColor(status))}>
                    {NODE_STATUS_LABELS[status] || status || 'not available'}
                  </span>
                  {!terminal && !run.pollError && (
                    <span className="inline-flex items-center gap-1 text-xs text-gray-500">
                      <Loader2 className="w-3 h-3 animate-spin" /> polling
                      {typeof st?.progress_percent === 'number' ? ` · ${Math.round(st.progress_percent)}%` : ''}
                    </span>
                  )}
                </div>
                <p className="text-gray-500 dark:text-gray-400">Execution ID: {run.executionId}</p>
                <div className="grid grid-cols-3 gap-2 text-xs text-gray-600 dark:text-gray-400">
                  <div>Started: {formatWhen(st?.started_at)}</div>
                  <div>Completed: {formatWhen(st?.completed_at)}</div>
                  <div>Duration: {formatMs(st?.duration_ms)}</div>
                </div>
                {status === 'partial' && <p className="text-amber-800 dark:text-amber-300">{PARTIAL_EXPLANATION}</p>}
                {st?.error_message && <p className="text-red-600 dark:text-red-400">{st.error_message}</p>}
              </div>

              {run.pollError ? (
                <div className="space-y-2">
                  <LoadErrorBanner what="the execution status" error={run.pollError} />
                  <button onClick={onRetryPoll} className="text-sm text-indigo-600 hover:text-indigo-700">
                    Retry polling
                  </button>
                </div>
              ) : null}

              <div>
                <h3 className="text-sm font-semibold mb-2">Node summary</h3>
                {Object.keys(nodeSummary).length === 0 ? (
                  <p className="text-sm text-gray-500">No node has finished yet.</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(nodeSummary).map(([k, v]) => (
                      <span key={k} className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', getStatusColor(k))}>
                        {NODE_STATUS_LABELS[k] || k}: {v}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <h3 className="text-sm font-semibold mb-2">Execution path</h3>
                {path.length === 0 ? (
                  <p className="text-sm text-gray-500">not available</p>
                ) : (
                  <p className="text-xs font-mono text-gray-700 dark:text-gray-300 break-words">{path.join(' → ')}</p>
                )}
              </div>

              {nodeExecutions.length > 0 && (
                <div className="space-y-2">
                  <h3 className="text-sm font-semibold">Nodes</h3>
                  {nodeExecutions.map((ne) => (
                    <div key={ne.id || ne.node_id} className="rounded-lg border border-gray-200 dark:border-gray-700 p-3 text-sm">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-medium">{ne.node_id}</span>
                        <span className={clsx('px-2 py-0.5 rounded-full text-xs font-medium', getStatusColor(ne.status))}>
                          {NODE_STATUS_LABELS[ne.status] || ne.status}
                        </span>
                      </div>
                      {ne.error_message && (
                        <p
                          className={clsx(
                            'text-xs mt-1',
                            ne.status === 'awaiting_integration' || ne.status === 'manual_required' || ne.status === 'not_implemented'
                              ? 'text-amber-800 dark:text-amber-300'
                              : 'text-red-600 dark:text-red-400'
                          )}
                        >
                          {ne.status === 'awaiting_integration' ? 'Missing dependency: ' : ''}
                          {ne.error_message}
                        </p>
                      )}
                      {ne.status === 'queued_for_approval' && (
                        <p className="text-xs mt-1 text-blue-700 dark:text-blue-300">
                          Not executed yet: waiting in the{' '}
                          <Link to="/live-response" className="underline">agent approval queue</Link>.
                        </p>
                      )}
                      <p className="text-[11px] text-gray-400 mt-1">Duration: {formatMs(ne.duration_ms)}</p>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

export default function PlaybookBuilder() {
  const [activeTab, setActiveTab] = useState('playbooks');
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null);
  const [run, setRun] = useState<RunState | null>(null);
  const [pollNonce, setPollNonce] = useState(0);
  const [validation, setValidation] = useState<{
    loading: boolean;
    error: unknown;
    result: { is_valid: boolean; errors: string[]; warnings: string[] } | null;
  } | null>(null);
  const [previewTemplate, setPreviewTemplate] = useState<Template | null>(null);
  const [showFilter, setShowFilter] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [notification, setNotification] = useState<{ type: string; text: string } | null>(null);
  const [loadErrors, setLoadErrors] = useState<Record<string, unknown>>({});
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [builderPlaybook, setBuilderPlaybook] = useState<Playbook | null>(null);
  const [builderNodes, setBuilderNodes] = useState<BuilderNode[]>([]);
  const [builderEdges, setBuilderEdges] = useState<BuilderEdge[]>([]);
  const [builderLoading, setBuilderLoading] = useState(false);
  const [builderError, setBuilderError] = useState<string | null>(null);
  const [selectedBuilderNode, setSelectedBuilderNode] = useState<BuilderNode | null>(null);
  const [nodeDragState, setNodeDragState] = useState<{
    nodeId: string;
    pointerX: number;
    pointerY: number;
    offsetX: number;
    offsetY: number;
  } | null>(null);
  const [newNodeName, setNewNodeName] = useState('');
  const [newNodeType, setNewNodeType] = useState('action');
  const [newEdgeSource, setNewEdgeSource] = useState('');
  const [newEdgeTarget, setNewEdgeTarget] = useState('');
  const [newEdgeType, setNewEdgeType] = useState('success');
  const [newEdgeLabel, setNewEdgeLabel] = useState('');
  const builderCanvasRef = useRef<HTMLDivElement | null>(null);

  const createPlaybook = async (values: Record<string, string>) => {
    const payload: Record<string, any> = {
      name: values.name.trim(),
      description: values.description?.trim() || '',
      category: values.category || 'custom',
      trigger_type: values.trigger_type || 'manual',
      status: 'draft',
    };
    const res = await api.post('/playbook-builder', payload);
    setPlaybooks((prev) => [...prev, res.data]);
    setNotification({ type: 'success', text: 'Playbook created' });
  };

  const newPlaybookFields = [
    { name: 'name', label: 'Name', required: true, placeholder: 'e.g. Phishing Triage' },
    { name: 'description', label: 'Description', type: 'textarea' as const, placeholder: 'What does this playbook automate?' },
    {
      name: 'category',
      label: 'Category',
      type: 'select' as const,
      defaultValue: 'custom',
      options: [
        { value: 'incident_response', label: 'Incident Response' },
        { value: 'threat_hunting', label: 'Threat Hunting' },
        { value: 'compliance', label: 'Compliance' },
        { value: 'enrichment', label: 'Enrichment' },
        { value: 'remediation', label: 'Remediation' },
        { value: 'notification', label: 'Notification' },
        { value: 'custom', label: 'Custom' },
      ],
    },
    {
      name: 'trigger_type',
      label: 'Trigger Type',
      type: 'select' as const,
      defaultValue: 'manual',
      options: [
        { value: 'manual', label: 'Manual' },
        { value: 'alert', label: 'Alert-based' },
        { value: 'schedule', label: 'Scheduled' },
        { value: 'webhook', label: 'Webhook' },
        { value: 'event', label: 'Event-driven' },
        { value: 'threshold', label: 'Threshold' },
        { value: 'api_call', label: 'API Call' },
      ],
      help: 'Defaults to Manual; configure scheduling later in the builder.',
    },
  ];

  const openBuilder = async (playbook: Playbook) => {
    setBuilderLoading(true);
    setBuilderError(null);
    setBuilderPlaybook(null);
    setBuilderNodes([]);
    setBuilderEdges([]);
    setSelectedBuilderNode(null);
    setActiveTab('builder');

    try {
      const res = await api.get(`/playbook-builder/${playbook.id}`);
      const builderData = res.data;
      setBuilderPlaybook(builderData);
      setBuilderNodes(builderData.nodes || []);
      setBuilderEdges(builderData.edges || []);
      setNewEdgeSource(builderData.nodes?.[0]?.node_id || '');
      setNewEdgeTarget(builderData.nodes?.[1]?.node_id || '');
    } catch (err) {
      setBuilderError('Failed to load visual playbook builder.');
      setNotification({ type: 'error', text: 'Unable to open playbook builder' });
    } finally {
      setBuilderLoading(false);
    }
  };

  const closeBuilder = () => {
    setBuilderPlaybook(null);
    setBuilderNodes([]);
    setBuilderEdges([]);
    setSelectedBuilderNode(null);
    setBuilderError(null);
    setNodeDragState(null);
  };

  const saveNodePosition = async (nodeId: string, position_x: number, position_y: number) => {
    if (!builderPlaybook) return;
    setBuilderNodes((prev) =>
      prev.map((node) =>
        node.node_id === nodeId ? { ...node, position_x, position_y } : node
      )
    );
    if (selectedBuilderNode?.node_id === nodeId) {
      setSelectedBuilderNode({ ...selectedBuilderNode, position_x, position_y });
    }

    try {
      await api.put(`/playbook-builder/${builderPlaybook.id}/nodes/${nodeId}`, {
        position_x,
        position_y,
      });
      setNotification({ type: 'success', text: 'Node position saved' });
    } catch (err) {
      setNotification({ type: 'error', text: 'Failed to save node position' });
    }
  };

  const handleNodePointerDown = (
    e: React.MouseEvent<HTMLButtonElement>,
    node: BuilderNode
  ) => {
    if (!builderCanvasRef.current) return;
    e.preventDefault();
    const bounds = builderCanvasRef.current.getBoundingClientRect();
    setSelectedBuilderNode(node);
    setNodeDragState({
      nodeId: node.node_id,
      pointerX: e.clientX,
      pointerY: e.clientY,
      offsetX: e.clientX - bounds.left - node.position_x,
      offsetY: e.clientY - bounds.top - node.position_y,
    });
  };

  const handleCanvasMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!nodeDragState || !builderCanvasRef.current) return;
    const bounds = builderCanvasRef.current.getBoundingClientRect();
    const newX = e.clientX - bounds.left - nodeDragState.offsetX;
    const newY = e.clientY - bounds.top - nodeDragState.offsetY;

    setBuilderNodes((prev) =>
      prev.map((node) =>
        node.node_id === nodeDragState.nodeId
          ? {
              ...node,
              position_x: Math.max(0, Math.min(newX, bounds.width - 180)),
              position_y: Math.max(0, Math.min(newY, bounds.height - 80)),
            }
          : node
      )
    );
  };

  const handleCanvasMouseUp = async () => {
    if (!nodeDragState || !builderPlaybook) {
      setNodeDragState(null);
      return;
    }

    const node = builderNodes.find((n) => n.node_id === nodeDragState.nodeId);
    if (node) {
      await saveNodePosition(node.node_id, node.position_x, node.position_y);
    }
    setNodeDragState(null);
  };

  const handleCreateBuilderNode = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!builderPlaybook) return;
    if (!newNodeName.trim()) {
      setNotification({ type: 'error', text: 'Enter a name for the node.' });
      return;
    }

    try {
      const position_x = 40 + (builderNodes.length % 4) * 180;
      const position_y = 40 + Math.floor(builderNodes.length / 4) * 100;
      const res = await api.post(`/playbook-builder/${builderPlaybook.id}/nodes`, {
        node_type: newNodeType,
        display_name: newNodeName.trim(),
        description: '',
        position_x,
        position_y,
        config: null,
        timeout_seconds: 300,
        retry_count: 0,
        on_error: 'stop',
      });

      setBuilderNodes((prev) => [...prev, res.data]);
      setNewNodeName('');
      setNewEdgeSource(res.data.node_id);
      setNotification({ type: 'success', text: 'Node created' });
    } catch (err) {
      setNotification({ type: 'error', text: 'Failed to create node' });
    }
  };

  const handleCreateEdge = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!builderPlaybook) return;
    if (!newEdgeSource || !newEdgeTarget) {
      setNotification({ type: 'error', text: 'Choose source and target nodes first.' });
      return;
    }
    if (newEdgeSource === newEdgeTarget) {
      setNotification({ type: 'error', text: 'Source and target cannot be the same node.' });
      return;
    }

    try {
      const res = await api.post(`/playbook-builder/${builderPlaybook.id}/edges`, {
        source_node_id: newEdgeSource,
        target_node_id: newEdgeTarget,
        edge_type: newEdgeType,
        label: newEdgeLabel || undefined,
        priority: 0,
      });
      setBuilderEdges((prev) => [...prev, res.data]);
      setNewEdgeLabel('');
      setNotification({ type: 'success', text: 'Connection added' });
    } catch (err) {
      setNotification({ type: 'error', text: 'Failed to create connection' });
    }
  };

  const handleDeleteEdge = async (edgeId: string) => {
    if (!builderPlaybook) return;
    try {
      await api.delete(`/playbook-builder/${builderPlaybook.id}/edges/${edgeId}`);
      setBuilderEdges((prev) => prev.filter((edge) => edge.id !== edgeId));
      setNotification({ type: 'success', text: 'Connection removed' });
    } catch (err) {
      setNotification({ type: 'error', text: 'Failed to remove connection' });
    }
  };

  const handleDeleteNode = async (nodeId: string) => {
    if (!builderPlaybook) return;
    try {
      await api.delete(`/playbook-builder/${builderPlaybook.id}/nodes/${nodeId}`);
      setBuilderNodes((prev) => prev.filter((node) => node.node_id !== nodeId));
      setBuilderEdges((prev) =>
        prev.filter((edge) => edge.source_node_id !== nodeId && edge.target_node_id !== nodeId)
      );
      if (selectedBuilderNode?.node_id === nodeId) {
        setSelectedBuilderNode(null);
      }
      setNotification({ type: 'success', text: 'Node removed' });
    } catch (err) {
      setNotification({ type: 'error', text: 'Failed to remove node' });
    }
  };

  /** POST /playbook-builder/{id}/run, then poll the execution until terminal. */
  const startRun = async (playbookId: string, playbookName: string) => {
    setRun({ playbookId, playbookName, executionId: null, starting: true, startError: null, pollError: null, status: null });
    try {
      const res = await api.post(`/playbook-builder/${playbookId}/run`, {});
      const row = res.data;
      setRun((prev) => (prev && prev.playbookId === playbookId ? { ...prev, starting: false, executionId: row?.id ?? null } : prev));
      setExecutions((prev) => [toExecution({ ...row, playbook_name: playbookName }), ...prev]);
    } catch (err) {
      // 501 not_implemented (nodes listed), 422 no_trigger_node,
      // 403 containment_requires_admin, 503 dispatch_failed: shown as sent.
      setRun((prev) => (prev && prev.playbookId === playbookId ? { ...prev, starting: false, startError: err } : prev));
    }
  };

  const openExecution = (execution: Execution) => {
    setRun({
      playbookId: execution.playbookId,
      playbookName: execution.playbookName,
      executionId: execution.id,
      starting: false,
      startError: null,
      pollError: null,
      status: null,
    });
  };

  const runExecutionId = run?.executionId ?? null;
  const runStatus: string | null = run?.status?.status ?? null;
  const runPollError = run?.pollError ?? null;
  useEffect(() => {
    if (!runExecutionId || runPollError) return;
    if (runStatus && TERMINAL_RUN_STATUSES.has(runStatus)) return;
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      try {
        const res = await api.get(`/playbook-builder/executions/${runExecutionId}`);
        if (cancelled) return;
        const st = res.data;
        setRun((prev) => (prev && prev.executionId === runExecutionId ? { ...prev, status: st } : prev));
        setExecutions((prev) =>
          prev.map((e) =>
            e.id === runExecutionId
              ? {
                  ...e,
                  status: st?.status ?? e.status,
                  durationMs: typeof st?.duration_ms === 'number' ? st.duration_ms : e.durationMs,
                  duration: typeof st?.duration_ms === 'number' ? formatMs(st.duration_ms) : e.duration,
                  nodesExecuted: typeof st?.node_summary?.completed === 'number' ? st.node_summary.completed : e.nodesExecuted,
                }
              : e
          )
        );
      } catch (err) {
        if (!cancelled) {
          setRun((prev) => (prev && prev.executionId === runExecutionId ? { ...prev, pollError: err } : prev));
        }
      }
    }, runStatus === null ? 0 : 2000);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [runExecutionId, runStatus, runPollError, pollNonce, run?.status]);

  /** POST /playbook-builder/{id}/validate: lists every node that cannot execute. */
  const validateBuilderPlaybook = async () => {
    if (!builderPlaybook) return;
    setValidation({ loading: true, error: null, result: null });
    try {
      const res = await api.post(`/playbook-builder/${builderPlaybook.id}/validate`, {});
      setValidation({ loading: false, error: null, result: res.data });
    } catch (err) {
      setValidation({ loading: false, error: err, result: null });
    }
  };

  const builderNodeOptions = builderNodes.map((node) => (
    <option key={node.node_id} value={node.node_id}>
      {node.display_name || node.node_type}
    </option>
  ));

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      // Each source reports its own failure; a failed request is shown as an
      // error, never rendered as an empty list.
      const [playbooksRes, templatesRes, execRes] = await Promise.allSettled([
        api.get('/playbook-builder'),
        api.get('/playbook-builder/templates', { params: { size: 100 } }),
        api.get('/playbook-builder/executions', { params: { size: 50 } }),
      ]);
      const errors: Record<string, unknown> = {};
      if (playbooksRes.status === 'fulfilled') {
        const pbItems = playbooksRes.value.data?.items ?? playbooksRes.value.data;
        setPlaybooks(Array.isArray(pbItems) ? pbItems : []);
      } else {
        errors.playbooks = playbooksRes.reason;
      }
      if (templatesRes.status === 'fulfilled') {
        const tplItems = templatesRes.value.data?.items ?? templatesRes.value.data;
        // Templates without nodes were deleted server-side; never offer one.
        setTemplates(Array.isArray(tplItems) ? tplItems.map(toTemplate).filter((t) => t.nodeCount > 0) : []);
      } else {
        errors.templates = templatesRes.reason;
      }
      if (execRes.status === 'fulfilled') {
        const execItems = execRes.value.data?.items;
        setExecutions(Array.isArray(execItems) ? execItems.map(toExecution) : []);
      } else {
        errors.executions = execRes.reason;
      }
      setLoadErrors(errors);
      setLoading(false);
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
    { id: 'builder', label: 'Builder', icon: Globe },
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
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg transition disabled:opacity-50"
          >
            <Plus className="w-4 h-4" />
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
        {notification ? (
          <div
            role={notification.type === 'error' ? 'alert' : 'status'}
            className={clsx(
              'mb-4 text-sm rounded p-3 border flex items-start justify-between gap-3',
              notification.type === 'error'
                ? 'text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
                : 'text-green-700 dark:text-green-300 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
            )}
          >
            <span>{notification.text}</span>
            <button onClick={() => setNotification(null)} className="text-xs underline">
              Dismiss
            </button>
          </div>
        ) : null}
        {Object.entries(loadErrors).map(([what, err]) => (
          <div key={what} className="mb-4">
            <LoadErrorBanner what={what} error={err} />
          </div>
        ))}
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
                      onClick={() => setShowCreateModal(true)}
                      className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 rounded-lg transition disabled:opacity-50"
                    >
                      <Plus className="w-5 h-5" />
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
                                  onClick={() => openBuilder(playbook)}
                                  className="p-1.5 text-gray-500 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition"
                                  title="Open Builder"
                                >
                                  <Globe className="w-4 h-4" />
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
                                  className="p-1.5 text-gray-500 hover:text-yellow-600 dark:hover:text-yellow-400 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition"
                                  title={playbook.status === 'active' ? 'Pause' : 'Activate'}
                                >
                                  {playbook.status === 'active' ? (
                                    <Pause className="w-4 h-4" />
                                  ) : (
                                    <CheckCircle className="w-4 h-4" />
                                  )}
                                </button>
                                <button
                                  onClick={() => startRun(playbook.id, playbook.name)}
                                  className="p-1.5 text-gray-500 hover:text-green-600 dark:hover:text-green-400 hover:bg-gray-100 dark:hover:bg-gray-600 rounded transition"
                                  title="Run now"
                                >
                                  <Play className="w-4 h-4" />
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
                              <GitBranch className="w-3.5 h-3.5" />
                              {template.edgeCount} connections
                            </span>
                          </div>
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
                                  setNotification({ type: 'error', text: `Failed to create playbook from template. ${describeLoadError(err)}` });
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
                          <span className="w-2 h-2 bg-amber-500 rounded-full" />
                          Partial
                        </span>
                        <span className="font-semibold">
                          {executions.filter((e) => e.status === 'partial').length}
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
                      {(() => {
                        // Mean of the backend's duration_ms over runs that recorded one.
                        const durations = executions
                          .map((e) => (typeof e.durationMs === 'number' && e.durationMs >= 0 ? e.durationMs / 1000 : null))
                          .filter((d): d is number => d !== null);
                        if (durations.length === 0) return 'not available';
                        const avg = durations.reduce((s: number, d: number) => s + d, 0) / durations.length;
                        const m = Math.floor(avg / 60);
                        const s = Math.round(avg % 60);
                        return `${m}m ${s}s`;
                      })()}
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
                        : 'not available'}
                    </p>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      runs where every node completed (partial runs do not count)
                    </p>
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
                                {execution.status === 'partial' && <AlertTriangle className="w-3 h-3" />}
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
                                      'bg-amber-500': execution.status === 'partial',
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
                                {execution.startedAt ? new Date(execution.startedAt).toLocaleString() : 'not available'}
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
                                  onClick={() => openExecution(execution)}
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
                                    onClick={() => startRun(execution.playbookId, execution.playbookName)}
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

            {/* Builder Tab */}
            {activeTab === 'builder' && (
              <div className="space-y-6">
                {builderLoading ? (
                  <div className="flex flex-col items-center justify-center h-64 gap-3">
                    <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
                    <p className="text-gray-500 dark:text-gray-400">Loading visual builder...</p>
                  </div>
                ) : builderError ? (
                  <div className="bg-red-50 dark:bg-red-900 border border-red-200 dark:border-red-700 rounded-lg p-8 text-center">
                    <p className="text-red-700 dark:text-red-200">{builderError}</p>
                  </div>
                ) : !builderPlaybook ? (
                  <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-12 text-center">
                    <Workflow className="w-16 h-16 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                    <h3 className="text-xl font-semibold text-gray-700 dark:text-gray-300 mb-2">
                      Visual Playbook Builder
                    </h3>
                    <p className="text-gray-500 dark:text-gray-400 mb-6">
                      Select a playbook from the Playbooks tab and click the builder icon to design it visually.
                    </p>
                    <button
                      onClick={() => setActiveTab('playbooks')}
                      className="inline-flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3 rounded-lg transition"
                    >
                      <GitBranch className="w-4 h-4" />
                      View Playbooks
                    </button>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 lg:grid-cols-[1.5fr_0.9fr] gap-6">
                    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow p-4">
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
                        <div>
                          <h2 className="text-2xl font-semibold text-gray-900 dark:text-white">{builderPlaybook.name}</h2>
                          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{builderPlaybook.description}</p>
                        </div>
                        <div className="flex gap-2 flex-wrap">
                          <button
                            onClick={validateBuilderPlaybook}
                            disabled={validation?.loading}
                            className="inline-flex items-center gap-2 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition disabled:opacity-50"
                          >
                            {validation?.loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <ListChecks className="w-4 h-4" />}
                            Validate
                          </button>
                          <button
                            onClick={() => startRun(builderPlaybook.id, builderPlaybook.name)}
                            className="inline-flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition"
                          >
                            <Play className="w-4 h-4" />
                            Run
                          </button>
                          <button
                            onClick={closeBuilder}
                            className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition"
                          >
                            Close builder
                          </button>
                          <button
                            onClick={() => setActiveTab('playbooks')}
                            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition"
                          >
                            Back to Playbooks
                          </button>
                        </div>
                      </div>

                      {validation && !validation.loading && (
                        <div className="mb-4">
                          {validation.error ? (
                            <ActionErrorBanner what="validate the playbook" error={validation.error} />
                          ) : validation.result ? (
                            <div
                              className={clsx(
                                'rounded p-3 text-sm border',
                                validation.result.is_valid
                                  ? 'text-green-700 dark:text-green-300 bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
                                  : 'text-amber-800 dark:text-amber-200 bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800'
                              )}
                            >
                              <p className="font-medium">
                                {validation.result.is_valid
                                  ? 'Valid: every node can execute.'
                                  : 'Not runnable as is. These problems were reported:'}
                              </p>
                              {validation.result.errors.length > 0 && (
                                <ul className="list-disc ml-5 mt-1 space-y-0.5">
                                  {validation.result.errors.map((m, i) => <li key={i}>{m}</li>)}
                                </ul>
                              )}
                              {validation.result.warnings.length > 0 && (
                                <ul className="list-disc ml-5 mt-1 space-y-0.5 text-gray-600 dark:text-gray-400">
                                  {validation.result.warnings.map((m, i) => <li key={`w${i}`}>Warning: {m}</li>)}
                                </ul>
                              )}
                            </div>
                          ) : null}
                        </div>
                      )}

                      <div className="mb-4 rounded-2xl border border-indigo-200 dark:border-indigo-700 bg-indigo-50 dark:bg-indigo-950 px-4 py-3 text-sm text-indigo-700 dark:text-indigo-200 shadow-sm">
                        <strong className="font-semibold">Visual builder ready:</strong> drag any node card to reposition it, then connect nodes with the toolbar on the right.
                      </div>

                      <div
                        ref={builderCanvasRef}
                        className="relative h-[580px] rounded-lg border border-dashed border-gray-300 dark:border-gray-600 bg-slate-50 dark:bg-gray-950 overflow-hidden"
                        onMouseMove={handleCanvasMouseMove}
                        onMouseUp={handleCanvasMouseUp}
                        onMouseLeave={handleCanvasMouseUp}
                      >
                        <svg className="absolute inset-0 w-full h-full pointer-events-none">
                          <defs>
                            <marker
                              id="builder-arrow"
                              viewBox="0 0 6 6"
                              refX="5"
                              refY="3"
                              markerWidth="6"
                              markerHeight="6"
                              orient="auto"
                            >
                              <path d="M0,0 L6,3 L0,6 Z" fill="#4338ca" />
                            </marker>
                          </defs>
                          {builderEdges.map((edge) => {
                            const source = builderNodes.find((node) => node.node_id === edge.source_node_id);
                            const target = builderNodes.find((node) => node.node_id === edge.target_node_id);
                            if (!source || !target) return null;
                            const sourceX = source.position_x + 160;
                            const sourceY = source.position_y + 32;
                            const targetX = target.position_x;
                            const targetY = target.position_y + 32;
                            return (
                              <line
                                key={edge.id}
                                x1={sourceX}
                                y1={sourceY}
                                x2={targetX}
                                y2={targetY}
                                stroke="#4338ca"
                                strokeWidth={2}
                                markerEnd="url(#builder-arrow)"
                                strokeLinecap="round"
                              />
                            );
                          })}
                        </svg>

                        {builderNodes.map((node) => (
                          <button
                            key={node.node_id}
                            type="button"
                            className={clsx(
                              'absolute w-40 min-h-[90px] rounded-[28px] border p-3 text-left shadow-[0px_10px_40px_rgba(15,23,42,0.08)] transition-all duration-200',
                              selectedBuilderNode?.node_id === node.node_id
                                ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900 ring-2 ring-indigo-500/20'
                                : 'border-gray-200 bg-white dark:border-gray-700 dark:bg-gray-800 hover:border-indigo-400 hover:shadow-[0px_16px_48px_rgba(15,23,42,0.12)]',
                              nodeDragState?.nodeId === node.node_id ? 'cursor-grabbing scale-[1.01]' : 'cursor-grab'
                            )}
                            style={{ left: node.position_x, top: node.position_y }}
                            onMouseDown={(e) => handleNodePointerDown(e, node)}
                            onClick={() => setSelectedBuilderNode(node)}
                          >
                            <div className="flex items-center justify-between gap-2 mb-2">
                              <span className="text-sm font-semibold text-gray-900 dark:text-gray-100">{node.display_name || node.node_type}</span>
                              <span className="text-[11px] uppercase tracking-[0.18em] text-gray-500 dark:text-gray-400">
                                {node.node_type}
                              </span>
                            </div>
                            <p className="text-xs text-gray-500 dark:text-gray-400 line-clamp-2">
                              {node.description || 'No description'}
                            </p>
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-6">
                      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">Add Node</h3>
                        <form className="space-y-3" onSubmit={handleCreateBuilderNode}>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                            <input
                              value={newNodeName}
                              onChange={(e) => setNewNodeName(e.target.value)}
                              placeholder="New node label"
                              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                            />
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Type</label>
                            <select
                              value={newNodeType}
                              onChange={(e) => setNewNodeType(e.target.value)}
                              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                            >
                              <option value="trigger">Trigger</option>
                              <option value="action">Action</option>
                              <option value="condition">Condition</option>
                              <option value="delay">Delay</option>
                              <option value="human_approval">Human Approval</option>
                              <option value="notification">Notification</option>
                              <option value="enrichment">Enrichment</option>
                            </select>
                          </div>
                          <button
                            type="submit"
                            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition"
                          >
                            <Plus className="w-4 h-4" />
                            Add Node
                          </button>
                        </form>
                      </div>

                      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow p-4">
                        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">Connect Nodes</h3>
                        <form className="space-y-3" onSubmit={handleCreateEdge}>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Source</label>
                            <select
                              value={newEdgeSource}
                              onChange={(e) => setNewEdgeSource(e.target.value)}
                              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                            >
                              {builderNodeOptions}
                            </select>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Target</label>
                            <select
                              value={newEdgeTarget}
                              onChange={(e) => setNewEdgeTarget(e.target.value)}
                              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                            >
                              {builderNodeOptions}
                            </select>
                          </div>
                          <div>
                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Label</label>
                            <input
                              value={newEdgeLabel}
                              onChange={(e) => setNewEdgeLabel(e.target.value)}
                              placeholder="Optional connection label"
                              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100"
                            />
                          </div>
                          <button
                            type="submit"
                            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg transition"
                          >
                            <Plus className="w-4 h-4" />
                            Add Connection
                          </button>
                        </form>
                      </div>

                      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 shadow p-4">
                        <div className="flex items-center justify-between mb-3">
                          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Connections</h3>
                          {selectedBuilderNode && (
                            <button
                              type="button"
                              onClick={() => handleDeleteNode(selectedBuilderNode.node_id)}
                              className="text-sm text-red-600 hover:text-red-700 transition"
                            >
                              Remove selected node
                            </button>
                          )}
                        </div>
                        {builderEdges.length === 0 ? (
                          <p className="text-sm text-gray-500 dark:text-gray-400">No connections created yet.</p>
                        ) : (
                          <div className="space-y-3">
                            {builderEdges.map((edge) => (
                              <div key={edge.id} className="flex items-center justify-between gap-3 rounded-lg border border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900 px-3 py-2">
                                <div>
                                  <p className="text-sm font-semibold text-gray-900 dark:text-gray-100">
                                    {edge.source_node_id} → {edge.target_node_id}
                                  </p>
                                  <p className="text-xs text-gray-500 dark:text-gray-400">{edge.label || edge.edge_type}</p>
                                </div>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteEdge(edge.id)}
                                  className="text-sm text-red-600 hover:text-red-700 transition"
                                >
                                  Remove
                                </button>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
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

      {run && (
        <BuilderRunModal
          run={run}
          onClose={() => setRun(null)}
          onRetryPoll={() => {
            setRun((prev) => (prev ? { ...prev, pollError: null } : prev));
            setPollNonce((n) => n + 1);
          }}
        />
      )}

      {previewTemplate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50" onClick={() => setPreviewTemplate(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg mx-4 max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{previewTemplate.name}</h2>
              <button onClick={() => setPreviewTemplate(null)} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
            </div>
            <div className="p-6 space-y-3 text-sm">
              <p className="text-gray-600 dark:text-gray-400">{previewTemplate.description || 'No description'}</p>
              <p className="text-gray-500">
                {previewTemplate.nodeCount} nodes · {previewTemplate.edgeCount} connections
              </p>
              <div className="space-y-1">
                {previewTemplate.nodes.map((node: any, i: number) => (
                  <div key={node.node_id || i} className="flex items-center gap-2 p-2 bg-gray-50 dark:bg-gray-700 rounded">
                    <span className="font-medium text-gray-800 dark:text-gray-200">{node.display_name || node.node_id}</span>
                    <span className="text-xs text-gray-500">{node.node_type}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* New Playbook Modal */}
      <FormModal
        open={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="New Playbook"
        description="Create a new automation playbook. You can wire up nodes after it is created."
        submitLabel="Create Playbook"
        fields={newPlaybookFields}
        onSubmit={createPlaybook}
      />
    </div>
  );
}
