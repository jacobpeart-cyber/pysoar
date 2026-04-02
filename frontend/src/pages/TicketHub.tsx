import { useState, useMemo, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Ticket,
  Columns,
  Zap,
  AlertCircle,
  CheckCircle,
  Clock,
  MessageSquare,
  Activity,
  Shield,
  Bug,
  FileCheck,
  ListTodo,
  Target,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Plus,
  X,
  Loader,
  ArrowRight,
  BarChart3,
  AlertTriangle,
  RefreshCw,
  Send,
  ToggleLeft,
  ToggleRight,
  Eye,
  ChevronDown,
} from 'lucide-react';
import clsx from 'clsx';
import { api } from '../api/client';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface UnifiedTicket {
  id: string;
  source_type: SourceType;
  source_id: string;
  title: string;
  description: string;
  status: string;
  priority: string;
  assigned_to: string | null;
  created_at: string;
  updated_at: string;
  due_date: string | null;
  tags: string[];
  metadata: Record<string, unknown>;
}

interface TicketListResponse {
  items: UnifiedTicket[];
  total: number;
  page: number;
  size: number;
}

interface KanbanColumn {
  column: string;
  tickets: UnifiedTicket[];
}

interface KanbanResponse {
  columns: KanbanColumn[];
}

interface AutomationRule {
  id: string;
  name: string;
  trigger_type: string;
  conditions: Record<string, unknown>;
  actions: Record<string, unknown>;
  is_enabled: boolean;
  execution_count: number;
  last_triggered_at: string | null;
  created_at: string;
}

interface DashboardStats {
  total: number;
  open: number;
  in_progress: number;
  overdue: number;
  by_source: Record<string, number>;
}

interface Comment {
  id: string;
  author: string;
  text: string;
  created_at: string;
}

interface ActivityEntry {
  id: string;
  action: string;
  actor: string;
  timestamp: string;
  details: string | null;
}

type SourceType = 'incident' | 'remediation_ticket' | 'poam' | 'case_task' | 'action_item';

type TabId = 'list' | 'kanban' | 'automation';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SOURCE_TYPE_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'All Sources' },
  { value: 'incident', label: 'Incident' },
  { value: 'remediation_ticket', label: 'Remediation' },
  { value: 'poam', label: 'POAM' },
  { value: 'case_task', label: 'Case Task' },
  { value: 'action_item', label: 'Action Item' },
];

const STATUS_OPTIONS = ['', 'new', 'open', 'in_progress', 'review', 'closed'];
const PRIORITY_OPTIONS = ['', 'critical', 'high', 'medium', 'low'];
const KANBAN_COLUMNS = ['New', 'In Progress', 'Review', 'Closed'];
const TRIGGER_TYPES = ['siem_alert', 'incident_created', 'ticket_status_change', 'manual'];

const PAGE_SIZE = 15;

const sourceTypeColors: Record<string, string> = {
  incident: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
  remediation_ticket: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
  poam: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
  case_task: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  action_item: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
};

const sourceTypeBorderColors: Record<string, string> = {
  incident: 'border-l-red-500',
  remediation_ticket: 'border-l-orange-500',
  poam: 'border-l-purple-500',
  case_task: 'border-l-blue-500',
  action_item: 'border-l-green-500',
};

const statusColors: Record<string, string> = {
  new: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  open: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
  in_progress: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300',
  review: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
  closed: 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300',
};

const priorityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sourceIcon(type: string, className = 'w-4 h-4') {
  switch (type) {
    case 'incident':
      return <Shield className={className} />;
    case 'remediation_ticket':
      return <Bug className={className} />;
    case 'poam':
      return <FileCheck className={className} />;
    case 'case_task':
      return <ListTodo className={className} />;
    case 'action_item':
      return <Target className={className} />;
    default:
      return <Ticket className={className} />;
  }
}

function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '--';
  try {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return '--';
  }
}

function formatDateTime(dateStr: string | null | undefined): string {
  if (!dateStr) return '--';
  try {
    return new Date(dateStr).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return '--';
  }
}

function sourceLabel(type: string): string {
  switch (type) {
    case 'incident':
      return 'Incident';
    case 'remediation_ticket':
      return 'Remediation';
    case 'poam':
      return 'POAM';
    case 'case_task':
      return 'Case Task';
    case 'action_item':
      return 'Action Item';
    default:
      return type;
  }
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function StatCard({
  label,
  value,
  icon,
  accent,
}: {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  accent?: string;
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 flex items-center gap-4">
      <div
        className={clsx(
          'flex items-center justify-center w-10 h-10 rounded-lg',
          accent ?? 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300'
        )}
      >
        {icon}
      </div>
      <div>
        <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
        <p className="text-xl font-semibold text-gray-900 dark:text-white">{value}</p>
      </div>
    </div>
  );
}

function Badge({ text, colorClass }: { text: string; colorClass?: string }) {
  return (
    <span
      className={clsx(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
        colorClass ?? 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
      )}
    >
      {text}
    </span>
  );
}

function Spinner() {
  return (
    <div className="flex items-center justify-center py-16">
      <Loader className="w-6 h-6 animate-spin text-blue-500" />
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-gray-400 dark:text-gray-500">
      <Ticket className="w-10 h-10 mb-2" />
      <p className="text-sm">{message}</p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Detail Panel
// ---------------------------------------------------------------------------

function DetailPanel({
  ticket,
  onClose,
}: {
  ticket: UnifiedTicket;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [commentText, setCommentText] = useState('');

  const { data: comments = [], isLoading: commentsLoading } = useQuery<Comment[]>({
    queryKey: ['ticketComments', ticket.source_type, ticket.source_id],
    queryFn: async () => {
      const res = await api.get(
        `/tickethub/tickets/${ticket.source_type}/${ticket.source_id}/comments`
      );
      return res.data?.items ?? res.data ?? [];
    },
  });

  const { data: activityLog = [], isLoading: activityLoading } = useQuery<ActivityEntry[]>({
    queryKey: ['ticketActivity', ticket.source_type, ticket.source_id],
    queryFn: async () => {
      const res = await api.get(
        `/tickethub/tickets/${ticket.source_type}/${ticket.source_id}/activity`
      );
      return res.data?.items ?? res.data ?? [];
    },
  });

  const addCommentMutation = useMutation({
    mutationFn: async (text: string) => {
      await api.post(
        `/tickethub/tickets/${ticket.source_type}/${ticket.source_id}/comments`,
        { text }
      );
    },
    onSuccess: () => {
      setCommentText('');
      queryClient.invalidateQueries({
        queryKey: ['ticketComments', ticket.source_type, ticket.source_id],
      });
      queryClient.invalidateQueries({
        queryKey: ['ticketActivity', ticket.source_type, ticket.source_id],
      });
    },
  });

  const statusChangeMutation = useMutation({
    mutationFn: async (newStatus: string) => {
      await api.put(`/tickethub/tickets/${ticket.source_type}/${ticket.source_id}`, {
        status: newStatus,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tickets'] });
      queryClient.invalidateQueries({ queryKey: ['ticketKanban'] });
      queryClient.invalidateQueries({ queryKey: ['ticketDashboard'] });
      queryClient.invalidateQueries({
        queryKey: ['ticketActivity', ticket.source_type, ticket.source_id],
      });
    },
  });

  const handleAddComment = () => {
    const trimmed = commentText.trim();
    if (!trimmed) return;
    addCommentMutation.mutate(trimmed);
  };

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-lg bg-white dark:bg-gray-800 shadow-xl border-l border-gray-200 dark:border-gray-700 z-50 flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-2 min-w-0">
          {sourceIcon(ticket.source_type, 'w-5 h-5 flex-shrink-0')}
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white truncate">
            {ticket.title}
          </h2>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-6">
        {/* Metadata */}
        <section className="space-y-3">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
            Details
          </h3>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <span className="text-gray-500 dark:text-gray-400">Source Type</span>
              <div className="mt-1">
                <Badge
                  text={sourceLabel(ticket.source_type)}
                  colorClass={sourceTypeColors[ticket.source_type]}
                />
              </div>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Status</span>
              <div className="mt-1">
                <Badge text={ticket.status} colorClass={statusColors[ticket.status]} />
              </div>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Priority</span>
              <div className="mt-1">
                <Badge text={ticket.priority} colorClass={priorityColors[ticket.priority]} />
              </div>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Assigned To</span>
              <p className="mt-1 text-gray-900 dark:text-white">
                {ticket.assigned_to ?? 'Unassigned'}
              </p>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Created</span>
              <p className="mt-1 text-gray-900 dark:text-white">
                {formatDateTime(ticket.created_at)}
              </p>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Due Date</span>
              <p className="mt-1 text-gray-900 dark:text-white">
                {formatDate(ticket.due_date)}
              </p>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Updated</span>
              <p className="mt-1 text-gray-900 dark:text-white">
                {formatDateTime(ticket.updated_at)}
              </p>
            </div>
            <div>
              <span className="text-gray-500 dark:text-gray-400">Source ID</span>
              <p className="mt-1 text-gray-900 dark:text-white font-mono text-xs">
                {ticket.source_id}
              </p>
            </div>
          </div>
          {ticket.description && (
            <div>
              <span className="text-gray-500 dark:text-gray-400 text-sm">Description</span>
              <p className="mt-1 text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                {ticket.description}
              </p>
            </div>
          )}
          {ticket.tags && ticket.tags.length > 0 && (
            <div>
              <span className="text-gray-500 dark:text-gray-400 text-sm">Tags</span>
              <div className="mt-1 flex flex-wrap gap-1">
                {ticket.tags.map((tag) => (
                  <Badge key={tag} text={tag} />
                ))}
              </div>
            </div>
          )}
        </section>

        {/* Status Actions */}
        <section className="space-y-2">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
            Change Status
          </h3>
          <div className="flex flex-wrap gap-2">
            {STATUS_OPTIONS.filter((s) => s !== '' && s !== ticket.status).map((st) => (
              <button
                key={st}
                onClick={() => statusChangeMutation.mutate(st)}
                disabled={statusChangeMutation.isPending}
                className={clsx(
                  'px-3 py-1 rounded text-xs font-medium border transition-colors',
                  'hover:opacity-80 disabled:opacity-50',
                  statusColors[st] ?? 'bg-gray-100 text-gray-700'
                )}
              >
                {st.replace('_', ' ')}
              </button>
            ))}
          </div>
        </section>

        {/* Comments */}
        <section className="space-y-3">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider flex items-center gap-1">
            <MessageSquare className="w-4 h-4" /> Comments
          </h3>
          {commentsLoading ? (
            <Spinner />
          ) : comments.length === 0 ? (
            <p className="text-sm text-gray-400 dark:text-gray-500">No comments yet.</p>
          ) : (
            <div className="space-y-3 max-h-48 overflow-y-auto">
              {comments.map((c) => (
                <div
                  key={c.id}
                  className="bg-gray-50 dark:bg-gray-700/50 rounded p-3 text-sm"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-medium text-gray-900 dark:text-white">
                      {c.author}
                    </span>
                    <span className="text-xs text-gray-400">{formatDateTime(c.created_at)}</span>
                  </div>
                  <p className="text-gray-700 dark:text-gray-300">{c.text}</p>
                </div>
              ))}
            </div>
          )}
          <div className="flex gap-2">
            <textarea
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              placeholder="Add a comment..."
              rows={2}
              className="flex-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-white p-2 resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <button
              onClick={handleAddComment}
              disabled={!commentText.trim() || addCommentMutation.isPending}
              className="self-end px-3 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              <Send className="w-4 h-4" />
            </button>
          </div>
        </section>

        {/* Activity Log */}
        <section className="space-y-3">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider flex items-center gap-1">
            <Activity className="w-4 h-4" /> Activity Log
          </h3>
          {activityLoading ? (
            <Spinner />
          ) : activityLog.length === 0 ? (
            <p className="text-sm text-gray-400 dark:text-gray-500">No activity recorded.</p>
          ) : (
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {activityLog.map((entry) => (
                <div
                  key={entry.id}
                  className="flex items-start gap-2 text-sm border-l-2 border-gray-200 dark:border-gray-600 pl-3 py-1"
                >
                  <div className="flex-1">
                    <span className="font-medium text-gray-900 dark:text-white">
                      {entry.actor}
                    </span>{' '}
                    <span className="text-gray-600 dark:text-gray-400">{entry.action}</span>
                    {entry.details && (
                      <p className="text-gray-500 dark:text-gray-500 text-xs mt-0.5">
                        {entry.details}
                      </p>
                    )}
                  </div>
                  <span className="text-xs text-gray-400 whitespace-nowrap">
                    {formatDateTime(entry.timestamp)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Kanban Card
// ---------------------------------------------------------------------------

function KanbanCard({
  ticket,
  onView,
  onMove,
  isMoving,
}: {
  ticket: UnifiedTicket;
  onView: (t: UnifiedTicket) => void;
  onMove: (sourceType: string, sourceId: string, targetColumn: string) => void;
  isMoving: boolean;
}) {
  const [showMoveMenu, setShowMoveMenu] = useState(false);

  return (
    <div
      className={clsx(
        'bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-3 space-y-2 border-l-4',
        sourceTypeBorderColors[ticket.source_type] ?? 'border-l-gray-400'
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <h4
          className="text-sm font-medium text-gray-900 dark:text-white line-clamp-2 cursor-pointer hover:text-blue-600 dark:hover:text-blue-400"
          onClick={() => onView(ticket)}
        >
          {ticket.title}
        </h4>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <Badge
          text={sourceLabel(ticket.source_type)}
          colorClass={sourceTypeColors[ticket.source_type]}
        />
        <Badge text={ticket.priority} colorClass={priorityColors[ticket.priority]} />
      </div>

      <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400">
        <span>{ticket.assigned_to ?? 'Unassigned'}</span>
        {ticket.due_date && (
          <span className="flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {formatDate(ticket.due_date)}
          </span>
        )}
      </div>

      <div className="flex items-center justify-between pt-1 border-t border-gray-100 dark:border-gray-700">
        <button
          onClick={() => onView(ticket)}
          className="text-xs text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1"
        >
          <Eye className="w-3 h-3" /> View
        </button>
        <div className="relative">
          <button
            onClick={() => setShowMoveMenu(!showMoveMenu)}
            disabled={isMoving}
            className="text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 flex items-center gap-1 disabled:opacity-50"
          >
            <ArrowRight className="w-3 h-3" /> Move <ChevronDown className="w-3 h-3" />
          </button>
          {showMoveMenu && (
            <div className="absolute right-0 bottom-6 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-600 rounded shadow-lg z-10 py-1 min-w-[120px]">
              {KANBAN_COLUMNS.map((col) => (
                <button
                  key={col}
                  onClick={() => {
                    onMove(ticket.source_type, ticket.source_id, col);
                    setShowMoveMenu(false);
                  }}
                  className="block w-full text-left px-3 py-1.5 text-xs text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
                >
                  {col}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Automation Rule Modal
// ---------------------------------------------------------------------------

function CreateRuleModal({
  onClose,
  onSubmit,
  isPending,
}: {
  onClose: () => void;
  onSubmit: (data: {
    name: string;
    trigger_type: string;
    conditions: string;
    actions: string;
  }) => void;
  isPending: boolean;
}) {
  const [name, setName] = useState('');
  const [triggerType, setTriggerType] = useState(TRIGGER_TYPES[0]);
  const [conditions, setConditions] = useState('{}');
  const [actions, setActions] = useState('{}');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit({ name, trigger_type: triggerType, conditions, actions });
  };

  return (
    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-lg">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Create Automation Rule
          </h3>
          <button
            onClick={onClose}
            className="p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-500"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Rule Name
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-white p-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              placeholder="e.g. Auto-assign critical incidents"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Trigger Type
            </label>
            <select
              value={triggerType}
              onChange={(e) => setTriggerType(e.target.value)}
              className="w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-white p-2 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              {TRIGGER_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Conditions (JSON)
            </label>
            <textarea
              value={conditions}
              onChange={(e) => setConditions(e.target.value)}
              rows={4}
              className="w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-white p-2 font-mono resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Actions (JSON)
            </label>
            <textarea
              value={actions}
              onChange={(e) => setActions(e.target.value)}
              rows={4}
              className="w-full rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-white p-2 font-mono resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isPending || !name.trim()}
              className="px-4 py-2 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {isPending ? 'Creating...' : 'Create Rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export default function TicketHub() {
  const queryClient = useQueryClient();

  // Navigation
  const [activeTab, setActiveTab] = useState<TabId>('list');
  const [selectedTicket, setSelectedTicket] = useState<UnifiedTicket | null>(null);

  // List filters
  const [sourceFilter, setSourceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [priorityFilter, setPriorityFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [page, setPage] = useState(1);

  // Automation
  const [showCreateRule, setShowCreateRule] = useState(false);

  // ---------------------------------------------------------------------------
  // Queries
  // ---------------------------------------------------------------------------

  const { data: dashboard, isLoading: dashboardLoading } = useQuery<DashboardStats>({
    queryKey: ['ticketDashboard'],
    queryFn: async () => {
      const res = await api.get('/tickethub/dashboard');
      return res.data;
    },
  });

  const ticketParams = useMemo(() => {
    const params: Record<string, string | number> = { page, size: PAGE_SIZE };
    if (sourceFilter) params.source_type = sourceFilter;
    if (statusFilter) params.status = statusFilter;
    if (priorityFilter) params.priority = priorityFilter;
    if (searchQuery.trim()) params.search = searchQuery.trim();
    return params;
  }, [page, sourceFilter, statusFilter, priorityFilter, searchQuery]);

  const {
    data: ticketData,
    isLoading: ticketsLoading,
    isFetching: ticketsFetching,
  } = useQuery<TicketListResponse>({
    queryKey: ['tickets', ticketParams],
    queryFn: async () => {
      const res = await api.get('/tickethub/tickets', { params: ticketParams });
      return res.data;
    },
    enabled: activeTab === 'list',
  });

  const { data: kanbanData, isLoading: kanbanLoading } = useQuery<KanbanResponse>({
    queryKey: ['ticketKanban'],
    queryFn: async () => {
      const res = await api.get('/tickethub/kanban');
      return res.data;
    },
    enabled: activeTab === 'kanban',
  });

  const { data: automationRules = [], isLoading: rulesLoading } = useQuery<AutomationRule[]>({
    queryKey: ['automationRules'],
    queryFn: async () => {
      const res = await api.get('/tickethub/automation/rules');
      return res.data?.items ?? res.data ?? [];
    },
    enabled: activeTab === 'automation',
  });

  // ---------------------------------------------------------------------------
  // Mutations
  // ---------------------------------------------------------------------------

  const kanbanMoveMutation = useMutation({
    mutationFn: async ({
      source_type,
      source_id,
      target_column,
    }: {
      source_type: string;
      source_id: string;
      target_column: string;
    }) => {
      await api.post('/tickethub/kanban/move', { source_type, source_id, target_column });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ticketKanban'] });
      queryClient.invalidateQueries({ queryKey: ['tickets'] });
      queryClient.invalidateQueries({ queryKey: ['ticketDashboard'] });
    },
  });

  const createRuleMutation = useMutation({
    mutationFn: async (data: {
      name: string;
      trigger_type: string;
      conditions: string;
      actions: string;
    }) => {
      let parsedConditions: Record<string, unknown> = {};
      let parsedActions: Record<string, unknown> = {};
      try {
        parsedConditions = JSON.parse(data.conditions);
      } catch {
        /* keep empty */
      }
      try {
        parsedActions = JSON.parse(data.actions);
      } catch {
        /* keep empty */
      }
      await api.post('/tickethub/automation/rules', {
        name: data.name,
        trigger_type: data.trigger_type,
        conditions: parsedConditions,
        actions: parsedActions,
      });
    },
    onSuccess: () => {
      setShowCreateRule(false);
      queryClient.invalidateQueries({ queryKey: ['automationRules'] });
    },
  });

  const toggleRuleMutation = useMutation({
    mutationFn: async ({ id, is_enabled }: { id: string; is_enabled: boolean }) => {
      await api.put(`/tickethub/automation/rules/${id}`, { is_enabled });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['automationRules'] });
    },
  });

  // ---------------------------------------------------------------------------
  // Handlers
  // ---------------------------------------------------------------------------

  const handleKanbanMove = useCallback(
    (sourceType: string, sourceId: string, targetColumn: string) => {
      kanbanMoveMutation.mutate({
        source_type: sourceType,
        source_id: sourceId,
        target_column: targetColumn,
      });
    },
    [kanbanMoveMutation]
  );

  const tickets = ticketData?.items ?? [];
  const totalTickets = ticketData?.total ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalTickets / PAGE_SIZE));

  const kanbanColumns = useMemo(() => {
    const map: Record<string, UnifiedTicket[]> = {};
    KANBAN_COLUMNS.forEach((col) => (map[col] = []));
    if (kanbanData?.columns) {
      kanbanData.columns.forEach((col) => {
        map[col.column] = col.tickets ?? [];
      });
    }
    return map;
  }, [kanbanData]);

  const stats = dashboard ?? { total: 0, open: 0, in_progress: 0, overdue: 0, by_source: {} };

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  const tabs: { id: TabId; label: string; icon: React.ReactNode }[] = [
    { id: 'list', label: 'List View', icon: <Ticket className="w-4 h-4" /> },
    { id: 'kanban', label: 'Kanban Board', icon: <Columns className="w-4 h-4" /> },
    { id: 'automation', label: 'Automation', icon: <Zap className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 p-6 space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
            <Ticket className="w-7 h-7 text-blue-600" />
            Ticket Hub
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Unified ticketing across incidents, remediation, POAMs, tasks, and actions
          </p>
        </div>
        <button
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ['ticketDashboard'] });
            queryClient.invalidateQueries({ queryKey: ['tickets'] });
            queryClient.invalidateQueries({ queryKey: ['ticketKanban'] });
            queryClient.invalidateQueries({ queryKey: ['automationRules'] });
          }}
          className="flex items-center gap-1.5 px-3 py-2 text-sm rounded border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
        >
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {dashboardLoading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 h-20 animate-pulse"
            />
          ))
        ) : (
          <>
            <StatCard
              label="Total Tickets"
              value={stats.total}
              icon={<BarChart3 className="w-5 h-5" />}
              accent="bg-blue-100 text-blue-600 dark:bg-blue-900/40 dark:text-blue-300"
            />
            <StatCard
              label="Open"
              value={stats.open}
              icon={<AlertCircle className="w-5 h-5" />}
              accent="bg-yellow-100 text-yellow-600 dark:bg-yellow-900/40 dark:text-yellow-300"
            />
            <StatCard
              label="In Progress"
              value={stats.in_progress}
              icon={<Clock className="w-5 h-5" />}
              accent="bg-indigo-100 text-indigo-600 dark:bg-indigo-900/40 dark:text-indigo-300"
            />
            <StatCard
              label="Overdue"
              value={stats.overdue}
              icon={<AlertTriangle className="w-5 h-5" />}
              accent="bg-red-100 text-red-600 dark:bg-red-900/40 dark:text-red-300"
            />
          </>
        )}
      </div>

      {/* Source Breakdown */}
      {!dashboardLoading && stats.by_source && Object.keys(stats.by_source).length > 0 && (
        <div className="flex flex-wrap gap-3">
          {Object.entries(stats.by_source).map(([src, count]) => (
            <div
              key={src}
              className="flex items-center gap-2 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 px-3 py-2"
            >
              {sourceIcon(src, 'w-4 h-4 text-gray-500 dark:text-gray-400')}
              <span className="text-sm text-gray-700 dark:text-gray-300">
                {sourceLabel(src)}
              </span>
              <span className="text-sm font-semibold text-gray-900 dark:text-white">{count}</span>
            </div>
          ))}
        </div>
      )}

      {/* Tab Navigation */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-6">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                'flex items-center gap-2 pb-3 px-1 text-sm font-medium border-b-2 transition-colors',
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600 dark:border-blue-400 dark:text-blue-400'
                  : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
              )}
            >
              {tab.icon}
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'list' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center gap-3 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-3">
            <Filter className="w-4 h-4 text-gray-400" />
            <select
              value={sourceFilter}
              onChange={(e) => {
                setSourceFilter(e.target.value);
                setPage(1);
              }}
              className="rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-white p-1.5 focus:ring-2 focus:ring-blue-500"
            >
              {SOURCE_TYPE_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-white p-1.5 focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Statuses</option>
              {STATUS_OPTIONS.filter(Boolean).map((s) => (
                <option key={s} value={s}>
                  {s.replace('_', ' ')}
                </option>
              ))}
            </select>
            <select
              value={priorityFilter}
              onChange={(e) => {
                setPriorityFilter(e.target.value);
                setPage(1);
              }}
              className="rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-white p-1.5 focus:ring-2 focus:ring-blue-500"
            >
              <option value="">All Priorities</option>
              {PRIORITY_OPTIONS.filter(Boolean).map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  setPage(1);
                }}
                placeholder="Search tickets..."
                className="w-full pl-8 pr-3 py-1.5 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-sm text-gray-900 dark:text-white focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>

          {/* Tickets Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            {ticketsLoading ? (
              <Spinner />
            ) : tickets.length === 0 ? (
              <EmptyState message="No tickets found matching your filters." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Source
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Title
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Status
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Priority
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Assigned To
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Source Type
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Created
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Due Date
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {tickets.map((ticket) => (
                      <tr
                        key={`${ticket.source_type}-${ticket.source_id}`}
                        className="border-b border-gray-100 dark:border-gray-700/50 hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors"
                      >
                        <td className="p-3">
                          <span
                            className={clsx(
                              'inline-flex items-center justify-center w-7 h-7 rounded',
                              sourceTypeColors[ticket.source_type]
                            )}
                          >
                            {sourceIcon(ticket.source_type)}
                          </span>
                        </td>
                        <td className="p-3">
                          <span className="text-gray-900 dark:text-white font-medium max-w-xs truncate block">
                            {ticket.title}
                          </span>
                        </td>
                        <td className="p-3">
                          <Badge
                            text={ticket.status}
                            colorClass={statusColors[ticket.status]}
                          />
                        </td>
                        <td className="p-3">
                          <Badge
                            text={ticket.priority}
                            colorClass={priorityColors[ticket.priority]}
                          />
                        </td>
                        <td className="p-3 text-gray-600 dark:text-gray-400">
                          {ticket.assigned_to ?? 'Unassigned'}
                        </td>
                        <td className="p-3">
                          <Badge
                            text={sourceLabel(ticket.source_type)}
                            colorClass={sourceTypeColors[ticket.source_type]}
                          />
                        </td>
                        <td className="p-3 text-gray-500 dark:text-gray-400 whitespace-nowrap">
                          {formatDate(ticket.created_at)}
                        </td>
                        <td className="p-3 text-gray-500 dark:text-gray-400 whitespace-nowrap">
                          {formatDate(ticket.due_date)}
                        </td>
                        <td className="p-3">
                          <button
                            onClick={() => setSelectedTicket(ticket)}
                            className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400 hover:underline text-xs font-medium"
                          >
                            <Eye className="w-3.5 h-3.5" /> View
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination */}
            {totalTickets > 0 && (
              <div className="flex items-center justify-between p-3 border-t border-gray-200 dark:border-gray-700">
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  Showing {(page - 1) * PAGE_SIZE + 1} -{' '}
                  {Math.min(page * PAGE_SIZE, totalTickets)} of {totalTickets}
                  {ticketsFetching && (
                    <Loader className="inline w-3 h-3 ml-2 animate-spin" />
                  )}
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                    disabled={page <= 1}
                    className="p-1.5 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-40 transition-colors"
                  >
                    <ChevronLeft className="w-4 h-4" />
                  </button>
                  <span className="text-sm text-gray-700 dark:text-gray-300">
                    Page {page} of {totalPages}
                  </span>
                  <button
                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                    disabled={page >= totalPages}
                    className="p-1.5 rounded border border-gray-300 dark:border-gray-600 text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-40 transition-colors"
                  >
                    <ChevronRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'kanban' && (
        <div className="space-y-4">
          {kanbanLoading ? (
            <Spinner />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
              {KANBAN_COLUMNS.map((column) => {
                const columnTickets = kanbanColumns[column] ?? [];
                return (
                  <div
                    key={column}
                    className="bg-gray-100 dark:bg-gray-800/50 rounded-lg border border-gray-200 dark:border-gray-700 flex flex-col"
                  >
                    {/* Column Header */}
                    <div className="flex items-center justify-between p-3 border-b border-gray-200 dark:border-gray-700">
                      <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300">
                        {column}
                      </h3>
                      <span className="text-xs font-medium bg-gray-200 dark:bg-gray-700 text-gray-600 dark:text-gray-400 px-2 py-0.5 rounded-full">
                        {columnTickets.length}
                      </span>
                    </div>
                    {/* Column Body */}
                    <div className="p-2 space-y-2 overflow-y-auto max-h-[60vh] min-h-[200px]">
                      {columnTickets.length === 0 ? (
                        <p className="text-xs text-gray-400 dark:text-gray-500 text-center py-8">
                          No tickets
                        </p>
                      ) : (
                        columnTickets.map((ticket) => (
                          <KanbanCard
                            key={`${ticket.source_type}-${ticket.source_id}`}
                            ticket={ticket}
                            onView={setSelectedTicket}
                            onMove={handleKanbanMove}
                            isMoving={kanbanMoveMutation.isPending}
                          />
                        ))
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {activeTab === 'automation' && (
        <div className="space-y-4">
          {/* Header */}
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Automation Rules
            </h2>
            <button
              onClick={() => setShowCreateRule(true)}
              className="inline-flex items-center gap-1.5 px-4 py-2 text-sm rounded bg-blue-600 text-white hover:bg-blue-700 transition-colors"
            >
              <Plus className="w-4 h-4" /> Create Rule
            </button>
          </div>

          {/* Rules Table */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            {rulesLoading ? (
              <Spinner />
            ) : automationRules.length === 0 ? (
              <EmptyState message="No automation rules configured." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Rule Name
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Trigger Type
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Enabled
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Executions
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Last Triggered
                      </th>
                      <th className="text-left p-3 font-medium text-gray-500 dark:text-gray-400">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {automationRules.map((rule) => (
                      <tr
                        key={rule.id}
                        className="border-b border-gray-100 dark:border-gray-700/50 hover:bg-gray-50 dark:hover:bg-gray-700/30 transition-colors"
                      >
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            <Zap className="w-4 h-4 text-yellow-500" />
                            <span className="text-gray-900 dark:text-white font-medium">
                              {rule.name}
                            </span>
                          </div>
                        </td>
                        <td className="p-3">
                          <Badge text={rule.trigger_type.replace(/_/g, ' ')} />
                        </td>
                        <td className="p-3">
                          <button
                            onClick={() =>
                              toggleRuleMutation.mutate({
                                id: rule.id,
                                is_enabled: !rule.is_enabled,
                              })
                            }
                            disabled={toggleRuleMutation.isPending}
                            className="flex items-center gap-1 text-sm disabled:opacity-50"
                          >
                            {rule.is_enabled ? (
                              <ToggleRight className="w-6 h-6 text-green-500" />
                            ) : (
                              <ToggleLeft className="w-6 h-6 text-gray-400" />
                            )}
                            <span
                              className={clsx(
                                'text-xs',
                                rule.is_enabled
                                  ? 'text-green-600 dark:text-green-400'
                                  : 'text-gray-400'
                              )}
                            >
                              {rule.is_enabled ? 'On' : 'Off'}
                            </span>
                          </button>
                        </td>
                        <td className="p-3 text-gray-600 dark:text-gray-400">
                          {rule.execution_count}
                        </td>
                        <td className="p-3 text-gray-500 dark:text-gray-400 whitespace-nowrap">
                          {formatDateTime(rule.last_triggered_at)}
                        </td>
                        <td className="p-3">
                          <button
                            onClick={() =>
                              toggleRuleMutation.mutate({
                                id: rule.id,
                                is_enabled: !rule.is_enabled,
                              })
                            }
                            className={clsx(
                              'text-xs font-medium px-2 py-1 rounded transition-colors',
                              rule.is_enabled
                                ? 'text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20'
                                : 'text-green-600 hover:bg-green-50 dark:hover:bg-green-900/20'
                            )}
                          >
                            {rule.is_enabled ? 'Disable' : 'Enable'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Detail Panel */}
      {selectedTicket && (
        <>
          <div
            className="fixed inset-0 bg-black/30 z-40"
            onClick={() => setSelectedTicket(null)}
          />
          <DetailPanel
            ticket={selectedTicket}
            onClose={() => setSelectedTicket(null)}
          />
        </>
      )}

      {/* Create Rule Modal */}
      {showCreateRule && (
        <CreateRuleModal
          onClose={() => setShowCreateRule(false)}
          onSubmit={(data) => createRuleMutation.mutate(data)}
          isPending={createRuleMutation.isPending}
        />
      )}
    </div>
  );
}
