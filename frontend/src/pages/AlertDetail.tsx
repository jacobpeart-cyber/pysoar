import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowLeft,
  Clock,
  Tag,
  FileWarning,
  Play,
  CheckCircle,
  XCircle,
  Edit,
  Trash2,
  Loader2,
  ChevronRight,
  User as UserIcon,
  Hash,
} from 'lucide-react';
import { alertsApi, incidentsApi, playbooksApi } from '../lib/api';
import type { Alert, Playbook } from '../lib/types';
import clsx from 'clsx';

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-900/50',
  high: 'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-900/50',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-900/50',
  low: 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-900/50',
  info: 'bg-gray-100 text-gray-700 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600',
};

const statusColors: Record<string, string> = {
  new: 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-900/50',
  acknowledged: 'bg-indigo-100 text-indigo-700 border-indigo-200 dark:bg-indigo-900/30 dark:text-indigo-300 dark:border-indigo-900/50',
  in_progress: 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-900/50',
  resolved: 'bg-green-100 text-green-700 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-900/50',
  closed: 'bg-gray-100 text-gray-700 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600',
  false_positive: 'bg-purple-100 text-purple-700 border-purple-200 dark:bg-purple-900/30 dark:text-purple-300 dark:border-purple-900/50',
};

const ALL_STATUSES = [
  { value: 'new', label: 'New' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'in_progress', label: 'In Progress' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'closed', label: 'Closed' },
  { value: 'false_positive', label: 'False Positive' },
];

type Toast = { type: 'success' | 'error'; text: string };

export default function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showPlaybookModal, setShowPlaybookModal] = useState(false);
  const [toast, setToast] = useState<Toast | null>(null);

  const showToast = (type: Toast['type'], text: string) => {
    setToast({ type, text });
    setTimeout(() => setToast(null), 4000);
  };

  const { data: alert, isLoading } = useQuery<Alert>({
    queryKey: ['alert', id],
    queryFn: () => alertsApi.get(id!),
    enabled: !!id,
  });

  const { data: playbooksData } = useQuery({
    queryKey: ['playbooks'],
    queryFn: () => playbooksApi.list({ size: 100 }),
  });

  const updateMutation = useMutation({
    mutationFn: (data: Partial<Alert>) => alertsApi.update(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alert', id] });
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      showToast('success', 'Alert updated');
    },
    onError: () => showToast('error', 'Update failed'),
  });

  const deleteMutation = useMutation({
    mutationFn: () => alertsApi.delete(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      navigate('/alerts');
    },
    onError: () => showToast('error', 'Delete failed'),
  });

  const createIncidentMutation = useMutation({
    mutationFn: () =>
      incidentsApi.create({
        title: `Incident from Alert: ${alert?.title}`,
        description: alert?.description,
        severity: alert?.severity,
        alert_ids: [id],
      }),
    onSuccess: (incident) => {
      navigate(`/incidents/${incident.id}`);
    },
    onError: () => showToast('error', 'Failed to create incident'),
  });

  const executePlaybookMutation = useMutation({
    mutationFn: (playbookId: string) => playbooksApi.execute(playbookId, { alert_id: id }),
    onSuccess: () => {
      setShowPlaybookModal(false);
      showToast('success', 'Playbook execution queued');
    },
    onError: () => showToast('error', 'Playbook execution failed'),
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500 dark:text-blue-400" />
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
        <p className="text-gray-500 dark:text-gray-400">Alert not found</p>
        <Link to="/alerts" className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 mt-2 inline-block">
          Back to Alerts
        </Link>
      </div>
    );
  }

  const formatDate = (dateString?: string | null) => (dateString ? new Date(dateString).toLocaleString() : '—');
  const tags = Array.isArray(alert.tags)
    ? alert.tags
    : typeof alert.tags === 'string' && alert.tags
      ? (() => {
          try {
            const parsed = JSON.parse(alert.tags as unknown as string);
            return Array.isArray(parsed) ? parsed : [];
          } catch {
            return [];
          }
        })()
      : [];

  return (
    <div className="space-y-6">
      {/* Toast */}
      {toast && (
        <div
          className={clsx(
            'fixed top-4 right-4 z-50 px-4 py-3 rounded-lg shadow-lg border text-sm font-medium',
            toast.type === 'success'
              ? 'bg-green-50 dark:bg-green-900/30 text-green-700 dark:text-green-300 border-green-200 dark:border-green-900/50'
              : 'bg-red-50 dark:bg-red-900/30 text-red-700 dark:text-red-300 border-red-200 dark:border-red-900/50',
          )}
        >
          {toast.text}
        </div>
      )}

      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex items-start gap-4">
          <button
            onClick={() => navigate('/alerts')}
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-6 h-6 text-orange-500" />
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white break-all">{alert.title}</h1>
            </div>
            <p className="text-gray-500 dark:text-gray-400 ml-9 text-xs font-mono">Alert ID: {alert.id}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowPlaybookModal(true)}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
          >
            <Play className="w-4 h-4" />
            Run Playbook
          </button>
          <button
            onClick={() => createIncidentMutation.mutate()}
            disabled={createIncidentMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            <FileWarning className="w-4 h-4" />
            Create Incident
          </button>
          <button
            onClick={() => {
              if (confirm('Delete this alert?')) deleteMutation.mutate();
            }}
            className="p-2 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg"
          >
            <Trash2 className="w-5 h-5" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Description */}
          <Card title="Description">
            <p className="text-gray-700 dark:text-gray-300 whitespace-pre-wrap break-words">
              {alert.description || <span className="text-gray-400 italic">No description provided</span>}
            </p>
          </Card>

          {/* Entity Context */}
          {(alert.source_ip || alert.destination_ip || alert.hostname || alert.username || alert.file_hash || alert.domain || alert.url) && (
            <Card title="Indicators">
              <dl className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {alert.source_ip && <ContextField label="Source IP" value={alert.source_ip} mono />}
                {alert.destination_ip && <ContextField label="Destination IP" value={alert.destination_ip} mono />}
                {alert.hostname && <ContextField label="Hostname" value={alert.hostname} mono />}
                {alert.username && <ContextField label="Username" value={alert.username} mono />}
                {alert.file_hash && <ContextField label="File Hash" value={alert.file_hash} mono />}
                {alert.domain && <ContextField label="Domain" value={alert.domain} mono />}
                {alert.url && <ContextField label="URL" value={alert.url} mono />}
              </dl>
            </Card>
          )}

          {/* Tags */}
          {tags.length > 0 && (
            <Card title="Tags">
              <div className="flex flex-wrap gap-2">
                {tags.map((tag: string, idx: number) => (
                  <span
                    key={idx}
                    className="px-2 py-1 rounded-full text-xs font-medium bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-900/50"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </Card>
          )}

          {/* Timeline */}
          <Card title="Timeline">
            <div className="space-y-4">
              <TimelineItem icon={AlertTriangle} iconColor="text-blue-600 dark:text-blue-400" bg="bg-blue-100 dark:bg-blue-900/30" label="Alert Created" date={formatDate(alert.created_at)} />
              {alert.updated_at && alert.updated_at !== alert.created_at && (
                <TimelineItem icon={Edit} iconColor="text-yellow-600 dark:text-yellow-400" bg="bg-yellow-100 dark:bg-yellow-900/30" label="Last Updated" date={formatDate(alert.updated_at)} />
              )}
              {alert.resolved_at && (
                <TimelineItem icon={CheckCircle} iconColor="text-green-600 dark:text-green-400" bg="bg-green-100 dark:bg-green-900/30" label="Resolved" date={formatDate(alert.resolved_at)} />
              )}
              {alert.incident_id && (
                <TimelineItem
                  icon={FileWarning}
                  iconColor="text-red-600 dark:text-red-400"
                  bg="bg-red-100 dark:bg-red-900/30"
                  label="Linked to Incident"
                  date={
                    <Link to={`/incidents/${alert.incident_id}`} className="text-blue-600 dark:text-blue-400 hover:underline font-mono text-xs">
                      {alert.incident_id}
                    </Link>
                  }
                />
              )}
            </div>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Status Card */}
          <Card title="Details">
            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-500 dark:text-gray-400">Status</label>
                <select
                  value={alert.status || 'new'}
                  disabled={updateMutation.isPending}
                  onChange={(e) => updateMutation.mutate({ status: e.target.value })}
                  className={clsx(
                    'mt-1 block w-full rounded-lg border px-3 py-2 text-sm font-medium capitalize',
                    statusColors[alert.status as keyof typeof statusColors] || statusColors.new,
                  )}
                >
                  {ALL_STATUSES.map((s) => (
                    <option key={s.value} value={s.value}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-sm text-gray-500 dark:text-gray-400">Severity</label>
                <div
                  className={clsx(
                    'mt-1 px-3 py-2 rounded-lg text-sm font-medium capitalize border',
                    severityColors[alert.severity as keyof typeof severityColors] || severityColors.info,
                  )}
                >
                  {alert.severity}
                </div>
              </div>
              <SidebarField icon={Tag} label="Source" value={alert.source || '—'} />
              <SidebarField icon={Hash} label="Priority" value={`P${alert.priority ?? 3}`} />
              <SidebarField icon={UserIcon} label="Assigned to" value={alert.assigned_to || 'Unassigned'} mono={!!alert.assigned_to} />
              <SidebarField icon={Clock} label="Created" value={formatDate(alert.created_at)} />
            </div>
          </Card>

          {/* Quick Actions */}
          <Card title="Quick Actions">
            <div className="space-y-2">
              <QuickAction
                icon={CheckCircle}
                iconColor="text-green-500"
                label="Mark as Resolved"
                disabled={updateMutation.isPending || alert.status === 'resolved'}
                onClick={() => updateMutation.mutate({ status: 'resolved' })}
              />
              <QuickAction
                icon={XCircle}
                iconColor="text-purple-500"
                label="Mark as False Positive"
                disabled={updateMutation.isPending || alert.status === 'false_positive'}
                onClick={() => updateMutation.mutate({ status: 'false_positive' })}
              />
              <QuickAction
                icon={CheckCircle}
                iconColor="text-indigo-500"
                label="Acknowledge"
                disabled={updateMutation.isPending || alert.status === 'acknowledged'}
                onClick={() => updateMutation.mutate({ status: 'acknowledged' })}
              />
            </div>
          </Card>
        </div>
      </div>

      {/* Playbook Modal */}
      {showPlaybookModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 dark:bg-opacity-70 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-md p-6">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Run Playbook</h2>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {(playbooksData?.items || [])
                .filter((p: Playbook) => p.is_enabled)
                .map((playbook: Playbook) => (
                  <button
                    key={playbook.id}
                    onClick={() => executePlaybookMutation.mutate(playbook.id)}
                    disabled={executePlaybookMutation.isPending}
                    className="w-full flex items-center justify-between p-3 text-left rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 border border-gray-200 dark:border-gray-700 disabled:opacity-50"
                  >
                    <div>
                      <p className="font-medium text-gray-900 dark:text-white">{playbook.name}</p>
                      <p className="text-sm text-gray-500 dark:text-gray-400">{playbook.description}</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-gray-400" />
                  </button>
                ))}
              {(playbooksData?.items || []).filter((p: Playbook) => p.is_enabled).length === 0 && (
                <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-4">No enabled playbooks</p>
              )}
            </div>
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setShowPlaybookModal(false)}
                className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
      <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">{title}</h2>
      {children}
    </div>
  );
}

function ContextField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">{label}</dt>
      <dd className={clsx('mt-1 text-sm text-gray-900 dark:text-gray-100 break-all', mono && 'font-mono')}>{value}</dd>
    </div>
  );
}

function SidebarField({
  icon: Icon,
  label,
  value,
  mono,
}: {
  icon: any;
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <label className="text-sm text-gray-500 dark:text-gray-400">{label}</label>
      <div className={clsx('mt-1 flex items-center gap-2 text-sm text-gray-900 dark:text-gray-100', mono && 'font-mono')}>
        <Icon className="w-4 h-4 text-gray-400" />
        <span className="truncate">{value}</span>
      </div>
    </div>
  );
}

function QuickAction({
  icon: Icon,
  iconColor,
  label,
  disabled,
  onClick,
}: {
  icon: any;
  iconColor: string;
  label: string;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="w-full flex items-center gap-2 px-4 py-2 text-left rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-200 disabled:opacity-40 disabled:cursor-not-allowed"
    >
      <Icon className={clsx('w-4 h-4', iconColor)} />
      {label}
    </button>
  );
}

function TimelineItem({
  icon: Icon,
  iconColor,
  bg,
  label,
  date,
}: {
  icon: any;
  iconColor: string;
  bg: string;
  label: string;
  date: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-4">
      <div className={clsx('w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0', bg)}>
        <Icon className={clsx('w-4 h-4', iconColor)} />
      </div>
      <div>
        <p className="text-sm font-medium text-gray-900 dark:text-white">{label}</p>
        <p className="text-sm text-gray-500 dark:text-gray-400">{date}</p>
      </div>
    </div>
  );
}
