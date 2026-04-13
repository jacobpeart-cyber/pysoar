import { useState, useRef } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  FileWarning,
  ArrowLeft,
  Clock,
  AlertTriangle,
  Play,
  CheckCircle,
  XCircle,
  Edit,
  Trash2,
  Loader2,
  ChevronRight,
  Plus,
  Link as LinkIcon,
  MessageSquare,
  Paperclip,
  ListTodo,
  History,
  Send,
  Pin,
  Download,
  User as UserIcon,
} from 'lucide-react';
import { incidentsApi, alertsApi, playbooksApi, api } from '../lib/api';
import type { Incident, Alert, Playbook } from '../lib/types';
import clsx from 'clsx';

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-900/50',
  high: 'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-900/50',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-900/50',
  low: 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-900/50',
  informational: 'bg-gray-100 text-gray-700 border-gray-200 dark:bg-gray-700 dark:text-gray-300 dark:border-gray-600',
};

const statusColors: Record<string, string> = {
  open: 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-900/50',
  investigating: 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-900/50',
  containment: 'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-900/50',
  eradication: 'bg-purple-100 text-purple-700 border-purple-200 dark:bg-purple-900/30 dark:text-purple-300 dark:border-purple-900/50',
  recovery: 'bg-indigo-100 text-indigo-700 border-indigo-200 dark:bg-indigo-900/30 dark:text-indigo-300 dark:border-indigo-900/50',
  closed: 'bg-green-100 text-green-700 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-900/50',
};

const ALL_STATUSES = [
  { value: 'open', label: 'Open' },
  { value: 'investigating', label: 'Investigating' },
  { value: 'containment', label: 'Containment' },
  { value: 'eradication', label: 'Eradication' },
  { value: 'recovery', label: 'Recovery' },
  { value: 'closed', label: 'Closed' },
];

interface CaseNote {
  id: string;
  content: string;
  note_type: string;
  is_pinned: boolean;
  is_internal: boolean;
  author_id: string;
  author_name?: string | null;
  created_at: string;
}

interface CaseTask {
  id: string;
  title: string;
  description?: string | null;
  status: string;
  priority: number;
  due_date?: string | null;
  assigned_to?: string | null;
  assignee_name?: string | null;
  creator_name?: string | null;
  created_at: string;
}

interface Attachment {
  id: string;
  filename: string;
  original_filename: string;
  file_size: number;
  mime_type: string;
  attachment_type: string;
  uploader_name?: string | null;
  created_at: string;
}

interface TimelineEvent {
  id: string;
  event_type: string;
  title: string;
  description?: string | null;
  old_value?: string | null;
  new_value?: string | null;
  actor_name?: string | null;
  created_at: string;
}

type Toast = { type: 'success' | 'error'; text: string };

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showPlaybookModal, setShowPlaybookModal] = useState(false);
  const [showAddAlertModal, setShowAddAlertModal] = useState(false);
  const [caseTab, setCaseTab] = useState<'notes' | 'tasks' | 'timeline' | 'attachments'>('notes');
  const [newNote, setNewNote] = useState('');
  const [newTaskTitle, setNewTaskTitle] = useState('');
  const [showAddTaskForm, setShowAddTaskForm] = useState(false);
  const [toast, setToast] = useState<Toast | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const showToast = (type: Toast['type'], text: string) => {
    setToast({ type, text });
    setTimeout(() => setToast(null), 4000);
  };

  // ---- QUERIES ----
  const { data: incident, isLoading } = useQuery<Incident>({
    queryKey: ['incident', id],
    queryFn: () => incidentsApi.get(id!),
    enabled: !!id,
  });

  const { data: notes = [] } = useQuery<CaseNote[]>({
    queryKey: ['incident', id, 'notes'],
    queryFn: () => incidentsApi.listNotes(id!),
    enabled: !!id,
  });

  const { data: tasks = [] } = useQuery<CaseTask[]>({
    queryKey: ['incident', id, 'tasks'],
    queryFn: () => incidentsApi.listTasks(id!),
    enabled: !!id,
  });

  const { data: timeline = [] } = useQuery<TimelineEvent[]>({
    queryKey: ['incident', id, 'timeline'],
    queryFn: () => incidentsApi.listTimeline(id!),
    enabled: !!id,
  });

  const { data: attachments = [] } = useQuery<Attachment[]>({
    queryKey: ['incident', id, 'attachments'],
    queryFn: () => incidentsApi.listAttachments(id!),
    enabled: !!id,
  });

  const { data: playbooksData } = useQuery({
    queryKey: ['playbooks'],
    queryFn: () => playbooksApi.list({ size: 100 }),
  });

  const { data: alertsData } = useQuery({
    queryKey: ['alerts', 'available-new'],
    queryFn: () => alertsApi.list({ size: 100, status: 'new' }),
    enabled: showAddAlertModal,
  });

  // ---- MUTATIONS ----
  const updateMutation = useMutation({
    mutationFn: (data: Partial<Incident>) => incidentsApi.update(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident', id] });
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      showToast('success', 'Incident updated');
    },
    onError: () => showToast('error', 'Update failed'),
  });

  const deleteMutation = useMutation({
    mutationFn: () => incidentsApi.delete(id!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      navigate('/incidents');
    },
    onError: () => showToast('error', 'Delete failed'),
  });

  const addNoteMutation = useMutation({
    mutationFn: (content: string) => incidentsApi.createNote(id!, content),
    onSuccess: () => {
      setNewNote('');
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'notes'] });
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'timeline'] });
      showToast('success', 'Note added');
    },
    onError: () => showToast('error', 'Failed to add note'),
  });

  const deleteNoteMutation = useMutation({
    mutationFn: (noteId: string) => incidentsApi.deleteNote(id!, noteId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'notes'] });
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'timeline'] });
      showToast('success', 'Note deleted');
    },
    onError: () => showToast('error', 'Failed to delete note'),
  });

  const addTaskMutation = useMutation({
    mutationFn: (title: string) => incidentsApi.createTask(id!, { title }),
    onSuccess: () => {
      setNewTaskTitle('');
      setShowAddTaskForm(false);
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'tasks'] });
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'timeline'] });
      showToast('success', 'Task added');
    },
    onError: () => showToast('error', 'Failed to add task'),
  });

  const updateTaskMutation = useMutation({
    mutationFn: ({ taskId, status }: { taskId: string; status: string }) =>
      incidentsApi.updateTask(id!, taskId, { status }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'tasks'] });
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'timeline'] });
    },
    onError: () => showToast('error', 'Failed to update task'),
  });

  const uploadFileMutation = useMutation({
    mutationFn: (file: File) => incidentsApi.uploadAttachment(id!, file),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'attachments'] });
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'timeline'] });
      showToast('success', 'File uploaded');
    },
    onError: () => showToast('error', 'Upload failed'),
  });

  const linkAlertMutation = useMutation({
    mutationFn: (alertId: string) => incidentsApi.linkAlert(id!, alertId),
    onSuccess: () => {
      setShowAddAlertModal(false);
      queryClient.invalidateQueries({ queryKey: ['incident', id] });
      queryClient.invalidateQueries({ queryKey: ['incident', id, 'timeline'] });
      showToast('success', 'Alert linked');
    },
    onError: () => showToast('error', 'Failed to link alert'),
  });

  const unlinkAlertMutation = useMutation({
    mutationFn: (alertId: string) => incidentsApi.unlinkAlert(id!, alertId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident', id] });
      showToast('success', 'Alert unlinked');
    },
    onError: () => showToast('error', 'Failed to unlink alert'),
  });

  const executePlaybookMutation = useMutation({
    mutationFn: (playbookId: string) => playbooksApi.execute(playbookId, { incident_id: id }),
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

  if (!incident) {
    return (
      <div className="text-center py-12">
        <FileWarning className="w-12 h-12 mx-auto mb-4 text-gray-300 dark:text-gray-600" />
        <p className="text-gray-500 dark:text-gray-400">Incident not found</p>
        <Link to="/incidents" className="text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 mt-2 inline-block">
          Back to Incidents
        </Link>
      </div>
    );
  }

  const formatDate = (d?: string | null) => (d ? new Date(d).toLocaleString() : '—');
  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

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
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div className="flex items-start gap-4">
          <button
            onClick={() => navigate('/incidents')}
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <FileWarning className="w-6 h-6 text-red-500" />
              <h1 className="text-2xl font-bold text-gray-900 dark:text-white break-all">{incident.title}</h1>
            </div>
            <p className="text-gray-500 dark:text-gray-400 ml-9 text-xs font-mono">Incident ID: {incident.id}</p>
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
            onClick={() => {
              if (confirm('Delete this incident? Linked alerts will be unlinked.')) deleteMutation.mutate();
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
              {incident.description || <span className="text-gray-400 italic">No description provided</span>}
            </p>
          </Card>

          {/* Related Alerts */}
          <Card
            title={`Related Alerts (${incident.alerts?.length ?? incident.alert_count ?? 0})`}
            action={
              <button
                onClick={() => setShowAddAlertModal(true)}
                className="flex items-center gap-1 text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
              >
                <Plus className="w-4 h-4" />
                Link Alert
              </button>
            }
          >
            {incident.alerts && incident.alerts.length > 0 ? (
              <div className="space-y-3">
                {incident.alerts.map((alert: Alert) => (
                  <div
                    key={alert.id}
                    className="flex items-center justify-between p-3 rounded-lg border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50"
                  >
                    <Link to={`/alerts/${alert.id}`} className="flex items-center gap-3 flex-1 min-w-0">
                      <AlertTriangle className="w-5 h-5 text-orange-500 flex-shrink-0" />
                      <div className="min-w-0">
                        <p className="font-medium text-gray-900 dark:text-white truncate">{alert.title}</p>
                        <p className="text-sm text-gray-500 dark:text-gray-400 truncate">
                          {alert.source} · {formatDate(alert.created_at)}
                        </p>
                      </div>
                    </Link>
                    <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                      <span className={clsx('px-2 py-1 text-xs font-medium rounded-full border capitalize', severityColors[alert.severity] || severityColors.medium)}>
                        {alert.severity}
                      </span>
                      <button
                        onClick={(e) => {
                          e.preventDefault();
                          if (confirm('Unlink this alert?')) unlinkAlertMutation.mutate(alert.id);
                        }}
                        className="p-1 text-gray-400 hover:text-red-600 dark:hover:text-red-400"
                        title="Unlink"
                      >
                        <XCircle className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                <LinkIcon className="w-8 h-8 mx-auto mb-2 text-gray-300 dark:text-gray-600" />
                <p>No alerts linked to this incident</p>
              </div>
            )}
          </Card>

          {/* Case Management */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
            {/* Tabs */}
            <div className="border-b border-gray-200 dark:border-gray-700 px-6">
              <nav className="flex gap-6">
                <TabButton active={caseTab === 'notes'} onClick={() => setCaseTab('notes')} icon={MessageSquare} label={`Notes (${notes.length})`} />
                <TabButton active={caseTab === 'tasks'} onClick={() => setCaseTab('tasks')} icon={ListTodo} label={`Tasks (${tasks.length})`} />
                <TabButton active={caseTab === 'timeline'} onClick={() => setCaseTab('timeline')} icon={History} label={`Timeline (${timeline.length})`} />
                <TabButton active={caseTab === 'attachments'} onClick={() => setCaseTab('attachments')} icon={Paperclip} label={`Attachments (${attachments.length})`} />
              </nav>
            </div>

            {/* Tab Content */}
            <div className="p-6">
              {caseTab === 'notes' && (
                <div className="space-y-4">
                  <div className="flex gap-3">
                    <textarea
                      value={newNote}
                      onChange={(e) => setNewNote(e.target.value)}
                      placeholder="Add a note…"
                      rows={2}
                      className="flex-1 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-3 py-2 text-sm"
                    />
                    <button
                      disabled={!newNote.trim() || addNoteMutation.isPending}
                      onClick={() => {
                        if (newNote.trim()) addNoteMutation.mutate(newNote.trim());
                      }}
                      className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 self-end"
                    >
                      <Send className="w-4 h-4" />
                    </button>
                  </div>

                  {notes.length === 0 ? (
                    <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                      <MessageSquare className="w-8 h-8 mx-auto mb-2 text-gray-300 dark:text-gray-600" />
                      <p>No notes yet</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {notes.map((note) => (
                        <div key={note.id} className="p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/40 flex items-center justify-center">
                                <span className="text-sm font-medium text-blue-600 dark:text-blue-300">
                                  {(note.author_name || '?').charAt(0).toUpperCase()}
                                </span>
                              </div>
                              <div>
                                <p className="text-sm font-medium text-gray-900 dark:text-white">
                                  {note.author_name || 'Unknown'}
                                </p>
                                <p className="text-xs text-gray-500 dark:text-gray-400">
                                  {note.note_type} · {formatDate(note.created_at)}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              {note.is_pinned && <Pin className="w-4 h-4 text-yellow-500" />}
                              <button
                                onClick={() => {
                                  if (confirm('Delete this note?')) deleteNoteMutation.mutate(note.id);
                                }}
                                className="text-gray-400 hover:text-red-600 dark:hover:text-red-400"
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          </div>
                          <p className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{note.content}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {caseTab === 'tasks' && (
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="font-medium text-gray-900 dark:text-white">Tasks</h3>
                    <button
                      onClick={() => setShowAddTaskForm(true)}
                      className="flex items-center gap-1 text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
                    >
                      <Plus className="w-4 h-4" />
                      Add Task
                    </button>
                  </div>

                  {showAddTaskForm && (
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={newTaskTitle}
                        onChange={(e) => setNewTaskTitle(e.target.value)}
                        placeholder="Task title…"
                        autoFocus
                        className="flex-1 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white px-3 py-2 text-sm"
                      />
                      <button
                        disabled={!newTaskTitle.trim() || addTaskMutation.isPending}
                        onClick={() => {
                          if (newTaskTitle.trim()) addTaskMutation.mutate(newTaskTitle.trim());
                        }}
                        className="px-3 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 text-sm"
                      >
                        Add
                      </button>
                      <button
                        onClick={() => {
                          setShowAddTaskForm(false);
                          setNewTaskTitle('');
                        }}
                        className="px-3 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 text-sm"
                      >
                        Cancel
                      </button>
                    </div>
                  )}

                  {tasks.length === 0 && !showAddTaskForm ? (
                    <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                      <ListTodo className="w-8 h-8 mx-auto mb-2 text-gray-300 dark:text-gray-600" />
                      <p>No tasks yet</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {tasks.map((task) => (
                        <div
                          key={task.id}
                          className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                        >
                          <input
                            type="checkbox"
                            checked={task.status === 'completed'}
                            onChange={(e) =>
                              updateTaskMutation.mutate({
                                taskId: task.id,
                                status: e.target.checked ? 'completed' : 'pending',
                              })
                            }
                            className="rounded border-gray-300 text-blue-600"
                          />
                          <div className="flex-1 min-w-0">
                            <p className={clsx('text-sm font-medium text-gray-900 dark:text-white', task.status === 'completed' && 'line-through opacity-60')}>
                              {task.title}
                            </p>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              {task.assignee_name ? `Assigned: ${task.assignee_name}` : 'Unassigned'}
                              {task.due_date && ` · Due: ${formatDate(task.due_date)}`}
                            </p>
                          </div>
                          <span
                            className={clsx(
                              'px-2 py-1 text-xs rounded whitespace-nowrap',
                              task.status === 'completed'
                                ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
                                : task.status === 'in_progress'
                                  ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                                  : 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300',
                            )}
                          >
                            {task.status.replace(/_/g, ' ')}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {caseTab === 'timeline' && (
                <div>
                  {timeline.length === 0 ? (
                    <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                      <History className="w-8 h-8 mx-auto mb-2 text-gray-300 dark:text-gray-600" />
                      <p>No timeline events yet</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {timeline.map((event) => (
                        <div key={event.id} className="flex items-start gap-4">
                          <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center flex-shrink-0">
                            <Edit className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-gray-900 dark:text-white">{event.title}</p>
                            {event.description && (
                              <p className="text-sm text-gray-600 dark:text-gray-400">{event.description}</p>
                            )}
                            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                              {event.actor_name && `${event.actor_name} · `}
                              {formatDate(event.created_at)}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {caseTab === 'attachments' && (
                <div className="space-y-4">
                  <div className="flex justify-between items-center">
                    <h3 className="font-medium text-gray-900 dark:text-white">Attachments</h3>
                    <input
                      ref={fileInputRef}
                      type="file"
                      className="hidden"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        if (file) uploadFileMutation.mutate(file);
                        e.target.value = '';
                      }}
                    />
                    <button
                      onClick={() => fileInputRef.current?.click()}
                      disabled={uploadFileMutation.isPending}
                      className="flex items-center gap-1 text-sm text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 disabled:opacity-50"
                    >
                      <Plus className="w-4 h-4" />
                      {uploadFileMutation.isPending ? 'Uploading…' : 'Upload File'}
                    </button>
                  </div>
                  {attachments.length === 0 ? (
                    <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                      <Paperclip className="w-8 h-8 mx-auto mb-2 text-gray-300 dark:text-gray-600" />
                      <p>No attachments yet</p>
                      <p className="text-xs mt-1">Upload evidence, logs, or other relevant files</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {attachments.map((att) => (
                        <div
                          key={att.id}
                          className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                        >
                          <Paperclip className="w-5 h-5 text-gray-400 flex-shrink-0" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                              {att.original_filename}
                            </p>
                            <p className="text-xs text-gray-500 dark:text-gray-400">
                              {formatFileSize(att.file_size)} · {att.mime_type} ·{' '}
                              {att.uploader_name || 'Unknown'} · {formatDate(att.created_at)}
                            </p>
                          </div>
                          <button
                            type="button"
                            onClick={async () => {
                              try {
                                const response = await api.get(
                                  `/incidents/${id}/attachments/${att.id}/download`,
                                  { responseType: 'blob' }
                                );
                                const blob = response.data as Blob;
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = att.original_filename || 'attachment';
                                document.body.appendChild(a);
                                a.click();
                                document.body.removeChild(a);
                                URL.revokeObjectURL(url);
                              } catch (err) {
                                console.error('Attachment download failed:', err);
                              }
                            }}
                            className="p-1.5 text-gray-400 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded transition"
                            title="Download attachment"
                          >
                            <Download className="w-4 h-4" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          <Card title="Details">
            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-500 dark:text-gray-400">Status</label>
                <select
                  value={incident.status || 'open'}
                  disabled={updateMutation.isPending}
                  onChange={(e) => updateMutation.mutate({ status: e.target.value })}
                  className={clsx(
                    'mt-1 block w-full rounded-lg border px-3 py-2 text-sm font-medium capitalize',
                    statusColors[incident.status as keyof typeof statusColors] || statusColors.open,
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
                <select
                  value={incident.severity || 'medium'}
                  disabled={updateMutation.isPending}
                  onChange={(e) => updateMutation.mutate({ severity: e.target.value })}
                  className={clsx(
                    'mt-1 block w-full rounded-lg border px-3 py-2 text-sm font-medium capitalize',
                    severityColors[incident.severity as keyof typeof severityColors] || severityColors.medium,
                  )}
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="informational">Informational</option>
                </select>
              </div>
              <SidebarField icon={UserIcon} label="Created" value={formatDate(incident.created_at)} />
              {(incident as any).incident_type && (
                <SidebarField icon={FileWarning} label="Type" value={(incident as any).incident_type.replace(/_/g, ' ')} />
              )}
              <SidebarField icon={Clock} label="Updated" value={formatDate(incident.updated_at)} />
            </div>
          </Card>

          <Card title="Quick Actions">
            <div className="space-y-2">
              <QuickAction
                icon={UserIcon}
                iconColor="text-yellow-500"
                label="Start Investigation"
                disabled={updateMutation.isPending || incident.status === 'investigating'}
                onClick={() => updateMutation.mutate({ status: 'investigating' })}
              />
              <QuickAction
                icon={XCircle}
                iconColor="text-orange-500"
                label="Mark Containment"
                disabled={updateMutation.isPending || incident.status === 'containment'}
                onClick={() => updateMutation.mutate({ status: 'containment' })}
              />
              <QuickAction
                icon={CheckCircle}
                iconColor="text-green-500"
                label="Mark Closed"
                disabled={updateMutation.isPending || incident.status === 'closed'}
                onClick={() => updateMutation.mutate({ status: 'closed' })}
              />
            </div>
          </Card>
        </div>
      </div>

      {/* Playbook Modal */}
      {showPlaybookModal && (
        <Modal title="Run Playbook" onClose={() => setShowPlaybookModal(false)}>
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
        </Modal>
      )}

      {/* Add Alert Modal */}
      {showAddAlertModal && (
        <Modal title="Link Alert to Incident" onClose={() => setShowAddAlertModal(false)}>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {(alertsData?.items || []).length === 0 ? (
              <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-4">No unlinked new alerts available</p>
            ) : (
              alertsData?.items.map((alert: Alert) => (
                <button
                  key={alert.id}
                  onClick={() => linkAlertMutation.mutate(alert.id)}
                  disabled={linkAlertMutation.isPending}
                  className="w-full flex items-center justify-between p-3 text-left rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 border border-gray-200 dark:border-gray-700 disabled:opacity-50"
                >
                  <div className="min-w-0">
                    <p className="font-medium text-gray-900 dark:text-white truncate">{alert.title}</p>
                    <p className="text-sm text-gray-500 dark:text-gray-400">{alert.source}</p>
                  </div>
                  <Plus className="w-4 h-4 text-blue-500 flex-shrink-0 ml-2" />
                </button>
              ))
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}

function Card({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
        {action}
      </div>
      {children}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: any;
  label: string;
}) {
  return (
    <button
      onClick={onClick}
      className={clsx(
        'py-4 text-sm font-medium border-b-2 transition-colors flex items-center gap-2',
        active
          ? 'border-blue-500 text-blue-600 dark:text-blue-400'
          : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200',
      )}
    >
      <Icon className="w-4 h-4" />
      {label}
    </button>
  );
}

function SidebarField({ icon: Icon, label, value }: { icon: any; label: string; value: string }) {
  return (
    <div>
      <label className="text-sm text-gray-500 dark:text-gray-400">{label}</label>
      <div className="mt-1 flex items-center gap-2 text-sm text-gray-900 dark:text-gray-100 capitalize">
        <Icon className="w-4 h-4 text-gray-400 flex-shrink-0" />
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

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 dark:bg-opacity-70 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-md p-6">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">{title}</h2>
        {children}
        <div className="mt-4 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
