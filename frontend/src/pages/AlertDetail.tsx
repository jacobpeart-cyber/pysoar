import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowLeft,
  Clock,
  User,
  Tag,
  FileWarning,
  Play,
  CheckCircle,
  XCircle,
  Edit,
  Trash2,
  Loader2,
  ChevronRight,
} from 'lucide-react';
import { alertsApi, incidentsApi, playbooksApi } from '../lib/api';
import type { Alert, Playbook } from '../lib/types';
import clsx from 'clsx';

const severityColors = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
  info: 'bg-gray-100 text-gray-700 border-gray-200',
};

const statusColors = {
  new: 'bg-blue-100 text-blue-700',
  investigating: 'bg-yellow-100 text-yellow-700',
  resolved: 'bg-green-100 text-green-700',
  closed: 'bg-gray-100 text-gray-700',
  false_positive: 'bg-purple-100 text-purple-700',
};

export default function AlertDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showPlaybookModal, setShowPlaybookModal] = useState(false);

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
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => alertsApi.delete(id!),
    onSuccess: () => {
      navigate('/alerts');
    },
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
  });

  const executePlaybookMutation = useMutation({
    mutationFn: (playbookId: string) =>
      playbooksApi.execute(playbookId, { alert_id: id }),
    onSuccess: () => {
      setShowPlaybookModal(false);
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  if (!alert) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 mx-auto mb-4 text-gray-300" />
        <p className="text-gray-500">Alert not found</p>
        <Link to="/alerts" className="text-blue-600 hover:text-blue-700 mt-2 inline-block">
          Back to Alerts
        </Link>
      </div>
    );
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/alerts')}
            className="p-2 rounded-lg hover:bg-gray-100"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-6 h-6 text-orange-500" />
              <h1 className="text-2xl font-bold text-gray-900">{alert.title}</h1>
            </div>
            <p className="text-gray-500 ml-9">Alert ID: {alert.id}</p>
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
            onClick={() => deleteMutation.mutate()}
            className="p-2 text-red-600 hover:bg-red-50 rounded-lg"
          >
            <Trash2 className="w-5 h-5" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="col-span-2 space-y-6">
          {/* Description */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Description</h2>
            <p className="text-gray-600 whitespace-pre-wrap">
              {alert.description || 'No description provided'}
            </p>
          </div>

          {/* Timeline */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Timeline</h2>
            <div className="space-y-4">
              <div className="flex items-start gap-4">
                <div className="w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center flex-shrink-0">
                  <AlertTriangle className="w-4 h-4 text-blue-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-900">Alert Created</p>
                  <p className="text-sm text-gray-500">{formatDate(alert.created_at)}</p>
                </div>
              </div>
              {alert.updated_at !== alert.created_at && (
                <div className="flex items-start gap-4">
                  <div className="w-8 h-8 rounded-full bg-yellow-100 flex items-center justify-center flex-shrink-0">
                    <Edit className="w-4 h-4 text-yellow-600" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Last Updated</p>
                    <p className="text-sm text-gray-500">{formatDate(alert.updated_at)}</p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Status Card */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Details</h2>
            <div className="space-y-4">
              <div>
                <label className="text-sm text-gray-500">Status</label>
                <select
                  value={alert.status}
                  onChange={(e) => updateMutation.mutate({ status: e.target.value })}
                  className={clsx(
                    'mt-1 block w-full rounded-lg border px-3 py-2 text-sm font-medium',
                    statusColors[alert.status as keyof typeof statusColors]
                  )}
                >
                  <option value="new">New</option>
                  <option value="investigating">Investigating</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>
              <div>
                <label className="text-sm text-gray-500">Severity</label>
                <div
                  className={clsx(
                    'mt-1 px-3 py-2 rounded-lg text-sm font-medium capitalize border',
                    severityColors[alert.severity as keyof typeof severityColors]
                  )}
                >
                  {alert.severity}
                </div>
              </div>
              <div>
                <label className="text-sm text-gray-500">Source</label>
                <div className="mt-1 flex items-center gap-2 text-sm text-gray-900">
                  <Tag className="w-4 h-4" />
                  {alert.source}
                </div>
              </div>
              <div>
                <label className="text-sm text-gray-500">Created</label>
                <div className="mt-1 flex items-center gap-2 text-sm text-gray-900">
                  <Clock className="w-4 h-4" />
                  {formatDate(alert.created_at)}
                </div>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h2>
            <div className="space-y-2">
              <button
                onClick={() => updateMutation.mutate({ status: 'resolved' })}
                className="w-full flex items-center gap-2 px-4 py-2 text-left rounded-lg hover:bg-gray-50"
              >
                <CheckCircle className="w-4 h-4 text-green-500" />
                Mark as Resolved
              </button>
              <button
                onClick={() => updateMutation.mutate({ status: 'false_positive' })}
                className="w-full flex items-center gap-2 px-4 py-2 text-left rounded-lg hover:bg-gray-50"
              >
                <XCircle className="w-4 h-4 text-purple-500" />
                Mark as False Positive
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Playbook Modal */}
      {showPlaybookModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg w-full max-w-md p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Run Playbook</h2>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {playbooksData?.items
                ?.filter((p: Playbook) => p.is_enabled)
                .map((playbook: Playbook) => (
                  <button
                    key={playbook.id}
                    onClick={() => executePlaybookMutation.mutate(playbook.id)}
                    disabled={executePlaybookMutation.isPending}
                    className="w-full flex items-center justify-between p-3 text-left rounded-lg hover:bg-gray-50 border border-gray-200"
                  >
                    <div>
                      <p className="font-medium text-gray-900">{playbook.name}</p>
                      <p className="text-sm text-gray-500">{playbook.description}</p>
                    </div>
                    <ChevronRight className="w-4 h-4 text-gray-400" />
                  </button>
                ))}
            </div>
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setShowPlaybookModal(false)}
                className="px-4 py-2 text-gray-600 hover:text-gray-900"
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
