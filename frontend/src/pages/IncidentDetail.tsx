import { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  FileWarning,
  ArrowLeft,
  Clock,
  User,
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
} from 'lucide-react';
import { incidentsApi, alertsApi, playbooksApi } from '../lib/api';
import type { Incident, Alert, Playbook } from '../lib/types';
import clsx from 'clsx';

const severityColors = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  low: 'bg-blue-100 text-blue-700 border-blue-200',
  info: 'bg-gray-100 text-gray-700 border-gray-200',
};

const statusColors = {
  open: 'bg-blue-100 text-blue-700',
  investigating: 'bg-yellow-100 text-yellow-700',
  contained: 'bg-orange-100 text-orange-700',
  resolved: 'bg-green-100 text-green-700',
  closed: 'bg-gray-100 text-gray-700',
};

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showPlaybookModal, setShowPlaybookModal] = useState(false);
  const [showAddAlertModal, setShowAddAlertModal] = useState(false);

  const { data: incident, isLoading } = useQuery<Incident>({
    queryKey: ['incident', id],
    queryFn: () => incidentsApi.get(id!),
    enabled: !!id,
  });

  const { data: playbooksData } = useQuery({
    queryKey: ['playbooks'],
    queryFn: () => playbooksApi.list({ size: 100 }),
  });

  const { data: alertsData } = useQuery({
    queryKey: ['alerts', 'available'],
    queryFn: () => alertsApi.list({ size: 100, status: 'new' }),
  });

  const updateMutation = useMutation({
    mutationFn: (data: Partial<Incident>) => incidentsApi.update(id!, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incident', id] });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => incidentsApi.delete(id!),
    onSuccess: () => {
      navigate('/incidents');
    },
  });

  const executePlaybookMutation = useMutation({
    mutationFn: (playbookId: string) =>
      playbooksApi.execute(playbookId, { incident_id: id }),
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

  if (!incident) {
    return (
      <div className="text-center py-12">
        <FileWarning className="w-12 h-12 mx-auto mb-4 text-gray-300" />
        <p className="text-gray-500">Incident not found</p>
        <Link to="/incidents" className="text-blue-600 hover:text-blue-700 mt-2 inline-block">
          Back to Incidents
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
            onClick={() => navigate('/incidents')}
            className="p-2 rounded-lg hover:bg-gray-100"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <FileWarning className="w-6 h-6 text-red-500" />
              <h1 className="text-2xl font-bold text-gray-900">{incident.title}</h1>
            </div>
            <p className="text-gray-500 ml-9">Incident ID: {incident.id}</p>
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
              {incident.description || 'No description provided'}
            </p>
          </div>

          {/* Related Alerts */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-900">
                Related Alerts ({incident.alert_count || 0})
              </h2>
              <button
                onClick={() => setShowAddAlertModal(true)}
                className="flex items-center gap-1 text-sm text-blue-600 hover:text-blue-700"
              >
                <Plus className="w-4 h-4" />
                Link Alert
              </button>
            </div>
            {incident.alerts && incident.alerts.length > 0 ? (
              <div className="space-y-3">
                {incident.alerts.map((alert: Alert) => (
                  <Link
                    key={alert.id}
                    to={`/alerts/${alert.id}`}
                    className="flex items-center justify-between p-3 rounded-lg border border-gray-200 hover:bg-gray-50"
                  >
                    <div className="flex items-center gap-3">
                      <AlertTriangle className="w-5 h-5 text-orange-500" />
                      <div>
                        <p className="font-medium text-gray-900">{alert.title}</p>
                        <p className="text-sm text-gray-500">
                          {alert.source} - {formatDate(alert.created_at)}
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full capitalize',
                          severityColors[alert.severity as keyof typeof severityColors]
                        )}
                      >
                        {alert.severity}
                      </span>
                      <ChevronRight className="w-4 h-4 text-gray-400" />
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-500">
                <LinkIcon className="w-8 h-8 mx-auto mb-2 text-gray-300" />
                <p>No alerts linked to this incident</p>
              </div>
            )}
          </div>

          {/* Timeline */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Timeline</h2>
            <div className="space-y-4">
              <div className="flex items-start gap-4">
                <div className="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center flex-shrink-0">
                  <FileWarning className="w-4 h-4 text-red-600" />
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-900">Incident Created</p>
                  <p className="text-sm text-gray-500">{formatDate(incident.created_at)}</p>
                </div>
              </div>
              {incident.updated_at !== incident.created_at && (
                <div className="flex items-start gap-4">
                  <div className="w-8 h-8 rounded-full bg-yellow-100 flex items-center justify-center flex-shrink-0">
                    <Edit className="w-4 h-4 text-yellow-600" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">Last Updated</p>
                    <p className="text-sm text-gray-500">{formatDate(incident.updated_at)}</p>
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
                  value={incident.status}
                  onChange={(e) => updateMutation.mutate({ status: e.target.value })}
                  className={clsx(
                    'mt-1 block w-full rounded-lg border px-3 py-2 text-sm font-medium',
                    statusColors[incident.status as keyof typeof statusColors]
                  )}
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="contained">Contained</option>
                  <option value="resolved">Resolved</option>
                  <option value="closed">Closed</option>
                </select>
              </div>
              <div>
                <label className="text-sm text-gray-500">Severity</label>
                <select
                  value={incident.severity}
                  onChange={(e) => updateMutation.mutate({ severity: e.target.value })}
                  className={clsx(
                    'mt-1 block w-full rounded-lg border px-3 py-2 text-sm font-medium capitalize',
                    severityColors[incident.severity as keyof typeof severityColors]
                  )}
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
              <div>
                <label className="text-sm text-gray-500">Created</label>
                <div className="mt-1 flex items-center gap-2 text-sm text-gray-900">
                  <Clock className="w-4 h-4" />
                  {formatDate(incident.created_at)}
                </div>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-white rounded-lg border border-gray-200 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h2>
            <div className="space-y-2">
              <button
                onClick={() => updateMutation.mutate({ status: 'investigating' })}
                className="w-full flex items-center gap-2 px-4 py-2 text-left rounded-lg hover:bg-gray-50"
              >
                <User className="w-4 h-4 text-yellow-500" />
                Start Investigation
              </button>
              <button
                onClick={() => updateMutation.mutate({ status: 'contained' })}
                className="w-full flex items-center gap-2 px-4 py-2 text-left rounded-lg hover:bg-gray-50"
              >
                <XCircle className="w-4 h-4 text-orange-500" />
                Mark as Contained
              </button>
              <button
                onClick={() => updateMutation.mutate({ status: 'resolved' })}
                className="w-full flex items-center gap-2 px-4 py-2 text-left rounded-lg hover:bg-gray-50"
              >
                <CheckCircle className="w-4 h-4 text-green-500" />
                Mark as Resolved
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

      {/* Add Alert Modal */}
      {showAddAlertModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <div className="bg-white rounded-lg w-full max-w-md p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Link Alert to Incident</h2>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {alertsData?.items?.map((alert: Alert) => (
                <button
                  key={alert.id}
                  className="w-full flex items-center justify-between p-3 text-left rounded-lg hover:bg-gray-50 border border-gray-200"
                >
                  <div>
                    <p className="font-medium text-gray-900">{alert.title}</p>
                    <p className="text-sm text-gray-500">{alert.source}</p>
                  </div>
                  <Plus className="w-4 h-4 text-blue-500" />
                </button>
              ))}
            </div>
            <div className="mt-4 flex justify-end">
              <button
                onClick={() => setShowAddAlertModal(false)}
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
