import { useState, useEffect, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import { incidentsApi, alertsApi } from '../lib/api';
import type { Incident, Alert } from '../lib/types';
import {
  Plus,
  Search,
  Eye,
  Trash2,
  X,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  RefreshCw,
  CheckCircle,
  FileWarning,
} from 'lucide-react';
import { format } from 'date-fns';
import clsx from 'clsx';

const statusColors: Record<string, string> = {
  open: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  investigating: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  containment: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  eradication: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
  recovery: 'bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300',
  closed: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
};

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  high: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  informational: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
};

const PAGE_SIZES = [10, 25, 50, 100];
const REFRESH_INTERVAL_MS = 30_000;

type Toast = { type: 'success' | 'error'; text: string };

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [availableAlerts, setAvailableAlerts] = useState<Alert[]>([]);
  const [toast, setToast] = useState<Toast | null>(null);
  const searchDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showToast = useCallback((type: Toast['type'], text: string) => {
    setToast({ type, text });
    setTimeout(() => setToast(null), 4000);
  }, []);

  const fetchIncidents = useCallback(
    async (showSpinner = true) => {
      if (showSpinner) setLoading(true);
      else setRefreshing(true);
      try {
        const params: Record<string, any> = { page, size: pageSize };
        if (statusFilter) params.status = statusFilter;
        if (severityFilter) params.severity = severityFilter;
        if (typeFilter) params.incident_type = typeFilter;
        if (search) params.search = search;
        const response = await incidentsApi.list(params);
        setIncidents(response.items || []);
        setTotal(response.total || 0);
      } catch (error) {
        console.error('Failed to fetch incidents:', error);
        showToast('error', 'Failed to load incidents');
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    },
    [page, pageSize, statusFilter, severityFilter, typeFilter, search, showToast],
  );

  const fetchAvailableAlerts = async () => {
    try {
      const response = await alertsApi.list({ size: 100, status: 'new' });
      setAvailableAlerts(response.items);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    }
  };

  useEffect(() => {
    fetchIncidents(true);
  }, [fetchIncidents]);

  useEffect(() => {
    const interval = setInterval(() => fetchIncidents(false), REFRESH_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [fetchIncidents]);

  // Debounced search
  useEffect(() => {
    if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current);
    searchDebounceRef.current = setTimeout(() => {
      setSearch(searchInput);
      setPage(1);
    }, 350);
    return () => {
      if (searchDebounceRef.current) clearTimeout(searchDebounceRef.current);
    };
  }, [searchInput]);

  useEffect(() => {
    if (showCreateModal) fetchAvailableAlerts();
  }, [showCreateModal]);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!confirm('Delete this incident? Linked alerts will be unlinked.')) return;
    try {
      await incidentsApi.delete(id);
      showToast('success', 'Incident deleted');
      fetchIncidents(false);
    } catch (error) {
      console.error('Failed to delete incident:', error);
      showToast('error', 'Failed to delete incident');
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

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

      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Incidents</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Coordinate investigation and response · {total.toLocaleString()} total
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchIncidents(false)}
            disabled={refreshing}
            className="inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium text-gray-700 dark:text-gray-200 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
          >
            <RefreshCw className={clsx('w-4 h-4', refreshing && 'animate-spin')} />
            Refresh
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="flex items-center gap-2 bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition-colors"
          >
            <Plus className="w-5 h-5" />
            New Incident
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[220px]">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Search</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
              <input
                type="text"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Title or description…"
                className="w-full pl-9 pr-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>
          </div>
          <FilterSelect
            label="Severity"
            value={severityFilter}
            onChange={(v) => {
              setSeverityFilter(v);
              setPage(1);
            }}
            options={[
              { value: '', label: 'All severities' },
              { value: 'critical', label: 'Critical' },
              { value: 'high', label: 'High' },
              { value: 'medium', label: 'Medium' },
              { value: 'low', label: 'Low' },
              { value: 'informational', label: 'Informational' },
            ]}
          />
          <FilterSelect
            label="Status"
            value={statusFilter}
            onChange={(v) => {
              setStatusFilter(v);
              setPage(1);
            }}
            options={[
              { value: '', label: 'All statuses' },
              { value: 'open', label: 'Open' },
              { value: 'investigating', label: 'Investigating' },
              { value: 'containment', label: 'Containment' },
              { value: 'eradication', label: 'Eradication' },
              { value: 'recovery', label: 'Recovery' },
              { value: 'closed', label: 'Closed' },
            ]}
          />
          <FilterSelect
            label="Type"
            value={typeFilter}
            onChange={(v) => {
              setTypeFilter(v);
              setPage(1);
            }}
            options={[
              { value: '', label: 'All types' },
              { value: 'malware', label: 'Malware' },
              { value: 'phishing', label: 'Phishing' },
              { value: 'data_breach', label: 'Data Breach' },
              { value: 'unauthorized_access', label: 'Unauthorized Access' },
              { value: 'denial_of_service', label: 'DoS' },
              { value: 'insider_threat', label: 'Insider Threat' },
              { value: 'ransomware', label: 'Ransomware' },
              { value: 'advanced_persistent_threat', label: 'APT' },
              { value: 'other', label: 'Other' },
            ]}
          />
          <FilterSelect
            label="Per page"
            value={String(pageSize)}
            onChange={(v) => {
              setPageSize(Number(v));
              setPage(1);
            }}
            options={PAGE_SIZES.map((n) => ({ value: String(n), label: String(n) }))}
            minWidth={100}
          />
        </div>
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 dark:border-blue-400"></div>
          </div>
        ) : incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-gray-500 dark:text-gray-400">
            <FileWarning className="w-12 h-12 mb-4 text-gray-300 dark:text-gray-600" />
            <p>No incidents found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-900/50 border-b border-gray-200 dark:border-gray-700">
                <tr>
                  <Th>Title</Th>
                  <Th>Severity</Th>
                  <Th>Status</Th>
                  <Th>Type</Th>
                  <Th>Alerts</Th>
                  <Th>Created</Th>
                  <Th align="right">Actions</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {incidents.map((incident) => (
                  <tr key={incident.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-6 py-4">
                      <Link to={`/incidents/${incident.id}`} className="block">
                        <div className="text-sm font-medium text-gray-900 dark:text-white hover:text-blue-600 dark:hover:text-blue-400">
                          {incident.title}
                        </div>
                        {incident.description && (
                          <div className="text-sm text-gray-500 dark:text-gray-400 truncate max-w-md">
                            {incident.description}
                          </div>
                        )}
                      </Link>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={clsx('inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium capitalize', severityColors[incident.severity] || severityColors.medium)}>
                        {incident.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={clsx('inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium capitalize', statusColors[incident.status] || statusColors.open)}>
                        {(incident.status || '').replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-xs text-gray-500 dark:text-gray-400 whitespace-nowrap">
                      {((incident as any).incident_type || '').replace(/_/g, ' ') || '—'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      <div className="flex items-center gap-1">
                        <AlertTriangle className="w-4 h-4" />
                        {incident.alert_count || 0}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {incident.created_at ? format(new Date(incident.created_at), 'MMM d, yyyy HH:mm') : '—'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <Link
                        to={`/incidents/${incident.id}`}
                        className="inline-block p-1 text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 mr-2"
                        title="View details"
                      >
                        <Eye className="w-5 h-5" />
                      </Link>
                      <button
                        onClick={(e) => handleDelete(incident.id, e)}
                        className="p-1 text-gray-400 hover:text-red-600 dark:hover:text-red-400"
                        title="Delete"
                      >
                        <Trash2 className="w-5 h-5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="bg-white dark:bg-gray-800 px-6 py-4 flex items-center justify-between border-t border-gray-200 dark:border-gray-700 flex-wrap gap-2">
            <div className="text-sm text-gray-500 dark:text-gray-400">
              Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setPage(page - 1)}
                disabled={page === 1}
                className="p-2 border border-gray-300 dark:border-gray-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
              >
                <ChevronLeft className="w-5 h-5" />
              </button>
              <span className="text-sm text-gray-700 dark:text-gray-300 px-2 self-center">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage(page + 1)}
                disabled={page === totalPages}
                className="p-2 border border-gray-300 dark:border-gray-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
              >
                <ChevronRight className="w-5 h-5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Create Modal */}
      {showCreateModal && (
        <CreateIncidentModal
          onClose={() => setShowCreateModal(false)}
          onCreated={() => {
            setShowCreateModal(false);
            showToast('success', 'Incident created');
            fetchIncidents(false);
          }}
          onError={() => showToast('error', 'Failed to create incident')}
          availableAlerts={availableAlerts}
        />
      )}
    </div>
  );
}

function Th({ children, align = 'left' }: { children: React.ReactNode; align?: 'left' | 'right' }) {
  return (
    <th
      className={clsx(
        'px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider',
        align === 'right' ? 'text-right' : 'text-left',
      )}
    >
      {children}
    </th>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
  minWidth = 180,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
  minWidth?: number;
}) {
  return (
    <div className="flex-1" style={{ minWidth: `${minWidth}px` }}>
      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function CreateIncidentModal({
  onClose,
  onCreated,
  onError,
  availableAlerts,
}: {
  onClose: () => void;
  onCreated: () => void;
  onError: () => void;
  availableAlerts: Alert[];
}) {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: 'medium',
    incident_type: 'other',
    alert_ids: [] as string[],
  });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      await incidentsApi.create(formData);
      onCreated();
    } catch (err) {
      console.error(err);
      onError();
    } finally {
      setLoading(false);
    }
  };

  const toggleAlert = (alertId: string) => {
    setFormData((prev) => ({
      ...prev,
      alert_ids: prev.alert_ids.includes(alertId)
        ? prev.alert_ids.filter((id) => id !== alertId)
        : [...prev.alert_ids, alertId],
    }));
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 dark:bg-opacity-70 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Create New Incident</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
            <X className="w-5 h-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Title *</label>
            <input
              type="text"
              required
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Description</label>
            <textarea
              rows={3}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Severity *</label>
              <select
                value={formData.severity}
                onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
                className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="informational">Informational</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Type *</label>
              <select
                value={formData.incident_type}
                onChange={(e) => setFormData({ ...formData, incident_type: e.target.value })}
                className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="malware">Malware</option>
                <option value="phishing">Phishing</option>
                <option value="data_breach">Data Breach</option>
                <option value="unauthorized_access">Unauthorized Access</option>
                <option value="denial_of_service">DoS</option>
                <option value="insider_threat">Insider Threat</option>
                <option value="ransomware">Ransomware</option>
                <option value="advanced_persistent_threat">APT</option>
                <option value="other">Other</option>
              </select>
            </div>
          </div>
          {availableAlerts.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Link Alerts ({formData.alert_ids.length} selected)
              </label>
              <div className="max-h-40 overflow-y-auto border border-gray-200 dark:border-gray-700 rounded-lg p-2 space-y-1">
                {availableAlerts.map((a) => (
                  <label
                    key={a.id}
                    className="flex items-center gap-2 p-2 rounded hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={formData.alert_ids.includes(a.id)}
                      onChange={() => toggleAlert(a.id)}
                      className="rounded border-gray-300"
                    />
                    <span className="text-sm text-gray-700 dark:text-gray-200 truncate">{a.title}</span>
                    <span className={clsx('ml-auto px-2 py-0.5 rounded text-xs capitalize', severityColors[a.severity] || severityColors.medium)}>
                      {a.severity}
                    </span>
                  </label>
                ))}
              </div>
            </div>
          )}
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 inline-flex items-center gap-2"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
              {loading ? 'Creating…' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
