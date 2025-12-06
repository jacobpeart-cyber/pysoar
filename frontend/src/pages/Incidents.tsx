import { useState, useEffect } from 'react'
import { incidentsApi, alertsApi, Incident, Alert } from '../lib/api'
import {
  Plus,
  Search,
  Filter,
  Eye,
  Trash2,
  X,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Link as LinkIcon
} from 'lucide-react'
import { format } from 'date-fns'
import clsx from 'clsx'

const statusColors: Record<string, string> = {
  new: 'bg-blue-100 text-blue-800',
  investigating: 'bg-yellow-100 text-yellow-800',
  containment: 'bg-orange-100 text-orange-800',
  eradication: 'bg-purple-100 text-purple-800',
  recovery: 'bg-indigo-100 text-indigo-800',
  closed: 'bg-green-100 text-green-800',
}

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800',
  high: 'bg-orange-100 text-orange-800',
  medium: 'bg-yellow-100 text-yellow-800',
  low: 'bg-blue-100 text-blue-800',
  informational: 'bg-gray-100 text-gray-800',
}

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [search, setSearch] = useState('')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showDetailsModal, setShowDetailsModal] = useState(false)
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null)
  const [availableAlerts, setAvailableAlerts] = useState<Alert[]>([])
  const pageSize = 10

  const fetchIncidents = async () => {
    setLoading(true)
    try {
      const params: Record<string, any> = { page, size: pageSize }
      if (statusFilter) params.status = statusFilter
      if (severityFilter) params.severity = severityFilter
      const response = await incidentsApi.list(params)
      setIncidents(response.data.items)
      setTotal(response.data.total)
    } catch (error) {
      console.error('Failed to fetch incidents:', error)
    } finally {
      setLoading(false)
    }
  }

  const fetchAvailableAlerts = async () => {
    try {
      const response = await alertsApi.list({ size: 100 })
      setAvailableAlerts(response.data.items)
    } catch (error) {
      console.error('Failed to fetch alerts:', error)
    }
  }

  useEffect(() => {
    fetchIncidents()
  }, [page, statusFilter, severityFilter])

  useEffect(() => {
    if (showCreateModal) {
      fetchAvailableAlerts()
    }
  }, [showCreateModal])

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this incident?')) return
    try {
      await incidentsApi.delete(id)
      fetchIncidents()
    } catch (error) {
      console.error('Failed to delete incident:', error)
    }
  }

  const handleViewDetails = (incident: Incident) => {
    setSelectedIncident(incident)
    setShowDetailsModal(true)
  }

  const totalPages = Math.ceil(total / pageSize)

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Incidents</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 transition-colors"
        >
          <Plus className="w-5 h-5" />
          New Incident
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 mb-6">
        <div className="flex flex-wrap gap-4">
          <div className="flex items-center gap-2 flex-1 min-w-[200px]">
            <Search className="w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search incidents..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="flex-1 border-0 focus:ring-0 text-sm"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="border border-gray-300 rounded-md text-sm px-3 py-1.5"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="border border-gray-300 rounded-md text-sm px-3 py-1.5"
            >
              <option value="">All Statuses</option>
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="containment">Containment</option>
              <option value="eradication">Eradication</option>
              <option value="recovery">Recovery</option>
              <option value="closed">Closed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Title
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Severity
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Alerts
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Created
              </th>
              <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {loading ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                  Loading...
                </td>
              </tr>
            ) : incidents.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                  No incidents found
                </td>
              </tr>
            ) : (
              incidents.map((incident) => (
                <tr key={incident.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="text-sm font-medium text-gray-900">
                      {incident.title}
                    </div>
                    <div className="text-sm text-gray-500 truncate max-w-xs">
                      {incident.description}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={clsx(
                        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                        severityColors[incident.severity]
                      )}
                    >
                      {incident.severity}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={clsx(
                        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                        statusColors[incident.status]
                      )}
                    >
                      {incident.status}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div className="flex items-center gap-1">
                      <AlertTriangle className="w-4 h-4" />
                      {incident.alert_count || 0}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {format(new Date(incident.created_at), 'MMM d, yyyy HH:mm')}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => handleViewDetails(incident)}
                      className="text-primary-600 hover:text-primary-900 mr-3"
                    >
                      <Eye className="w-5 h-5" />
                    </button>
                    <button
                      onClick={() => handleDelete(incident.id)}
                      className="text-red-600 hover:text-red-900"
                    >
                      <Trash2 className="w-5 h-5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="bg-white px-4 py-3 flex items-center justify-between border-t border-gray-200">
            <div className="text-sm text-gray-700">
              Showing {(page - 1) * pageSize + 1} to{' '}
              {Math.min(page * pageSize, total)} of {total} results
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setPage(page - 1)}
                disabled={page === 1}
                className="px-3 py-1 border border-gray-300 rounded-md text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
              >
                <ChevronLeft className="w-5 h-5" />
              </button>
              <button
                onClick={() => setPage(page + 1)}
                disabled={page === totalPages}
                className="px-3 py-1 border border-gray-300 rounded-md text-sm disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
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
            setShowCreateModal(false)
            fetchIncidents()
          }}
          availableAlerts={availableAlerts}
        />
      )}

      {/* Details Modal */}
      {showDetailsModal && selectedIncident && (
        <IncidentDetailsModal
          incident={selectedIncident}
          onClose={() => {
            setShowDetailsModal(false)
            setSelectedIncident(null)
          }}
          onUpdated={() => {
            fetchIncidents()
          }}
        />
      )}
    </div>
  )
}

function CreateIncidentModal({
  onClose,
  onCreated,
  availableAlerts,
}: {
  onClose: () => void
  onCreated: () => void
  availableAlerts: Alert[]
}) {
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    severity: 'medium',
    alert_ids: [] as string[],
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      await incidentsApi.create(formData)
      onCreated()
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to create incident')
    } finally {
      setLoading(false)
    }
  }

  const toggleAlert = (alertId: string) => {
    setFormData((prev) => ({
      ...prev,
      alert_ids: prev.alert_ids.includes(alertId)
        ? prev.alert_ids.filter((id) => id !== alertId)
        : [...prev.alert_ids, alertId],
    }))
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold">Create New Incident</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-5 h-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {error && (
            <div className="bg-red-50 text-red-700 p-3 rounded-lg text-sm">
              {error}
            </div>
          )}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Title
            </label>
            <input
              type="text"
              value={formData.title}
              onChange={(e) =>
                setFormData({ ...formData, title: e.target.value })
              }
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Description
            </label>
            <textarea
              value={formData.description}
              onChange={(e) =>
                setFormData({ ...formData, description: e.target.value })
              }
              rows={3}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Severity
            </label>
            <select
              value={formData.severity}
              onChange={(e) =>
                setFormData({ ...formData, severity: e.target.value })
              }
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Link Alerts (Optional)
            </label>
            <div className="border border-gray-300 rounded-lg max-h-48 overflow-y-auto">
              {availableAlerts.length === 0 ? (
                <div className="p-3 text-sm text-gray-500">No alerts available</div>
              ) : (
                availableAlerts.map((alert) => (
                  <label
                    key={alert.id}
                    className="flex items-center gap-3 p-3 hover:bg-gray-50 cursor-pointer border-b last:border-b-0"
                  >
                    <input
                      type="checkbox"
                      checked={formData.alert_ids.includes(alert.id)}
                      onChange={() => toggleAlert(alert.id)}
                      className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                    />
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-gray-900 truncate">
                        {alert.title}
                      </div>
                      <div className="text-xs text-gray-500">
                        {alert.severity} - {alert.source}
                      </div>
                    </div>
                  </label>
                ))
              )}
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50"
            >
              {loading ? 'Creating...' : 'Create Incident'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function IncidentDetailsModal({
  incident,
  onClose,
  onUpdated,
}: {
  incident: Incident
  onClose: () => void
  onUpdated: () => void
}) {
  const [status, setStatus] = useState(incident.status)
  const [loading, setLoading] = useState(false)

  const handleStatusChange = async (newStatus: string) => {
    setLoading(true)
    try {
      await incidentsApi.update(incident.id, { status: newStatus })
      setStatus(newStatus)
      onUpdated()
    } catch (error) {
      console.error('Failed to update status:', error)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold">Incident Details</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div>
            <h3 className="text-xl font-semibold text-gray-900">{incident.title}</h3>
            <p className="text-gray-600 mt-1">{incident.description}</p>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-500">Severity</label>
              <span
                className={clsx(
                  'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium mt-1',
                  severityColors[incident.severity]
                )}
              >
                {incident.severity}
              </span>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-1">Status</label>
              <select
                value={status}
                onChange={(e) => handleStatusChange(e.target.value)}
                disabled={loading}
                className="border border-gray-300 rounded-md text-sm px-3 py-1.5 disabled:opacity-50"
              >
                <option value="new">New</option>
                <option value="investigating">Investigating</option>
                <option value="containment">Containment</option>
                <option value="eradication">Eradication</option>
                <option value="recovery">Recovery</option>
                <option value="closed">Closed</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-500">Created</label>
              <p className="text-sm text-gray-900">
                {format(new Date(incident.created_at), 'MMMM d, yyyy HH:mm')}
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-500">Updated</label>
              <p className="text-sm text-gray-900">
                {format(new Date(incident.updated_at), 'MMMM d, yyyy HH:mm')}
              </p>
            </div>
          </div>

          {incident.alerts && incident.alerts.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-2">
                <LinkIcon className="w-4 h-4 inline mr-1" />
                Linked Alerts ({incident.alerts.length})
              </label>
              <div className="border border-gray-200 rounded-lg divide-y">
                {incident.alerts.map((alert) => (
                  <div key={alert.id} className="p-3 flex items-center justify-between">
                    <div>
                      <div className="text-sm font-medium text-gray-900">{alert.title}</div>
                      <div className="text-xs text-gray-500">{alert.source}</div>
                    </div>
                    <span
                      className={clsx(
                        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
                        severityColors[alert.severity]
                      )}
                    >
                      {alert.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="flex justify-end pt-4">
            <button
              onClick={onClose}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
