import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { playbooksApi } from '../lib/api'
import type { Playbook, PlaybookExecution } from '../lib/types'
import {
  Plus,
  Search,
  Eye,
  Trash2,
  X,
  ChevronLeft,
  ChevronRight,
  Play,
  Pause,
  CheckCircle,
  XCircle,
  Clock,
  Zap,
  Edit,
  Copy,
  AlertTriangle,
} from 'lucide-react'
import clsx from 'clsx'
import LoadErrorBanner from '../components/LoadErrorBanner'
import { describeLoadError } from '../lib/loadError'
import ActionErrorBanner from '../components/ActionErrorBanner'

const statusColors: Record<string, string> = {
  draft: 'bg-gray-100 text-gray-700',
  active: 'bg-green-100 text-green-700',
  disabled: 'bg-yellow-100 text-yellow-700',
  archived: 'bg-red-100 text-red-700',
}

const executionStatusColors: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700',
  running: 'bg-blue-100 text-blue-700',
  completed: 'bg-green-100 text-green-700',
  partial: 'bg-amber-100 text-amber-800',
  failed: 'bg-red-100 text-red-700',
  cancelled: 'bg-yellow-100 text-yellow-700',
  paused: 'bg-purple-100 text-purple-700',
}

/** Run statuses after which an execution no longer changes. */
const TERMINAL_RUN_STATUSES = new Set(['completed', 'partial', 'failed', 'cancelled'])

const PARTIAL_EXPLANATION =
  'Partial: every step ran, but at least one did not complete. It is waiting on an integration, ' +
  'queued for approval, needs a manual action, or failed with continue-on-error. Only steps ' +
  'marked Completed actually happened.'

const stepStatusStyles: Record<string, { label: string; className: string }> = {
  completed: { label: 'Completed', className: 'bg-green-100 text-green-700' },
  failed: { label: 'Failed', className: 'bg-red-100 text-red-700' },
  awaiting_integration: { label: 'Awaiting integration', className: 'bg-amber-100 text-amber-800' },
  manual_required: { label: 'Manual action required', className: 'bg-amber-100 text-amber-800' },
  queued_for_approval: { label: 'Queued for approval', className: 'bg-blue-100 text-blue-700' },
  skipped: { label: 'Skipped', className: 'bg-gray-100 text-gray-600' },
}

/**
 * Step types the backend executes (src/services/playbook_engine.py
 * SUPPORTED_ACTIONS). `run_script` was removed server-side and is not
 * offered; the server still rejects anything unknown with 422 invalid_steps.
 */
const STEP_ACTION_OPTIONS: { value: string; label: string }[] = [
  { value: 'enrich_ip', label: 'Enrich IP' },
  { value: 'enrich_domain', label: 'Enrich Domain' },
  { value: 'enrich_hash', label: 'Enrich Hash' },
  { value: 'send_notification', label: 'Send Notification' },
  { value: 'create_ticket', label: 'Create Ticket' },
  { value: 'update_alert', label: 'Update Alert' },
  { value: 'update_incident', label: 'Update Incident' },
  { value: 'create_incident', label: 'Create Incident' },
  { value: 'add_comment', label: 'Add Comment' },
  { value: 'assign_to', label: 'Assign To' },
  { value: 'block_ip', label: 'Block IP (admin)' },
  { value: 'isolate_host', label: 'Isolate Host (admin)' },
  { value: 'disable_user', label: 'Disable User (admin)' },
  { value: 'quarantine_file', label: 'Quarantine File (admin)' },
  { value: 'wait', label: 'Wait' },
]

function formatTime(value: unknown): string {
  if (!value || typeof value !== 'string') return 'not available'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString()
}

const triggerTypeLabels: Record<string, string> = {
  manual: 'Manual',
  alert: 'On Alert',
  incident: 'On Incident',
  schedule: 'Scheduled',
  webhook: 'Webhook',
}

export default function Playbooks() {
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [isLoading, setIsLoading] = useState(true)
  const [loadError, setLoadError] = useState<unknown>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null)
  const [showExecuteModal, setShowExecuteModal] = useState(false)
  const [executePlaybook, setExecutePlaybook] = useState<Playbook | null>(null)
  const [filters, setFilters] = useState({ status: '', trigger_type: '' })

  const fetchPlaybooks = async () => {
    setIsLoading(true)
    setLoadError(null)
    try {
      const response = await playbooksApi.list({
        page,
        size: 10,
        ...(filters.status && { status: filters.status }),
        ...(filters.trigger_type && { trigger_type: filters.trigger_type }),
      })
      setPlaybooks(response.items || [])
      setTotal(response.total || 0)
    } catch (error) {
      setLoadError(error)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchPlaybooks()
  }, [page, filters])

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this playbook?')) return
    try {
      await playbooksApi.delete(id)
      fetchPlaybooks()
    } catch (error) {
      alert(`Delete failed: ${describeLoadError(error)}`)
    }
  }

  const handleExecute = (playbook: Playbook) => {
    setExecutePlaybook(playbook)
    setShowExecuteModal(true)
  }

  const handlePublish = async (id: string) => {
    try {
      await playbooksApi.update(id, { status: 'active', is_enabled: true })
      fetchPlaybooks()
    } catch (error) {
      alert(`Publish failed: ${describeLoadError(error)}`)
    }
  }

  const handleArchive = async (id: string) => {
    try {
      await playbooksApi.update(id, { status: 'draft' })
      fetchPlaybooks()
    } catch (error) {
      alert(`Archive failed: ${describeLoadError(error)}`)
    }
  }

  const totalPages = Math.ceil(total / 10)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Playbooks</h1>
          <p className="text-gray-500 mt-1">Automate incident response with playbooks</p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus className="w-5 h-5 mr-2" />
          New Playbook
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl border border-gray-200 p-4">
        <div className="flex flex-wrap gap-4">
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
            <select
              value={filters.status}
              onChange={(e) => setFilters({ ...filters, status: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="">All Statuses</option>
              <option value="draft">Draft</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
              <option value="archived">Archived</option>
            </select>
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-sm font-medium text-gray-700 mb-1">Trigger Type</label>
            <select
              value={filters.trigger_type}
              onChange={(e) => setFilters({ ...filters, trigger_type: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="">All Triggers</option>
              <option value="manual">Manual</option>
              <option value="alert">On Alert</option>
              <option value="incident">On Incident</option>
              <option value="schedule">Scheduled</option>
              <option value="webhook">Webhook</option>
            </select>
          </div>
        </div>
      </div>

      {/* Playbooks Grid */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        ) : loadError ? (
          <div className="p-4">
            <LoadErrorBanner what="playbooks" error={loadError} />
          </div>
        ) : playbooks.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-gray-500">
            <Zap className="w-12 h-12 mb-4 text-gray-300" />
            <p>No playbooks found</p>
            <button
              onClick={() => setShowCreateModal(true)}
              className="mt-4 text-blue-600 hover:text-blue-700"
            >
              Create your first playbook
            </button>
          </div>
        ) : (
          <div className="divide-y divide-gray-100">
            {playbooks.map((playbook) => (
              <div key={playbook.id} className="p-6 hover:bg-gray-50">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <h3 className="text-lg font-medium text-gray-900">{playbook.name}</h3>
                      <span
                        className={clsx(
                          'px-2 py-1 text-xs font-medium rounded-full capitalize',
                          statusColors[playbook.status] || statusColors.draft
                        )}
                      >
                        {playbook.status}
                      </span>
                    </div>
                    {playbook.description && (
                      <p className="text-gray-500 mt-1 text-sm">{playbook.description}</p>
                    )}
                    <div className="flex items-center space-x-4 mt-3 text-sm text-gray-500">
                      <span className="flex items-center">
                        <Zap className="w-4 h-4 mr-1" />
                        {triggerTypeLabels[playbook.trigger_type] || playbook.trigger_type}
                      </span>
                      <span className="flex items-center">
                        <Clock className="w-4 h-4 mr-1" />
                        {playbook.steps?.length || 0} steps
                      </span>
                      {playbook.category && (
                        <span className="px-2 py-0.5 bg-gray-100 rounded text-gray-600">
                          {playbook.category}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center space-x-2 ml-4">
                    {playbook.status === 'active' && (
                      <button
                        onClick={() => handleExecute(playbook)}
                        className="flex items-center px-3 py-1.5 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm"
                        title="Execute playbook"
                      >
                        <Play className="w-4 h-4 mr-1" />
                        Run
                      </button>
                    )}
                    {/* Draft → Active toggle. Previously there was no
                        UI way to activate a draft, and the executor
                        rejected non-active playbooks — so every
                        playbook a user created was permanently
                        unrunnable. */}
                    {playbook.status !== 'active' && (
                      <button
                        onClick={() => handlePublish(playbook.id)}
                        className="flex items-center px-3 py-1.5 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
                        title="Publish playbook (draft → active)"
                      >
                        Publish
                      </button>
                    )}
                    {playbook.status === 'active' && (
                      <button
                        onClick={() => handleArchive(playbook.id)}
                        className="flex items-center px-3 py-1.5 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 text-sm"
                        title="Archive playbook (active → draft)"
                      >
                        Archive
                      </button>
                    )}
                    <button
                      onClick={() => setSelectedPlaybook(playbook)}
                      className="p-2 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg"
                      title="View details"
                    >
                      <Eye className="w-5 h-5" />
                    </button>
                    <button
                      onClick={() => handleDelete(playbook.id)}
                      className="p-2 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg"
                      title="Delete"
                    >
                      <Trash2 className="w-5 h-5" />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between">
            <p className="text-sm text-gray-500">
              Showing {(page - 1) * 10 + 1} to {Math.min(page * 10, total)} of {total} playbooks
            </p>
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setPage(page - 1)}
                disabled={page === 1}
                className="p-2 border border-gray-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
              >
                <ChevronLeft className="w-5 h-5" />
              </button>
              <span className="text-sm text-gray-700">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage(page + 1)}
                disabled={page === totalPages}
                className="p-2 border border-gray-300 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50"
              >
                <ChevronRight className="w-5 h-5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Create Playbook Modal */}
      {showCreateModal && (
        <CreatePlaybookModal
          onClose={() => setShowCreateModal(false)}
          onCreated={() => {
            setShowCreateModal(false)
            fetchPlaybooks()
          }}
        />
      )}

      {/* Playbook Details Modal */}
      {selectedPlaybook && (
        <PlaybookDetailsModal
          playbook={selectedPlaybook}
          onClose={() => setSelectedPlaybook(null)}
        />
      )}

      {/* Execute Playbook Modal */}
      {showExecuteModal && executePlaybook && (
        <ExecutePlaybookModal
          playbook={executePlaybook}
          onClose={() => {
            setShowExecuteModal(false)
            setExecutePlaybook(null)
          }}
          onExecuted={() => {
            setShowExecuteModal(false)
            setExecutePlaybook(null)
          }}
        />
      )}
    </div>
  )
}

function CreatePlaybookModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    trigger_type: 'manual',
    category: '',
    steps: [{ id: 'step_1', name: 'Step 1', action: 'send_notification', parameters: {} }],
  })
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [submitError, setSubmitError] = useState<unknown>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!formData.name.trim()) { setError('Name is required'); return; }
    setIsSubmitting(true)
    setError('')
    setSubmitError(null)
    try {
      await playbooksApi.create(formData)
      onCreated()
    } catch (err) {
      // 422 invalid_steps lists each rejected step with the server's reason.
      setSubmitError(err)
    } finally {
      setIsSubmitting(false)
    }
  }

  const addStep = () => {
    const stepNum = formData.steps.length + 1
    setFormData({
      ...formData,
      steps: [
        ...formData.steps,
        { id: `step_${stepNum}`, name: `Step ${stepNum}`, action: 'send_notification', parameters: {} },
      ],
    })
  }

  const removeStep = (index: number) => {
    if (formData.steps.length <= 1) return
    setFormData({
      ...formData,
      steps: formData.steps.filter((_, i) => i !== index),
    })
  }

  const updateStep = (index: number, field: string, value: string) => {
    const newSteps = [...formData.steps]
    newSteps[index] = { ...newSteps[index], [field]: value }
    setFormData({ ...formData, steps: newSteps })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
          <h2 className="text-lg font-semibold text-gray-900">Create New Playbook</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-5 h-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Name *</label>
            <input
              type="text"
              required
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="e.g., IP Enrichment Playbook"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
            <textarea
              rows={2}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="What does this playbook do?"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Trigger Type *</label>
              <select
                required
                value={formData.trigger_type}
                onChange={(e) => setFormData({ ...formData, trigger_type: e.target.value })}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="manual">Manual</option>
                <option value="alert">On Alert</option>
                <option value="incident">On Incident</option>
                <option value="schedule">Scheduled</option>
                <option value="webhook">Webhook</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Category</label>
              <input
                type="text"
                value={formData.category}
                onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                placeholder="e.g., Enrichment, Response"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>

          {/* Steps */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-gray-700">Steps</label>
              <button
                type="button"
                onClick={addStep}
                className="text-sm text-blue-600 hover:text-blue-700"
              >
                + Add Step
              </button>
            </div>
            <div className="space-y-3">
              {formData.steps.map((step, index) => (
                <div key={index} className="flex items-start space-x-3 p-3 bg-gray-50 rounded-lg">
                  <div className="flex-shrink-0 w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center text-xs">
                    {index + 1}
                  </div>
                  <div className="flex-1 grid grid-cols-2 gap-3">
                    <input
                      type="text"
                      value={step.name}
                      onChange={(e) => updateStep(index, 'name', e.target.value)}
                      placeholder="Step name"
                      className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                    <select
                      value={step.action}
                      onChange={(e) => updateStep(index, 'action', e.target.value)}
                      className="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    >
                      {STEP_ACTION_OPTIONS.map((o) => (
                        <option key={o.value} value={o.value}>{o.label}</option>
                      ))}
                    </select>
                  </div>
                  {formData.steps.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeStep(index)}
                      className="text-gray-400 hover:text-red-600"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>

          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">{error}</div>
          )}
          <ActionErrorBanner what="create the playbook" error={submitError} />
          <div className="flex justify-end space-x-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
            >
              {isSubmitting ? 'Creating...' : 'Create Playbook'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function PlaybookDetailsModal({ playbook, onClose }: { playbook: Playbook; onClose: () => void }) {
  const [executions, setExecutions] = useState<PlaybookExecution[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [executionsError, setExecutionsError] = useState<unknown>(null)

  useEffect(() => {
    const fetchExecutions = async () => {
      try {
        const response = await playbooksApi.getExecutions(playbook.id)
        setExecutions(response.items || [])
      } catch (error) {
        setExecutionsError(error)
      } finally {
        setIsLoading(false)
      }
    }
    fetchExecutions()
  }, [playbook.id])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-3xl mx-4 max-h-[85vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 sticky top-0 bg-white">
          <h2 className="text-lg font-semibold text-gray-900">Playbook Details</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6 space-y-6">
          {/* Header Info */}
          <div>
            <div className="flex items-center space-x-3">
              <h3 className="text-xl font-semibold text-gray-900">{playbook.name}</h3>
              <span
                className={clsx(
                  'px-2 py-1 text-xs font-medium rounded-full capitalize',
                  statusColors[playbook.status]
                )}
              >
                {playbook.status}
              </span>
            </div>
            {playbook.description && (
              <p className="text-gray-500 mt-2">{playbook.description}</p>
            )}
          </div>

          {/* Details Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gray-50 rounded-lg p-3">
              <p className="text-xs text-gray-500">Trigger</p>
              <p className="text-sm font-medium text-gray-900 capitalize">{playbook.trigger_type}</p>
            </div>
            <div className="bg-gray-50 rounded-lg p-3">
              <p className="text-xs text-gray-500">Steps</p>
              <p className="text-sm font-medium text-gray-900">{playbook.steps?.length || 0}</p>
            </div>
            <div className="bg-gray-50 rounded-lg p-3">
              <p className="text-xs text-gray-500">Version</p>
              <p className="text-sm font-medium text-gray-900">{playbook.version}</p>
            </div>
            <div className="bg-gray-50 rounded-lg p-3">
              <p className="text-xs text-gray-500">Category</p>
              <p className="text-sm font-medium text-gray-900">{playbook.category || 'N/A'}</p>
            </div>
          </div>

          {/* Steps */}
          <div>
            <h4 className="font-medium text-gray-900 mb-3">Workflow Steps</h4>
            <div className="space-y-2">
              {playbook.steps?.map((step, index) => (
                <div key={step.id} className="flex items-center space-x-3 p-3 bg-gray-50 rounded-lg">
                  <div className="flex-shrink-0 w-6 h-6 bg-blue-600 text-white rounded-full flex items-center justify-center text-xs">
                    {index + 1}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-900">{step.name}</p>
                    <p className="text-xs text-gray-500">Action: {step.action}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recent Executions */}
          <div>
            <h4 className="font-medium text-gray-900 mb-3">Recent Executions</h4>
            {isLoading ? (
              <div className="flex items-center justify-center py-8">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
              </div>
            ) : executionsError ? (
              <LoadErrorBanner what="recent executions" error={executionsError} />
            ) : executions.length === 0 ? (
              <p className="text-gray-500 text-sm py-4">No executions yet</p>
            ) : (
              <div className="space-y-2">
                {executions.slice(0, 5).map((exec) => (
                  <div key={exec.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      {exec.status === 'completed' && <CheckCircle className="w-5 h-5 text-green-500" />}
                      {exec.status === 'failed' && <XCircle className="w-5 h-5 text-red-500" />}
                      {exec.status === 'partial' && <AlertTriangle className="w-5 h-5 text-amber-500" />}
                      {exec.status === 'running' && <Clock className="w-5 h-5 text-blue-500 animate-pulse" />}
                      {exec.status === 'pending' && <Clock className="w-5 h-5 text-gray-400" />}
                      <span
                        className={clsx(
                          'px-2 py-0.5 text-xs font-medium rounded-full capitalize',
                          executionStatusColors[exec.status]
                        )}
                      >
                        {exec.status}
                      </span>
                    </div>
                    <div className="text-xs text-gray-500 text-right">
                      <div>{formatTime(exec.created_at)}</div>
                      {exec.step_summary && (
                        <div>
                          {Object.entries(exec.step_summary)
                            .map(([k, v]) => `${v} ${stepStatusStyles[k]?.label.toLowerCase() ?? k}`)
                            .join(' · ')}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-gray-500">Created</p>
              <p className="text-gray-900">{new Date(playbook.created_at || "").toLocaleString()}</p>
            </div>
            <div>
              <p className="text-gray-500">Updated</p>
              <p className="text-gray-900">{new Date(playbook.updated_at || "").toLocaleString()}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function StepResultRow({ step }: { step: Record<string, any> }) {
  const status = String(step.status || 'not available')
  const style = stepStatusStyles[status] ?? { label: status, className: 'bg-gray-100 text-gray-700' }
  const details = (step.result && typeof step.result === 'object' ? step.result.details : null) || {}
  const commandId = typeof details.command_id === 'string' ? details.command_id : null
  return (
    <div className="p-3 bg-gray-50 rounded-lg">
      <div className="flex items-center justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-medium text-gray-900 truncate">
            {step.step ?? '?'}. {step.name || 'Unnamed step'}
          </p>
          <p className="text-xs text-gray-500">Action: {step.action || 'not available'}</p>
        </div>
        <span className={clsx('px-2 py-0.5 text-xs font-medium rounded-full whitespace-nowrap', style.className)}>
          {style.label}
        </span>
      </div>
      {(status === 'awaiting_integration' || status === 'manual_required') && (
        <p className="text-xs text-amber-800 mt-2">
          {status === 'awaiting_integration' ? 'Missing dependency: ' : 'Operator action needed: '}
          {step.missing_dependency || 'not available'}
        </p>
      )}
      {status === 'queued_for_approval' && (
        <p className="text-xs text-blue-700 mt-2">
          Not executed yet: the command waits in the{' '}
          <Link to="/live-response" className="underline font-medium">
            agent approval queue
          </Link>
          {commandId ? ` (command ${commandId})` : ''}.
        </p>
      )}
      {status === 'failed' && (
        <p className="text-xs text-red-700 mt-2">Error: {step.error || 'not available'}</p>
      )}
      <p className="text-[11px] text-gray-400 mt-1">
        Started {formatTime(step.started_at)} · Finished {formatTime(step.finished_at)}
      </p>
    </div>
  )
}

function ExecutePlaybookModal({
  playbook,
  onClose,
  onExecuted,
}: {
  playbook: Playbook
  onClose: () => void
  onExecuted: () => void
}) {
  const [inputData, setInputData] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [result, setResult] = useState<PlaybookExecution | null>(null)
  const [inputError, setInputError] = useState<string | null>(null)
  const [execError, setExecError] = useState<unknown>(null)
  const [pollError, setPollError] = useState<unknown>(null)
  const [pollNonce, setPollNonce] = useState(0)

  const isTerminal = result ? TERMINAL_RUN_STATUSES.has(result.status) : false

  // Poll the execution until it reaches a terminal status.
  useEffect(() => {
    if (!result || isTerminal || pollError) return
    let cancelled = false
    const timer = window.setTimeout(async () => {
      try {
        const next = await playbooksApi.getExecution(playbook.id, result.id)
        if (!cancelled) setResult(next)
      } catch (err) {
        if (!cancelled) setPollError(err)
      }
    }, 2000)
    return () => {
      cancelled = true
      window.clearTimeout(timer)
    }
  }, [result, isTerminal, pollError, pollNonce, playbook.id])

  const handleExecute = async () => {
    setIsSubmitting(true)
    setExecError(null)
    setInputError(null)
    try {
      let parsedInput = {}
      if (inputData.trim()) {
        try {
          parsedInput = JSON.parse(inputData)
        } catch {
          setInputError('Input data is not valid JSON.')
          setIsSubmitting(false)
          return
        }
      }
      const execution = await playbooksApi.execute(playbook.id, { input_data: parsedInput })
      setResult(execution)
    } catch (error) {
      // 403 containment_requires_admin is shown as the server sent it.
      setExecError(error)
    } finally {
      setIsSubmitting(false)
    }
  }

  const steps: Record<string, any>[] = Array.isArray(result?.step_results) ? result.step_results : []

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Execute Playbook</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6 space-y-4">
          <div className="bg-blue-50 rounded-lg p-4">
            <h3 className="font-medium text-blue-900">{playbook.name}</h3>
            <p className="text-sm text-blue-700 mt-1">{playbook.steps?.length || 0} steps</p>
          </div>

          {!result ? (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Input Data (JSON, optional)
                </label>
                <textarea
                  rows={4}
                  value={inputData}
                  onChange={(e) => setInputData(e.target.value)}
                  placeholder='{"key": "value"}'
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              {inputError && (
                <div role="alert" className="text-sm text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
                  {inputError}
                </div>
              )}
              <ActionErrorBanner what="execute the playbook" error={execError} />

              <div className="flex justify-end space-x-3">
                <button
                  onClick={onClose}
                  className="px-4 py-2 border border-gray-300 rounded-lg text-gray-700 hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleExecute}
                  disabled={isSubmitting}
                  className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
                >
                  <Play className="w-4 h-4 mr-2" />
                  {isSubmitting ? 'Executing...' : 'Execute'}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="bg-gray-50 rounded-lg p-4">
                <div className="flex items-center space-x-2 mb-2">
                  {result.status === 'completed' && <CheckCircle className="w-5 h-5 text-green-500" />}
                  {result.status === 'failed' && <XCircle className="w-5 h-5 text-red-500" />}
                  {result.status === 'partial' && <AlertTriangle className="w-5 h-5 text-amber-500" />}
                  {!isTerminal && <Clock className="w-5 h-5 text-blue-500 animate-pulse" />}
                  <span
                    className={clsx(
                      'px-2 py-0.5 text-xs font-medium rounded-full capitalize',
                      executionStatusColors[result.status] || 'bg-gray-100 text-gray-700'
                    )}
                  >
                    {result.status || 'not available'}
                  </span>
                  {!isTerminal && !pollError && (
                    <span className="text-xs text-gray-500">
                      step {result.current_step || 0} of {result.total_steps || 0}, polling...
                    </span>
                  )}
                </div>
                <p className="text-sm text-gray-500">Execution ID: {result.id}</p>
                <p className="text-xs text-gray-500 mt-1">
                  Started {formatTime(result.started_at)} · Finished {formatTime(result.completed_at)}
                </p>
                {result.status === 'partial' && (
                  <p className="text-sm text-amber-800 mt-2">{PARTIAL_EXPLANATION}</p>
                )}
                {result.error_message && (
                  <p className="text-sm text-red-600 mt-2">{result.error_message}</p>
                )}
              </div>

              {pollError ? (
                <div className="space-y-2">
                  <LoadErrorBanner what="the execution status" error={pollError} />
                  <button
                    onClick={() => {
                      setPollError(null)
                      setPollNonce((n) => n + 1)
                    }}
                    className="text-sm text-blue-600 hover:text-blue-700"
                  >
                    Retry polling
                  </button>
                </div>
              ) : null}

              <div>
                <h4 className="text-sm font-medium text-gray-900 mb-2">Steps</h4>
                {steps.length === 0 ? (
                  <p className="text-sm text-gray-500">
                    {isTerminal ? 'No step results were recorded.' : 'No step has finished yet.'}
                  </p>
                ) : (
                  <div className="space-y-2">
                    {steps.map((step, i) => (
                      <StepResultRow key={`${step.step ?? i}-${i}`} step={step} />
                    ))}
                  </div>
                )}
              </div>

              <div className="flex justify-end">
                <button
                  onClick={onExecuted}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  {isTerminal ? 'Done' : 'Close (run continues)'}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
