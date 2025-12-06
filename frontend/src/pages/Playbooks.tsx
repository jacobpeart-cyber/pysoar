import { useState, useEffect } from 'react'
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
} from 'lucide-react'
import clsx from 'clsx'

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
  failed: 'bg-red-100 text-red-700',
  cancelled: 'bg-yellow-100 text-yellow-700',
  paused: 'bg-purple-100 text-purple-700',
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
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null)
  const [showExecuteModal, setShowExecuteModal] = useState(false)
  const [executePlaybook, setExecutePlaybook] = useState<Playbook | null>(null)
  const [filters, setFilters] = useState({ status: '', trigger_type: '' })

  const fetchPlaybooks = async () => {
    setIsLoading(true)
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
      console.error('Failed to fetch playbooks:', error)
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
      console.error('Failed to delete playbook:', error)
    }
  }

  const handleExecute = (playbook: Playbook) => {
    setExecutePlaybook(playbook)
    setShowExecuteModal(true)
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    try {
      await playbooksApi.create(formData)
      onCreated()
    } catch (error) {
      console.error('Failed to create playbook:', error)
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
                      <option value="enrich_ip">Enrich IP</option>
                      <option value="enrich_domain">Enrich Domain</option>
                      <option value="enrich_hash">Enrich Hash</option>
                      <option value="send_notification">Send Notification</option>
                      <option value="update_alert">Update Alert</option>
                      <option value="create_incident">Create Incident</option>
                      <option value="block_ip">Block IP</option>
                      <option value="run_script">Run Script</option>
                      <option value="wait">Wait</option>
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

  useEffect(() => {
    const fetchExecutions = async () => {
      try {
        const response = await playbooksApi.getExecutions(playbook.id)
        setExecutions(response.items || [])
      } catch (error) {
        console.error('Failed to fetch executions:', error)
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
            ) : executions.length === 0 ? (
              <p className="text-gray-500 text-sm py-4">No executions yet</p>
            ) : (
              <div className="space-y-2">
                {executions.slice(0, 5).map((exec) => (
                  <div key={exec.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                    <div className="flex items-center space-x-3">
                      {exec.status === 'completed' && <CheckCircle className="w-5 h-5 text-green-500" />}
                      {exec.status === 'failed' && <XCircle className="w-5 h-5 text-red-500" />}
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
                    <div className="text-xs text-gray-500">
                      {new Date(exec.created_at).toLocaleString()}
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
              <p className="text-gray-900">{new Date(playbook.created_at).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-gray-500">Updated</p>
              <p className="text-gray-900">{new Date(playbook.updated_at).toLocaleString()}</p>
            </div>
          </div>
        </div>
      </div>
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

  const handleExecute = async () => {
    setIsSubmitting(true)
    try {
      let parsedInput = {}
      if (inputData.trim()) {
        try {
          parsedInput = JSON.parse(inputData)
        } catch {
          alert('Invalid JSON input')
          setIsSubmitting(false)
          return
        }
      }
      const execution = await playbooksApi.execute(playbook.id, { input_data: parsedInput })
      setResult(execution)
    } catch (error) {
      console.error('Failed to execute playbook:', error)
      alert('Failed to execute playbook')
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
      <div className="bg-white rounded-xl shadow-xl w-full max-w-lg mx-4">
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
                  {(result.status === 'running' || result.status === 'pending') && (
                    <Clock className="w-5 h-5 text-blue-500 animate-pulse" />
                  )}
                  <span className="font-medium capitalize">{result.status}</span>
                </div>
                <p className="text-sm text-gray-500">Execution ID: {result.id}</p>
                {result.error_message && (
                  <p className="text-sm text-red-600 mt-2">{result.error_message}</p>
                )}
              </div>
              <div className="flex justify-end">
                <button
                  onClick={onExecuted}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
                >
                  Done
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
