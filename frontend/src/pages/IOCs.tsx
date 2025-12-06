import { useState, useEffect } from 'react'
import { iocsApi } from '../lib/api'
import type { IOC } from '../lib/types'
import {
  Plus,
  Search,
  Filter,
  Eye,
  Trash2,
  X,
  ChevronLeft,
  ChevronRight,
  Globe,
  Hash,
  FileText,
  Mail,
  Link as LinkIcon
} from 'lucide-react'
import { format } from 'date-fns'
import clsx from 'clsx'

const typeIcons: Record<string, React.ReactNode> = {
  ip: <Globe className="w-4 h-4" />,
  domain: <Globe className="w-4 h-4" />,
  url: <LinkIcon className="w-4 h-4" />,
  hash: <Hash className="w-4 h-4" />,
  email: <Mail className="w-4 h-4" />,
  file: <FileText className="w-4 h-4" />,
}

const threatLevelColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-200',
  high: 'bg-orange-100 text-orange-800 border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  low: 'bg-blue-100 text-blue-800 border-blue-200',
  unknown: 'bg-gray-100 text-gray-800 border-gray-200',
}

export default function IOCs() {
  const [iocs, setIocs] = useState<IOC[]>([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [typeFilter, setTypeFilter] = useState('')
  const [threatLevelFilter, setThreatLevelFilter] = useState('')
  const [search, setSearch] = useState('')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showDetailsModal, setShowDetailsModal] = useState(false)
  const [selectedIOC, setSelectedIOC] = useState<IOC | null>(null)
  const pageSize = 10

  const fetchIOCs = async () => {
    setLoading(true)
    try {
      const params: Record<string, any> = { page, size: pageSize }
      if (typeFilter) params.ioc_type = typeFilter
      if (threatLevelFilter) params.threat_level = threatLevelFilter
      const response = await iocsApi.list(params)
      setIocs(response.data.items)
      setTotal(response.data.total)
    } catch (error) {
      console.error('Failed to fetch IOCs:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchIOCs()
  }, [page, typeFilter, threatLevelFilter])

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this IOC?')) return
    try {
      await iocsApi.delete(id)
      fetchIOCs()
    } catch (error) {
      console.error('Failed to delete IOC:', error)
    }
  }

  const handleViewDetails = (ioc: IOC) => {
    setSelectedIOC(ioc)
    setShowDetailsModal(true)
  }

  const totalPages = Math.ceil(total / pageSize)

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Indicators of Compromise</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 transition-colors"
        >
          <Plus className="w-5 h-5" />
          Add IOC
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 mb-6">
        <div className="flex flex-wrap gap-4">
          <div className="flex items-center gap-2 flex-1 min-w-[200px]">
            <Search className="w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search IOCs..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="flex-1 border-0 focus:ring-0 text-sm"
            />
          </div>
          <div className="flex items-center gap-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="border border-gray-300 rounded-md text-sm px-3 py-1.5"
            >
              <option value="">All Types</option>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="hash">Hash</option>
              <option value="email">Email</option>
              <option value="file">File</option>
            </select>
            <select
              value={threatLevelFilter}
              onChange={(e) => setThreatLevelFilter(e.target.value)}
              className="border border-gray-300 rounded-md text-sm px-3 py-1.5"
            >
              <option value="">All Threat Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="unknown">Unknown</option>
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
                Type
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Value
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Threat Level
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Source
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                First Seen
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
            ) : iocs.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                  No IOCs found
                </td>
              </tr>
            ) : (
              iocs.map((ioc) => (
                <tr key={ioc.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="flex items-center gap-2">
                      <span className="text-gray-400">
                        {typeIcons[ioc.ioc_type] || <Hash className="w-4 h-4" />}
                      </span>
                      <span className="text-sm font-medium text-gray-900 uppercase">
                        {ioc.ioc_type}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm font-mono text-gray-900 truncate max-w-xs">
                      {ioc.value}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={clsx(
                        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border',
                        threatLevelColors[ioc.threat_level]
                      )}
                    >
                      {ioc.threat_level}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {ioc.source || '-'}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {format(new Date(ioc.first_seen), 'MMM d, yyyy HH:mm')}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => handleViewDetails(ioc)}
                      className="text-primary-600 hover:text-primary-900 mr-3"
                    >
                      <Eye className="w-5 h-5" />
                    </button>
                    <button
                      onClick={() => handleDelete(ioc.id)}
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
        <CreateIOCModal
          onClose={() => setShowCreateModal(false)}
          onCreated={() => {
            setShowCreateModal(false)
            fetchIOCs()
          }}
        />
      )}

      {/* Details Modal */}
      {showDetailsModal && selectedIOC && (
        <IOCDetailsModal
          ioc={selectedIOC}
          onClose={() => {
            setShowDetailsModal(false)
            setSelectedIOC(null)
          }}
        />
      )}
    </div>
  )
}

function CreateIOCModal({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: () => void
}) {
  const [formData, setFormData] = useState({
    ioc_type: 'ip',
    value: '',
    threat_level: 'medium',
    source: '',
    description: '',
    tags: '',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const payload = {
        ...formData,
        tags: formData.tags ? formData.tags.split(',').map((t) => t.trim()) : [],
      }
      await iocsApi.create(payload)
      onCreated()
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to create IOC')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg">
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold">Add New IOC</h2>
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
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Type
              </label>
              <select
                value={formData.ioc_type}
                onChange={(e) =>
                  setFormData({ ...formData, ioc_type: e.target.value })
                }
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              >
                <option value="ip">IP Address</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash">Hash</option>
                <option value="email">Email</option>
                <option value="file">File</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Threat Level
              </label>
              <select
                value={formData.threat_level}
                onChange={(e) =>
                  setFormData({ ...formData, threat_level: e.target.value })
                }
                className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Value
            </label>
            <input
              type="text"
              value={formData.value}
              onChange={(e) =>
                setFormData({ ...formData, value: e.target.value })
              }
              placeholder="e.g., 192.168.1.1 or malware.example.com"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500 font-mono"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Source
            </label>
            <input
              type="text"
              value={formData.source}
              onChange={(e) =>
                setFormData({ ...formData, source: e.target.value })
              }
              placeholder="e.g., VirusTotal, Internal Analysis"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
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
              rows={2}
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Tags (comma-separated)
            </label>
            <input
              type="text"
              value={formData.tags}
              onChange={(e) =>
                setFormData({ ...formData, tags: e.target.value })
              }
              placeholder="e.g., malware, phishing, apt"
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            />
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
              {loading ? 'Adding...' : 'Add IOC'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function IOCDetailsModal({
  ioc,
  onClose,
}: {
  ioc: IOC
  onClose: () => void
}) {
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg">
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold">IOC Details</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div className="flex items-center gap-3">
            <span className="text-gray-400">
              {typeIcons[ioc.ioc_type] || <Hash className="w-5 h-5" />}
            </span>
            <span className="text-sm font-medium text-gray-500 uppercase">
              {ioc.ioc_type}
            </span>
            <span
              className={clsx(
                'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ml-auto',
                threatLevelColors[ioc.threat_level]
              )}
            >
              {ioc.threat_level}
            </span>
          </div>

          <div className="bg-gray-50 rounded-lg p-3">
            <label className="block text-xs font-medium text-gray-500 mb-1">Value</label>
            <p className="text-sm font-mono text-gray-900 break-all">{ioc.value}</p>
          </div>

          {ioc.description && (
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-1">Description</label>
              <p className="text-sm text-gray-700">{ioc.description}</p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-500">Source</label>
              <p className="text-sm text-gray-900">{ioc.source || '-'}</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-500">Active</label>
              <p className="text-sm text-gray-900">{ioc.is_active ? 'Yes' : 'No'}</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-500">First Seen</label>
              <p className="text-sm text-gray-900">
                {format(new Date(ioc.first_seen), 'MMMM d, yyyy HH:mm')}
              </p>
            </div>
            {ioc.last_seen && (
              <div>
                <label className="block text-sm font-medium text-gray-500">Last Seen</label>
                <p className="text-sm text-gray-900">
                  {format(new Date(ioc.last_seen), 'MMMM d, yyyy HH:mm')}
                </p>
              </div>
            )}
          </div>

          {ioc.tags && ioc.tags.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-2">Tags</label>
              <div className="flex flex-wrap gap-2">
                {ioc.tags.map((tag, index) => (
                  <span
                    key={index}
                    className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800"
                  >
                    {tag}
                  </span>
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
