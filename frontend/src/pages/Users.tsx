import { useState, useEffect } from 'react'
import { usersApi } from '../lib/api'
import type { User } from '../lib/types'
import type { CustomRole } from '../api/endpoints'
import {
  Plus,
  Search,
  Eye,
  Trash2,
  X,
  ChevronLeft,
  ChevronRight,
  Shield,
  UserIcon,
  Mail,
  Calendar
} from 'lucide-react'
import { format } from 'date-fns'
import clsx from 'clsx'
import LoadErrorBanner from '../components/LoadErrorBanner'
import { useRoleGate, ADMIN_ONLY_REASON } from '../lib/roles'
import { useAuth } from '../contexts/AuthContext'
import { describeIdentityError } from '../components/identity/identityErrors'
import { roleLabel, useCustomRoles } from '../components/identity/identityShared'
import { RoleSelect } from '../components/identity/IdentityUI'
import ScimLinkControl from '../components/identity/ScimLinkControl'

const roleColors: Record<string, string> = {
  admin: 'bg-purple-100 text-purple-800',
  analyst: 'bg-blue-100 text-blue-800',
  viewer: 'bg-gray-100 text-gray-800',
}

const BUILTIN = ['admin', 'analyst', 'viewer']

const SOURCE_LABEL: Record<string, string> = {
  local: 'Local account',
  oidc: 'SSO (provisioned at sign-in)',
  scim: 'SCIM (managed by the identity provider)',
}

/** The value a role picker shows for a user: the custom role id, else the built-in role. */
function roleValueOf(user: User): string {
  return user.custom_role_id || user.role
}

/**
 * PATCH / POST body fields for a role choice (src/api/v1/endpoints/users.py):
 * a custom role sends `custom_role_id` (the built-in role is floored to
 * viewer server side); a built-in sends `role` and clears the custom role.
 */
function roleFields(value: string): { role?: string; custom_role_id: string | null } {
  return BUILTIN.includes(value) ? { role: value, custom_role_id: null } : { custom_role_id: value }
}

function sourceOf(user: User): string {
  return user.identity_source || 'local'
}

export default function Users() {
  const gate = useRoleGate()
  // A custom-role holder may hold admin tier in `users`; only the server knows.
  const canManage = gate.isAdmin || gate.hasCustomRole
  const roles = useCustomRoles(canManage)
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<unknown>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [search, setSearch] = useState('')
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [showDetailsModal, setShowDetailsModal] = useState(false)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const pageSize = 10

  const fetchUsers = async () => {
    setLoading(true)
    try {
      const params: Record<string, any> = { page, size: pageSize }
      if (search) params.search = search
      const response = await usersApi.list(params)
      setUsers(response.items)
      setTotal(response.total)
      setLoadError(null)
    } catch (error) {
      setLoadError(error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchUsers()
  }, [page, search])

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this user?')) return
    setActionError(null)
    try {
      await usersApi.delete(id)
      fetchUsers()
    } catch (error) {
      setActionError(describeIdentityError(error))
    }
  }

  const handleViewDetails = (user: User) => {
    setSelectedUser(user)
    setShowDetailsModal(true)
  }

  const totalPages = Math.ceil(total / pageSize)

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold text-gray-900">User Management</h1>
        <button
          onClick={() => setShowCreateModal(true)}
          disabled={!canManage}
          title={!canManage ? ADMIN_ONLY_REASON : undefined}
          className="flex items-center gap-2 bg-primary-600 text-white px-4 py-2 rounded-lg hover:bg-primary-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Plus className="w-5 h-5" />
          Add User
        </button>
      </div>

      <div className="space-y-3 mb-4">
        <LoadErrorBanner what="users" error={loadError} />
        {actionError && (
          <div role="alert" className="text-sm text-red-700 bg-red-50 border border-red-200 rounded p-3">{actionError}</div>
        )}
        {canManage && roles.error ? (
          <p className="text-xs text-amber-700">
            Custom roles could not be listed, so role pickers offer the built-in roles only. {describeIdentityError(roles.error)}
          </p>
        ) : null}
      </div>

      {/* Search */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 mb-6">
        <div className="flex items-center gap-2">
          <Search className="w-5 h-5 text-gray-400" />
          <input
            type="text"
            placeholder="Search users by name or email..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="flex-1 border-0 focus:ring-0 text-sm"
          />
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                User
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Role
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Identity
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                Joined
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
            ) : loadError ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                  Users could not be loaded (see the error above).
                </td>
              </tr>
            ) : users.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-6 py-12 text-center text-gray-500">
                  No users found
                </td>
              </tr>
            ) : (
              users.map((user) => (
                <tr key={user.id} className="hover:bg-gray-50">
                  <td className="px-6 py-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-primary-100 flex items-center justify-center">
                        <UserIcon className="w-5 h-5 text-primary-600" />
                      </div>
                      <div>
                        <div className="text-sm font-medium text-gray-900">
                          {user.full_name || 'No name'}
                        </div>
                        <div className="text-sm text-gray-500 flex items-center gap-1">
                          <Mail className="w-3 h-3" />
                          {user.email}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={clsx(
                        'inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium',
                        user.custom_role_id ? 'bg-indigo-100 text-indigo-800' : roleColors[user.role]
                      )}
                    >
                      <Shield className="w-3 h-3" />
                      {user.custom_role_id
                        ? roles.custom.some((r) => r.id === user.custom_role_id)
                          ? roleLabel(user.custom_role_id, roles.custom)
                          : 'custom role'
                        : user.role}
                    </span>
                    {user.is_superuser && (
                      <span className="ml-2 inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-yellow-100 text-yellow-800">
                        Superuser
                      </span>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-700">
                      {sourceOf(user)}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <span
                      className={clsx(
                        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                        user.is_active
                          ? 'bg-green-100 text-green-800'
                          : 'bg-red-100 text-red-800'
                      )}
                    >
                      {user.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    <div className="flex items-center gap-1">
                      <Calendar className="w-4 h-4" />
                      {format(new Date(user.created_at || ""), 'MMM d, yyyy')}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button
                      onClick={() => handleViewDetails(user)}
                      className="text-primary-600 hover:text-primary-900 mr-3"
                      aria-label={`Details of ${user.email}`}
                    >
                      <Eye className="w-5 h-5" />
                    </button>
                    <button
                      onClick={() => handleDelete(user.id)}
                      disabled={user.is_superuser || !canManage}
                      title={!canManage ? ADMIN_ONLY_REASON : undefined}
                      aria-label={`Delete ${user.email}`}
                      className="text-red-600 hover:text-red-900 disabled:opacity-30 disabled:cursor-not-allowed"
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
        <CreateUserModal
          customRoles={roles.custom}
          onClose={() => setShowCreateModal(false)}
          onCreated={() => {
            setShowCreateModal(false)
            fetchUsers()
          }}
        />
      )}

      {/* Details Modal */}
      {showDetailsModal && selectedUser && (
        <UserDetailsModal
          key={`${selectedUser.id}:${selectedUser.identity_source ?? ''}:${selectedUser.custom_role_id ?? ''}:${selectedUser.role}:${selectedUser.is_active}`}
          user={selectedUser}
          customRoles={roles.custom}
          canManage={canManage}
          onClose={() => {
            setShowDetailsModal(false)
            setSelectedUser(null)
          }}
          onUpdated={(updated) => {
            if (updated) setSelectedUser(updated)
            fetchUsers()
          }}
        />
      )}
    </div>
  )
}

function CreateUserModal({
  customRoles,
  onClose,
  onCreated,
}: {
  customRoles: CustomRole[]
  onClose: () => void
  onCreated: () => void
}) {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    full_name: '',
  })
  const [roleValue, setRoleValue] = useState('analyst')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const fields = roleFields(roleValue)
      await usersApi.create({ ...formData, role: fields.role ?? 'viewer', custom_role_id: fields.custom_role_id })
      onCreated()
    } catch (err) {
      setError(describeIdentityError(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-md">
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold">Add New User</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600" aria-label="Close">
            <X className="w-5 h-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          {error && (
            <div className="bg-red-50 text-red-700 p-3 rounded-lg text-sm">
              {error}
            </div>
          )}
          <p className="text-xs text-gray-500">
            Creates a local account with a PySOAR password. Accounts for SSO or SCIM users are created by the identity
            provider (at first sign-in or by provisioning).
          </p>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Email
            </label>
            <input
              type="email"
              value={formData.email}
              onChange={(e) =>
                setFormData({ ...formData, email: e.target.value })
              }
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Password
            </label>
            <input
              type="password"
              value={formData.password}
              onChange={(e) =>
                setFormData({ ...formData, password: e.target.value })
              }
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              required
              minLength={8}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Full Name
            </label>
            <input
              type="text"
              value={formData.full_name}
              onChange={(e) =>
                setFormData({ ...formData, full_name: e.target.value })
              }
              className="w-full border border-gray-300 rounded-lg px-3 py-2 focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Role
            </label>
            <RoleSelect value={roleValue} onChange={setRoleValue} custom={customRoles} />
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
              {loading ? 'Creating...' : 'Create User'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function UserDetailsModal({
  user,
  customRoles,
  canManage,
  onClose,
  onUpdated,
}: {
  user: User
  customRoles: CustomRole[]
  canManage: boolean
  onClose: () => void
  onUpdated: (updated?: User) => void
}) {
  const { user: me } = useAuth()
  const [roleValue, setRoleValue] = useState(roleValueOf(user))
  const [isActive, setIsActive] = useState(user.is_active)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const source = sourceOf(user)
  const isSelf = me?.id === user.id
  const locked = user.is_superuser || !canManage || isSelf
  const lockReason = user.is_superuser
    ? 'This is a superuser account. Role and status cannot be modified.'
    : isSelf
      ? 'You cannot change your own role or status.'
      : !canManage
        ? ADMIN_ONLY_REASON
        : null

  const handleUpdate = async () => {
    setLoading(true)
    setError('')
    try {
      const body: Record<string, unknown> = { is_active: isActive }
      if (roleValue !== roleValueOf(user)) Object.assign(body, roleFields(roleValue))
      const updated = (await usersApi.update(user.id, body)) as User
      onUpdated(updated)
    } catch (err) {
      setError(describeIdentityError(err))
    } finally {
      setLoading(false)
    }
  }

  const hasChanges = roleValue !== roleValueOf(user) || isActive !== user.is_active

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-xl w-full max-w-lg">
        <div className="flex items-center justify-between p-4 border-b">
          <h2 className="text-lg font-semibold">User Details</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600" aria-label="Close">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-full bg-primary-100 flex items-center justify-center">
              <UserIcon className="w-8 h-8 text-primary-600" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-900">
                {user.full_name || 'No name'}
              </h3>
              <p className="text-sm text-gray-500">{user.email}</p>
            </div>
          </div>

          {error && <div role="alert" className="bg-red-50 text-red-700 p-3 rounded-lg text-sm">{error}</div>}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-1">Role</label>
              <RoleSelect value={roleValue} onChange={setRoleValue} custom={customRoles} disabled={locked} title={lockReason ?? undefined} />
              {!BUILTIN.includes(roleValue) && (
                <p className="text-xs text-gray-500 mt-1">A custom role decides access per area; the built-in role is stored as viewer.</p>
              )}
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-500 mb-1">Status</label>
              <select
                value={isActive ? 'active' : 'inactive'}
                onChange={(e) => setIsActive(e.target.value === 'active')}
                disabled={locked}
                title={lockReason ?? undefined}
                className="w-full border border-gray-300 rounded-md text-sm px-3 py-1.5 disabled:opacity-50"
              >
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
              </select>
              {source === 'scim' && (
                <p className="text-xs text-gray-500 mt-1">
                  The identity provider manages this account&apos;s lifecycle; it may reactivate or deactivate it on its next push.
                </p>
              )}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 pt-2">
            <div>
              <label className="block text-sm font-medium text-gray-500">Created</label>
              <p className="text-sm text-gray-900">
                {format(new Date(user.created_at || ""), 'MMMM d, yyyy')}
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-500">Identity source</label>
              <p className="text-sm text-gray-900">{SOURCE_LABEL[source] ?? source}</p>
            </div>
          </div>

          <div className="text-sm rounded-lg p-3 bg-gray-50 border border-gray-200 text-gray-700">
            <span className="font-medium">Password: </span>
            {source === 'local'
              ? 'A local PySOAR password. A reset link is issued by an administrator (remediation password_reset action).'
              : 'Managed by the identity provider. PySOAR has no password for this account and refuses a password reset (sso_managed); reset it at the provider.'}
          </div>

          {canManage && !user.is_superuser && source !== 'oidc' && source !== 'saml' && (
            <div className="space-y-1">
              <label className="block text-sm font-medium text-gray-500">SCIM management</label>
              <p className="text-xs text-gray-500">
                {source === 'local'
                  ? 'The identity provider cannot create or manage this existing local account until it is linked.'
                  : 'Unlinking returns the account to local management; an account SCIM created then has no usable password until a password reset.'}
              </p>
              <ScimLinkControl user={user} onChanged={() => onUpdated({ ...user, identity_source: source === 'local' ? 'scim' : 'local' })} />
            </div>
          )}

          {lockReason && (
            <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3 text-sm text-yellow-800">
              {lockReason}
            </div>
          )}

          <div className="flex justify-end gap-3 pt-4">
            <button
              onClick={onClose}
              className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50"
            >
              Close
            </button>
            {hasChanges && !locked && (
              <button
                onClick={handleUpdate}
                disabled={loading}
                className="px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50"
              >
                {loading ? 'Saving...' : 'Save Changes'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
