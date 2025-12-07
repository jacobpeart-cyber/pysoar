import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Building2,
  Users,
  Plus,
  Settings,
  Trash2,
  Edit2,
  Crown,
  UserPlus,
  Loader2,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import { api } from '../lib/api';
import clsx from 'clsx';

interface Organization {
  id: string;
  name: string;
  slug: string;
  description: string | null;
  plan: string;
  is_active: boolean;
  max_users: number;
  member_count?: number;
  created_at: string;
}

interface Team {
  id: string;
  name: string;
  description: string | null;
  organization_id: string;
  is_default: boolean;
  member_count?: number;
}

interface OrganizationMember {
  id: string;
  user_id: string;
  role: string;
  is_primary: boolean;
  user: {
    id: string;
    email: string;
    full_name: string;
  };
}

export default function Organizations() {
  const [activeTab, setActiveTab] = useState<'organizations' | 'teams'>('organizations');
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Organizations & Teams
          </h1>
          <p className="text-gray-500 dark:text-gray-400">
            Manage organizations and team access
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <Plus className="w-4 h-4" />
          {activeTab === 'organizations' ? 'New Organization' : 'New Team'}
        </button>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="flex gap-8">
          <button
            onClick={() => setActiveTab('organizations')}
            className={clsx(
              'pb-4 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'organizations'
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
            )}
          >
            <div className="flex items-center gap-2">
              <Building2 className="w-4 h-4" />
              Organizations
            </div>
          </button>
          <button
            onClick={() => setActiveTab('teams')}
            className={clsx(
              'pb-4 text-sm font-medium border-b-2 transition-colors',
              activeTab === 'teams'
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 dark:hover:text-gray-300'
            )}
          >
            <div className="flex items-center gap-2">
              <Users className="w-4 h-4" />
              Teams
            </div>
          </button>
        </nav>
      </div>

      {activeTab === 'organizations' ? (
        <OrganizationsList onSelect={setSelectedOrg} />
      ) : (
        <TeamsList />
      )}

      {showCreateModal && (
        <CreateModal
          type={activeTab === 'organizations' ? 'organization' : 'team'}
          onClose={() => setShowCreateModal(false)}
        />
      )}

      {selectedOrg && (
        <OrganizationDetailModal
          organization={selectedOrg}
          onClose={() => setSelectedOrg(null)}
        />
      )}
    </div>
  );
}

function OrganizationsList({
  onSelect,
}: {
  onSelect: (org: Organization) => void;
}) {
  const queryClient = useQueryClient();

  const { data: organizations, isLoading } = useQuery<Organization[]>({
    queryKey: ['organizations'],
    queryFn: async () => {
      const response = await api.get('/organizations');
      return response.data;
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/organizations/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  const planColors: Record<string, string> = {
    free: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
    starter: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    professional: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
    enterprise: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      {organizations?.map((org) => (
        <div
          key={org.id}
          className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6 hover:shadow-md transition-shadow"
        >
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
                <Building2 className="w-6 h-6 text-blue-600 dark:text-blue-400" />
              </div>
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">{org.name}</h3>
                <p className="text-sm text-gray-500 dark:text-gray-400">@{org.slug}</p>
              </div>
            </div>
            <span
              className={clsx(
                'px-2 py-1 text-xs font-medium rounded capitalize',
                planColors[org.plan] || planColors.free
              )}
            >
              {org.plan}
            </span>
          </div>

          {org.description && (
            <p className="mt-3 text-sm text-gray-600 dark:text-gray-300 line-clamp-2">
              {org.description}
            </p>
          )}

          <div className="mt-4 flex items-center gap-4 text-sm text-gray-500 dark:text-gray-400">
            <div className="flex items-center gap-1">
              <Users className="w-4 h-4" />
              {org.member_count || 0} / {org.max_users} members
            </div>
            {org.is_active ? (
              <span className="flex items-center gap-1 text-green-600 dark:text-green-400">
                <CheckCircle className="w-4 h-4" />
                Active
              </span>
            ) : (
              <span className="flex items-center gap-1 text-gray-500">
                <XCircle className="w-4 h-4" />
                Inactive
              </span>
            )}
          </div>

          <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-2">
            <button
              onClick={() => onSelect(org)}
              className="p-2 text-gray-500 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded"
            >
              <Settings className="w-4 h-4" />
            </button>
            <button
              onClick={() => {
                if (confirm('Delete this organization?')) {
                  deleteMutation.mutate(org.id);
                }
              }}
              className="p-2 text-gray-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/30 rounded"
            >
              <Trash2 className="w-4 h-4" />
            </button>
          </div>
        </div>
      ))}

      {(!organizations || organizations.length === 0) && (
        <div className="col-span-full p-12 text-center bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <Building2 className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">
            No Organizations
          </h3>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Create your first organization to get started
          </p>
        </div>
      )}
    </div>
  );
}

function TeamsList() {
  const queryClient = useQueryClient();

  const { data: teams, isLoading } = useQuery<Team[]>({
    queryKey: ['teams'],
    queryFn: async () => {
      const response = await api.get('/teams');
      return response.data;
    },
  });

  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      await api.delete(`/teams/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['teams'] });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
      </div>
    );
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
      <table className="w-full">
        <thead>
          <tr className="border-b border-gray-200 dark:border-gray-700">
            <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Team
            </th>
            <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Members
            </th>
            <th className="text-left px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Type
            </th>
            <th className="text-right px-6 py-3 text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Actions
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
          {teams?.map((team) => (
            <tr key={team.id} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
              <td className="px-6 py-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-green-100 dark:bg-green-900/30 rounded-lg flex items-center justify-center">
                    <Users className="w-5 h-5 text-green-600 dark:text-green-400" />
                  </div>
                  <div>
                    <div className="font-medium text-gray-900 dark:text-white">
                      {team.name}
                    </div>
                    {team.description && (
                      <div className="text-sm text-gray-500 dark:text-gray-400">
                        {team.description}
                      </div>
                    )}
                  </div>
                </div>
              </td>
              <td className="px-6 py-4 text-gray-500 dark:text-gray-400">
                {team.member_count || 0} members
              </td>
              <td className="px-6 py-4">
                {team.is_default ? (
                  <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-xs rounded">
                    Default
                  </span>
                ) : (
                  <span className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300 text-xs rounded">
                    Custom
                  </span>
                )}
              </td>
              <td className="px-6 py-4">
                <div className="flex items-center justify-end gap-2">
                  <button className="p-2 text-gray-500 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded">
                    <UserPlus className="w-4 h-4" />
                  </button>
                  <button className="p-2 text-gray-500 hover:text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/30 rounded">
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => {
                      if (confirm('Delete this team?')) {
                        deleteMutation.mutate(team.id);
                      }
                    }}
                    disabled={team.is_default}
                    className="p-2 text-gray-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-900/30 rounded disabled:opacity-50"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {(!teams || teams.length === 0) && (
        <div className="p-12 text-center">
          <Users className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white">No Teams</h3>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Create a team to organize your members
          </p>
        </div>
      )}
    </div>
  );
}

function CreateModal({
  type,
  onClose,
}: {
  type: 'organization' | 'team';
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [description, setDescription] = useState('');
  const [plan, setPlan] = useState('free');

  const createMutation = useMutation({
    mutationFn: async () => {
      if (type === 'organization') {
        await api.post('/organizations', { name, slug, description, plan });
      } else {
        await api.post('/teams', { name, description });
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [type === 'organization' ? 'organizations' : 'teams'] });
      onClose();
    },
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-md">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white capitalize">
            Create {type}
          </h2>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                if (type === 'organization') {
                  setSlug(e.target.value.toLowerCase().replace(/\s+/g, '-'));
                }
              }}
              className="mt-1 block w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {type === 'organization' && (
            <>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Slug *
                </label>
                <input
                  type="text"
                  value={slug}
                  onChange={(e) => setSlug(e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Plan
                </label>
                <select
                  value={plan}
                  onChange={(e) => setPlan(e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                >
                  <option value="free">Free</option>
                  <option value="starter">Starter</option>
                  <option value="professional">Professional</option>
                  <option value="enterprise">Enterprise</option>
                </select>
              </div>
            </>
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="mt-1 block w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>
        </div>

        <div className="p-6 border-t border-gray-200 dark:border-gray-700 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
          >
            Cancel
          </button>
          <button
            onClick={() => createMutation.mutate()}
            disabled={!name || (type === 'organization' && !slug) || createMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            {createMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Create
          </button>
        </div>
      </div>
    </div>
  );
}

function OrganizationDetailModal({
  organization,
  onClose,
}: {
  organization: Organization;
  onClose: () => void;
}) {
  const [activeTab, setActiveTab] = useState<'members' | 'settings'>('members');

  const { data: members, isLoading } = useQuery<OrganizationMember[]>({
    queryKey: ['organization-members', organization.id],
    queryFn: async () => {
      const response = await api.get(`/organizations/${organization.id}/members`);
      return response.data;
    },
  });

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-3xl max-h-[80vh] overflow-hidden">
        <div className="p-6 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center">
              <Building2 className="w-6 h-6 text-blue-600 dark:text-blue-400" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                {organization.name}
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">@{organization.slug}</p>
            </div>
          </div>

          <div className="mt-4 flex gap-4">
            <button
              onClick={() => setActiveTab('members')}
              className={clsx(
                'px-3 py-1.5 text-sm font-medium rounded-lg',
                activeTab === 'members'
                  ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
              )}
            >
              Members
            </button>
            <button
              onClick={() => setActiveTab('settings')}
              className={clsx(
                'px-3 py-1.5 text-sm font-medium rounded-lg',
                activeTab === 'settings'
                  ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300'
                  : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
              )}
            >
              Settings
            </button>
          </div>
        </div>

        <div className="p-6 overflow-y-auto max-h-96">
          {activeTab === 'members' && (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <h3 className="font-medium text-gray-900 dark:text-white">Members</h3>
                <button className="flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                  <UserPlus className="w-4 h-4" />
                  Add Member
                </button>
              </div>

              {isLoading ? (
                <div className="flex justify-center py-8">
                  <Loader2 className="w-6 h-6 animate-spin text-blue-500" />
                </div>
              ) : (
                <div className="space-y-2">
                  {members?.map((member) => (
                    <div
                      key={member.id}
                      className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-gray-200 dark:bg-gray-600 rounded-full flex items-center justify-center">
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-300">
                            {member.user.full_name?.charAt(0) || member.user.email.charAt(0).toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <div className="font-medium text-gray-900 dark:text-white">
                            {member.user.full_name || member.user.email}
                          </div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {member.user.email}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {member.role === 'owner' && (
                          <Crown className="w-4 h-4 text-yellow-500" />
                        )}
                        <span
                          className={clsx(
                            'px-2 py-1 text-xs font-medium rounded capitalize',
                            member.role === 'owner'
                              ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                              : member.role === 'admin'
                              ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300'
                              : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
                          )}
                        >
                          {member.role}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === 'settings' && (
            <div className="space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Organization Name
                </label>
                <input
                  type="text"
                  defaultValue={organization.name}
                  className="mt-1 block w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300">
                  Description
                </label>
                <textarea
                  defaultValue={organization.description || ''}
                  rows={3}
                  className="mt-1 block w-full rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 px-3 py-2 text-sm"
                />
              </div>
            </div>
          )}
        </div>

        <div className="p-6 border-t border-gray-200 dark:border-gray-700 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
