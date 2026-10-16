import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Edit3, Loader2, Plus, Save, Trash2, Users as UsersIcon, X } from 'lucide-react';
import clsx from 'clsx';
import { identityApi } from '../../api/endpoints';
import type { AreaEntry, CustomRole, IdentityTier, RoleBody } from '../../api/endpoints';
import LoadErrorBanner from '../LoadErrorBanner';
import { identityErrorKey } from './identityErrors';
import { btnDanger, btnPrimary, btnSecondary, inputCls, labelCls } from './identityShared';
import { ActionError, Chip } from './IdentityUI';

/**
 * Settings > Identity > Roles. Contract: src/api/v1/endpoints/roles.py.
 * A custom role holds one tier (none < read < write < admin) per area (the
 * first path segment under /api/v1, catalogue from GET /roles/areas) with a
 * default for unlisted areas. The grid shows the built-in roles' tier in each
 * area for comparison. Exempt areas (auth, mfa, own API keys, ...) are never
 * denied by tier, whatever the role says.
 */

const TIERS: IdentityTier[] = ['none', 'read', 'write', 'admin'];
const TIER_TONE: Record<string, string> = {
  none: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
  read: 'bg-sky-100 text-sky-800 dark:bg-sky-900/30 dark:text-sky-300',
  write: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
  admin: 'bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-300',
};

function TierBadge({ tier }: { tier: string }) {
  return <span className={clsx('inline-block px-1.5 py-0.5 rounded text-xs font-medium', TIER_TONE[tier] ?? TIER_TONE.none)}>{tier}</span>;
}

interface Draft {
  id: string | null;
  name: string;
  description: string;
  default_tier: IdentityTier;
  /** Only the overrides; an absent area takes default_tier. */
  area_tiers: Record<string, IdentityTier>;
}

const NEW_DRAFT: Draft = { id: null, name: '', description: '', default_tier: 'read', area_tiers: {} };

export default function RolesEditor() {
  const qc = useQueryClient();
  const roles = useQuery({ queryKey: ['identity', 'roles'], queryFn: identityApi.listRoles, retry: false });
  const areas = useQuery({ queryKey: ['identity', 'roles', 'areas'], queryFn: identityApi.roleAreas, retry: false });
  const [draft, setDraft] = useState<Draft | null>(null);
  const [membersOf, setMembersOf] = useState<CustomRole | null>(null);
  const [deleteError, setDeleteError] = useState<{ id: string; error: unknown } | null>(null);
  const [loadingRole, setLoadingRole] = useState<string | null>(null);
  const [openError, setOpenError] = useState<unknown>(null);

  const remove = useMutation({
    mutationFn: (id: string) => identityApi.deleteRole(id),
    onSuccess: () => {
      setDeleteError(null);
      qc.invalidateQueries({ queryKey: ['identity', 'roles'] });
    },
    onError: (error, id) => setDeleteError({ id, error }),
  });

  const openEditor = async (role: CustomRole) => {
    // Fresh copy: another admin may have changed it since the list loaded.
    setOpenError(null);
    setLoadingRole(role.id);
    try {
      const r = await identityApi.getRole(role.id);
      setDraft({ id: r.id, name: r.name, description: r.description ?? '', default_tier: r.default_tier, area_tiers: { ...r.area_tiers } });
    } catch (err) {
      setOpenError(err);
      if (identityErrorKey(err) === 'role_not_found') qc.invalidateQueries({ queryKey: ['identity', 'roles'] });
    } finally {
      setLoadingRole(null);
    }
  };

  if (roles.isLoading) {
    return <p className="text-sm text-gray-500 flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" /> Loading roles...</p>;
  }
  if (roles.error) return <LoadErrorBanner what="roles" error={roles.error} />;
  const data = roles.data;
  if (!data) return null;

  return (
    <section className="space-y-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Roles</h3>
          <p className="text-sm text-gray-500 dark:text-gray-400">
            Built-in roles hold one tier everywhere. A custom role sets a tier per area; holders are judged by the new
            tiers from their next request. A role never grants more than you hold yourself.
          </p>
        </div>
        <button type="button" className={btnPrimary} disabled={Boolean(draft) || !areas.data}
          title={!areas.data ? 'The area catalogue has not loaded.' : undefined}
          onClick={() => setDraft({ ...NEW_DRAFT })}>
          <Plus className="w-4 h-4" /> New role
        </button>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full text-sm">
          <thead className="text-left text-xs uppercase text-gray-500">
            <tr><th className="py-2 pr-3">Role</th><th className="pr-3">Tiers</th><th className="pr-3">Members</th><th /></tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700 text-gray-800 dark:text-gray-200">
            {data.builtin.map((b) => (
              <tr key={b.name}>
                <td className="py-2 pr-3">
                  <span className="font-medium">{b.name}</span> <Chip tone="gray">built-in</Chip>
                  <p className="text-xs text-gray-500">{b.description}</p>
                </td>
                <td className="pr-3"><TierBadge tier={b.tier} /> everywhere</td>
                <td className="pr-3">{b.member_count}</td>
                <td />
              </tr>
            ))}
            {data.custom.map((r) => (
              <tr key={r.id}>
                <td className="py-2 pr-3">
                  <span className="font-medium">{r.name}</span> <Chip tone="blue">custom</Chip>
                  {r.description && <p className="text-xs text-gray-500">{r.description}</p>}
                </td>
                <td className="pr-3 text-xs">
                  default <TierBadge tier={r.default_tier} />
                  {Object.keys(r.area_tiers).length > 0 && <> , {Object.keys(r.area_tiers).length} area override(s)</>}
                </td>
                <td className="pr-3">{r.member_count}</td>
                <td className="text-right space-x-2 whitespace-nowrap py-2">
                  <button type="button" className={btnSecondary} onClick={() => setMembersOf(r)}>
                    <UsersIcon className="w-4 h-4" /> Members
                  </button>
                  <button type="button" className={btnSecondary} disabled={Boolean(draft) || loadingRole === r.id || !areas.data}
                    onClick={() => openEditor(r)}>
                    {loadingRole === r.id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Edit3 className="w-4 h-4" />} Edit
                  </button>
                  <button type="button" className={btnDanger} disabled={remove.isPending}
                    title={r.member_count ? `${r.member_count} user(s) hold this role; the server refuses the delete until none do.` : undefined}
                    onClick={() => { if (confirm(`Delete the role "${r.name}"?`)) remove.mutate(r.id); }}>
                    <Trash2 className="w-4 h-4" /> Delete
                  </button>
                  {deleteError?.id === r.id && <div className="text-left mt-2"><ActionError error={deleteError.error} /></div>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {data.custom.length === 0 && <p className="text-sm text-gray-500 mt-2">No custom roles yet.</p>}
      </div>

      <ActionError error={openError} />
      <LoadErrorBanner what="the area catalogue" error={areas.error} />

      {membersOf && <MembersPanel role={membersOf} onClose={() => setMembersOf(null)} />}

      {draft && areas.data && (
        <RoleForm
          draft={draft}
          areas={areas.data.areas}
          onCancel={() => setDraft(null)}
          onSaved={() => {
            setDraft(null);
            qc.invalidateQueries({ queryKey: ['identity', 'roles'] });
          }}
        />
      )}
    </section>
  );
}

function MembersPanel({ role, onClose }: { role: CustomRole; onClose: () => void }) {
  const members = useQuery({ queryKey: ['identity', 'roles', role.id, 'members'], queryFn: () => identityApi.roleMembers(role.id), retry: false });
  return (
    <div className="rounded border border-gray-200 dark:border-gray-700 p-4 space-y-2">
      <div className="flex justify-between items-center">
        <h4 className="font-medium text-gray-900 dark:text-gray-100">Members of {role.name}</h4>
        <button type="button" className={btnSecondary} onClick={onClose} aria-label="Close members"><X className="w-4 h-4" /></button>
      </div>
      <LoadErrorBanner what="role members" error={members.error} />
      {members.isLoading && <p className="text-sm text-gray-500 flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" /> Loading...</p>}
      {members.data && members.data.items.length === 0 && <p className="text-sm text-gray-500">Nobody holds this role.</p>}
      {members.data && members.data.items.length > 0 && (
        <ul className="text-sm text-gray-800 dark:text-gray-200 space-y-1">
          {members.data.items.map((m) => (
            <li key={m.id} className="flex items-center gap-2">
              {m.full_name ? `${m.full_name} · ` : ''}{m.email}
              <Chip tone="gray">{m.identity_source}</Chip>
              {!m.is_active && <Chip tone="red">inactive</Chip>}
            </li>
          ))}
          {members.data.total > members.data.items.length && (
            <li className="text-xs text-gray-500">and {members.data.total - members.data.items.length} more</li>
          )}
        </ul>
      )}
    </div>
  );
}

function RoleForm({
  draft: initial,
  areas,
  onCancel,
  onSaved,
}: {
  draft: Draft;
  areas: AreaEntry[];
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [draft, setDraft] = useState<Draft>(initial);
  const [filter, setFilter] = useState('');
  const save = useMutation({
    mutationFn: (body: RoleBody) => (draft.id ? identityApi.updateRole(draft.id, body) : identityApi.createRole(body)),
    onSuccess: onSaved,
  });
  const visible = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return f ? areas.filter((a) => a.area.toLowerCase().includes(f) || a.label.toLowerCase().includes(f)) : areas;
  }, [areas, filter]);

  // Areas the server reported as exceeding the caller's tiers, highlighted in the grid.
  const overAreas = new Set<string>(
    (() => {
      const detail = (save.error as { response?: { data?: { detail?: { error?: string; areas?: string[] } } } } | null)?.response?.data?.detail;
      return detail?.error === 'tier_exceeds_caller' || detail?.error === 'unknown_area' ? detail.areas ?? [] : [];
    })(),
  );

  const setArea = (area: string, tier: IdentityTier | 'default') => {
    setDraft((d) => {
      const next = { ...d.area_tiers };
      if (tier === 'default') delete next[area];
      else next[area] = tier;
      return { ...d, area_tiers: next };
    });
  };

  return (
    <form
      className="rounded border border-blue-200 dark:border-blue-800 p-4 space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate({
          name: draft.name.trim(),
          description: draft.description.trim() || null,
          default_tier: draft.default_tier,
          area_tiers: draft.area_tiers,
        });
      }}
    >
      <h4 className="font-medium text-gray-900 dark:text-gray-100">{draft.id ? `Edit role "${initial.name}"` : 'New custom role'}</h4>
      <div className="grid gap-4 md:grid-cols-3">
        <div>
          <label htmlFor="role-name" className={labelCls}>Name</label>
          <input id="role-name" className={inputCls} value={draft.name} required maxLength={100}
            onChange={(e) => setDraft({ ...draft, name: e.target.value })} />
          <p className="text-xs text-gray-500 mt-1">admin, analyst and viewer are reserved.</p>
        </div>
        <div className="md:col-span-2">
          <label htmlFor="role-desc" className={labelCls}>Description</label>
          <input id="role-desc" className={inputCls} value={draft.description} maxLength={2000}
            onChange={(e) => setDraft({ ...draft, description: e.target.value })} />
        </div>
        <div>
          <label htmlFor="role-default" className={labelCls}>Default tier (areas without an override)</label>
          <select id="role-default" className={inputCls} value={draft.default_tier}
            onChange={(e) => setDraft({ ...draft, default_tier: e.target.value as IdentityTier })}>
            {TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div className="md:col-span-2">
          <label htmlFor="role-filter" className={labelCls}>Filter areas</label>
          <input id="role-filter" className={inputCls} value={filter} placeholder="e.g. siem" onChange={(e) => setFilter(e.target.value)} />
        </div>
      </div>

      <p className="text-xs text-gray-500">
        Tiers: <TierBadge tier="none" /> no access (403 area_denied, reads included), <TierBadge tier="read" /> view,{' '}
        <TierBadge tier="write" /> analyst actions, <TierBadge tier="admin" /> configuration and containment.
      </p>

      <div className="overflow-x-auto max-h-[28rem] overflow-y-auto border border-gray-200 dark:border-gray-700 rounded">
        <table className="min-w-full text-sm">
          <thead className="sticky top-0 bg-gray-50 dark:bg-gray-900 text-left text-xs uppercase text-gray-500">
            <tr>
              <th className="py-2 px-3">Area</th>
              <th className="px-2">Routes (write / admin)</th>
              <th className="px-2">This role</th>
              <th className="px-2">Effective</th>
              <th className="px-2">viewer</th>
              <th className="px-2">analyst</th>
              <th className="px-2">admin</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700 text-gray-800 dark:text-gray-200">
            {visible.map((a) => {
              const override = draft.area_tiers[a.area];
              const effective = override ?? draft.default_tier;
              return (
                <tr key={a.area} className={clsx(overAreas.has(a.area) && 'bg-red-50 dark:bg-red-900/20')}>
                  <td className="py-1.5 px-3">
                    <div className="font-medium">{a.label}</div>
                    <code className="text-xs text-gray-500">{a.area}</code>
                    {a.exempt && (
                      <div className="text-xs text-amber-700 dark:text-amber-300">exempt: {a.exempt_reason ?? 'never denied by tier'}</div>
                    )}
                  </td>
                  <td className="px-2 text-xs text-gray-500">{a.routes} ({a.write_routes} / {a.admin_routes})</td>
                  <td className="px-2">
                    <select aria-label={`Tier for ${a.label}`} className={clsx(inputCls, 'py-1')} value={override ?? 'default'}
                      onChange={(e) => setArea(a.area, e.target.value as IdentityTier | 'default')}>
                      <option value="default">default ({draft.default_tier})</option>
                      {TIERS.map((t) => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </td>
                  <td className="px-2">{a.exempt ? <span className="text-xs text-gray-500">exempt</span> : <TierBadge tier={effective} />}</td>
                  {(['viewer', 'analyst', 'admin'] as const).map((b) => (
                    <td key={b} className="px-2"><TierBadge tier={a.builtin_tiers[b] ?? 'none'} /></td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
        {visible.length === 0 && <p className="text-sm text-gray-500 p-3">No area matches the filter.</p>}
      </div>

      <ActionError error={save.error} />
      <div className="flex gap-2">
        <button type="submit" className={btnPrimary} disabled={save.isPending || !draft.name.trim()}>
          {save.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />} {draft.id ? 'Save role' : 'Create role'}
        </button>
        <button type="button" className={btnSecondary} onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}
