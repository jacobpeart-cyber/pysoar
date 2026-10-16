import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertTriangle, KeyRound, Loader2, Save, XCircle } from 'lucide-react';
import { identityApi } from '../../api/endpoints';
import type { SCIMGroup, SCIMTokenCreated } from '../../api/endpoints';
import { usersApi } from '../../lib/api';
import type { User } from '../../lib/types';
import LoadErrorBanner from '../LoadErrorBanner';
import { useRoleGate, FULL_ADMIN_ONLY_REASON } from '../../lib/roles';
import { describeIdentityError } from './identityErrors';
import { btnDanger, btnPrimary, btnSecondary, fmtDate, inputCls, labelCls, roleLabel, useCustomRoles } from './identityShared';
import { ActionError, Chip, CopyValue, RoleSelect } from './IdentityUI';
import ScimLinkControl from './ScimLinkControl';

/**
 * Settings > Identity > SCIM provisioning. Contract: src/api/v1/endpoints/scim_admin.py.
 * The IdP-facing /scim/v2 routes are called by the identity provider, never by
 * this page. A minted token is held only in this component's state and shown
 * once; the API stores its sha256 and prefix.
 */
export default function SCIMPanel() {
  const gate = useRoleGate();
  const qc = useQueryClient();
  const roles = useCustomRoles();
  const tokens = useQuery({ queryKey: ['identity', 'scim', 'tokens'], queryFn: identityApi.listScimTokens, retry: false });
  const groups = useQuery({ queryKey: ['identity', 'scim', 'groups'], queryFn: identityApi.listScimGroups, retry: false });
  const users = useQuery({
    queryKey: ['identity', 'scim', 'users'],
    queryFn: () => usersApi.list({ page: 1, size: 100 }) as Promise<{ items: User[]; total: number }>,
    retry: false,
  });

  const [name, setName] = useState('');
  const [days, setDays] = useState('');
  const [minted, setMinted] = useState<SCIMTokenCreated | null>(null);

  const mint = useMutation({
    mutationFn: () => identityApi.createScimToken({ name: name.trim(), expires_in_days: days ? Number(days) : null }),
    onSuccess: (t) => {
      setMinted(t);
      setName('');
      setDays('');
      qc.invalidateQueries({ queryKey: ['identity', 'scim', 'tokens'] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: string) => identityApi.revokeScimToken(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['identity', 'scim', 'tokens'] }),
  });

  const mintReason = !gate.isFullAdmin ? `${FULL_ADMIN_ONLY_REASON} A SCIM token can provision administrators.` : null;
  const daysNum = days ? Number(days) : null;
  const daysInvalid = daysNum !== null && (!Number.isInteger(daysNum) || daysNum < 1 || daysNum > 730);

  return (
    <section className="space-y-6">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">SCIM 2.0 provisioning</h3>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Your identity provider (Okta, Entra ID) creates, updates and deactivates users through SCIM. SCIM users sign
          in through single sign-on (they have no PySOAR password), so configure SSO as well. Local accounts
          (identity source <em>local</em>) are never changed by SCIM unless an admin links them below; the provider's
          create for an existing local email answers 409 until then.
        </p>
      </div>

      {tokens.error ? (
        <LoadErrorBanner what="SCIM tokens" error={tokens.error} />
      ) : tokens.data ? (
        <CopyValue label="SCIM base URL (configure this at the identity provider)" value={tokens.data.scim_base_url} />
      ) : null}

      {minted && (
        <div role="alert" className="rounded p-4 border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20 space-y-2">
          <p className="text-sm font-medium text-amber-900 dark:text-amber-200 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" /> Copy this token now. It is shown once and cannot be retrieved again.
          </p>
          <CopyValue label={`Token "${minted.name}"`} value={minted.token} />
          <p className="text-xs text-amber-900 dark:text-amber-200">
            Paste it into the identity provider's SCIM connection as the bearer token, with the base URL above. If it is
            lost, revoke it and issue a new one.
          </p>
          <button type="button" className={btnSecondary} onClick={() => setMinted(null)}>
            I have stored the token
          </button>
        </div>
      )}

      <div className="space-y-3">
        <h4 className="font-medium text-gray-900 dark:text-gray-100 flex items-center gap-2"><KeyRound className="w-4 h-4" /> Tokens</h4>
        <form className="flex flex-wrap gap-2 items-end"
          onSubmit={(e) => { e.preventDefault(); if (!mintReason) mint.mutate(); }}>
          <div className="flex-1 min-w-[12rem]">
            <label htmlFor="scim-token-name" className={labelCls}>Name</label>
            <input id="scim-token-name" className={inputCls} value={name} disabled={Boolean(mintReason)} title={mintReason ?? undefined}
              placeholder="e.g. Okta production" onChange={(e) => setName(e.target.value)} />
          </div>
          <div className="w-40">
            <label htmlFor="scim-token-days" className={labelCls}>Expires in (days)</label>
            <input id="scim-token-days" type="number" min={1} max={730} className={inputCls} value={days}
              disabled={Boolean(mintReason)} placeholder="never" onChange={(e) => setDays(e.target.value)} />
          </div>
          <button type="submit" className={btnPrimary} disabled={Boolean(mintReason) || !name.trim() || daysInvalid || mint.isPending}
            title={mintReason ?? (daysInvalid ? 'Expiry must be 1 to 730 days, or blank for none.' : undefined)}>
            {mint.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />} Issue token
          </button>
        </form>
        {mintReason && <p className="text-xs text-gray-500">{mintReason}</p>}
        {daysInvalid && <p className="text-xs text-red-600">Expiry must be a whole number of days from 1 to 730, or blank for none.</p>}
        <ActionError error={mint.error} />
        <ActionError error={revoke.error} />

        {tokens.isLoading ? (
          <p className="text-sm text-gray-500 flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" /> Loading tokens...</p>
        ) : tokens.data && tokens.data.items.length === 0 ? (
          <p className="text-sm text-gray-500">No SCIM tokens issued. The identity provider cannot provision until one is.</p>
        ) : tokens.data ? (
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead className="text-left text-xs uppercase text-gray-500">
                <tr><th className="py-2 pr-3">Name</th><th className="pr-3">Prefix</th><th className="pr-3">Status</th><th className="pr-3">Created</th><th className="pr-3">Last used</th><th className="pr-3">Expires</th><th /></tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-700 text-gray-800 dark:text-gray-200">
                {tokens.data.items.map((t) => (
                  <tr key={t.id}>
                    <td className="py-2 pr-3">{t.name}</td>
                    <td className="pr-3"><code className="text-xs">{t.token_prefix}...</code></td>
                    <td className="pr-3">
                      <Chip tone={t.status === 'active' ? 'green' : t.status === 'expired' ? 'amber' : 'gray'}>{t.status}</Chip>
                    </td>
                    <td className="pr-3 text-xs">{fmtDate(t.created_at)}</td>
                    <td className="pr-3 text-xs">{t.last_used_at ? fmtDate(t.last_used_at) : 'never'}</td>
                    <td className="pr-3 text-xs">{t.expires_at ? fmtDate(t.expires_at) : 'never'}</td>
                    <td className="text-right">
                      <button type="button" className={btnDanger} disabled={t.status === 'revoked' || revoke.isPending}
                        title={t.status === 'revoked' ? `Revoked ${fmtDate(t.revoked_at)}` : undefined}
                        onClick={() => { if (confirm(`Revoke "${t.name}"? The identity provider's next call with it fails.`)) revoke.mutate(t.id); }}>
                        <XCircle className="w-4 h-4" /> Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>

      <div className="space-y-3">
        <h4 className="font-medium text-gray-900 dark:text-gray-100">Groups pushed by the identity provider</h4>
        <p className="text-xs text-gray-500">
          A group maps to a role; its members receive that role, recomputed as soon as the mapping changes. With an
          SSO configuration the mapping is stored in its group-to-role map (keyed by the group name), otherwise on the
          group record.
        </p>
        {roles.error ? (
          <p className="text-xs text-amber-700 dark:text-amber-300">
            Custom roles could not be listed, so only built-in roles are offered. {describeIdentityError(roles.error)}
          </p>
        ) : null}
        <LoadErrorBanner what="SCIM groups" error={groups.error} />
        {groups.isLoading ? (
          <p className="text-sm text-gray-500 flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" /> Loading groups...</p>
        ) : groups.data && groups.data.items.length === 0 ? (
          <p className="text-sm text-gray-500">No groups pushed yet. They appear once the identity provider pushes groups over SCIM.</p>
        ) : groups.data ? (
          <div className="space-y-2">
            {groups.data.items.map((g) => (
              <GroupRow key={g.id} group={g} custom={roles.custom} lockReason={gate.isFullAdmin ? null : FULL_ADMIN_ONLY_REASON}
                onSaved={() => {
                  qc.invalidateQueries({ queryKey: ['identity', 'scim', 'groups'] });
                  qc.invalidateQueries({ queryKey: ['identity', 'sso'] });
                  qc.invalidateQueries({ queryKey: ['identity', 'roles'] });
                }} />
            ))}
          </div>
        ) : null}
      </div>

      <div className="space-y-3">
        <h4 className="font-medium text-gray-900 dark:text-gray-100">Link local accounts to the identity provider</h4>
        <p className="text-xs text-gray-500">
          Linking hands an existing local account to SCIM (identity source becomes <em>scim</em>): from then on the
          provider manages its email, activation and role. Unlinking returns it to local management; an account SCIM
          created then has no usable password until a password reset.
        </p>
        <LoadErrorBanner what="users" error={users.error} />
        {users.isLoading ? (
          <p className="text-sm text-gray-500 flex items-center gap-2"><Loader2 className="w-4 h-4 animate-spin" /> Loading users...</p>
        ) : users.data ? (
          <>
            {users.data.total > users.data.items.length && (
              <p className="text-xs text-gray-500">
                Showing the first {users.data.items.length} of {users.data.total} users; the Users page offers the same control for every account.
              </p>
            )}
            <div className="divide-y divide-gray-200 dark:divide-gray-700">
              {users.data.items.filter((u) => !u.is_superuser).map((u) => (
                <div key={u.id} className="py-2 flex flex-wrap items-center gap-3 justify-between">
                  <div className="text-sm text-gray-800 dark:text-gray-200">
                    {u.email}{' '}
                    <Chip tone={u.identity_source === 'scim' ? 'blue' : u.identity_source === 'oidc' ? 'amber' : 'gray'}>
                      {u.identity_source ?? 'local'}
                    </Chip>
                    {!u.is_active && <> <Chip tone="red">inactive</Chip></>}
                  </div>
                  <ScimLinkControl user={u} compact onChanged={() => qc.invalidateQueries({ queryKey: ['identity', 'scim', 'users'] })} />
                </div>
              ))}
            </div>
          </>
        ) : null}
      </div>
    </section>
  );
}

function GroupRow({
  group,
  custom,
  lockReason,
  onSaved,
}: {
  group: SCIMGroup;
  custom: ReturnType<typeof useCustomRoles>['custom'];
  lockReason: string | null;
  onSaved: () => void;
}) {
  const [role, setRole] = useState(group.role ?? '');
  const save = useMutation({
    mutationFn: () => identityApi.setScimGroupRole(group.id, role || null),
    onSuccess: onSaved,
  });
  const changed = (group.role ?? '') !== role;
  return (
    <div className="rounded border border-gray-200 dark:border-gray-700 p-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-sm text-gray-800 dark:text-gray-200">
        <span className="font-medium">{group.display_name}</span>
        <Chip tone="gray">{group.member_count} member(s)</Chip>
        {group.role ? <Chip tone="blue">maps to {roleLabel(group.role, custom)}</Chip> : <Chip tone="amber">unmapped</Chip>}
        {group.mapping_source && <span className="text-xs text-gray-500">stored in {group.mapping_source}</span>}
        {group.mapping_error && <Chip tone="red">mapping broken: {group.mapping_error}</Chip>}
      </div>
      <div className="flex gap-2 items-center">
        <RoleSelect value={role} onChange={setRole} custom={custom} allowNone disabled={Boolean(lockReason)} title={lockReason ?? undefined} />
        <button type="button" className={btnSecondary} disabled={Boolean(lockReason) || !changed || save.isPending}
          title={lockReason ?? undefined} onClick={() => save.mutate()}>
          {save.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />} Save mapping
        </button>
      </div>
      <ActionError error={save.error} />
    </div>
  );
}
