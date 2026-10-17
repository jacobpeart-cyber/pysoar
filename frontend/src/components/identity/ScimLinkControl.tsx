import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Link2, Unlink, Loader2 } from 'lucide-react';
import { identityApi } from '../../api/endpoints';
import { useRoleGate, FULL_ADMIN_ONLY_REASON } from '../../lib/roles';
import { useAuth } from '../../contexts/AuthContext';
import { btnSecondary, inputCls } from './identityShared';
import { ActionError } from './IdentityUI';

/**
 * "Link to SCIM" / "Unlink" for one account (POST / DELETE
 * /settings/scim/users/{id}/link). The identity provider can neither create
 * nor manage a pre-existing local account until an administrator links it;
 * unlinking returns it to local management (an account SCIM created then has
 * no usable password until a password reset). Built-in admin only.
 */
export default function ScimLinkControl({
  user,
  onChanged,
  compact,
}: {
  user: { id: string; email: string; identity_source?: string; is_active: boolean; is_superuser?: boolean };
  onChanged: () => void;
  compact?: boolean;
}) {
  const gate = useRoleGate();
  const { user: me } = useAuth();
  const [externalId, setExternalId] = useState('');
  const source = user.identity_source ?? 'local';
  const link = useMutation({
    mutationFn: () => identityApi.linkScimUser(user.id, externalId.trim() || null),
    onSuccess: () => { setExternalId(''); onChanged(); },
  });
  const unlink = useMutation({
    mutationFn: () => identityApi.unlinkScimUser(user.id),
    onSuccess: onChanged,
  });

  if (user.is_superuser) {
    return <span className="text-xs text-gray-500">The platform superuser is never managed through SCIM.</span>;
  }
  if (source === 'oidc' || source === 'saml') {
    return <span className="text-xs text-gray-500">Provisioned by SSO sign-in; SCIM linking applies to local accounts.</span>;
  }
  const lockReason = !gate.isFullAdmin ? FULL_ADMIN_ONLY_REASON : null;

  if (source === 'scim') {
    const selfReason = me?.id === user.id ? 'You cannot take your own account out of identity-provider management; ask another admin.' : null;
    const reason = lockReason ?? selfReason;
    return (
      <div className="space-y-1">
        <button type="button" className={btnSecondary} disabled={Boolean(reason) || unlink.isPending} title={reason ?? undefined}
          onClick={() => {
            if (confirm(`Return ${user.email} to local management? SCIM will no longer change its email, status or role. An account SCIM created has no usable password until a password reset.`)) unlink.mutate();
          }}>
          {unlink.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Unlink className="w-4 h-4" />} Unlink from SCIM
        </button>
        {reason && !compact && <p className="text-xs text-gray-500">{reason}</p>}
        <ActionError error={unlink.error} />
      </div>
    );
  }

  const inactiveReason = !user.is_active ? 'Reactivate the account before linking it.' : null;
  const reason = lockReason ?? inactiveReason;
  return (
    <div className="space-y-1">
      <div className="flex gap-2 items-center">
        {!compact && (
          <input aria-label="IdP externalId (optional)" className={inputCls} placeholder="IdP externalId (optional)"
            value={externalId} disabled={Boolean(reason)} onChange={(e) => setExternalId(e.target.value)} />
        )}
        <button type="button" className={btnSecondary} disabled={Boolean(reason) || link.isPending} title={reason ?? undefined}
          onClick={() => {
            if (confirm(`Hand ${user.email} to the identity provider? SCIM will then manage its email, activation and role (through mapped groups).`)) link.mutate();
          }}>
          {link.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Link2 className="w-4 h-4" />} Link to SCIM
        </button>
      </div>
      {reason && !compact && <p className="text-xs text-gray-500">{reason}</p>}
      <ActionError error={link.error} />
    </div>
  );
}
