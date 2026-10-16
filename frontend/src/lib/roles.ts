import { useAuth } from '../contexts/AuthContext';

/**
 * The caller's role as the backend gates it: superusers pass every
 * organisation role check, `admin` > `analyst` > `viewer`. Pages use this to
 * render a control disabled with the reason instead of letting the request
 * come back 403.
 *
 * A custom-role holder's built-in `role` is floored to `viewer`; what they may
 * do is decided per area by the role's tiers (src/identity/roles.py), which
 * the client does not know. `hasCustomRole` lets a page offer the control and
 * render the server's `insufficient_tier` / `area_denied` answer instead of
 * hiding something the role may grant.
 */
export interface RoleGate {
  role: string | null;
  isAdmin: boolean;
  isAnalyst: boolean;
  /** Built-in admin without a custom role, or the platform superuser. */
  isFullAdmin: boolean;
  hasCustomRole: boolean;
}

export function roleGate(
  role?: string | null,
  isSuperuser?: boolean | null,
  customRoleId?: string | null,
): RoleGate {
  const r = role ?? null;
  const hasCustomRole = Boolean(customRoleId);
  const isAdmin = Boolean(isSuperuser) || r === 'admin';
  return {
    role: r,
    isAdmin,
    isAnalyst: isAdmin || r === 'analyst',
    isFullAdmin: Boolean(isSuperuser) || (r === 'admin' && !hasCustomRole),
    hasCustomRole,
  };
}

export function useRoleGate(): RoleGate {
  const { user } = useAuth();
  return roleGate(user?.role, user?.is_superuser, user?.custom_role_id);
}

export const ADMIN_ONLY_REASON = 'Requires the admin role.';
export const ANALYST_ONLY_REASON = 'Requires the analyst or admin role (viewers are read-only).';
export const FULL_ADMIN_ONLY_REASON =
  'Requires the built-in admin role without a custom role: whoever controls this decides which identities (administrators included) can sign in.';
