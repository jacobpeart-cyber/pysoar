import { useAuth } from '../contexts/AuthContext';

/**
 * The caller's role as the backend gates it: superusers pass every
 * organisation role check, `admin` > `analyst` > `viewer`. Pages use this to
 * render a control disabled with the reason instead of letting the request
 * come back 403.
 */
export interface RoleGate {
  role: string | null;
  isAdmin: boolean;
  isAnalyst: boolean;
}

export function roleGate(role?: string | null, isSuperuser?: boolean | null): RoleGate {
  const r = role ?? null;
  const isAdmin = Boolean(isSuperuser) || r === 'admin';
  return { role: r, isAdmin, isAnalyst: isAdmin || r === 'analyst' };
}

export function useRoleGate(): RoleGate {
  const { user } = useAuth();
  return roleGate(user?.role, user?.is_superuser);
}

export const ADMIN_ONLY_REASON = 'Requires the admin role.';
export const ANALYST_ONLY_REASON = 'Requires the analyst or admin role (viewers are read-only).';
