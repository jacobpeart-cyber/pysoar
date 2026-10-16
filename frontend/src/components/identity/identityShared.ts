import { useQuery } from '@tanstack/react-query';
import { identityApi } from '../../api/endpoints';
import type { CustomRole } from '../../api/endpoints';

export const BUILTIN_ROLES = ['admin', 'analyst', 'viewer'] as const;

export const inputCls =
  'w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60 disabled:cursor-not-allowed';
export const labelCls = 'block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1';
export const btnPrimary =
  'inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed';
export const btnSecondary =
  'inline-flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed';
export const btnDanger =
  'inline-flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-lg border border-red-300 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50 disabled:cursor-not-allowed';

export function fmtDate(value: string | null | undefined): string {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

/**
 * The organisation's custom roles for role pickers. GET /roles needs admin
 * tier in `roles`; when it fails the pickers fall back to the built-ins and
 * the caller shows `error` (never an invented list).
 */
export function useCustomRoles(enabled = true) {
  const q = useQuery({
    queryKey: ['identity', 'roles'],
    queryFn: identityApi.listRoles,
    enabled,
    retry: false,
  });
  const custom: CustomRole[] = q.data?.custom ?? [];
  return { custom, error: q.error, isLoading: q.isLoading, data: q.data };
}

/** Label for a stored role value: a built-in name, or a custom role id / name. */
export function roleLabel(value: string | null | undefined, custom: CustomRole[]): string {
  if (!value) return 'none';
  if ((BUILTIN_ROLES as readonly string[]).includes(value)) return value;
  const byId = custom.find((r) => r.id === value);
  if (byId) return `${byId.name} (custom)`;
  const byName = custom.find((r) => r.name === value);
  return byName ? `${byName.name} (custom)` : value;
}

