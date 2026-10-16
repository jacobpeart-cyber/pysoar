import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import clsx from 'clsx';
import type { CustomRole } from '../../api/endpoints';
import { describeIdentityError } from './identityErrors';
import { BUILTIN_ROLES, btnSecondary, inputCls, labelCls } from './identityShared';

/** Inline failure strip for a mutation, with the server's key made readable. */
export function ActionError({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div
      role="alert"
      className="text-sm text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3"
    >
      {describeIdentityError(error)}
    </div>
  );
}

/** A read-only value with a copy control (clipboard may be refused outside https). */
export function CopyValue({ value, label }: { value: string; label: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState('copied');
    } catch {
      setState('failed');
    }
  };
  return (
    <div>
      <span className={labelCls}>{label}</span>
      <div className="flex items-center gap-2">
        <code className="flex-1 min-w-0 break-all text-xs px-3 py-2 rounded bg-gray-100 dark:bg-gray-900 text-gray-900 dark:text-gray-100">
          {value}
        </code>
        <button type="button" onClick={copy} className={btnSecondary} aria-label={`Copy ${label}`}>
          {state === 'copied' ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
          {state === 'copied' ? 'Copied' : 'Copy'}
        </button>
      </div>
      {state === 'failed' && (
        <p className="text-xs text-amber-700 dark:text-amber-300 mt-1">
          The browser refused clipboard access; select the value and copy it by hand.
        </p>
      )}
    </div>
  );
}

export function Chip({ tone, children }: { tone: 'green' | 'red' | 'amber' | 'gray' | 'blue'; children: React.ReactNode }) {
  return (
    <span
      className={clsx('inline-flex items-center px-2 py-0.5 rounded text-xs font-medium', {
        'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300': tone === 'green',
        'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300': tone === 'red',
        'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300': tone === 'amber',
        'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200': tone === 'gray',
        'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300': tone === 'blue',
      })}
    >
      {children}
    </span>
  );
}

/**
 * Select over built-ins plus custom roles. `value` may be a built-in name or a
 * custom role id or name (the SSO group map accepts both); an unknown stored
 * value stays selectable so it is never silently replaced.
 */
export function RoleSelect({
  value,
  onChange,
  custom,
  disabled,
  allowNone,
  id,
  title,
}: {
  value: string;
  onChange: (v: string) => void;
  custom: CustomRole[];
  disabled?: boolean;
  allowNone?: boolean;
  id?: string;
  title?: string;
}) {
  const known =
    !value ||
    (BUILTIN_ROLES as readonly string[]).includes(value) ||
    custom.some((r) => r.id === value || r.name === value);
  return (
    <select id={id} value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} title={title} className={inputCls}>
      {allowNone && <option value="">No mapping</option>}
      {BUILTIN_ROLES.map((r) => (
        <option key={r} value={r}>
          {r} (built-in)
        </option>
      ))}
      {custom.map((r) => (
        <option key={r.id} value={custom.some((c) => c.name === value && c.id === r.id) ? value : r.id}>
          {r.name} (custom)
        </option>
      ))}
      {!known && <option value={value}>{value} (not found)</option>}
    </select>
  );
}
