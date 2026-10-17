import clsx from 'clsx';

const PILL = 'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium w-fit';

const STATUS_STYLE: Record<string, { label: string; className: string; title: string }> = {
  implemented: {
    label: 'Implemented',
    className: 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-200',
    title: 'A connector class ships in this release: install, connection test and actions.',
  },
  log_ingest: {
    label: 'Log ingest',
    className: 'bg-blue-100 dark:bg-blue-900/40 text-blue-800 dark:text-blue-200',
    title: 'Installable log source polled by the SIEM; no actions and no connection test.',
  },
  planned: {
    label: 'Planned',
    className: 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200',
    title: 'Catalogue entry only: not installable in this release.',
  },
};

export function ImplementationBadge({ status }: { status: string }) {
  const s = STATUS_STYLE[status] ?? {
    label: status || 'unknown status',
    className: 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200',
    title: 'Status reported by the server.',
  };
  return (
    <span className={clsx(PILL, s.className)} title={s.title}>
      {s.label}
    </span>
  );
}

const HEALTH_STYLE: Record<string, { label: string; className: string }> = {
  healthy: { label: 'healthy', className: 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-200' },
  unhealthy: { label: 'unhealthy', className: 'bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-200' },
  unknown: { label: 'unknown', className: 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200' },
  unavailable: {
    label: 'unavailable: no connector implementation',
    className: 'bg-amber-100 dark:bg-amber-900/40 text-amber-800 dark:text-amber-200',
  },
};

export function HealthBadge({ health }: { health: string | null | undefined }) {
  const key = health || 'unknown';
  const s = HEALTH_STYLE[key] ?? { label: key, className: HEALTH_STYLE.unknown.className };
  return <span className={clsx(PILL, 'rounded-full px-3 py-1', s.className)}>{s.label}</span>;
}

export function SideEffectBadge() {
  return (
    <span
      className={clsx(PILL, 'bg-orange-100 dark:bg-orange-900/40 text-orange-800 dark:text-orange-200')}
      title="Changes state at the vendor (requires_approval)."
    >
      side effect
    </span>
  );
}

export function ExecutionStatusBadge({ status }: { status: string | null | undefined }) {
  const s = status || 'unknown';
  const className =
    s === 'success'
      ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100'
      : s === 'failed' || s === 'error' || s === 'timeout'
        ? 'bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100'
        : s === 'running' || s === 'pending'
          ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-100'
          : 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100';
  return <span className={clsx('px-3 py-1 rounded-full text-xs font-medium', className)}>{s}</span>;
}
