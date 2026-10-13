import { describeLoadError } from '../lib/loadError';

/**
 * The inline error strip ChatWorkbench renders above its message list,
 * shared so data pages show the same honest failure state instead of an
 * empty list when a request fails.
 */
export default function LoadErrorBanner({ what, error }: { what: string; error: unknown }) {
  if (!error) return null;
  return (
    <div
      role="alert"
      className="text-sm text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3"
    >
      Could not load {what}. {describeLoadError(error)}
    </div>
  );
}
