import { describeActionError } from '../lib/automationErrors';

/**
 * A refused action (run, save, validate) with the server's code and every
 * itemised reason it returned. Same styling as LoadErrorBanner.
 */
export default function ActionErrorBanner({ what, error }: { what: string; error: unknown }) {
  if (!error) return null;
  const { summary, items } = describeActionError(error);
  return (
    <div
      role="alert"
      className="text-sm text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3"
    >
      <p>
        Could not {what}. {summary}
      </p>
      {items.length > 0 && (
        <ul className="list-disc ml-5 mt-1 space-y-0.5">
          {items.map((m, i) => (
            <li key={i}>{m}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
