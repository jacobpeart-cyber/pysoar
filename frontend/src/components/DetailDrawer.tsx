import { useEffect } from 'react';
import { X } from 'lucide-react';

/**
 * Right-side slide-in drawer for record detail views.
 *
 * This is the ONE place in the app that renders structured detail panes so
 * individual pages don't fall back to window.alert(JSON.stringify(...)).
 * Pages pass either a pre-formatted ``fields`` list (preferred) or a ``raw``
 * object, which is rendered as a pretty-printed JSON block inside a real
 * styled container — not a browser alert.
 *
 * Close on: X button click, backdrop click, or ESC key.
 */
export interface DetailField {
  label: string;
  value: React.ReactNode;
  /** If true, render value in a monospace block (for IPs, hashes, CIDRs, etc.) */
  mono?: boolean;
  /** If true, span both columns (full width) */
  full?: boolean;
}

export interface DetailSection {
  title: string;
  fields: DetailField[];
}

interface DetailDrawerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  /** Structured field sections — preferred rendering path */
  sections?: DetailSection[];
  /** Fallback: dump any object as a formatted JSON block at the bottom */
  raw?: unknown;
  /** Optional action buttons rendered in the footer */
  actions?: React.ReactNode;
}

export default function DetailDrawer({
  open,
  onClose,
  title,
  subtitle,
  sections,
  raw,
  actions,
}: DetailDrawerProps) {
  // Close on ESC
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden" aria-modal="true" role="dialog">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
        aria-label="Close details"
      />

      {/* Drawer */}
      <div className="absolute right-0 top-0 h-full w-full max-w-2xl bg-white dark:bg-gray-900 shadow-2xl flex flex-col animate-slide-in-right">
        {/* Header */}
        <div className="flex items-start justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex-1 min-w-0">
            <h2 className="text-xl font-semibold text-gray-900 dark:text-white truncate">
              {title}
            </h2>
            {subtitle && (
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1 truncate">
                {subtitle}
              </p>
            )}
          </div>
          <button
            onClick={onClose}
            className="ml-4 p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-6">
          {sections?.map((section) => (
            <div key={section.title}>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-3">
                {section.title}
              </h3>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
                {section.fields.map((field, idx) => (
                  <div
                    key={`${section.title}-${idx}`}
                    className={field.full ? 'col-span-2' : undefined}
                  >
                    <dt className="text-xs font-medium text-gray-500 dark:text-gray-400">
                      {field.label}
                    </dt>
                    <dd
                      className={
                        field.mono
                          ? 'mt-1 font-mono text-sm text-gray-900 dark:text-gray-100 break-all'
                          : 'mt-1 text-sm text-gray-900 dark:text-gray-100 break-words'
                      }
                    >
                      {field.value === null ||
                      field.value === undefined ||
                      field.value === ''
                        ? '—'
                        : field.value}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          ))}

          {raw !== undefined && raw !== null && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-3">
                Raw Record
              </h3>
              <pre className="text-xs bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 overflow-x-auto text-gray-800 dark:text-gray-200">
                {JSON.stringify(raw, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        {actions && (
          <div className="border-t border-gray-200 dark:border-gray-700 px-6 py-4 flex items-center justify-end gap-2">
            {actions}
          </div>
        )}
      </div>
    </div>
  );
}
