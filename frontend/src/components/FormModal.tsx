import { useEffect, useState, FormEvent } from 'react';
import { X, Loader2 } from 'lucide-react';

/**
 * Centered modal for structured create/edit forms.
 *
 * This is the replacement for chained window.prompt() calls. Pages define a
 * list of fields (text, textarea, select, number, date) and a submit handler.
 * The modal renders a proper form with labels, validation, a submit button
 * that shows loading state, and a cancel button.
 *
 * Close on: X, Cancel, backdrop click (unless submitting), or ESC.
 */
export interface FormField {
  name: string;
  label: string;
  type?: 'text' | 'textarea' | 'select' | 'number' | 'date' | 'email';
  required?: boolean;
  placeholder?: string;
  /** Options for type='select' */
  options?: Array<{ value: string; label: string }>;
  /** Default value (uncontrolled initial) */
  defaultValue?: string | number;
  /** Helper text under the field */
  help?: string;
}

interface FormModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: string;
  fields: FormField[];
  submitLabel?: string;
  /** Called with the form values. Must return a promise; modal waits. */
  onSubmit: (values: Record<string, string>) => Promise<void>;
}

export default function FormModal({
  open,
  onClose,
  title,
  description,
  fields,
  submitLabel = 'Save',
  onSubmit,
}: FormModalProps) {
  const [values, setValues] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Seed defaults every time the modal opens
  useEffect(() => {
    if (open) {
      const seed: Record<string, string> = {};
      for (const f of fields) {
        seed[f.name] = f.defaultValue !== undefined ? String(f.defaultValue) : '';
      }
      setValues(seed);
      setError(null);
    }
  }, [open, fields]);

  // ESC to close
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !submitting) onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose, submitting]);

  if (!open) return null;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    // Client-side required check
    for (const f of fields) {
      if (f.required && !values[f.name]?.toString().trim()) {
        setError(`${f.label} is required`);
        return;
      }
    }
    setError(null);
    setSubmitting(true);
    try {
      await onSubmit(values);
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err?.message || 'Submit failed');
    } finally {
      setSubmitting(false);
    }
  };

  const set = (name: string, v: string) =>
    setValues((prev) => ({ ...prev, [name]: v }));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" aria-modal="true" role="dialog">
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={() => !submitting && onClose()}
      />

      <div className="relative w-full max-w-lg bg-white dark:bg-gray-900 rounded-lg shadow-2xl border border-gray-200 dark:border-gray-700">
        {/* Header */}
        <div className="flex items-start justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              {title}
            </h2>
            {description && (
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                {description}
              </p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="ml-4 p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-200 rounded disabled:opacity-50"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit}>
          <div className="px-6 py-5 space-y-4 max-h-[60vh] overflow-y-auto">
            {fields.map((field) => (
              <div key={field.name}>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  {field.label}
                  {field.required && <span className="text-red-500 ml-1">*</span>}
                </label>

                {field.type === 'textarea' ? (
                  <textarea
                    value={values[field.name] || ''}
                    onChange={(e) => set(field.name, e.target.value)}
                    placeholder={field.placeholder}
                    rows={3}
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                ) : field.type === 'select' ? (
                  <select
                    value={values[field.name] || ''}
                    onChange={(e) => set(field.name, e.target.value)}
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  >
                    {!field.required && <option value="">—</option>}
                    {field.options?.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type={field.type || 'text'}
                    value={values[field.name] || ''}
                    onChange={(e) => set(field.name, e.target.value)}
                    placeholder={field.placeholder}
                    className="w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                )}

                {field.help && (
                  <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    {field.help}
                  </p>
                )}
              </div>
            ))}

            {error && (
              <div className="px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-300">
                {error}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="border-t border-gray-200 dark:border-gray-700 px-6 py-4 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
            >
              {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
              {submitLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
