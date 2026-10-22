import { useEffect, useState, type FormEvent } from 'react';
import { Loader2, X } from 'lucide-react';
import ActionErrorBanner from '../ActionErrorBanner';
import type { InstalledIntegration } from './types';

export interface WebhookCreateBody {
  endpoint_path: string;
  http_method: string;
  event_types: string[];
  secret?: string;
  transform_template?: string;
}

interface Props {
  open: boolean;
  installed: InstalledIntegration[];
  /** Pre-selects this install (the create button of one integration's group). */
  initialIntegrationId?: string | null;
  onClose: () => void;
  /** Throws the request error; the modal shows it and stays open. */
  onCreate: (integrationId: string, body: WebhookCreateBody) => Promise<void>;
}

const INPUT =
  'w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100';
const LABEL = 'block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1';
const HELP = 'mt-1 text-xs text-gray-500 dark:text-gray-400';
// The column is String(10); these are the methods an inbound sender would use.
const METHODS = ['POST', 'PUT', 'PATCH'];

/**
 * Registers a webhook endpoint on an installed integration
 * (`POST /integrations/installed/{id}/webhooks`, admin). The fields are the
 * request schema's (src/schemas/integrations.py WebhookRegisterRequest).
 * PySOAR has no inbound receiver yet, so the stored endpoint receives
 * nothing until one exists; the modal says so rather than implying delivery.
 */
export default function WebhookFormModal({ open, installed, initialIntegrationId, onClose, onCreate }: Props) {
  const [integrationId, setIntegrationId] = useState('');
  const [path, setPath] = useState('');
  const [method, setMethod] = useState('POST');
  const [events, setEvents] = useState('');
  const [secret, setSecret] = useState('');
  const [template, setTemplate] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    if (!open) return;
    setIntegrationId(initialIntegrationId ?? '');
    setPath('');
    setMethod('POST');
    setEvents('');
    setSecret('');
    setTemplate('');
    setLocalError(null);
    setError(null);
  }, [open, initialIntegrationId]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !submitting) onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose, submitting]);

  if (!open) return null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalError(null);
    setError(null);
    if (!integrationId) {
      setLocalError('Select an installed integration.');
      return;
    }
    if (!path.trim()) {
      setLocalError('Endpoint path is required.');
      return;
    }
    const eventTypes = events
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const body: WebhookCreateBody = { endpoint_path: path.trim(), http_method: method, event_types: eventTypes };
    if (secret) body.secret = secret;
    if (template.trim()) body.transform_template = template;
    setSubmitting(true);
    try {
      await onCreate(integrationId, body);
      onClose();
    } catch (err) {
      setError(err);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" aria-modal="true" role="dialog">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => !submitting && onClose()} />
      <div className="relative w-full max-w-lg bg-white dark:bg-gray-900 rounded-lg shadow-2xl border border-gray-200 dark:border-gray-700">
        <div className="flex items-start justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Create webhook endpoint</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              The endpoint is stored on the integration. PySOAR has no inbound webhook receiver yet, so nothing is
              delivered to it until one exists.
            </p>
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
        <form onSubmit={submit}>
          <div className="px-6 py-5 space-y-4 max-h-[60vh] overflow-y-auto">
            <div>
              <label htmlFor="wh-integration" className={LABEL}>
                Installed integration<span className="text-red-500 ml-1">*</span>
              </label>
              <select id="wh-integration" value={integrationId} onChange={(e) => setIntegrationId(e.target.value)} className={INPUT}>
                <option value="">Select an integration...</option>
                {installed.map((inst) => (
                  <option key={inst.id} value={inst.id}>
                    {inst.display_name || inst.connector_id}
                  </option>
                ))}
              </select>
              {installed.length === 0 && <p className={HELP}>No integrations installed. Install one from the Marketplace first.</p>}
            </div>
            <div>
              <label htmlFor="wh-path" className={LABEL}>
                Endpoint path<span className="text-red-500 ml-1">*</span>
              </label>
              <input id="wh-path" type="text" value={path} onChange={(e) => setPath(e.target.value)} maxLength={255} className={INPUT} />
            </div>
            <div>
              <label htmlFor="wh-method" className={LABEL}>
                HTTP method
              </label>
              <select id="wh-method" value={method} onChange={(e) => setMethod(e.target.value)} className={INPUT}>
                {METHODS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="wh-events" className={LABEL}>
                Event types
              </label>
              <input id="wh-events" type="text" value={events} onChange={(e) => setEvents(e.target.value)} className={INPUT} />
              <p className={HELP}>Comma-separated. Stored as given; nothing routes on them until an inbound receiver exists.</p>
            </div>
            <div>
              <label htmlFor="wh-secret" className={LABEL}>
                Shared secret
              </label>
              <input
                id="wh-secret"
                type="password"
                autoComplete="new-password"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                className={INPUT}
              />
              <p className={HELP}>Optional. Stored as a hash, never returned.</p>
            </div>
            <div>
              <label htmlFor="wh-template" className={LABEL}>
                Transform template
              </label>
              <textarea
                id="wh-template"
                rows={3}
                value={template}
                onChange={(e) => setTemplate(e.target.value)}
                className={`${INPUT} font-mono`}
              />
              <p className={HELP}>Optional Jinja2 template, stored with the endpoint.</p>
            </div>
            {localError && (
              <div
                role="alert"
                className="px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-300"
              >
                {localError}
              </div>
            )}
            <ActionErrorBanner what="create the webhook endpoint" error={error} />
          </div>
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
              disabled={submitting || installed.length === 0}
              className="px-4 py-2 text-sm font-medium text-white bg-cyan-600 rounded-lg hover:bg-cyan-700 disabled:opacity-50 flex items-center gap-2"
            >
              {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
              Create
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
