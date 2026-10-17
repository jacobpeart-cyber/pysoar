import { useEffect, useState, FormEvent } from 'react';
import { X, Loader2 } from 'lucide-react';
import ActionErrorBanner from '../ActionErrorBanner';
import type { Connector, ConnectorField, InstalledIntegration } from './types';
import { errorBody, httpStatusOf } from './types';

/**
 * Install or configure form for one connector, generated from the
 * catalogue's `config_fields` and `credential_fields`.
 *
 * FormModal (components/FormModal.tsx) has no password inputs and no
 * per-field server errors, so this keeps its layout and adds both: a 422
 * `missing_fields` / `invalid_fields` marks the named inputs, anything else
 * (501 `not_implemented`, 409, 403) is an ActionErrorBanner with the server's
 * code and detail.
 *
 * Configure mode (an `installation` is given): the server never returns
 * credentials and returns `config` as `{}`, so every input starts blank (or
 * at the returned value) and only the inputs the user fills in are sent;
 * the PATCH merges them over the stored values.
 */
interface Props {
  open: boolean;
  connector: Connector | null;
  installation?: InstalledIntegration | null;
  onClose: () => void;
  onInstall: (body: {
    connector_id: string;
    display_name: string;
    config: Record<string, unknown>;
    credentials: Record<string, unknown>;
  }) => Promise<unknown>;
  onUpdate: (
    id: string,
    body: { display_name?: string; config?: Record<string, unknown>; credentials?: Record<string, unknown> },
  ) => Promise<unknown>;
}

const INPUT =
  'w-full px-3 py-2 text-sm border rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:ring-2 focus:ring-blue-500 focus:border-transparent';

function initialValue(field: ConnectorField, installation: InstalledIntegration | null | undefined): string {
  if (installation) {
    const v = field.secret ? undefined : installation.config?.[field.name];
    return v === undefined || v === null ? '' : String(v);
  }
  return field.default === undefined || field.default === null ? '' : String(field.default);
}

function coerce(field: ConnectorField, raw: string): unknown {
  if (field.type === 'integer' || field.type === 'number') {
    const n = Number(raw);
    return Number.isFinite(n) ? n : raw;
  }
  if (field.type === 'boolean') return raw === 'true';
  return raw;
}

export default function ConnectorFormModal({ open, connector, installation, onClose, onInstall, onUpdate }: Props) {
  const configuring = Boolean(installation);
  const [displayName, setDisplayName] = useState('');
  const [values, setValues] = useState<Record<string, string>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<unknown>(null);
  const [localError, setLocalError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const configFields = connector?.config_fields ?? [];
  const credentialFields = connector?.credential_fields ?? [];

  useEffect(() => {
    if (!open || !connector) return;
    setDisplayName(installation?.display_name || connector.display_name || connector.name);
    const seed: Record<string, string> = {};
    for (const f of [...connector.config_fields, ...connector.credential_fields]) {
      seed[keyOf(f, connector)] = initialValue(f, installation);
    }
    setValues(seed);
    setFieldErrors({});
    setError(null);
    setLocalError(null);
  }, [open, connector, installation]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !submitting) onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose, submitting]);

  if (!open || !connector) return null;

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLocalError(null);
    setFieldErrors({});
    if (!displayName.trim()) {
      setLocalError('Display name is required.');
      return;
    }
    const config: Record<string, unknown> = {};
    const credentials: Record<string, unknown> = {};
    const missing: Record<string, string> = {};
    for (const [fields, target, group] of [
      [configFields, config, 'config'],
      [credentialFields, credentials, 'credentials'],
    ] as const) {
      for (const f of fields) {
        const raw = (values[`${group}.${f.name}`] ?? '').trim();
        if (raw === '') {
          // Install: a required field must be given. Configure: blank keeps the stored value.
          if (!configuring && f.required) missing[f.name] = 'Required.';
          continue;
        }
        target[f.name] = coerce(f, raw);
      }
    }
    if (Object.keys(missing).length) {
      setFieldErrors(missing);
      return;
    }
    setSubmitting(true);
    try {
      if (installation) {
        const body: { display_name?: string; config?: Record<string, unknown>; credentials?: Record<string, unknown> } = {};
        if (displayName.trim() !== installation.display_name) body.display_name = displayName.trim();
        if (Object.keys(config).length) body.config = config;
        if (Object.keys(credentials).length) body.credentials = credentials;
        await onUpdate(installation.id, body);
      } else {
        await onInstall({ connector_id: connector.id, display_name: displayName.trim(), config, credentials });
      }
      onClose();
    } catch (err) {
      const body = errorBody(err);
      const code = typeof body?.error === 'string' ? body.error : null;
      if (httpStatusOf(err) === 422 && (code === 'missing_fields' || code === 'invalid_fields') && Array.isArray(body?.fields)) {
        const msg = code === 'missing_fields' ? 'Required by the connector.' : 'Invalid format.';
        const marked: Record<string, string> = {};
        for (const name of body.fields as unknown[]) marked[String(name)] = msg;
        setFieldErrors(marked);
      }
      setError(err);
    } finally {
      setSubmitting(false);
    }
  };

  const renderField = (f: ConnectorField, group: 'config' | 'credentials') => {
    const key = `${group}.${f.name}`;
    const problem = fieldErrors[f.name];
    const hint = configuring
      ? f.secret || group === 'credentials'
        ? 'Leave blank to keep the stored value.'
        : 'Leave blank to keep the stored value (stored config values are not returned by the server).'
      : null;
    return (
      <div key={key}>
        <label htmlFor={`cf-${key}`} className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
          {f.display_name || f.name}
          {f.required && !configuring && <span className="text-red-500 ml-1">*</span>}
          {f.secret && <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">(secret, write-only)</span>}
        </label>
        {f.type === 'boolean' ? (
          <select
            id={`cf-${key}`}
            value={values[key] ?? ''}
            onChange={(e) => setValues((p) => ({ ...p, [key]: e.target.value }))}
            className={`${INPUT} ${problem ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'}`}
          >
            <option value="">{configuring ? 'keep stored value' : 'not set'}</option>
            <option value="true">true</option>
            <option value="false">false</option>
          </select>
        ) : (
          <input
            id={`cf-${key}`}
            type={f.secret || f.type === 'password' ? 'password' : f.type === 'integer' || f.type === 'number' ? 'number' : 'text'}
            autoComplete={f.secret ? 'new-password' : 'off'}
            value={values[key] ?? ''}
            onChange={(e) => setValues((p) => ({ ...p, [key]: e.target.value }))}
            className={`${INPUT} ${problem ? 'border-red-500' : 'border-gray-300 dark:border-gray-600'}`}
            aria-invalid={problem ? true : undefined}
          />
        )}
        {f.description && <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{f.description}</p>}
        {!configuring && f.default !== undefined && f.default !== null && (
          <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">Default: {String(f.default)}</p>
        )}
        {hint && <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{hint}</p>}
        {problem && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{problem}</p>}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" aria-modal="true" role="dialog">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => !submitting && onClose()} />
      <div className="relative w-full max-w-lg bg-white dark:bg-gray-900 rounded-lg shadow-2xl border border-gray-200 dark:border-gray-700">
        <div className="flex items-start justify-between px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              {configuring ? `Configure ${installation?.display_name}` : `Install ${connector.display_name}`}
            </h2>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              Credentials are stored encrypted and never returned.
              {configuring ? ' Only the fields you fill in are changed.' : ''}
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
        <form onSubmit={handleSubmit}>
          <div className="px-6 py-5 space-y-4 max-h-[60vh] overflow-y-auto">
            <div>
              <label htmlFor="cf-display-name" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                Display name<span className="text-red-500 ml-1">*</span>
              </label>
              <input
                id="cf-display-name"
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                maxLength={255}
                className={`${INPUT} border-gray-300 dark:border-gray-600`}
              />
            </div>
            {configFields.length > 0 && (
              <fieldset className="space-y-4">
                <legend className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-2">
                  Configuration
                </legend>
                {configFields.map((f) => renderField(f, 'config'))}
              </fieldset>
            )}
            {credentialFields.length > 0 && (
              <fieldset className="space-y-4">
                <legend className="text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-2">
                  Credentials
                </legend>
                {credentialFields.map((f) => renderField(f, 'credentials'))}
              </fieldset>
            )}
            {configFields.length === 0 && credentialFields.length === 0 && (
              <p className="text-sm text-gray-500 dark:text-gray-400">This connector declares no configuration or credential fields.</p>
            )}
            {localError && (
              <div role="alert" className="px-3 py-2 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 text-sm text-red-700 dark:text-red-300">
                {localError}
              </div>
            )}
            <ActionErrorBanner what={configuring ? 'save the configuration' : 'install the connector'} error={error} />
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
              disabled={submitting}
              className="px-4 py-2 text-sm font-medium text-white bg-cyan-600 rounded-lg hover:bg-cyan-700 disabled:opacity-50 flex items-center gap-2"
            >
              {submitting && <Loader2 className="w-4 h-4 animate-spin" />}
              {configuring ? 'Save' : 'Install'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function keyOf(f: ConnectorField, connector: Connector): string {
  return connector.config_fields.includes(f) ? `config.${f.name}` : `credentials.${f.name}`;
}
