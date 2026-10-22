import { useEffect, useState } from 'react';
import { Loader2, Play } from 'lucide-react';
import clsx from 'clsx';
import DetailDrawer, { DetailSection } from '../DetailDrawer';
import LoadErrorBanner from '../LoadErrorBanner';
import ActionErrorBanner from '../ActionErrorBanner';
import { ExecutionStatusBadge, SideEffectBadge } from './Badges';
import ServerMessage from './ServerMessage';
import { buildInputData, inputKind, isRequired, schemaProperties } from './schemaForm';
import type { InstalledAction, InstalledIntegration, IntegrationExecution } from './types';
import { errorBody, formatJson, httpStatusOf } from './types';
import { ADMIN_ONLY_REASON, ANALYST_ONLY_REASON } from '../../lib/roles';

interface Props {
  installation: InstalledIntegration | null;
  isAdmin: boolean;
  isAnalyst: boolean;
  onClose: () => void;
  loadActions: (integrationId: string) => Promise<InstalledAction[]>;
  execute: (integrationId: string, actionId: string, input: Record<string, unknown>) => Promise<IntegrationExecution>;
  /** Called after a run so the Executions tab and health refresh. */
  onExecuted: () => void;
  onShowExecutions: () => void;
}

const INPUT =
  'w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100';

/**
 * Runs an installed integration's declared actions. The form is generated
 * from the action's `input_schema` (the connector's params_schema); the
 * result shown is the execution row the server recorded.
 */
export default function ActionRunnerDrawer({
  installation,
  isAdmin,
  isAnalyst,
  onClose,
  loadActions,
  execute,
  onExecuted,
  onShowExecutions,
}: Props) {
  const [actions, setActions] = useState<InstalledAction[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [selected, setSelected] = useState<InstalledAction | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<IntegrationExecution | null>(null);
  const [runError, setRunError] = useState<unknown>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [approvalMessage, setApprovalMessage] = useState<string | null>(null);

  const installationId = installation?.id ?? null;

  useEffect(() => {
    if (!installationId) return;
    let cancelled = false;
    setActions([]);
    setSelected(null);
    setResult(null);
    setRunError(null);
    setProblems([]);
    setApprovalMessage(null);
    setLoadError(null);
    setLoading(true);
    loadActions(installationId)
      .then((items) => {
        if (!cancelled) setActions(items);
      })
      .catch((err) => {
        if (!cancelled) setLoadError(err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [installationId, loadActions]);

  const pick = (a: InstalledAction) => {
    setSelected(a);
    const seed: Record<string, string> = {};
    for (const [name, prop] of schemaProperties(a.input_schema)) {
      seed[name] = prop.default === undefined || prop.default === null ? '' : String(prop.default);
    }
    setValues(seed);
    setResult(null);
    setRunError(null);
    setProblems([]);
    setApprovalMessage(null);
  };

  const needsAdmin = (a: InstalledAction) => a.requires_approval && !isAdmin;

  const run = async () => {
    if (!installation || !selected) return;
    setResult(null);
    setRunError(null);
    setApprovalMessage(null);
    const built = buildInputData(selected.input_schema, values);
    setProblems(built.problems);
    if (built.problems.length) return;
    setRunning(true);
    try {
      const exec = await execute(installation.id, selected.id, built.data);
      setResult(exec);
      onExecuted();
    } catch (err) {
      const body = errorBody(err);
      const code = typeof body?.error === 'string' ? body.error : null;
      const status = httpStatusOf(err);
      // A server-side 422 invalid_parameters lists its `problems` through
      // ActionErrorBanner (describeActionError); `problems` here holds only
      // the form's own checks before the request.
      if (status === 403 && code === 'approval_required') {
        const why = typeof body?.detail === 'string' ? body.detail : typeof body?.message === 'string' ? body.message : null;
        setApprovalMessage(
          `This action changes state at the vendor and needs an administrator.${why ? ` ${why}` : ''}`,
        );
      } else {
        setRunError(err);
      }
    } finally {
      setRunning(false);
    }
  };

  const actionList = (
    <div className="space-y-2">
      <LoadErrorBanner what="the declared actions" error={loadError} />
      {loading && <p className="text-sm text-gray-500 dark:text-gray-400">Loading actions...</p>}
      {!loading && !loadError && actions.length === 0 && (
        <p className="text-sm text-gray-500 dark:text-gray-400">
          This integration&apos;s connector declares no actions (log-ingest sources and planned connectors have none).
        </p>
      )}
      {actions.map((a) => (
        <button
          key={a.id}
          type="button"
          onClick={() => pick(a)}
          className={clsx(
            'w-full text-left border rounded-lg px-3 py-2 transition',
            selected?.id === a.id
              ? 'border-cyan-600 bg-cyan-50 dark:bg-cyan-900/20'
              : 'border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800',
          )}
        >
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm">{a.action_name}</span>
            {a.requires_approval && <SideEffectBadge />}
            {a.is_idempotent && <span className="text-xs text-gray-500 dark:text-gray-400">idempotent</span>}
            {needsAdmin(a) && (
              <span className="text-xs text-amber-700 dark:text-amber-300">needs an administrator</span>
            )}
          </div>
          {a.description && <p className="text-xs text-gray-600 dark:text-gray-400 mt-1">{a.description}</p>}
        </button>
      ))}
    </div>
  );

  const runBlocked = !selected || running || !isAnalyst || (selected ? needsAdmin(selected) : false);
  const runTitle = !isAnalyst
    ? ANALYST_ONLY_REASON
    : selected && needsAdmin(selected)
      ? `${ADMIN_ONLY_REASON} This action changes state at the vendor.`
      : undefined;

  const paramForm = selected ? (
    <form
      className="space-y-3"
      onSubmit={(e) => {
        e.preventDefault();
        void run();
      }}
    >
      {schemaProperties(selected.input_schema).length === 0 && (
        <p className="text-sm text-gray-500 dark:text-gray-400">This action takes no parameters.</p>
      )}
      {schemaProperties(selected.input_schema).map(([name, prop]) => {
        const kind = inputKind(prop);
        const id = `param-${name}`;
        const set = (v: string) => setValues((p) => ({ ...p, [name]: v }));
        return (
          <div key={name}>
            <label htmlFor={id} className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              <span className="font-mono">{name}</span>
              {isRequired(selected.input_schema, name) && <span className="text-red-500 ml-1">*</span>}
              <span className="ml-2 text-xs text-gray-500 dark:text-gray-400">
                {prop.type === 'array' ? `array of ${prop.items?.type ?? 'values'}` : prop.type ?? 'value'}
              </span>
            </label>
            {kind === 'enum' ? (
              <select id={id} value={values[name] ?? ''} onChange={(e) => set(e.target.value)} className={INPUT}>
                <option value="">not set</option>
                {(prop.enum ?? []).map((v) => (
                  <option key={String(v)} value={String(v)}>
                    {String(v)}
                  </option>
                ))}
              </select>
            ) : kind === 'boolean' ? (
              <select id={id} value={values[name] ?? ''} onChange={(e) => set(e.target.value)} className={INPUT}>
                <option value="">not set</option>
                <option value="true">true</option>
                <option value="false">false</option>
              </select>
            ) : kind === 'json' ? (
              <textarea
                id={id}
                rows={4}
                value={values[name] ?? ''}
                onChange={(e) => set(e.target.value)}
                className={`${INPUT} font-mono`}
                placeholder={prop.type === 'array' ? 'JSON array' : 'JSON object'}
              />
            ) : (
              <input
                id={id}
                type={kind === 'number' ? 'number' : 'text'}
                min={prop.minimum}
                max={prop.maximum}
                value={values[name] ?? ''}
                onChange={(e) => set(e.target.value)}
                className={INPUT}
                placeholder={kind === 'list' ? 'comma-separated' : undefined}
              />
            )}
            {(prop.description || prop.minimum !== undefined || prop.maximum !== undefined) && (
              <p className="mt-1 text-xs text-gray-500 dark:text-gray-400">
                {prop.description}
                {prop.minimum !== undefined || prop.maximum !== undefined
                  ? ` Range: ${prop.minimum ?? '-'} to ${prop.maximum ?? '-'}.`
                  : ''}
              </p>
            )}
          </div>
        );
      })}
      {problems.length > 0 && (
        <div role="alert" className="text-sm text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
          <p>The parameters were refused before sending:</p>
          <ul className="list-disc ml-5 mt-1 space-y-0.5">
            {problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        </div>
      )}
      {approvalMessage && (
        <div role="alert" className="text-sm text-amber-800 dark:text-amber-200 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded p-3">
          {approvalMessage}
        </div>
      )}
      <ActionErrorBanner what={`run ${selected.action_name}`} error={runError} />
      <button
        type="submit"
        disabled={runBlocked}
        title={runTitle}
        className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-cyan-600 rounded-lg hover:bg-cyan-700 disabled:opacity-50"
      >
        {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
        Run {selected.action_name}
      </button>
      {runTitle && <p className="text-xs text-gray-500 dark:text-gray-400">{runTitle}</p>}
    </form>
  ) : (
    <p className="text-sm text-gray-500 dark:text-gray-400">Select an action above.</p>
  );

  const resultView = result ? (
    <div className="space-y-2 text-sm">
      <div className="flex items-center gap-3 flex-wrap">
        <ExecutionStatusBadge status={result.status} />
        <span>HTTP status: {result.http_status ?? 'none recorded'}</span>
        <span>Duration: {typeof result.duration_ms === 'number' ? `${result.duration_ms} ms` : 'not recorded'}</span>
      </div>
      {result.error_code && (
        <p>
          Error code: <span className="font-mono">{result.error_code}</span>
        </p>
      )}
      <ServerMessage text={result.error_message} className="text-red-700 dark:text-red-300 break-words" />
      <p className="text-xs text-gray-500 dark:text-gray-400 font-mono">execution {result.id}</p>
      {formatJson(result.output_data) ? (
        <pre className="text-xs bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-3 overflow-x-auto max-h-96 text-gray-800 dark:text-gray-200">
          {formatJson(result.output_data)}
        </pre>
      ) : (
        <p className="text-xs text-gray-500 dark:text-gray-400">No output data.</p>
      )}
    </div>
  ) : null;

  const sections: DetailSection[] = [
    { title: 'Declared actions', fields: [{ label: 'Pick one to run', value: actionList, full: true }] },
    {
      title: selected ? `Parameters · ${selected.action_name}` : 'Parameters',
      fields: [{ label: selected?.description || 'Generated from the action input schema', value: paramForm, full: true }],
    },
  ];
  if (resultView) sections.push({ title: 'Result', fields: [{ label: 'Recorded execution', value: resultView, full: true }] });

  return (
    <DetailDrawer
      open={!!installation}
      onClose={onClose}
      title={`Actions · ${installation?.display_name ?? ''}`}
      subtitle={installation ? installation.connector_id : undefined}
      sections={sections}
      actions={
        <button
          type="button"
          onClick={onShowExecutions}
          className="text-sm text-cyan-700 dark:text-cyan-400 hover:underline"
        >
          View all executions
        </button>
      }
    />
  );
}
