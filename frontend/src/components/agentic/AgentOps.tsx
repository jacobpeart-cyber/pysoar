/**
 * Agentic SOC operations surfaces (wave 5): the run timeline drawer opened
 * from a run id, the trust lockdown acknowledgement, SOC agent create /
 * detail / edit, and the auditor panel (usage, policy events, evidence
 * export). Every panel renders exactly what the API returned; a failed
 * request shows the server's error key, never an empty list.
 */
import React, { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Download, Lock, X } from 'lucide-react';
import clsx from 'clsx';
import { agenticApi } from '../../api/endpoints';
import type { TrustHit } from '../../api/endpoints';
import type { Row } from '../../lib/apiRow';
import LoadErrorBanner from '../LoadErrorBanner';
import ActionErrorBanner from '../ActionErrorBanner';
import { parseBlobError, saveBlob, filenameFromDisposition } from '../../lib/download';
import { ADMIN_ONLY_REASON, ANALYST_ONLY_REASON } from '../../lib/roles';
import type { RoleGate } from '../../lib/roles';

const NA = 'not available';
const inputCls =
  'w-full px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-gray-100';
const btnPrimary =
  'px-3 py-2 text-sm rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed';
const btnSecondary =
  'px-3 py-2 text-sm rounded-lg border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-200 hover:bg-gray-50 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed';

const fmtTime = (v: unknown): string => (v ? new Date(String(v)).toLocaleString() : NA);
const fmtNum = (v: unknown): string => (typeof v === 'number' && Number.isFinite(v) ? v.toLocaleString() : NA);

const AGENT_TYPES = [
  'triage_analyst',
  'threat_hunter',
  'incident_responder',
  'forensic_analyst',
  'compliance_auditor',
  'vulnerability_analyst',
];
const AUTONOMY_LEVELS = ['advisory_only', 'human_in_loop', 'semi_auto', 'full_auto'];
const AGENT_STATUSES = ['idle', 'paused', 'investigating', 'reasoning', 'executing', 'awaiting_approval', 'error'];

const Gate: React.FC<{ reason: string | null }> = ({ reason }) =>
  reason ? <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">{reason}</p> : null;

const Shell: React.FC<{ title: string; subtitle?: string; onClose: () => void; children: React.ReactNode }> = ({
  title,
  subtitle,
  onClose,
  children,
}) => (
  <div className="fixed inset-0 z-50 flex justify-end bg-black/40" onClick={onClose}>
    <div
      role="dialog"
      aria-label={title}
      className="w-full max-w-3xl h-full overflow-y-auto bg-white dark:bg-gray-800 shadow-xl p-6 space-y-4"
      onClick={(e) => e.stopPropagation()}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
          {subtitle ? <p className="text-xs font-mono text-gray-500 dark:text-gray-400 break-all">{subtitle}</p> : null}
        </div>
        <button onClick={onClose} aria-label="Close" className="text-gray-500 hover:text-gray-800 dark:hover:text-gray-200">
          <X className="w-5 h-5" />
        </button>
      </div>
      {children}
    </div>
  </div>
);

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <section className="border border-gray-200 dark:border-gray-700 rounded-lg p-3">
    <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-2">{title}</h3>
    {children}
  </section>
);

const Empty: React.FC<{ text: string }> = ({ text }) => (
  <p className="text-xs text-gray-500 dark:text-gray-400">{text}</p>
);

/* --------------------------------------------------------- run timeline */

export const RunTimelineDrawer: React.FC<{ runId: string; gate: RoleGate; onClose: () => void }> = ({
  runId,
  gate,
  onClose,
}) => {
  const q = useQuery({
    queryKey: ['agentic-run', runId],
    queryFn: () => agenticApi.getRun(runId),
    enabled: gate.isAnalyst,
    retry: false,
  });
  const run: Row | undefined = q.data;
  const transcript: Row | null = run?.transcript ?? null;
  const steps: Row[] = Array.isArray(transcript?.steps) ? transcript.steps : [];
  const audit: Row[] = Array.isArray(run?.audit_events) ? run.audit_events : [];
  const calls: Row[] = Array.isArray(run?.llm_calls) ? run.llm_calls : [];
  const actions: Row[] = Array.isArray(run?.actions) ? run.actions : [];

  return (
    <Shell title="Run timeline" subtitle={runId} onClose={onClose}>
      {!gate.isAnalyst ? (
        <Empty text={`The run timeline is an auditor surface. ${ANALYST_ONLY_REASON}`} />
      ) : null}
      <LoadErrorBanner what="the run timeline" error={q.error} />
      {q.isLoading && gate.isAnalyst ? <Empty text="Loading run..." /> : null}
      {run ? (
        <>
          {run.truncated ? (
            <p className="text-xs text-amber-700 dark:text-amber-300">
              The server capped one or more lists of this run; older rows are not shown.
            </p>
          ) : null}
          <Section title="Totals">
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
              {(['audit_events', 'llm_calls', 'actions', 'chat_messages', 'billable_tokens'] as const).map((k) => (
                <div key={k}>
                  <div className="text-gray-500 dark:text-gray-400">{k.replace(/_/g, ' ')}</div>
                  <div className="font-semibold text-gray-900 dark:text-white">{fmtNum(run.totals?.[k])}</div>
                </div>
              ))}
            </div>
          </Section>
          <Section title="Transcript">
            {transcript ? (
              <div className="space-y-2 text-xs">
                <div className="grid grid-cols-2 gap-2">
                  <div>Mode: {transcript.mode ?? NA}</div>
                  <div>Outcome: {transcript.outcome ?? NA}</div>
                  <div>Provider: {transcript.provider ?? NA} {transcript.model ? `/ ${transcript.model}` : ''}</div>
                  <div>Tokens: {fmtNum(transcript.tokens_used)}</div>
                  <div>Trust tier: {transcript.injection_tier ?? NA}</div>
                  <div>Stop: {transcript.summary?.stop_reason ?? NA}</div>
                  <div>Started: {fmtTime(transcript.started_at)}</div>
                  <div>Finished: {fmtTime(transcript.finished_at)}</div>
                  {transcript.error_class ? (
                    <div className="col-span-2 text-red-700 dark:text-red-300">Error: {transcript.error_class}</div>
                  ) : null}
                </div>
                {steps.length === 0 ? (
                  <Empty text="This run recorded no tool steps." />
                ) : (
                  <ol className="space-y-1">
                    {steps.map((s, i) => (
                      <li key={`${s.tool_use_id || i}`} className="border border-gray-200 dark:border-gray-700 rounded p-2">
                        <div className="flex flex-wrap gap-2 items-center">
                          <span className="font-mono">#{s.step ?? i + 1}</span>
                          <span className="font-mono font-semibold">{s.tool ?? NA}</span>
                          <span className="px-1.5 rounded bg-gray-100 dark:bg-gray-700">{s.decision ?? NA}</span>
                          {s.reason_code ? <span className="text-gray-500">{s.reason_code}</span> : null}
                          <span
                            className={clsx(
                              'px-1.5 rounded',
                              s.is_error || s.success === false
                                ? 'bg-red-100 dark:bg-red-900/40 text-red-800 dark:text-red-200'
                                : 'bg-green-100 dark:bg-green-900/40 text-green-800 dark:text-green-200',
                            )}
                          >
                            {s.is_error ? 'error' : s.success === false ? 'not executed' : 'ok'}
                          </span>
                          {typeof s.duration_ms === 'number' ? <span className="text-gray-500">{s.duration_ms} ms</span> : null}
                        </div>
                        {s.args_preview ? (
                          <p className="mt-1 font-mono text-[11px] text-gray-600 dark:text-gray-400 break-all">args: {s.args_preview}</p>
                        ) : null}
                        {s.result_preview ? (
                          <p className="font-mono text-[11px] text-gray-600 dark:text-gray-400 break-all">result: {s.result_preview}</p>
                        ) : null}
                      </li>
                    ))}
                  </ol>
                )}
                {transcript.summary?.final_text ? (
                  <details>
                    <summary className="cursor-pointer text-gray-600 dark:text-gray-300">Final answer (redacted)</summary>
                    <p className="whitespace-pre-wrap mt-1">{transcript.summary.final_text}</p>
                  </details>
                ) : null}
              </div>
            ) : (
              <Empty text="No transcript was persisted for this run (it may have failed before the runtime recorded it)." />
            )}
          </Section>
          <Section title={`Provider calls (${calls.length})`}>
            {calls.length === 0 ? (
              <Empty text="No provider calls were logged for this run." />
            ) : (
              <table className="w-full text-xs">
                <thead className="text-left text-gray-500">
                  <tr><th>Time</th><th>Provider / model</th><th>Tokens</th><th>Latency</th><th>Stop</th></tr>
                </thead>
                <tbody>
                  {calls.map((c) => (
                    <tr key={c.id} className="border-t border-gray-100 dark:border-gray-700">
                      <td>{fmtTime(c.created_at)}</td>
                      <td>{c.provider}/{c.model}</td>
                      <td>{fmtNum(c.total_billable_tokens)}{c.usage_estimated ? ' (est.)' : ''}</td>
                      <td>{typeof c.latency_ms === 'number' ? `${c.latency_ms} ms` : NA}</td>
                      <td className={c.error_class ? 'text-red-700 dark:text-red-300' : ''}>{c.error_class || c.stop_reason || NA}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Section>
          <Section title={`Proposals (${actions.length})`}>
            {actions.length === 0 ? (
              <Empty text="This run raised no proposals." />
            ) : (
              <ul className="space-y-1 text-xs">
                {actions.map((a) => (
                  <li key={a.id} className="flex flex-wrap gap-2">
                    <span className="font-mono font-semibold">{a.tool_name}</span>
                    <span>{a.execution_status}</span>
                    {a.suspect ? <span className="text-amber-700 dark:text-amber-300">suspect</span> : null}
                    {a.approved_by ? <span>approved by {a.approved_by} ({a.approver_role ?? NA})</span> : null}
                    {a.rollback_executed ? <span>rolled back</span> : null}
                  </li>
                ))}
              </ul>
            )}
          </Section>
          <Section title={`Policy and tool audit rows (${audit.length})`}>
            {audit.length === 0 ? (
              <Empty text="No audit rows carry this run id." />
            ) : (
              <ul className="space-y-1 text-xs">
                {audit.map((e) => (
                  <li key={e.id} className="flex flex-wrap gap-2">
                    <span className="text-gray-500">{fmtTime(e.created_at)}</span>
                    <span className="font-mono">{e.event_type}/{e.action}</span>
                    <span className="font-mono">{e.resource_id}</span>
                    {e.payload?.reason_code ? <span>{String(e.payload.reason_code)}</span> : null}
                    <span>{e.result}</span>
                  </li>
                ))}
              </ul>
            )}
          </Section>
        </>
      ) : null}
    </Shell>
  );
};

/* --------------------------------------------------- trust acknowledgement */

/**
 * Lockdown exit. The analyst names a reason; the server re-scores the session
 * with the acknowledged hashes allow-listed and reports the tier it settled
 * on (normally `flagged`: proposals stay marked suspect). The banner shows
 * the server's answer, not an assumed one.
 */
export const TrustAcknowledge: React.FC<{
  sessionId: string | null | undefined;
  hits: TrustHit[];
  gate: RoleGate;
  onAcknowledged: (tier: string) => void;
}> = ({ sessionId, hits, gate, onAcknowledged }) => {
  const [reason, setReason] = useState('');
  const [recordHash, setRecordHash] = useState('');
  const m = useMutation({
    mutationFn: () =>
      agenticApi.acknowledgeTrust({
        session_id: sessionId || undefined,
        record_hash: recordHash || undefined,
        reason: reason.trim(),
      }),
    onSuccess: (data) => {
      const rows: Row[] = Array.isArray(data?.downgraded) ? data.downgraded : [];
      const mine = rows.find((r) => r.kind === 'chat_session');
      if (mine?.to) onAcknowledged(String(mine.to));
    },
  });
  const hashed = hits.filter((h) => h.snippet_sha256);
  const blocked = !sessionId
    ? 'This turn is not attached to a saved session, so there is no persisted trust state to acknowledge.'
    : !gate.isAnalyst
      ? ANALYST_ONLY_REASON
      : null;
  return (
    <div className="mt-2 border-t border-red-200 dark:border-red-800 pt-2 space-y-2">
      <p className="text-[11px] text-red-800 dark:text-red-200">
        After reading the flagged content you can acknowledge it. The session drops to flagged: write tools become
        admissible again, every proposal stays marked suspect, and the acknowledgement is audited.
      </p>
      {hashed.length > 1 ? (
        <select value={recordHash} onChange={(e) => setRecordHash(e.target.value)} className={inputCls} disabled={!!blocked}>
          <option value="">Acknowledge every hit in this session</option>
          {hashed.map((h) => (
            <option key={h.snippet_sha256 as string} value={h.snippet_sha256 as string}>
              Only {h.family || 'hit'} {String(h.snippet_sha256).slice(0, 12)}
            </option>
          ))}
        </select>
      ) : null}
      <textarea
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Why this content is safe to continue with (audited, at least 3 characters)"
        className={inputCls}
        rows={2}
        disabled={!!blocked}
      />
      <button
        className={btnPrimary}
        disabled={!!blocked || reason.trim().length < 3 || m.isPending}
        title={blocked ?? undefined}
        onClick={() => m.mutate()}
      >
        <Lock className="w-3.5 h-3.5 inline mr-1" />
        {m.isPending ? 'Acknowledging...' : 'Acknowledge and lift lockdown'}
      </button>
      <Gate reason={blocked} />
      <ActionErrorBanner what="acknowledge the finding" error={m.error} />
      {m.data ? (
        <p className="text-[11px] text-gray-700 dark:text-gray-300">
          Server recorded the acknowledgement:{' '}
          {(Array.isArray(m.data.downgraded) ? m.data.downgraded : [])
            .map((d: Row) => `${d.kind} ${d.from} to ${d.to}`)
            .join('; ') || 'no state changed'}
          .
        </p>
      ) : null}
    </div>
  );
};

/* ------------------------------------------------------------ SOC agents */

export const CreateAgentModal: React.FC<{ onClose: () => void; onCreated?: (agent: Row) => void }> = ({
  onClose,
  onCreated,
}) => {
  const qc = useQueryClient();
  const [form, setForm] = useState({
    name: '',
    agent_type: AGENT_TYPES[0],
    autonomy_level: 'human_in_loop',
    temperature: '0.3',
    max_reasoning_steps: '15',
    capabilities: '',
  });
  const m = useMutation({
    mutationFn: () =>
      agenticApi.createAgent({
        name: form.name.trim(),
        agent_type: form.agent_type,
        autonomy_level: form.autonomy_level,
        temperature: Number(form.temperature),
        max_reasoning_steps: Number(form.max_reasoning_steps),
        capabilities: form.capabilities
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      }),
    onSuccess: (agent) => {
      qc.invalidateQueries({ queryKey: ['agentic-agents'] });
      onCreated?.(agent);
      onClose();
    },
  });
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    setForm((f) => ({ ...f, [k]: e.target.value }));
  return (
    <Shell title="Create SOC agent" onClose={onClose}>
      <p className="text-xs text-gray-600 dark:text-gray-400">
        Without a SOC agent, proposals answer 409 and auto-triage skips the organisation. The agent uses the
        organisation's configured LLM provider; nothing runs until one is configured.
      </p>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          m.mutate();
        }}
      >
        <label className="block text-sm">Name<input required value={form.name} onChange={set('name')} className={inputCls} /></label>
        <label className="block text-sm">
          Type
          <select value={form.agent_type} onChange={set('agent_type')} className={inputCls}>
            {AGENT_TYPES.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
        </label>
        <label className="block text-sm">
          Autonomy
          <select value={form.autonomy_level} onChange={set('autonomy_level')} className={inputCls}>
            {AUTONOMY_LEVELS.map((t) => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
          </select>
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="block text-sm">Temperature (0-1)<input type="number" min={0} max={1} step={0.05} value={form.temperature} onChange={set('temperature')} className={inputCls} /></label>
          <label className="block text-sm">Max reasoning steps (1-100)<input type="number" min={1} max={100} value={form.max_reasoning_steps} onChange={set('max_reasoning_steps')} className={inputCls} /></label>
        </div>
        <label className="block text-sm">Capabilities (comma separated, optional)<input value={form.capabilities} onChange={set('capabilities')} className={inputCls} /></label>
        <ActionErrorBanner what="create the agent" error={m.error} />
        <div className="flex gap-2">
          <button type="submit" className={btnPrimary} disabled={m.isPending || !form.name.trim()}>
            {m.isPending ? 'Creating...' : 'Create agent'}
          </button>
          <button type="button" className={btnSecondary} onClick={onClose}>Cancel</button>
        </div>
      </form>
    </Shell>
  );
};

export const AgentDetailDrawer: React.FC<{
  agentId: string;
  gate: RoleGate;
  onClose: () => void;
  onSaved?: (agent: Row) => void;
}> = ({ agentId, gate, onClose, onSaved }) => {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['agentic-agent', agentId], queryFn: () => agenticApi.getAgent(agentId) });
  const [edit, setEdit] = useState<Row | null>(null);
  const m = useMutation({
    mutationFn: (body: Row) => agenticApi.updateAgent(agentId, body),
    onSuccess: (data) => {
      qc.setQueryData(['agentic-agent', agentId], data);
      qc.invalidateQueries({ queryKey: ['agentic-agents'] });
      onSaved?.(data);
      setEdit(null);
    },
  });
  const a = q.data;
  return (
    <Shell title={a?.name ?? 'SOC agent'} subtitle={agentId} onClose={onClose}>
      <LoadErrorBanner what="the SOC agent" error={q.error} />
      {a ? (
        <>
          <Section title="Configuration">
            <dl className="grid grid-cols-2 gap-2 text-xs">
              {[
                ['Type', a.agent_type],
                ['Status', a.status],
                ['Autonomy', a.autonomy_level],
                ['LLM model', a.llm_model],
                ['Temperature', a.temperature],
                ['Max reasoning steps', a.max_reasoning_steps],
                ['Current task', a.current_task_id],
                ['Investigations', a.total_investigations],
                ['Created', fmtTime(a.created_at)],
                ['Updated', fmtTime(a.updated_at)],
              ].map(([k, v]) => (
                <div key={String(k)}>
                  <dt className="text-gray-500 dark:text-gray-400">{k}</dt>
                  <dd className="text-gray-900 dark:text-white">{v === null || v === undefined || v === '' ? NA : String(v)}</dd>
                </div>
              ))}
            </dl>
            <p className="text-xs text-gray-500 mt-2">
              Capabilities: {(() => {
                try {
                  const c = typeof a.capabilities === 'string' ? JSON.parse(a.capabilities) : a.capabilities;
                  return Array.isArray(c) && c.length ? c.join(', ') : 'none recorded';
                } catch {
                  return String(a.capabilities);
                }
              })()}
            </p>
          </Section>
          {edit ? (
            <Section title="Edit agent">
              <form
                className="space-y-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  m.mutate({
                    name: edit.name || undefined,
                    status: edit.status || undefined,
                    autonomy_level: edit.autonomy_level || undefined,
                    temperature: edit.temperature === '' ? undefined : Number(edit.temperature),
                    max_reasoning_steps: edit.max_reasoning_steps === '' ? undefined : Number(edit.max_reasoning_steps),
                  });
                }}
              >
                <label className="block text-sm">Name<input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} className={inputCls} /></label>
                <label className="block text-sm">
                  Status
                  <select value={edit.status} onChange={(e) => setEdit({ ...edit, status: e.target.value })} className={inputCls}>
                    {AGENT_STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </label>
                <label className="block text-sm">
                  Autonomy
                  <select value={edit.autonomy_level} onChange={(e) => setEdit({ ...edit, autonomy_level: e.target.value })} className={inputCls}>
                    {AUTONOMY_LEVELS.map((s) => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
                  </select>
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <label className="block text-sm">Temperature<input type="number" min={0} max={1} step={0.05} value={edit.temperature} onChange={(e) => setEdit({ ...edit, temperature: e.target.value })} className={inputCls} /></label>
                  <label className="block text-sm">Max steps<input type="number" min={1} max={100} value={edit.max_reasoning_steps} onChange={(e) => setEdit({ ...edit, max_reasoning_steps: e.target.value })} className={inputCls} /></label>
                </div>
                <ActionErrorBanner what="save the agent" error={m.error} />
                <div className="flex gap-2">
                  <button type="submit" className={btnPrimary} disabled={m.isPending}>{m.isPending ? 'Saving...' : 'Save'}</button>
                  <button type="button" className={btnSecondary} onClick={() => setEdit(null)}>Cancel</button>
                </div>
              </form>
            </Section>
          ) : (
            <div>
              <button
                className={btnSecondary}
                disabled={!gate.isAdmin}
                title={gate.isAdmin ? undefined : ADMIN_ONLY_REASON}
                onClick={() =>
                  setEdit({
                    name: a.name ?? '',
                    status: a.status ?? 'idle',
                    autonomy_level: a.autonomy_level ?? 'human_in_loop',
                    temperature: String(a.temperature ?? ''),
                    max_reasoning_steps: String(a.max_reasoning_steps ?? ''),
                  })
                }
              >
                Edit agent
              </button>
              <Gate reason={gate.isAdmin ? null : `Editing a SOC agent: ${ADMIN_ONLY_REASON}`} />
            </div>
          )}
        </>
      ) : null}
    </Shell>
  );
};

/* ---------------------------------------------------- auditor panel */

const UsagePanel: React.FC<{ gate: RoleGate }> = ({ gate }) => {
  const [days, setDays] = useState(30);
  const q = useQuery({
    queryKey: ['agentic-usage', days],
    queryFn: () => agenticApi.getUsage(days),
    enabled: gate.isAnalyst,
  });
  const u = q.data;
  const totals: Row = u?.totals ?? {};
  const byModel: Row[] = Array.isArray(u?.by_provider_model) ? u.by_provider_model : [];
  const byPurpose: Row[] = Array.isArray(u?.by_purpose_mode) ? u.by_purpose_mode : [];
  const budget: Row | null = u?.budget_remaining_today ?? null;
  return (
    <Section title="LLM usage">
      {!gate.isAnalyst ? <Empty text={`Usage counters: ${ANALYST_ONLY_REASON}`} /> : null}
      <div className="flex items-center gap-2 mb-2 text-xs">
        <span>Window</span>
        <select value={days} onChange={(e) => setDays(Number(e.target.value))} className="border rounded px-2 py-1 bg-white dark:bg-gray-700">
          {[1, 7, 30, 90, 365].map((d) => <option key={d} value={d}>{d} days</option>)}
        </select>
      </div>
      <LoadErrorBanner what="agent usage" error={q.error} />
      {u ? (
        <div className="space-y-3 text-xs">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <div><div className="text-gray-500">Calls</div><div className="font-semibold">{fmtNum(totals.calls)}</div></div>
            <div><div className="text-gray-500">Errors</div><div className="font-semibold">{fmtNum(totals.errors)}</div></div>
            <div><div className="text-gray-500">Billable tokens</div><div className="font-semibold">{fmtNum(totals.total_billable_tokens)}</div></div>
            <div>
              <div className="text-gray-500">Estimated cost (USD)</div>
              <div className="font-semibold">{typeof totals.cost_usd === 'number' ? `$${totals.cost_usd.toFixed(4)}` : NA}</div>
              {totals.unpriced_calls ? (
                <div className="text-amber-700 dark:text-amber-300">{totals.unpriced_calls} calls have no price configured and are not in the cost</div>
              ) : null}
            </div>
          </div>
          <div>
            <div className="text-gray-500 mb-1">Remaining budget today</div>
            {budget ? (
              <ul>
                {Object.entries(budget).map(([k, v]) => (
                  <li key={k}>{k}: {fmtNum((v as Row)?.remaining)} of {fmtNum((v as Row)?.cap)} (used {fmtNum((v as Row)?.used)})</li>
                ))}
              </ul>
            ) : (
              <Empty text="not available: the quota backend did not answer." />
            )}
          </div>
          {Array.isArray(u.rolled_up_days) && u.rolled_up_days.length > 0 ? (
            <p className="text-gray-500">{u.rolled_up_days.length} day(s) come from the daily rollup (raw call logs purged by retention).</p>
          ) : null}
          {[['By provider / model', byModel], ['By purpose / mode', byPurpose]].map(([label, rows]) => (
            <div key={label as string}>
              <div className="text-gray-500 mb-1">{label as string}</div>
              {(rows as Row[]).length === 0 ? (
                <Empty text="No calls in this window." />
              ) : (
                <table className="w-full">
                  <thead className="text-left text-gray-500"><tr><th>Key</th><th>Calls</th><th>Tokens</th><th>Cost</th></tr></thead>
                  <tbody>
                    {(rows as Row[]).map((r) => (
                      <tr key={r.key} className="border-t border-gray-100 dark:border-gray-700">
                        <td className="font-mono">{r.key}</td>
                        <td>{fmtNum(r.calls)}</td>
                        <td>{fmtNum(r.total_billable_tokens)}</td>
                        <td>{typeof r.cost_usd === 'number' ? `$${r.cost_usd.toFixed(4)}` : NA}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          ))}
        </div>
      ) : null}
    </Section>
  );
};

const DECISIONS = ['', 'allow', 'deny', 'propose', 'executed', 'failed', 'blocked', 'proposed'];

const PolicyEventsPanel: React.FC<{ gate: RoleGate; onOpenRun: (id: string) => void }> = ({ gate, onOpenRun }) => {
  const [decision, setDecision] = useState('');
  const [tool, setTool] = useState('');
  const [page, setPage] = useState(1);
  const q = useQuery({
    queryKey: ['agentic-policy-events', decision, tool, page],
    queryFn: () =>
      agenticApi.getPolicyEvents({
        decision: decision || undefined,
        tool: tool.trim() || undefined,
        page,
        size: 50,
      }),
    enabled: gate.isAnalyst,
  });
  const items: Row[] = Array.isArray(q.data?.items) ? q.data.items : [];
  const pages = Number(q.data?.pages ?? 0);
  return (
    <Section title="Policy and trust events">
      {!gate.isAnalyst ? <Empty text={`Policy events: ${ANALYST_ONLY_REASON}`} /> : null}
      <div className="flex flex-wrap gap-2 mb-2 text-xs">
        <select value={decision} onChange={(e) => { setDecision(e.target.value); setPage(1); }} className="border rounded px-2 py-1 bg-white dark:bg-gray-700">
          {DECISIONS.map((d) => <option key={d} value={d}>{d || 'every decision'}</option>)}
        </select>
        <input value={tool} onChange={(e) => { setTool(e.target.value); setPage(1); }} placeholder="tool name" className="border rounded px-2 py-1 bg-white dark:bg-gray-700" />
      </div>
      <LoadErrorBanner what="policy events" error={q.error} />
      {q.data && items.length === 0 ? <Empty text="No policy or tool audit rows match." /> : null}
      {items.length > 0 ? (
        <table className="w-full text-xs">
          <thead className="text-left text-gray-500"><tr><th>Time</th><th>Decision</th><th>Tool</th><th>Reason</th><th>Actor</th><th>Run</th></tr></thead>
          <tbody>
            {items.map((e) => (
              <tr key={e.id} className="border-t border-gray-100 dark:border-gray-700">
                <td>{fmtTime(e.created_at)}</td>
                <td className="font-mono">{e.event_type}/{e.action}</td>
                <td className="font-mono">{e.resource_id ?? NA}</td>
                <td>{e.payload?.reason_code ? String(e.payload.reason_code) : ''}</td>
                <td className="font-mono">{e.actor_id ?? NA}</td>
                <td>
                  {e.run_id ? (
                    <button className="font-mono text-blue-600 dark:text-blue-400 hover:underline" onClick={() => onOpenRun(String(e.run_id))}>
                      {String(e.run_id).slice(0, 8)}
                    </button>
                  ) : NA}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      {pages > 1 ? (
        <div className="flex items-center gap-2 mt-2 text-xs">
          <button className={btnSecondary} disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</button>
          <span>Page {page} of {pages} ({q.data?.total} rows)</span>
          <button className={btnSecondary} disabled={page >= pages} onClick={() => setPage((p) => p + 1)}>Next</button>
        </div>
      ) : null}
    </Section>
  );
};

const EvidenceExportPanel: React.FC<{ gate: RoleGate }> = ({ gate }) => {
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [note, setNote] = useState<string | null>(null);
  const m = useMutation({
    mutationFn: async (format: 'csv' | 'json') => {
      try {
        const res = await agenticApi.exportEvidence({
          format,
          from: from ? new Date(from).toISOString() : undefined,
          to: to ? new Date(`${to}T23:59:59`).toISOString() : undefined,
        });
        const stamp = new Date().toISOString().slice(0, 10);
        const name = filenameFromDisposition(res.headers?.['content-disposition'], `agent-evidence-${stamp}.${format}`);
        saveBlob(res.data as Blob, name);
        const rows = res.headers?.['x-evidence-rows'];
        const truncated = res.headers?.['x-evidence-truncated'] === 'true';
        return { format, rows, truncated };
      } catch (err) {
        throw await parseBlobError(err);
      }
    },
    onSuccess: (r) =>
      setNote(
        r.format === 'csv'
          ? `Saved ${r.rows ?? 'the'} rows${r.truncated ? ' (the server capped the export; narrow the date range for the rest)' : ''}.`
          : 'Saved the JSON export (rows, columns and the control mapping as the server returned them).',
      ),
  });
  const blocked = gate.isAdmin ? null : `Evidence export: ${ADMIN_ONLY_REASON}`;
  return (
    <Section title="Evidence export (AU-6 / AU-7)">
      <p className="text-xs text-gray-600 dark:text-gray-400 mb-2">
        One row per tool decision with its reason code, role, mode, provider tokens and approver. Defaults to the last 30 days.
      </p>
      <div className="flex flex-wrap items-end gap-2 text-xs">
        <label>From<input type="date" value={from} onChange={(e) => setFrom(e.target.value)} className="block border rounded px-2 py-1 bg-white dark:bg-gray-700" /></label>
        <label>To<input type="date" value={to} onChange={(e) => setTo(e.target.value)} className="block border rounded px-2 py-1 bg-white dark:bg-gray-700" /></label>
        {(['csv', 'json'] as const).map((f) => (
          <button key={f} className={btnSecondary} disabled={!!blocked || m.isPending} title={blocked ?? undefined} onClick={() => { setNote(null); m.mutate(f); }}>
            <Download className="w-3.5 h-3.5 inline mr-1" />
            {f.toUpperCase()}
          </button>
        ))}
      </div>
      <Gate reason={blocked} />
      <div className="mt-2"><ActionErrorBanner what="export the evidence" error={m.error} /></div>
      {note ? <p className="text-xs text-gray-700 dark:text-gray-300 mt-2">{note}</p> : null}
    </Section>
  );
};

export const AgentOversightPanel: React.FC<{ gate: RoleGate }> = ({ gate }) => {
  const [runId, setRunId] = useState<string | null>(null);
  const [lookup, setLookup] = useState('');
  return (
    <div className="space-y-4">
      <Section title="Open a run">
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (lookup.trim().length >= 4) setRunId(lookup.trim());
          }}
        >
          <input value={lookup} onChange={(e) => setLookup(e.target.value)} placeholder="run id" className={inputCls} />
          <button type="submit" className={btnSecondary} disabled={lookup.trim().length < 4}>Open timeline</button>
        </form>
      </Section>
      <UsagePanel gate={gate} />
      <PolicyEventsPanel gate={gate} onOpenRun={setRunId} />
      <EvidenceExportPanel gate={gate} />
      {runId ? <RunTimelineDrawer runId={runId} gate={gate} onClose={() => setRunId(null)} /> : null}
    </div>
  );
};
