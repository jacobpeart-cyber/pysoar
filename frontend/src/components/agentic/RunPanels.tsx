/**
 * Presentational panels for one guarded agent run.
 *
 * Every panel renders from the structured run record only — the tool log,
 * the policy events, the trust assessment, the usage counters. None of them
 * parses the assistant's prose, so the UI cannot claim an action that policy
 * did not actually allow.
 */
import React from 'react';
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  FileWarning,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Timer,
  Wrench,
  XCircle,
} from 'lucide-react';
import clsx from 'clsx';
import type {
  AgenticChatFailure,
  EffectiveTarget,
  PolicyEvent,
  RunUsage,
  ToolInvocation,
  TrustAssessment,
} from '../../api/endpoints';
import { actionsTaken, formatArgValue } from './runtime';

/* ------------------------------------------------------------------ badges */

export const ProvenanceBadge: React.FC<{ provenance?: string | null }> = ({ provenance }) => {
  const p = provenance || 'unknown';
  const structured = p === 'structured';
  const untrusted = p === 'untrusted_text';
  return (
    <span
      title={
        structured
          ? 'Resolved from a structured field on a record in your organization.'
          : untrusted
            ? 'Taken from untrusted free text (log line, email body, model output). Verify before approving.'
            : 'Provenance not recorded for this target.'
      }
      className={clsx(
        'inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded',
        structured
          ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
          : untrusted
            ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
            : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
      )}
    >
      {structured ? <ShieldCheck className="w-3 h-3" /> : <FileWarning className="w-3 h-3" />}
      {structured ? 'structured' : untrusted ? 'untrusted text' : 'unknown source'}
    </span>
  );
};

export const SuspectBadge: React.FC<{ injectionTier?: string | null }> = ({ injectionTier }) => (
  <span className="inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300">
    <ShieldAlert className="w-3 h-3" />
    suspect{injectionTier ? ` · injection: ${injectionTier}` : ''}
  </span>
);

export const TierBadge: React.FC<{ tier?: string | null }> = ({ tier }) => {
  if (!tier) return null;
  const danger = tier === 'destructive' || tier === 'privileged';
  return (
    <span
      className={clsx(
        'inline-flex items-center text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded',
        danger
          ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300'
          : 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
      )}
    >
      {tier}
    </span>
  );
};

/* ------------------------------------------------------------- target list */

export const TargetList: React.FC<{ targets: EffectiveTarget[] }> = ({ targets }) => {
  if (targets.length === 0) {
    return (
      <p className="text-xs text-gray-500 dark:text-gray-400">
        No effective targets recorded on this proposal.
      </p>
    );
  }
  return (
    <ul className="space-y-1">
      {targets.map((t, idx) => (
        <li
          key={`${t.kind || 'target'}-${t.value || idx}`}
          className="flex flex-wrap items-center gap-2 text-xs bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded px-2 py-1"
        >
          <span className="text-gray-500 dark:text-gray-400">{t.kind || 'target'}</span>
          <span className="font-mono text-gray-900 dark:text-white break-all">
            {t.value ?? '—'}
          </span>
          {t.resolved_id ? (
            <span className="font-mono text-[10px] text-gray-500 dark:text-gray-400">
              → {t.resolved_id}
            </span>
          ) : null}
          <ProvenanceBadge provenance={t.provenance} />
        </li>
      ))}
    </ul>
  );
};

/* ------------------------------------------------------- actions taken */

export const ActionsTakenPanel: React.FC<{ tools?: ToolInvocation[] | null }> = ({ tools }) => {
  const taken = actionsTaken(tools);
  if (taken.length === 0) return null;
  return (
    <div className="mt-3 border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20 rounded-md">
      <div className="px-3 py-2 flex items-center gap-2 border-b border-green-200 dark:border-green-800">
        <CheckCircle2 className="w-3.5 h-3.5 text-green-700 dark:text-green-300" />
        <span className="text-xs font-semibold text-green-800 dark:text-green-200">
          Actions taken
        </span>
        <span className="text-[10px] text-green-700 dark:text-green-300">
          {taken.length} change{taken.length === 1 ? '' : 's'} applied
        </span>
      </div>
      <ul className="p-2 space-y-1">
        {taken.map((step) => (
          <li
            key={`${step.step}-${step.tool}`}
            className="text-xs bg-white dark:bg-gray-900 border border-green-200 dark:border-green-800 rounded px-2 py-1"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-gray-500 dark:text-gray-400">step {step.step}</span>
              <span className="font-mono font-semibold text-gray-900 dark:text-white">
                {step.tool}
              </span>
              <TierBadge tier={step.tier} />
              {typeof step.duration_ms === 'number' ? (
                <span className="text-[10px] text-gray-500 dark:text-gray-400">
                  {step.duration_ms} ms
                </span>
              ) : null}
            </div>
            {step.args && Object.keys(step.args).length > 0 ? (
              <dl className="mt-1 grid grid-cols-[minmax(0,8rem)_1fr] gap-x-2 gap-y-0.5">
                {Object.entries(step.args).map(([k, v]) => (
                  <React.Fragment key={k}>
                    <dt className="font-mono text-[10px] text-gray-500 dark:text-gray-400 truncate">
                      {k}
                    </dt>
                    <dd className="font-mono text-[10px] text-gray-800 dark:text-gray-200 break-all">
                      {formatArgValue(v)}
                    </dd>
                  </React.Fragment>
                ))}
              </dl>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
};

/* -------------------------------------------------------- policy events */

const decisionStyles: Record<string, string> = {
  allow: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
  deny: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  propose: 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-300',
};

export const PolicyEventList: React.FC<{ events?: PolicyEvent[] | null }> = ({ events }) => {
  if (!events || events.length === 0) return null;
  return (
    <details className="mt-3 border border-gray-200 dark:border-gray-700 rounded-md bg-gray-50 dark:bg-gray-900">
      <summary className="px-3 py-2 text-xs font-semibold text-gray-700 dark:text-gray-300 cursor-pointer flex items-center gap-2">
        <Wrench className="w-3.5 h-3.5" />
        Policy decisions
        <span className="text-[10px] font-normal text-gray-500 dark:text-gray-400">
          {events.length}
        </span>
      </summary>
      <ul className="px-3 pb-2 space-y-0.5">
        {events.map((e, idx) => (
          <li
            key={`${e.step ?? idx}-${e.tool ?? 'tool'}-${idx}`}
            className="flex flex-wrap items-center gap-2 text-[11px]"
          >
            {typeof e.step === 'number' ? (
              <span className="text-gray-400 dark:text-gray-500 w-10">#{e.step}</span>
            ) : null}
            <span className="font-mono text-gray-900 dark:text-white">{e.tool || '—'}</span>
            <span
              className={clsx(
                'px-1.5 py-0.5 rounded font-semibold uppercase tracking-wide text-[9px]',
                decisionStyles[e.decision || ''] ||
                  'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
              )}
            >
              {e.decision || 'unknown'}
            </span>
            <span className="font-mono text-gray-600 dark:text-gray-400">
              {e.reason_code || '—'}
            </span>
          </li>
        ))}
      </ul>
    </details>
  );
};

/* ----------------------------------------------------------- trust banner */

export const TrustBanner: React.FC<{ trust?: TrustAssessment | null }> = ({ trust }) => {
  const tier = trust?.tier;
  if (!tier || tier === 'clean') return null;
  const lockdown = tier === 'lockdown';
  const hits = trust?.hits || [];
  return (
    <div
      className={clsx(
        'mt-3 border rounded-md',
        lockdown
          ? 'border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20'
          : 'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20',
      )}
    >
      <div className="px-3 py-2 flex items-center gap-2">
        {lockdown ? (
          <Lock className="w-4 h-4 text-red-700 dark:text-red-300" />
        ) : (
          <ShieldAlert className="w-4 h-4 text-amber-700 dark:text-amber-300" />
        )}
        <span
          className={clsx(
            'text-xs font-semibold uppercase tracking-wide',
            lockdown ? 'text-red-800 dark:text-red-200' : 'text-amber-800 dark:text-amber-200',
          )}
        >
          Session trust: {tier}
        </span>
      </div>
      <div className="px-3 pb-2 space-y-1">
        <p
          className={clsx(
            'text-[11px]',
            lockdown ? 'text-red-800 dark:text-red-200' : 'text-amber-800 dark:text-amber-200',
          )}
        >
          {lockdown
            ? 'Prompt-injection content was found in this session. Write actions are locked: the runtime will not execute or propose any state-changing tool until the session is reset.'
            : 'Suspicious instruction-like content was found in the data this session read. Proposals raised here are marked suspect and need admin review.'}
        </p>
        {hits.length > 0 ? (
          <ul className="space-y-1">
            {hits.map((hit, idx) => (
              <li
                key={`${hit.family || 'hit'}-${idx}`}
                className="text-[11px] bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded px-2 py-1"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono font-semibold text-gray-900 dark:text-white">
                    {hit.family || 'unknown family'}
                  </span>
                  {hit.label ? (
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                      {hit.label}
                    </span>
                  ) : null}
                </div>
                {hit.preview ? (
                  <p className="mt-0.5 font-mono text-[10px] text-gray-600 dark:text-gray-400 break-all">
                    “{hit.preview}”
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        ) : null}
      </div>
    </div>
  );
};

/* ------------------------------------------------------------- run footer */

export const RunFooter: React.FC<{
  provider?: string | null;
  model?: string | null;
  credentialSource?: string | null;
  usage?: RunUsage | null;
  runId?: string | null;
  stopReason?: string | null;
  honestyNote?: boolean | null;
}> = ({ provider, model, credentialSource, usage, runId, stopReason, honestyNote }) => {
  const bits: string[] = [];
  if (provider) bits.push(provider);
  if (model) bits.push(model);
  if (credentialSource) bits.push(`${credentialSource} credential`);
  const tokens = usage?.total_billable;
  if (typeof tokens === 'number') {
    bits.push(`${tokens.toLocaleString()} tokens${usage?.estimated ? ' (est.)' : ''}`);
  }
  if (stopReason) bits.push(`stop: ${stopReason}`);
  if (runId) bits.push(`run ${runId.slice(0, 8)}`);
  if (bits.length === 0) return null;
  return (
    <div className="mt-2 text-[10px] text-gray-500 dark:text-gray-400 flex flex-wrap gap-x-2 gap-y-0.5">
      <span>{bits.join(' · ')}</span>
      {honestyNote ? (
        <span className="text-amber-600 dark:text-amber-400">honesty note applied</span>
      ) : null}
    </div>
  );
};

/* ------------------------------------------------------------- error card */

const failureTitles: Record<string, string> = {
  llm_not_configured: 'No LLM provider is configured',
  llm_unavailable: 'The LLM provider is unreachable',
  llm_provider_error: 'The LLM provider returned an error',
  llm_quota_exceeded: 'Token quota exceeded',
};

export const AgentErrorCard: React.FC<{
  failure: AgenticChatFailure;
  onRetry?: () => void;
  retrying?: boolean;
}> = ({ failure, onRetry, retrying }) => {
  const forbidden = failure.status === 403;
  const quota = failure.status === 429;
  const title =
    failureTitles[failure.code] ||
    (forbidden
      ? 'Not permitted'
      : quota
        ? 'Rate limited'
        : 'The agent could not answer');
  return (
    <div className="border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20 rounded-md p-3 space-y-2">
      <div className="flex items-center gap-2">
        {forbidden ? (
          <Ban className="w-4 h-4 text-red-700 dark:text-red-300" />
        ) : quota ? (
          <Timer className="w-4 h-4 text-red-700 dark:text-red-300" />
        ) : (
          <AlertTriangle className="w-4 h-4 text-red-700 dark:text-red-300" />
        )}
        <span className="text-sm font-semibold text-red-800 dark:text-red-200">{title}</span>
        <span className="ml-auto font-mono text-[10px] text-red-700 dark:text-red-300">
          {failure.status ? `HTTP ${failure.status} · ` : ''}
          {failure.code}
        </span>
      </div>
      <p className="text-xs text-red-800 dark:text-red-200">
        No answer was produced. Nothing below this line is a model reply — the request failed.
      </p>
      {failure.detail ? (
        <p className="text-xs text-red-900 dark:text-red-100 font-mono break-words">
          {failure.detail}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-red-700 dark:text-red-300 font-mono">
        {failure.source ? <span>source: {failure.source}</span> : null}
        {failure.request_id ? <span>request: {failure.request_id}</span> : null}
        {failure.run_id ? <span>run: {failure.run_id}</span> : null}
        {quota && failure.retry_after_seconds !== null && failure.retry_after_seconds !== undefined ? (
          <span>retry after: {failure.retry_after_seconds}s</span>
        ) : null}
      </div>
      {onRetry ? (
        <button
          onClick={onRetry}
          disabled={retrying}
          className="inline-flex items-center gap-1.5 text-xs font-medium px-2.5 py-1 rounded border border-red-300 dark:border-red-700 text-red-800 dark:text-red-200 hover:bg-red-100 dark:hover:bg-red-900/40 disabled:opacity-50"
        >
          <RefreshCw className={clsx('w-3.5 h-3.5', retrying && 'animate-spin')} />
          {retrying ? 'Retrying…' : 'Retry'}
        </button>
      ) : null}
    </div>
  );
};

/* ------------------------------------------------------------- tool log */

export const ToolLogPanel: React.FC<{ tools?: ToolInvocation[] | null }> = ({ tools }) => {
  if (!tools || tools.length === 0) return null;
  return (
    <details className="mt-3 border border-gray-200 dark:border-gray-700 rounded-md bg-gray-50 dark:bg-gray-900">
      <summary className="px-3 py-2 text-xs font-semibold text-gray-700 dark:text-gray-300 cursor-pointer flex items-center gap-2">
        <Wrench className="w-3.5 h-3.5" />
        Tool log
        <span className="text-[10px] font-normal text-gray-500 dark:text-gray-400">
          {tools.length} step{tools.length === 1 ? '' : 's'}
        </span>
      </summary>
      <div className="px-3 pb-3 space-y-2">
        {tools.map((step) => (
          <div
            key={`${step.step}-${step.tool}`}
            className="border border-gray-200 dark:border-gray-700 rounded bg-white dark:bg-gray-800 p-2"
          >
            <div className="flex flex-wrap items-center gap-2 text-[11px]">
              <span className="text-gray-400 dark:text-gray-500">#{step.step}</span>
              <span className="font-mono font-semibold text-gray-900 dark:text-white">
                {step.tool}
              </span>
              <TierBadge tier={step.tier} />
              <span
                className={clsx(
                  'px-1.5 py-0.5 rounded font-semibold uppercase tracking-wide text-[9px]',
                  decisionStyles[step.decision || ''] ||
                    'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
                )}
              >
                {step.decision || 'unknown'}
              </span>
              {step.reason_code ? (
                <span className="font-mono text-gray-600 dark:text-gray-400">
                  {step.reason_code}
                </span>
              ) : null}
              {step.blocked ? (
                <span className="inline-flex items-center gap-1 text-red-700 dark:text-red-300">
                  <ShieldAlert className="w-3 h-3" /> blocked
                </span>
              ) : null}
              {step.error ? (
                <span className="inline-flex items-center gap-1 text-orange-700 dark:text-orange-300">
                  <AlertTriangle className="w-3 h-3" /> error
                </span>
              ) : null}
              {typeof step.duration_ms === 'number' ? (
                <span className="ml-auto text-[10px] text-gray-500 dark:text-gray-400">
                  {step.duration_ms} ms
                </span>
              ) : null}
            </div>
            {step.error ? (
              <p className="mt-1 font-mono text-[10px] text-orange-700 dark:text-orange-300 break-words">
                {step.error}
              </p>
            ) : null}
            {step.args && Object.keys(step.args).length > 0 ? (
              <pre className="mt-1 text-[10px] bg-gray-50 dark:bg-gray-900 rounded p-1.5 overflow-x-auto text-gray-800 dark:text-gray-200">
                {JSON.stringify(step.args, null, 2)}
              </pre>
            ) : null}
            {step.result !== undefined && step.result !== null ? (
              <pre className="mt-1 text-[10px] bg-gray-50 dark:bg-gray-900 rounded p-1.5 overflow-x-auto max-h-48 text-gray-800 dark:text-gray-200">
                {JSON.stringify(step.result, null, 2)}
              </pre>
            ) : null}
          </div>
        ))}
      </div>
    </details>
  );
};

/* ------------------------------------------------------- inline card error */

export const InlineCardError: React.FC<{ text: string }> = ({ text }) => (
  <div className="flex items-start gap-2 text-xs text-red-800 dark:text-red-200 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded px-2 py-1.5">
    <XCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
    <span className="break-words">{text}</span>
  </div>
);
