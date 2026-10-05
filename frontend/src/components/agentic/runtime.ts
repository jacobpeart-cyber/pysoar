/**
 * Shared, pure helpers for rendering the guarded agent runtime (design v2
 * sections 8/9) in the UI.
 *
 * The rule that drives everything here: the UI may only claim something
 * happened when the structured run record says it happened. Nothing is ever
 * inferred from the model's prose.
 */
import { useEffect, useState } from 'react';
import type {
  AgenticChatErrorBody,
  AgenticChatFailure,
  EffectiveTarget,
  PendingApprovalRow,
  ToolInvocation,
} from '../../api/endpoints';

interface MaybeAxiosError {
  response?: {
    status?: number;
    data?: unknown;
    headers?: Record<string, unknown>;
  };
  message?: string;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function stringify(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return null;
  }
}

/**
 * The machine-readable error code + detail behind a failed request.
 *
 * Both shapes the API uses are handled: a top-level body (`{error, detail}`,
 * used by `/settings/ai` and `/agentic/chat`) and FastAPI's nested
 * `{detail: {error: ...}}` (used by the approve/rollback endpoints).
 */
export function errorCodeOf(err: unknown): { code: string | null; detail: string | null } {
  const data = (err as MaybeAxiosError)?.response?.data;
  const body = asRecord(data);
  if (!body) {
    return { code: null, detail: typeof data === 'string' ? data : null };
  }
  const nested = asRecord(body.detail);
  if (nested && typeof nested.error === 'string') {
    return { code: nested.error, detail: stringify(nested.detail) };
  }
  if (typeof body.error === 'string') {
    return { code: body.error, detail: stringify(body.detail) };
  }
  return { code: null, detail: stringify(body.detail) };
}

/** Normalize any thrown request failure into something the error card can render. */
export function normalizeFailure(err: unknown): AgenticChatFailure {
  const axiosish = err as MaybeAxiosError;
  const status = axiosish?.response?.status ?? null;
  const body = (asRecord(axiosish?.response?.data) ?? {}) as AgenticChatErrorBody &
    Record<string, unknown>;
  const { code, detail } = errorCodeOf(err);
  const retryAfterRaw = axiosish?.response?.headers?.['retry-after'];
  const retryAfter = retryAfterRaw === undefined ? NaN : Number(retryAfterRaw);

  return {
    status,
    code: code || (status ? `http_${status}` : 'network_error'),
    detail: detail || (status ? null : axiosish?.message || 'Request failed'),
    source: typeof body.source === 'string' ? body.source : null,
    request_id: typeof body.request_id === 'string' ? body.request_id : null,
    run_id: typeof body.run_id === 'string' ? body.run_id : null,
    retry_after_seconds: Number.isFinite(retryAfter) ? retryAfter : null,
  };
}

/**
 * The only source of truth for the "Actions taken" panel.
 *
 * A step counts as an action the platform actually performed when policy
 * allowed it, nothing blocked it, it did not error, and it was not a read.
 * A step with no `tier` is excluded: without the tier we cannot honestly
 * claim it changed anything.
 */
export function actionsTaken(tools: ToolInvocation[] | null | undefined): ToolInvocation[] {
  return (tools || []).filter((step) => {
    if (step.decision !== 'allow') return false;
    if (step.blocked) return false;
    if (step.error) return false;
    if (!step.tier || step.tier === 'read') return false;
    const result = asRecord(step.result);
    if (result && result.success === false) return false;
    return true;
  });
}

/** `AgentAction.parameters` normalized — dict rows and legacy JSON strings. */
export function parseParameters(
  raw: Record<string, unknown> | string | null | undefined,
): Record<string, unknown> {
  if (!raw) return {};
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      return asRecord(parsed) ?? {};
    } catch {
      return { value: raw };
    }
  }
  return asRecord(raw) ?? {};
}

/** Render one argument value compactly without hiding structure. */
export function formatArgValue(value: unknown): string {
  if (value === null) return 'null';
  if (value === undefined) return '—';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

/** Pending-approval rows have been keyed `action_id` historically, `id` lately. */
export function rowActionId(row: PendingApprovalRow): string {
  return row.action_id || row.id || '';
}

/** What the row says it would do, across both the new and legacy projections. */
export function rowToolName(row: PendingApprovalRow): string {
  return row.tool_name || row.action_type || 'unknown';
}

/**
 * Targets for a row. Prefers the structured `effective_targets` list; falls
 * back to the legacy flat `target` string, marked `unknown` provenance so the
 * UI never implies it was resolved from a structured field.
 */
export function rowTargets(row: PendingApprovalRow): EffectiveTarget[] {
  if (Array.isArray(row.effective_targets) && row.effective_targets.length > 0) {
    return row.effective_targets;
  }
  if (row.target) {
    return [{ kind: 'target', value: row.target, provenance: 'unknown' }];
  }
  return [];
}

/**
 * A row can only be approved when it carries the integrity binding the API
 * requires. Legacy rows (written before the guarded runtime) have no hashes:
 * approving them would be approving something unverifiable, and the request
 * would be rejected anyway, so the UI must say so instead.
 */
export function hasIntegrityBinding(row: {
  params_sha256?: string | null;
  evidence_sha256?: string | null;
}): boolean {
  return Boolean(row.params_sha256 && row.evidence_sha256);
}

export function isAdminRole(role?: string | null, isSuperuser?: boolean | null): boolean {
  return Boolean(isSuperuser) || role === 'admin';
}

export interface Countdown {
  /** null when there is no expiry on the record. */
  label: string | null;
  expired: boolean;
}

/** Live "expires in …" countdown, re-rendered once a second. */
export function useExpiryCountdown(expiresAt?: string | null): Countdown {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!expiresAt) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [expiresAt]);

  if (!expiresAt) return { label: null, expired: false };
  const target = Date.parse(expiresAt);
  if (Number.isNaN(target)) return { label: null, expired: false };

  const remaining = Math.floor((target - now) / 1000);
  if (remaining <= 0) return { label: 'expired', expired: true };

  const hours = Math.floor(remaining / 3600);
  const minutes = Math.floor((remaining % 3600) / 60);
  const seconds = remaining % 60;
  const label =
    hours > 0
      ? `${hours}h ${String(minutes).padStart(2, '0')}m`
      : `${minutes}m ${String(seconds).padStart(2, '0')}s`;
  return { label, expired: false };
}

/** Human-readable text for the approval/rollback error codes the API returns. */
export function approvalErrorText(code: string | null, detail: string | null): string {
  switch (code) {
    case 'approval_stale':
      return 'The proposal changed since this card was rendered (approval_stale). Reload the pending list and review the current arguments before approving.';
    case 'approval_expired':
      return 'This proposal has expired (approval_expired). Re-run the investigation to raise a fresh proposal.';
    case 'suspect_action_requires_reinvestigation':
      return 'This proposal came out of a flagged or lockdown session (suspect_action_requires_reinvestigation). Re-investigate from trusted input before approving.';
    default:
      if (code && detail) return `${code}: ${detail}`;
      if (code) return code;
      return detail || 'Request failed.';
  }
}
