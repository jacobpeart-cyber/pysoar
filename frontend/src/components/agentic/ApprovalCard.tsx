/**
 * The one approve/deny surface for an agent-proposed action.
 *
 * Used inline in the chat workbench (from `response.proposals`) and on the
 * Agentic SOC → Approvals tab (from `GET /agentic/actions/pending-approval`),
 * so the integrity rules are enforced in exactly one place:
 *
 *  - every argument is shown, never a summary;
 *  - every effective target is shown with its provenance;
 *  - the approve request echoes the `params_sha256`/`evidence_sha256` that
 *    were rendered on this card, so a changed proposal is rejected (409
 *    `approval_stale`) instead of silently executing;
 *  - a row with no hashes cannot be approved from the UI at all;
 *  - a suspect proposal can only be approved by an admin, with a written
 *    reason and an explicit acknowledgement.
 */
import React, { useState } from 'react';
import { CheckCircle2, ChevronDown, ChevronRight, Clock, Hash, ThumbsDown } from 'lucide-react';
import clsx from 'clsx';
import type { EffectiveTarget } from '../../api/endpoints';
import { agenticApi } from '../../api/endpoints';
import {
  approvalErrorText,
  errorCodeOf,
  formatArgValue,
  isAdminRole,
  useExpiryCountdown,
} from './runtime';
import { InlineCardError, SuspectBadge, TargetList, TierBadge } from './RunPanels';

export interface ApprovalCardProps {
  /** AgentAction id. Null/empty when the backend did not return one — then
   *  nothing can be approved and the card says why. */
  actionId?: string | null;
  tool: string;
  args: Record<string, unknown>;
  targets: EffectiveTarget[];
  paramsSha256?: string | null;
  evidenceSha256?: string | null;
  suspect?: boolean | null;
  injectionTier?: string | null;
  expiresAt?: string | null;
  tier?: string | null;
  /** Extra context rows: investigation, proposer, source, … */
  meta?: Array<{ label: string; value: string }>;
  role?: string | null;
  isSuperuser?: boolean | null;
  onResolved?: (actionId: string, outcome: 'approved' | 'denied') => void;
}

type Outcome = 'approved' | 'denied' | null;

const ApprovalCard: React.FC<ApprovalCardProps> = ({
  actionId,
  tool,
  args,
  targets,
  paramsSha256,
  evidenceSha256,
  suspect,
  injectionTier,
  expiresAt,
  tier,
  meta,
  role,
  isSuperuser,
  onResolved,
}) => {
  const [showHashes, setShowHashes] = useState(false);
  const [denying, setDenying] = useState(false);
  const [denyNotes, setDenyNotes] = useState('');
  const [reason, setReason] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [cardError, setCardError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome>(null);

  const { label: expiryLabel, expired } = useExpiryCountdown(expiresAt);
  const admin = isAdminRole(role, isSuperuser);
  const viewer = role === 'viewer';
  const hasBinding = Boolean(paramsSha256 && evidenceSha256);
  const hasId = Boolean(actionId);
  const isSuspect = Boolean(suspect);

  let blockedReason: string | null = null;
  if (!hasId) {
    blockedReason =
      'This proposal carries no action id, so it cannot be approved from the UI. Re-run the investigation.';
  } else if (!hasBinding) {
    blockedReason =
      'This action cannot be approved from the UI (no integrity binding: params_sha256/evidence_sha256 are missing) — re-run the investigation to raise a proposal that can be verified.';
  } else if (expired) {
    blockedReason =
      'This proposal is past its expiry. Re-run the investigation to raise a fresh proposal.';
  } else if (viewer) {
    blockedReason = 'Viewers cannot approve agent actions.';
  } else if (isSuspect && !admin) {
    blockedReason =
      'This proposal was raised in a flagged or lockdown session (suspect). Only an admin may approve it, after re-investigating from trusted input.';
  }

  const needsAdminAttestation = isSuspect && admin && !blockedReason;
  const approveDisabled =
    busy ||
    outcome !== null ||
    Boolean(blockedReason) ||
    (needsAdminAttestation && (!acknowledged || reason.trim().length === 0));

  const handleApprove = async () => {
    if (!actionId || !paramsSha256 || !evidenceSha256) return;
    setBusy(true);
    setCardError(null);
    try {
      await agenticApi.approveAction(actionId, {
        params_sha256: paramsSha256,
        evidence_sha256: evidenceSha256,
        acknowledge_suspect: needsAdminAttestation ? true : undefined,
        reason: reason.trim() || undefined,
      });
      setOutcome('approved');
      onResolved?.(actionId, 'approved');
    } catch (err) {
      const { code, detail } = errorCodeOf(err);
      setCardError(approvalErrorText(code, detail));
    } finally {
      setBusy(false);
    }
  };

  const handleDeny = async () => {
    if (!actionId) return;
    setBusy(true);
    setCardError(null);
    try {
      await agenticApi.denyAction(actionId, denyNotes.trim() || undefined);
      setOutcome('denied');
      onResolved?.(actionId, 'denied');
    } catch (err) {
      const { code, detail } = errorCodeOf(err);
      setCardError(approvalErrorText(code, detail));
    } finally {
      setBusy(false);
    }
  };

  const argEntries = Object.entries(args || {});

  return (
    <div
      className={clsx(
        'mt-3 rounded-md border text-left',
        isSuspect
          ? 'border-red-300 dark:border-red-800 bg-red-50/60 dark:bg-red-900/10'
          : 'border-amber-300 dark:border-amber-800 bg-amber-50/60 dark:bg-amber-900/10',
      )}
    >
      {/* Header */}
      <div className="px-3 py-2 flex flex-wrap items-center gap-2 border-b border-amber-200 dark:border-amber-800">
        <span className="text-xs font-semibold uppercase tracking-wide text-amber-800 dark:text-amber-200">
          Awaiting approval
        </span>
        <span className="font-mono text-sm font-semibold text-gray-900 dark:text-white break-all">
          {tool}
        </span>
        <TierBadge tier={tier} />
        {isSuspect ? <SuspectBadge injectionTier={injectionTier} /> : null}
        {expiryLabel ? (
          <span
            className={clsx(
              'ml-auto inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded',
              expired
                ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
                : 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
            )}
          >
            <Clock className="w-3 h-3" />
            {expired ? 'expired' : `expires in ${expiryLabel}`}
          </span>
        ) : null}
      </div>

      <div className="p-3 space-y-3">
        {meta && meta.length > 0 ? (
          <dl className="grid grid-cols-[minmax(0,8rem)_1fr] gap-x-2 gap-y-0.5 text-xs">
            {meta.map((m) => (
              <React.Fragment key={m.label}>
                <dt className="text-gray-500 dark:text-gray-400">{m.label}</dt>
                <dd className="text-gray-900 dark:text-white break-all">{m.value}</dd>
              </React.Fragment>
            ))}
          </dl>
        ) : null}

        {/* Arguments — all of them, verbatim */}
        <div>
          <div className="text-[10px] uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-1">
            arguments ({argEntries.length})
          </div>
          {argEntries.length === 0 ? (
            <p className="text-xs text-gray-500 dark:text-gray-400">No arguments.</p>
          ) : (
            <dl className="grid grid-cols-[minmax(0,10rem)_1fr] gap-x-2 gap-y-0.5">
              {argEntries.map(([k, v]) => (
                <React.Fragment key={k}>
                  <dt className="font-mono text-xs text-gray-600 dark:text-gray-400 break-all">
                    {k}
                  </dt>
                  <dd className="font-mono text-xs text-gray-900 dark:text-white break-all">
                    {formatArgValue(v)}
                  </dd>
                </React.Fragment>
              ))}
            </dl>
          )}
        </div>

        {/* Effective targets with provenance */}
        <div>
          <div className="text-[10px] uppercase tracking-wide text-gray-500 dark:text-gray-400 mb-1">
            effective targets ({targets.length})
          </div>
          <TargetList targets={targets} />
        </div>

        {/* Hash echo */}
        <div>
          <button
            type="button"
            onClick={() => setShowHashes((s) => !s)}
            className="inline-flex items-center gap-1 text-[10px] uppercase tracking-wide text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200"
          >
            {showHashes ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
            <Hash className="w-3 h-3" /> integrity binding
          </button>
          {showHashes ? (
            <div className="mt-1 space-y-0.5 font-mono text-[10px] text-gray-600 dark:text-gray-400 break-all">
              <div>params_sha256: {paramsSha256 || '—'}</div>
              <div>evidence_sha256: {evidenceSha256 || '—'}</div>
            </div>
          ) : null}
        </div>

        {needsAdminAttestation ? (
          <div className="space-y-2 border border-red-200 dark:border-red-800 rounded p-2 bg-white dark:bg-gray-900">
            <p className="text-xs text-red-800 dark:text-red-200">
              This proposal is marked suspect. Approving it overrides the injection guard and is
              audited against your account.
            </p>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={2}
              placeholder="Required: why is this safe to approve despite the injection signal?"
              className="w-full resize-none text-xs border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white rounded px-2 py-1"
            />
            <label className="flex items-start gap-2 text-xs text-gray-700 dark:text-gray-300 cursor-pointer">
              <input
                type="checkbox"
                checked={acknowledged}
                onChange={(e) => setAcknowledged(e.target.checked)}
                className="mt-0.5 rounded"
              />
              <span>
                I reviewed the targets and arguments above and accept the risk of approving a
                suspect action.
              </span>
            </label>
          </div>
        ) : null}

        {blockedReason ? (
          <p className="text-xs text-amber-800 dark:text-amber-200 bg-amber-100/70 dark:bg-amber-900/30 border border-amber-200 dark:border-amber-800 rounded px-2 py-1.5">
            {blockedReason}
          </p>
        ) : null}

        {cardError ? <InlineCardError text={cardError} /> : null}

        {outcome ? (
          <p
            className={clsx(
              'text-xs font-medium',
              outcome === 'approved'
                ? 'text-green-700 dark:text-green-300'
                : 'text-gray-600 dark:text-gray-400',
            )}
          >
            {outcome === 'approved'
              ? 'Approved — the action was queued for execution.'
              : 'Denied — the action will not run.'}
          </p>
        ) : (
          <div className="space-y-2">
            {denying ? (
              <textarea
                value={denyNotes}
                onChange={(e) => setDenyNotes(e.target.value)}
                rows={2}
                placeholder="Optional denial note (recorded on the action)"
                className="w-full resize-none text-xs border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-white rounded px-2 py-1"
              />
            ) : null}
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={handleApprove}
                disabled={approveDisabled}
                title={blockedReason || undefined}
                className="inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded bg-green-600 hover:bg-green-700 disabled:bg-gray-300 dark:disabled:bg-gray-700 disabled:text-gray-500 dark:disabled:text-gray-400 text-white disabled:cursor-not-allowed"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                {busy ? 'Working…' : 'Approve'}
              </button>
              <button
                type="button"
                onClick={() => (denying ? handleDeny() : setDenying(true))}
                disabled={busy || !hasId || viewer}
                title={
                  viewer
                    ? 'Viewers cannot act on agent proposals.'
                    : !hasId
                      ? 'No action id on this proposal.'
                      : undefined
                }
                className="inline-flex items-center gap-1.5 text-xs font-medium px-3 py-1.5 rounded border border-gray-300 dark:border-gray-600 text-gray-800 dark:text-gray-200 hover:bg-gray-100 dark:hover:bg-gray-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ThumbsDown className="w-3.5 h-3.5" />
                {denying ? 'Confirm deny' : 'Deny'}
              </button>
              {denying ? (
                <button
                  type="button"
                  onClick={() => {
                    setDenying(false);
                    setDenyNotes('');
                  }}
                  disabled={busy}
                  className="text-xs px-3 py-1.5 text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-200"
                >
                  Cancel
                </button>
              ) : null}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ApprovalCard;
