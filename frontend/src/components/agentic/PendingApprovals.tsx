/**
 * Agentic SOC → Approvals.
 *
 * Renders every action the runtime parked for human approval, using the same
 * ApprovalCard the chat workbench uses, so the hash echo and the suspect
 * rules cannot diverge between the two surfaces.
 *
 * There is deliberately no bulk-approve control: destructive, privileged and
 * suspect actions each require the approver to have read the arguments and
 * targets on that specific card.
 */
import React from 'react';
import { CheckSquare, ShieldAlert } from 'lucide-react';
import type { PendingApprovalRow } from '../../api/endpoints';
import { useAuth } from '../../contexts/AuthContext';
import {
  hasIntegrityBinding,
  parseParameters,
  rowActionId,
  rowTargets,
  rowToolName,
} from './runtime';
import ApprovalCard from './ApprovalCard';

interface PendingApprovalsProps {
  rows: PendingApprovalRow[];
  role?: string | null;
  isSuperuser?: boolean | null;
  onResolved?: (actionId: string, outcome: 'approved' | 'denied') => void;
}

function metaFor(row: PendingApprovalRow): Array<{ label: string; value: string }> {
  const proposer =
    row.proposed_by_user_id
      ? `user ${row.proposed_by_user_id}`
      : row.proposed_by_agent_id
        ? `agent ${row.proposed_by_agent_id}`
        : row.agent_name
          ? `agent ${row.agent_name}`
          : null;

  const meta: Array<{ label: string; value: string }> = [];
  meta.push({ label: 'Source', value: row.source || 'not recorded' });
  if (proposer) meta.push({ label: 'Proposed by', value: proposer });
  if (row.investigation_title) {
    meta.push({ label: 'Investigation', value: row.investigation_title });
  }
  if (row.created_at) {
    meta.push({ label: 'Proposed at', value: new Date(row.created_at).toLocaleString() });
  }
  if (typeof row.confidence_score === 'number') {
    meta.push({ label: 'Confidence', value: `${Math.round(row.confidence_score)}%` });
  }
  if (typeof row.risk_score === 'number') {
    meta.push({ label: 'Risk score', value: String(row.risk_score) });
  }
  if (row.requires_second_approver) {
    meta.push({
      label: 'Approvals',
      value: row.first_approved_by
        ? `1 of 2 (first by user ${row.first_approved_by})`
        : '0 of 2 (two distinct approvers required)',
    });
  }
  return meta;
}

const PendingApprovals: React.FC<PendingApprovalsProps> = ({
  rows,
  role,
  isSuperuser,
  onResolved,
}) => {
  const { user } = useAuth();
  const unverifiable = rows.filter((r) => !hasIntegrityBinding(r)).length;
  const suspectCount = rows.filter((r) => Boolean(r.suspect)).length;
  const awaitingSecond = rows.filter((r) => Boolean(r.first_approved_by)).length;

  return (
    <div>
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <h2 className="text-xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <CheckSquare className="w-5 h-5" />
          Pending approvals
        </h2>
        <span className="text-xs text-gray-500 dark:text-gray-400">{rows.length} action(s)</span>
        {suspectCount > 0 ? (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300">
            <ShieldAlert className="w-3 h-3" /> {suspectCount} suspect
          </span>
        ) : null}
        {awaitingSecond > 0 ? (
          <span className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
            {awaitingSecond} awaiting second approval
          </span>
        ) : null}
      </div>

      <p className="text-xs text-gray-500 dark:text-gray-400 mb-4">
        Each action is approved on its own card after reading its arguments and resolved targets.
        There is no bulk approve: destructive and privileged actions are never batch-authorized.
      </p>

      {unverifiable > 0 ? (
        <p className="text-xs text-amber-800 dark:text-amber-200 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded px-3 py-2 mb-4">
          {unverifiable} of these rows carry no integrity binding (no params_sha256 /
          evidence_sha256). They predate the guarded runtime and cannot be approved from the UI —
          re-run the investigation to raise a verifiable proposal.
        </p>
      ) : null}

      {rows.length === 0 ? (
        <p className="py-8 text-center text-sm text-gray-500 dark:text-gray-400">
          No actions awaiting approval.
        </p>
      ) : (
        <div className="space-y-4">
          {rows.map((row) => {
            const id = rowActionId(row);
            return (
              <ApprovalCard
                key={id || JSON.stringify(row).slice(0, 64)}
                actionId={id || null}
                tool={rowToolName(row)}
                args={parseParameters(row.parameters)}
                targets={rowTargets(row)}
                paramsSha256={row.params_sha256}
                evidenceSha256={row.evidence_sha256}
                suspect={row.suspect}
                injectionTier={row.injection_tier}
                expiresAt={row.expires_at}
                meta={metaFor(row)}
                role={role}
                isSuperuser={isSuperuser}
                currentUserId={user?.id ?? null}
                requiresSecondApprover={row.requires_second_approver}
                firstApprovedBy={row.first_approved_by}
                firstApprovedAt={row.first_approved_at}
                proposedByUserId={row.proposed_by_user_id}
                onResolved={onResolved}
              />
            );
          })}
        </div>
      )}
    </div>
  );
};

export default PendingApprovals;
