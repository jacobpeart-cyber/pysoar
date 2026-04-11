import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import {
  ShieldAlert,
  Check,
  X,
  Terminal,
  AlertTriangle,
  Play,
} from 'lucide-react';
import clsx from 'clsx';

interface Command {
  id: string;
  agent_id: string;
  action: string;
  payload: Record<string, any>;
  status: string;
  approval_required: boolean;
  approved_by?: string | null;
  approved_at?: string | null;
  command_hash: string;
  chain_hash: string;
  dispatched_at?: string | null;
  completed_at?: string | null;
  created_at?: string | null;
}

interface Agent {
  id: string;
  hostname: string;
  status: string;
  capabilities: string[];
}

const IR_ACTIONS: Array<{
  action: string;
  label: string;
  requiresApproval: boolean;
  payloadHint: string;
}> = [
  { action: 'collect_process_list', label: 'Collect processes', requiresApproval: false, payloadHint: '{}' },
  { action: 'collect_network_connections', label: 'Collect network', requiresApproval: false, payloadHint: '{}' },
  { action: 'kill_process', label: 'Kill process', requiresApproval: true, payloadHint: '{"pid": 1234}' },
  { action: 'isolate_host', label: 'Isolate host', requiresApproval: true, payloadHint: '{"mgmt_cidr": "10.0.0.0/8"}' },
  { action: 'release_host', label: 'Release host', requiresApproval: true, payloadHint: '{}' },
  { action: 'disable_account', label: 'Disable account', requiresApproval: true, payloadHint: '{"username": "alice"}' },
  { action: 'collect_file', label: 'Collect file', requiresApproval: false, payloadHint: '{"path": "/etc/passwd"}' },
  { action: 'quarantine_file', label: 'Quarantine file', requiresApproval: true, payloadHint: '{"path": "/tmp/evil.bin"}' },
  { action: 'collect_memory_dump', label: 'Memory dump', requiresApproval: true, payloadHint: '{"pid": 1234}' },
];

const statusColors: Record<string, string> = {
  queued: 'text-blue-600',
  dispatched: 'text-cyan-600',
  running: 'text-indigo-600',
  completed: 'text-green-600',
  failed: 'text-red-600',
  rejected: 'text-red-600',
  awaiting_approval: 'text-yellow-600',
  expired: 'text-gray-500',
};

function ageText(iso: string | null | undefined): string {
  if (!iso) return '--';
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ago`;
}

export default function LiveResponse() {
  const qc = useQueryClient();
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [selectedAction, setSelectedAction] = useState<string>(IR_ACTIONS[0].action);
  const [payloadText, setPayloadText] = useState('{}');
  const [issuing, setIssuing] = useState(false);
  const [rejectModalFor, setRejectModalFor] = useState<Command | null>(null);
  const [rejectReason, setRejectReason] = useState('');
  const [approveReason, setApproveReason] = useState<Record<string, string>>({});

  const { data: agents } = useQuery({
    queryKey: ['lr-agents'],
    queryFn: async () => {
      try {
        const r = await api.get<{ agents: Agent[] }>('/agents');
        return (r.data.agents ?? []).filter(
          (a) => a.capabilities?.includes('ir') && a.status === 'active',
        );
      } catch {
        return [];
      }
    },
    refetchInterval: 10000,
  });

  const { data: pending } = useQuery({
    queryKey: ['lr-pending'],
    queryFn: async () => {
      try {
        const r = await api.get<Command[]>('/agents/commands/pending-approval');
        return r.data;
      } catch {
        return [];
      }
    },
    refetchInterval: 5000,
  });

  const { data: recent } = useQuery({
    queryKey: ['lr-recent', selectedAgent],
    queryFn: async () => {
      if (!selectedAgent) return [];
      try {
        const r = await api.get<Command[]>(`/agents/${selectedAgent}/commands?limit=50`);
        return r.data;
      } catch {
        return [];
      }
    },
    enabled: !!selectedAgent,
    refetchInterval: 3000,
  });

  // WebSocket push — invalidate on every agent event
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) return;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/ws?token=${token}`);
    ws.onopen = () => ws.send(JSON.stringify({ action: 'subscribe', channel: 'agents' }));
    ws.onmessage = () => {
      qc.invalidateQueries({ queryKey: ['lr-pending'] });
      qc.invalidateQueries({ queryKey: ['lr-recent', selectedAgent] });
    };
    return () => {
      try {
        ws.close();
      } catch {
        /* noop */
      }
    };
  }, [qc, selectedAgent]);

  const issueCommand = async () => {
    if (!selectedAgent || !selectedAction) return;
    setIssuing(true);
    try {
      let payload: Record<string, any> = {};
      try {
        payload = JSON.parse(payloadText || '{}');
      } catch {
        alert('Payload is not valid JSON');
        setIssuing(false);
        return;
      }
      await api.post(`/agents/${selectedAgent}/commands`, {
        action: selectedAction,
        payload,
      });
      qc.invalidateQueries({ queryKey: ['lr-pending'] });
      qc.invalidateQueries({ queryKey: ['lr-recent', selectedAgent] });
    } catch (e: any) {
      alert(e?.response?.data?.detail ?? 'issue failed');
    } finally {
      setIssuing(false);
    }
  };

  const approve = async (cmdId: string) => {
    try {
      await api.post(`/agents/commands/${cmdId}/approve`, {
        reason: approveReason[cmdId] || 'approved via Live Response console',
      });
      setApproveReason((prev) => {
        const next = { ...prev };
        delete next[cmdId];
        return next;
      });
      qc.invalidateQueries({ queryKey: ['lr-pending'] });
    } catch (e: any) {
      alert(e?.response?.data?.detail ?? 'approve failed');
    }
  };

  const reject = async () => {
    if (!rejectModalFor) return;
    try {
      await api.post(`/agents/commands/${rejectModalFor.id}/reject`, {
        reason: rejectReason || 'no reason given',
      });
      setRejectModalFor(null);
      setRejectReason('');
      qc.invalidateQueries({ queryKey: ['lr-pending'] });
    } catch (e: any) {
      alert(e?.response?.data?.detail ?? 'reject failed');
    }
  };

  const actionMeta = IR_ACTIONS.find((a) => a.action === selectedAction);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Live Response</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Issue incident response commands to enrolled endpoints. High-blast actions require a
            second analyst to approve.
          </p>
        </div>
        <Terminal className="w-10 h-10 text-red-600 dark:text-red-400" />
      </div>

      {/* Approval queue (always first) */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-yellow-300 dark:border-yellow-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 bg-yellow-50 dark:bg-yellow-900/10 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-yellow-600 dark:text-yellow-400" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Pending Approval ({pending?.length ?? 0})
          </h3>
        </div>
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {(!pending || pending.length === 0) && (
            <div className="px-6 py-6 text-sm text-gray-500 text-center">
              No actions awaiting approval.
            </div>
          )}
          {pending?.map((cmd) => (
            <div key={cmd.id} className="px-6 py-4 space-y-3">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-600" />
                    <span className="font-mono font-semibold text-gray-900 dark:text-white">
                      {cmd.action}
                    </span>
                    <span className="text-xs text-gray-500">{ageText(cmd.created_at)}</span>
                  </div>
                  <div className="text-xs text-gray-500 font-mono mt-1">agent: {cmd.agent_id}</div>
                  {Object.keys(cmd.payload ?? {}).length > 0 && (
                    <pre className="mt-2 bg-gray-50 dark:bg-gray-900 p-2 rounded text-xs text-gray-700 dark:text-gray-300 overflow-x-auto">
                      {JSON.stringify(cmd.payload, null, 2)}
                    </pre>
                  )}
                </div>
              </div>
              <div className="flex gap-2">
                <input
                  value={approveReason[cmd.id] ?? ''}
                  onChange={(e) =>
                    setApproveReason({ ...approveReason, [cmd.id]: e.target.value })
                  }
                  placeholder="Reason for approval (optional)"
                  className="flex-1 px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                />
                <button
                  onClick={() => approve(cmd.id)}
                  className="px-4 py-2 bg-green-600 text-white rounded font-medium text-sm flex items-center gap-1"
                >
                  <Check className="w-4 h-4" /> Approve
                </button>
                <button
                  onClick={() => setRejectModalFor(cmd)}
                  className="px-4 py-2 bg-red-600 text-white rounded font-medium text-sm flex items-center gap-1"
                >
                  <X className="w-4 h-4" /> Reject
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Issue command */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
          <Play className="w-5 h-5 text-red-600" />
          Issue Command
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-900 dark:text-white">
              Target Agent
            </label>
            <select
              value={selectedAgent}
              onChange={(e) => setSelectedAgent(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            >
              <option value="">-- Select an IR-capable agent --</option>
              {agents?.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-900 dark:text-white">
              Action
            </label>
            <select
              value={selectedAction}
              onChange={(e) => {
                setSelectedAction(e.target.value);
                const meta = IR_ACTIONS.find((a) => a.action === e.target.value);
                setPayloadText(meta?.payloadHint ?? '{}');
              }}
              className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            >
              {IR_ACTIONS.map((a) => (
                <option key={a.action} value={a.action}>
                  {a.label} {a.requiresApproval ? '(approval)' : ''}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-900 dark:text-white">
              &nbsp;
            </label>
            <button
              onClick={issueCommand}
              disabled={issuing || !selectedAgent}
              className={clsx(
                'w-full px-4 py-2 rounded-lg font-medium text-white',
                issuing || !selectedAgent
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-red-600 hover:bg-red-700',
              )}
            >
              {issuing
                ? 'Queuing...'
                : actionMeta?.requiresApproval
                  ? 'Queue (awaits approval)'
                  : 'Dispatch'}
            </button>
          </div>
        </div>
        <div className="mt-4">
          <label className="block text-sm font-medium mb-1 text-gray-900 dark:text-white">
            Payload (JSON)
          </label>
          <textarea
            value={payloadText}
            onChange={(e) => setPayloadText(e.target.value)}
            rows={4}
            className="w-full font-mono text-sm px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          />
        </div>
      </div>

      {/* Recent commands for selected agent */}
      {selectedAgent && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              Recent Commands
            </h3>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                  Action
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                  Status
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                  Created
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                  Completed
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
              {(!recent || recent.length === 0) && (
                <tr>
                  <td colSpan={4} className="px-6 py-6 text-sm text-gray-500 text-center">
                    No commands for this agent yet.
                  </td>
                </tr>
              )}
              {recent?.map((c) => (
                <tr key={c.id}>
                  <td className="px-6 py-3 font-mono text-sm text-gray-900 dark:text-white">
                    {c.action}
                  </td>
                  <td
                    className={clsx(
                      'px-6 py-3 text-sm font-medium',
                      statusColors[c.status] ?? 'text-gray-500',
                    )}
                  >
                    {c.status}
                  </td>
                  <td className="px-6 py-3 text-xs text-gray-500">{ageText(c.created_at)}</td>
                  <td className="px-6 py-3 text-xs text-gray-500">{ageText(c.completed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Reject modal */}
      {rejectModalFor && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-96">
            <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-2">
              Reject {rejectModalFor.action}
            </h3>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
              Rejection is terminal and gets recorded in the audit chain. Reason is required.
            </p>
            <textarea
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              rows={3}
              placeholder="Reason for rejection"
              className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
            <div className="flex gap-2 mt-4">
              <button
                onClick={() => {
                  setRejectModalFor(null);
                  setRejectReason('');
                }}
                className="flex-1 px-4 py-2 border rounded-lg text-gray-900 dark:text-white"
              >
                Cancel
              </button>
              <button
                onClick={reject}
                disabled={!rejectReason.trim()}
                className={clsx(
                  'flex-1 px-4 py-2 text-white rounded-lg font-medium',
                  !rejectReason.trim() ? 'bg-gray-400' : 'bg-red-600 hover:bg-red-700',
                )}
              >
                Reject
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
