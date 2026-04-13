import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';
import {
  Cpu,
  CheckCircle,
  XCircle,
  Clock,
  Plus,
  Shield,
  ShieldAlert,
  Copy,
  ChevronRight,
} from 'lucide-react';
import clsx from 'clsx';

interface Agent {
  id: string;
  hostname: string;
  display_name?: string | null;
  os_type?: string | null;
  os_version?: string | null;
  agent_version?: string | null;
  ip_address?: string | null;
  status: 'pending' | 'active' | 'offline' | 'disabled' | 'revoked';
  capabilities: string[];
  last_heartbeat_at?: string | null;
  tags: string[];
  created_at?: string | null;
}

interface Dashboard {
  total_agents: number;
  active_agents: number;
  offline_agents: number;
  pending_enroll: number;
  capability_counts: { bas: number; ir: number; purple: number };
  commands_in_flight: number;
  commands_awaiting_approval: number;
  recent_commands: Array<{
    id: string;
    action: string;
    status: string;
    agent_id: string;
    created_at: string | null;
    completed_at: string | null;
    incident_id: string | null;
    simulation_id: string | null;
  }>;
}

interface EnrollResult {
  agent_id: string;
  hostname: string;
  capabilities: string[];
  status: string;
  enrollment_token: string;
  enrollment_expires_at: string | null;
}

const statusColors: Record<string, string> = {
  active: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300',
  offline: 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400',
  pending: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-300',
  disabled: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
  revoked: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
};

const capabilityColors: Record<string, string> = {
  bas: 'bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300',
  ir: 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300',
  purple: 'bg-indigo-100 dark:bg-indigo-900/30 text-indigo-700 dark:text-indigo-300',
};

const commandStatusColors: Record<string, string> = {
  queued: 'text-blue-600 dark:text-blue-400',
  dispatched: 'text-cyan-600 dark:text-cyan-400',
  running: 'text-indigo-600 dark:text-indigo-400',
  completed: 'text-green-600 dark:text-green-400',
  failed: 'text-red-600 dark:text-red-400',
  rejected: 'text-red-600 dark:text-red-400',
  awaiting_approval: 'text-yellow-600 dark:text-yellow-400',
  expired: 'text-gray-500',
};

function formatAge(iso: string | null | undefined): string {
  if (!iso) return '--';
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

export default function AgentManagement() {
  const qc = useQueryClient();
  const { user } = useAuth();
  const orgChannel = `agents:${user?.organization_id ?? 'global'}`;
  const [showEnroll, setShowEnroll] = useState(false);
  const [enrollResult, setEnrollResult] = useState<EnrollResult | null>(null);
  const [enrollForm, setEnrollForm] = useState({
    hostname: '',
    display_name: '',
    capabilities: { bas: true, ir: false, purple: false },
    tags: '',
  });
  const [copied, setCopied] = useState(false);

  const { data: dashboard } = useQuery({
    queryKey: ['agents-dashboard'],
    queryFn: async () => {
      try {
        const r = await api.get<Dashboard>('/agents/dashboard');
        return r.data;
      } catch {
        return null;
      }
    },
    refetchInterval: 5000,
  });

  const { data: agents } = useQuery({
    queryKey: ['agents-list'],
    queryFn: async () => {
      try {
        const r = await api.get<{ total: number; agents: Agent[] }>('/agents');
        return r.data.agents ?? [];
      } catch {
        return [];
      }
    },
    refetchInterval: 5000,
  });

  // Live WebSocket — subscribe to the per-org agents channel so events
  // push into the React Query cache without polling. Channel is
  // `agents:<org_id>` (or `agents:global` in single-tenant mode) so
  // events never leak between tenants.
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) return;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/ws?token=${token}`);
    ws.onopen = () => ws.send(JSON.stringify({ action: 'subscribe', channel: orgChannel }));
    ws.onmessage = () => {
      // Any inbound event invalidates both queries so the UI re-renders
      qc.invalidateQueries({ queryKey: ['agents-dashboard'] });
      qc.invalidateQueries({ queryKey: ['agents-list'] });
    };
    return () => {
      try {
        ws.send(JSON.stringify({ action: 'unsubscribe', channel: orgChannel }));
        ws.close();
      } catch {
        /* noop */
      }
    };
  }, [qc, orgChannel]);

  const submitEnroll = async () => {
    const capabilities = Object.entries(enrollForm.capabilities)
      .filter(([, v]) => v)
      .map(([k]) => k);
    if (!enrollForm.hostname.trim() || capabilities.length === 0) return;
    try {
      const r = await api.post<EnrollResult>('/agents/enroll', {
        hostname: enrollForm.hostname.trim(),
        display_name: enrollForm.display_name.trim() || null,
        capabilities,
        tags: enrollForm.tags
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      });
      setEnrollResult(r.data);
      qc.invalidateQueries({ queryKey: ['agents-list'] });
      qc.invalidateQueries({ queryKey: ['agents-dashboard'] });
    } catch (e: any) {
      alert(e?.response?.data?.detail ?? 'enroll failed');
    }
  };

  const copyToken = () => {
    if (!enrollResult) return;
    navigator.clipboard.writeText(enrollResult.enrollment_token);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Endpoint Agents</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Unified BAS execution, Live Response, and Purple Team agents
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Cpu className="w-10 h-10 text-indigo-600 dark:text-indigo-400" />
          <button
            onClick={() => {
              setEnrollResult(null);
              setShowEnroll(true);
            }}
            className="px-4 py-2 rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 font-medium flex items-center gap-2"
          >
            <Plus className="w-4 h-4" /> Enroll Agent
          </button>
        </div>
      </div>

      {/* Stat tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatTile
          label="Active Agents"
          value={dashboard?.active_agents ?? 0}
          total={dashboard?.total_agents ?? 0}
          icon={<CheckCircle className="w-5 h-5" />}
          color="text-green-600"
        />
        <StatTile
          label="Offline"
          value={dashboard?.offline_agents ?? 0}
          icon={<XCircle className="w-5 h-5" />}
          color="text-gray-500"
        />
        <StatTile
          label="Commands in Flight"
          value={dashboard?.commands_in_flight ?? 0}
          icon={<Clock className="w-5 h-5" />}
          color="text-blue-600"
        />
        <StatTile
          label="Awaiting Approval"
          value={dashboard?.commands_awaiting_approval ?? 0}
          icon={<ShieldAlert className="w-5 h-5" />}
          color="text-yellow-600"
        />
      </div>

      {/* Capability breakdown */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
        <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
          Capability Breakdown
        </h3>
        <div className="flex gap-2 flex-wrap">
          {['bas', 'ir', 'purple'].map((cap) => (
            <span
              key={cap}
              className={clsx('px-3 py-1 rounded-full text-xs font-medium', capabilityColors[cap])}
            >
              {cap.toUpperCase()}:{' '}
              {dashboard?.capability_counts?.[cap as 'bas' | 'ir' | 'purple'] ?? 0}
            </span>
          ))}
        </div>
      </div>

      {/* Agent list */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Enrolled Agents</h3>
        </div>
        <table className="w-full">
          <thead>
            <tr className="border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-700">
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                Host
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                Status
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                Capabilities
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                OS
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                Last Seen
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {(!agents || agents.length === 0) && (
              <tr>
                <td
                  colSpan={5}
                  className="px-6 py-8 text-center text-gray-500 dark:text-gray-400"
                >
                  No agents enrolled yet. Click "Enroll Agent" to get started.
                </td>
              </tr>
            )}
            {agents?.map((a) => (
              <tr key={a.id} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                <td className="px-6 py-4">
                  <div className="font-medium text-gray-900 dark:text-white">{a.hostname}</div>
                  {a.display_name && (
                    <div className="text-xs text-gray-500">{a.display_name}</div>
                  )}
                </td>
                <td className="px-6 py-4">
                  <span
                    className={clsx(
                      'px-3 py-1 rounded-full text-xs font-medium',
                      statusColors[a.status] ?? statusColors.offline,
                    )}
                  >
                    {a.status}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex gap-1 flex-wrap">
                    {(a.capabilities ?? []).map((c) => (
                      <span
                        key={c}
                        className={clsx(
                          'px-2 py-1 rounded text-xs font-medium',
                          capabilityColors[c] ?? 'bg-gray-100 text-gray-600',
                        )}
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {a.os_type ? `${a.os_type} ${a.os_version ?? ''}` : '--'}
                </td>
                <td className="px-6 py-4 text-sm text-gray-600 dark:text-gray-400">
                  {formatAge(a.last_heartbeat_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Recent commands */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Commands</h3>
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
                Linked
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-900 dark:text-white uppercase">
                When
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-700">
            {(!dashboard?.recent_commands || dashboard.recent_commands.length === 0) && (
              <tr>
                <td colSpan={4} className="px-6 py-6 text-center text-sm text-gray-500">
                  No recent commands.
                </td>
              </tr>
            )}
            {dashboard?.recent_commands?.map((c) => (
              <tr key={c.id}>
                <td className="px-6 py-3 font-mono text-sm text-gray-900 dark:text-white">
                  {c.action}
                </td>
                <td
                  className={clsx(
                    'px-6 py-3 text-sm font-medium',
                    commandStatusColors[c.status] ?? 'text-gray-500',
                  )}
                >
                  {c.status}
                </td>
                <td className="px-6 py-3 text-xs text-gray-500">
                  {c.incident_id ? `incident:${c.incident_id.slice(0, 8)}` : ''}
                  {c.simulation_id ? `sim:${c.simulation_id.slice(0, 8)}` : ''}
                </td>
                <td className="px-6 py-3 text-xs text-gray-500">{formatAge(c.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Enroll modal */}
      {showEnroll && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 w-[480px] max-h-screen overflow-y-auto">
            {!enrollResult ? (
              <>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
                  Enroll Endpoint Agent
                </h2>
                <div className="space-y-3">
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-900 dark:text-white">
                      Hostname *
                    </label>
                    <input
                      value={enrollForm.hostname}
                      onChange={(e) =>
                        setEnrollForm({ ...enrollForm, hostname: e.target.value })
                      }
                      placeholder="prod-edr-01"
                      className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-900 dark:text-white">
                      Display Name
                    </label>
                    <input
                      value={enrollForm.display_name}
                      onChange={(e) =>
                        setEnrollForm({ ...enrollForm, display_name: e.target.value })
                      }
                      placeholder="Production EDR host #1"
                      className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-2 text-gray-900 dark:text-white">
                      Capabilities *
                    </label>
                    <div className="space-y-1">
                      {(['bas', 'ir', 'purple'] as const).map((cap) => (
                        <label key={cap} className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={enrollForm.capabilities[cap]}
                            onChange={(e) =>
                              setEnrollForm({
                                ...enrollForm,
                                capabilities: {
                                  ...enrollForm.capabilities,
                                  [cap]: e.target.checked,
                                },
                              })
                            }
                          />
                          <span className="text-sm text-gray-900 dark:text-white">
                            <span className="font-mono font-semibold">{cap}</span>
                            {cap === 'bas' && ' — BAS atomic test execution'}
                            {cap === 'ir' &&
                              ' — Live Response (kill, isolate, disable, collect)'}
                            {cap === 'purple' && ' — Purple team correlated execution'}
                          </span>
                        </label>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-900 dark:text-white">
                      Tags (comma-separated)
                    </label>
                    <input
                      value={enrollForm.tags}
                      onChange={(e) => setEnrollForm({ ...enrollForm, tags: e.target.value })}
                      placeholder="lab,east-1"
                      className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                    />
                  </div>
                </div>
                <div className="flex gap-2 mt-6">
                  <button
                    onClick={() => setShowEnroll(false)}
                    className="flex-1 px-4 py-2 border rounded-lg text-gray-900 dark:text-white"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={submitEnroll}
                    className="flex-1 px-4 py-2 bg-indigo-600 text-white rounded-lg font-medium"
                  >
                    Create
                  </button>
                </div>
              </>
            ) : (
              <>
                <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-2 flex items-center gap-2">
                  <Shield className="w-6 h-6 text-green-600" />
                  Agent Enrolled
                </h2>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">
                  Copy this one-time enrollment token and run it on the target host. The token
                  expires in 30 minutes and can only be used once.
                </p>
                <div className="bg-gray-100 dark:bg-gray-900 rounded p-3 font-mono text-xs break-all mb-2">
                  {enrollResult.enrollment_token}
                </div>
                <button
                  onClick={copyToken}
                  className="w-full mb-3 px-3 py-2 bg-gray-700 text-white rounded text-sm flex items-center justify-center gap-2"
                >
                  <Copy className="w-4 h-4" />
                  {copied ? 'Copied!' : 'Copy enrollment token'}
                </button>
                <div className="bg-gray-100 dark:bg-gray-900 rounded p-3 font-mono text-xs mb-4">
                  <div className="text-gray-500"># On the target host:</div>
                  <div>python pysoar_agent.py \</div>
                  <div className="pl-4">--server https://pysoar.it.com \</div>
                  <div className="pl-4">--enroll {enrollResult.enrollment_token}</div>
                  <div className="text-gray-500 mt-2"># Then start the poll loop:</div>
                  <div>python pysoar_agent.py --server https://pysoar.it.com --poll</div>
                </div>
                <button
                  onClick={() => {
                    setShowEnroll(false);
                    setEnrollResult(null);
                    setEnrollForm({
                      hostname: '',
                      display_name: '',
                      capabilities: { bas: true, ir: false, purple: false },
                      tags: '',
                    });
                  }}
                  className="w-full px-4 py-2 bg-indigo-600 text-white rounded-lg font-medium"
                >
                  Done
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function StatTile({
  label,
  value,
  total,
  icon,
  color,
}: {
  label: string;
  value: number;
  total?: number;
  icon: React.ReactNode;
  color: string;
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-600 dark:text-gray-400">{label}</p>
        <span className={color}>{icon}</span>
      </div>
      <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
        {value}
        {total !== undefined && (
          <span className="text-lg text-gray-400 dark:text-gray-500 font-normal"> / {total}</span>
        )}
      </p>
    </div>
  );
}
