import { useState, useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import {
  Swords,
  Play,
  Zap,
  Eye,
  CheckCircle,
  XCircle,
} from 'lucide-react';
import clsx from 'clsx';

interface AttackTechnique {
  id: string;
  mitre_id: string;
  name: string;
  tactic: string;
  risk_level: string;
  is_safe: boolean;
}

interface Agent {
  id: string;
  hostname: string;
  status: string;
  capabilities: string[];
}

interface StreamEvent {
  id: string; // local id for react key
  timestamp: string;
  type: string;
  action?: string;
  command_id?: string;
  agent_id?: string;
  hostname?: string;
  status?: string;
  stdout_preview?: string;
  stderr_preview?: string;
  raw?: Record<string, any>;
}

const eventColor: Record<string, string> = {
  agent_command_queued: 'border-blue-500 bg-blue-50 dark:bg-blue-900/20',
  agent_command_dispatched: 'border-cyan-500 bg-cyan-50 dark:bg-cyan-900/20',
  agent_command_result: 'border-green-500 bg-green-50 dark:bg-green-900/20',
};

export default function PurpleTeam() {
  const [selectedAgent, setSelectedAgent] = useState('');
  const [selectedTechnique, setSelectedTechnique] = useState('');
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [isFiring, setIsFiring] = useState(false);
  const [lastResult, setLastResult] = useState<{ detected: boolean; hostname: string; technique: string } | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const { data: agents } = useQuery({
    queryKey: ['pt-agents'],
    queryFn: async () => {
      try {
        const r = await api.get<{ agents: Agent[] }>('/agents');
        return (r.data.agents ?? []).filter(
          (a) =>
            a.status === 'active' &&
            (a.capabilities?.includes('bas') || a.capabilities?.includes('purple')),
        );
      } catch {
        return [];
      }
    },
  });

  const { data: techniques } = useQuery({
    queryKey: ['pt-techniques'],
    queryFn: async () => {
      try {
        const r = await api.get<{ techniques: AttackTechnique[] }>('/simulation/techniques');
        return (r.data.techniques ?? []).filter((t) => t.is_safe);
      } catch {
        return [];
      }
    },
  });

  // Open a long-lived WebSocket and subscribe to the purple team channel
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) return;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/ws?token=${token}`);
    wsRef.current = ws;
    ws.onopen = () => {
      // Subscribe to both the global 'agents' stream and a purple-team
      // wildcard. The server only broadcasts purple:<sim_id> if a
      // simulation_id was attached to the command, so we still rely on
      // the 'agents' channel to catch ad-hoc fires.
      ws.send(JSON.stringify({ action: 'subscribe', channel: 'agents' }));
    };
    ws.onmessage = (msg) => {
      try {
        const raw = JSON.parse(msg.data);
        if (!raw || typeof raw !== 'object') return;
        if (!raw.type || !String(raw.type).startsWith('agent_command')) return;
        setEvents((prev) =>
          [
            {
              id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              timestamp: raw.timestamp ?? new Date().toISOString(),
              type: raw.type,
              action: raw.action,
              command_id: raw.command_id,
              agent_id: raw.agent_id,
              hostname: raw.hostname,
              status: raw.status,
              stdout_preview: raw.stdout_preview,
              stderr_preview: raw.stderr_preview,
              raw,
            },
            ...prev,
          ].slice(0, 50),
        );
      } catch {
        /* noop */
      }
    };
    return () => {
      try {
        ws.close();
      } catch {
        /* noop */
      }
    };
  }, []);

  const fireTechnique = async () => {
    if (!selectedAgent || !selectedTechnique) return;
    setIsFiring(true);
    try {
      // Issue a run_atomic_test command via the agents API so it
      // streams through the WebSocket channel. We pull the command
      // body from the technique details.
      const techRes = await api.get<AttackTechnique & { test_command?: string; test_commands?: any[] }>(
        `/simulation/techniques/${selectedTechnique}`,
      );
      const t: any = techRes.data;
      const cmd =
        t.test_command ??
        (Array.isArray(t.test_commands) && t.test_commands[0]?.command) ??
        'echo "no test command"';
      const executor =
        (Array.isArray(t.test_commands) && t.test_commands[0]?.executor) ?? 'sh';

      await api.post(`/agents/${selectedAgent}/commands`, {
        action: 'run_atomic_test',
        payload: {
          command: cmd,
          executor,
          mitre_id: selectedTechnique,
        },
      });

      // Also fire the simulation's standalone /technique/{id}/test to
      // score coverage against detection rules in parallel
      const simRes = await api.post<{ detected: boolean }>(
        `/simulation/techniques/${selectedTechnique}/test`,
        {},
      );
      const hostname = agents?.find((a) => a.id === selectedAgent)?.hostname ?? selectedAgent;
      setLastResult({
        detected: simRes.data?.detected ?? false,
        hostname,
        technique: selectedTechnique,
      });
    } catch (e: any) {
      alert(e?.response?.data?.detail ?? 'fire failed');
    } finally {
      setIsFiring(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Purple Team</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Fire a MITRE ATT&amp;CK technique on a live agent and watch the detection pipeline in
            real time.
          </p>
        </div>
        <Swords className="w-10 h-10 text-indigo-600 dark:text-indigo-400" />
      </div>

      {/* Controls */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-6">
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
              <option value="">-- Select BAS-capable agent --</option>
              {agents?.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.hostname}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-900 dark:text-white">
              MITRE Technique
            </label>
            <select
              value={selectedTechnique}
              onChange={(e) => setSelectedTechnique(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            >
              <option value="">-- Select a technique --</option>
              {techniques?.map((t) => (
                <option key={t.mitre_id} value={t.mitre_id}>
                  {t.mitre_id} — {t.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-900 dark:text-white">
              &nbsp;
            </label>
            <button
              onClick={fireTechnique}
              disabled={isFiring || !selectedAgent || !selectedTechnique}
              className={clsx(
                'w-full px-4 py-2 rounded-lg font-medium text-white flex items-center justify-center gap-2',
                isFiring || !selectedAgent || !selectedTechnique
                  ? 'bg-gray-400 cursor-not-allowed'
                  : 'bg-indigo-600 hover:bg-indigo-700',
              )}
            >
              <Play className="w-4 h-4" />
              {isFiring ? 'Firing...' : 'Fire Technique'}
            </button>
          </div>
        </div>

        {lastResult && (
          <div
            className={clsx(
              'mt-4 p-3 rounded border flex items-center gap-2 text-sm',
              lastResult.detected
                ? 'bg-green-50 dark:bg-green-900/20 border-green-300 text-green-700 dark:text-green-300'
                : 'bg-red-50 dark:bg-red-900/20 border-red-300 text-red-700 dark:text-red-300',
            )}
          >
            {lastResult.detected ? (
              <>
                <CheckCircle className="w-4 h-4" />
                <span>
                  <strong>{lastResult.technique}</strong> fired on {lastResult.hostname} —
                  DETECTED by at least one active rule.
                </span>
              </>
            ) : (
              <>
                <XCircle className="w-4 h-4" />
                <span>
                  <strong>{lastResult.technique}</strong> fired on {lastResult.hostname} — NOT
                  DETECTED. No active detection rule covers this technique. Consider adding a
                  Sigma rule or SIEM correlation.
                </span>
              </>
            )}
          </div>
        )}
      </div>

      {/* Live stream */}
      <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex items-center gap-2">
          <Eye className="w-5 h-5 text-indigo-600" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
            Live Event Stream
          </h3>
          <span className="ml-auto text-xs text-gray-500">
            {events.length} event{events.length === 1 ? '' : 's'}
          </span>
        </div>
        <div className="max-h-[500px] overflow-y-auto">
          {events.length === 0 && (
            <div className="px-6 py-12 text-center text-sm text-gray-500">
              Waiting for agent command events. Fire a technique above, or create an incident
              with an affected system that has an enrolled agent.
            </div>
          )}
          {events.map((ev) => (
            <div
              key={ev.id}
              className={clsx(
                'px-6 py-3 border-l-4 border-b border-gray-100 dark:border-gray-700',
                eventColor[ev.type] ?? 'border-gray-400',
              )}
            >
              <div className="flex items-center gap-3 text-sm">
                <Zap className="w-4 h-4 text-indigo-500 flex-shrink-0" />
                <span className="font-mono font-semibold text-gray-900 dark:text-white">
                  {ev.type.replace('agent_command_', '')}
                </span>
                <span className="font-mono text-xs text-gray-600 dark:text-gray-400">
                  {ev.action}
                </span>
                {ev.hostname && (
                  <span className="text-xs text-gray-500">on {ev.hostname}</span>
                )}
                {ev.status && (
                  <span className="ml-auto text-xs font-semibold text-gray-700 dark:text-gray-300">
                    {ev.status}
                  </span>
                )}
                <span className="text-xs text-gray-400">
                  {new Date(ev.timestamp).toLocaleTimeString()}
                </span>
              </div>
              {(ev.stdout_preview || ev.stderr_preview) && (
                <pre className="mt-2 bg-gray-900 text-green-200 p-2 rounded text-xs overflow-x-auto font-mono">
                  {ev.stdout_preview}
                  {ev.stderr_preview ? `\n[stderr] ${ev.stderr_preview}` : ''}
                </pre>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
