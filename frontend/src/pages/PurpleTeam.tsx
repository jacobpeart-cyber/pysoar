import { useState, useEffect, useRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from '../lib/api';
import { useAuth } from '../contexts/AuthContext';
import {
  Swords,
  Play,
  Zap,
  Eye,
  CheckCircle,
  XCircle,
  ShieldCheck,
  RadioTower,
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
  // siem_match fields
  rule_id?: string;
  rule_title?: string;
  severity?: string;
  mitre_techniques?: string[];
  alert_id?: string;
  correlates_with_fired?: boolean;
  raw?: Record<string, any>;
}

const eventColor: Record<string, string> = {
  agent_command_queued: 'border-blue-500 bg-blue-50 dark:bg-blue-900/20',
  agent_command_dispatched: 'border-cyan-500 bg-cyan-50 dark:bg-cyan-900/20',
  agent_command_result: 'border-green-500 bg-green-50 dark:bg-green-900/20',
  siem_match: 'border-fuchsia-500 bg-fuchsia-50 dark:bg-fuchsia-900/20',
};

const severityColors: Record<string, string> = {
  critical: 'text-red-700 dark:text-red-300',
  high: 'text-orange-700 dark:text-orange-300',
  medium: 'text-yellow-700 dark:text-yellow-300',
  low: 'text-blue-700 dark:text-blue-300',
};

export default function PurpleTeam() {
  const { user } = useAuth();
  const orgChannel = `agents:${user?.organization_id ?? 'global'}`;
  const [selectedAgent, setSelectedAgent] = useState('');
  const [selectedTechnique, setSelectedTechnique] = useState('');
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [isFiring, setIsFiring] = useState(false);
  const [lastResult, setLastResult] = useState<{ detected: boolean; hostname: string; technique: string } | null>(null);
  // Techniques that have been fired in this session — used to correlate
  // incoming siem_match events against red-team activity. The Set is
  // refilled every time the user fires a new technique and persists
  // until page reload.
  const firedTechniquesRef = useRef<Set<string>>(new Set());
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

  // Open a long-lived WebSocket and subscribe to the per-org purple
  // team / agents channel. Three event types feed the timeline:
  //   agent_command_queued / dispatched / result  — red team activity
  //   siem_match                                  — blue team detection
  // We correlate by MITRE technique id: if a SIEM match's
  // mitre_techniques list overlaps with anything we've fired in this
  // session, we flag it with correlates_with_fired so the UI can
  // render it as a successful purple-team catch.
  useEffect(() => {
    const token = localStorage.getItem('access_token');
    if (!token) return;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/ws?token=${token}`);
    wsRef.current = ws;
    ws.onopen = () => {
      ws.send(JSON.stringify({ action: 'subscribe', channel: orgChannel }));
    };
    ws.onmessage = (msg) => {
      try {
        const raw = JSON.parse(msg.data);
        if (!raw || typeof raw !== 'object') return;
        const t = String(raw.type || '');
        if (!t.startsWith('agent_command') && t !== 'siem_match') return;

        const correlates =
          t === 'siem_match' &&
          Array.isArray(raw.mitre_techniques) &&
          raw.mitre_techniques.some((tid: string) =>
            firedTechniquesRef.current.has(tid),
          );

        setEvents((prev) =>
          [
            {
              id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              timestamp: raw.timestamp ?? new Date().toISOString(),
              type: t,
              action: raw.action,
              command_id: raw.command_id,
              agent_id: raw.agent_id,
              hostname: raw.hostname,
              status: raw.status,
              stdout_preview: raw.stdout_preview,
              stderr_preview: raw.stderr_preview,
              rule_id: raw.rule_id,
              rule_title: raw.rule_title,
              severity: raw.severity,
              mitre_techniques: raw.mitre_techniques,
              alert_id: raw.alert_id,
              correlates_with_fired: correlates,
              raw,
            },
            ...prev,
          ].slice(0, 100),
        );
      } catch {
        /* noop */
      }
    };
    return () => {
      try {
        ws.send(JSON.stringify({ action: 'unsubscribe', channel: orgChannel }));
        ws.close();
      } catch {
        /* noop */
      }
    };
  }, [orgChannel]);

  const fireTechnique = async () => {
    if (!selectedAgent || !selectedTechnique) return;
    setIsFiring(true);
    // Remember which technique we just fired so subsequent siem_match
    // events can be flagged as correlated red->blue hits.
    firedTechniquesRef.current.add(selectedTechnique);
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
          {events.map((ev) => {
            const isSiem = ev.type === 'siem_match';
            return (
              <div
                key={ev.id}
                className={clsx(
                  'px-6 py-3 border-l-4 border-b border-gray-100 dark:border-gray-700',
                  eventColor[ev.type] ?? 'border-gray-400',
                  ev.correlates_with_fired && 'ring-2 ring-green-500 ring-inset',
                )}
              >
                <div className="flex items-center gap-3 text-sm">
                  {isSiem ? (
                    <RadioTower className="w-4 h-4 text-fuchsia-600 flex-shrink-0" />
                  ) : (
                    <Zap className="w-4 h-4 text-indigo-500 flex-shrink-0" />
                  )}
                  <span className="font-mono font-semibold text-gray-900 dark:text-white">
                    {isSiem ? 'siem_match' : ev.type.replace('agent_command_', '')}
                  </span>

                  {isSiem ? (
                    <>
                      <span className="font-mono text-xs text-gray-700 dark:text-gray-300">
                        {ev.rule_title}
                      </span>
                      {ev.severity && (
                        <span
                          className={clsx(
                            'text-xs font-semibold',
                            severityColors[ev.severity] ?? 'text-gray-600',
                          )}
                        >
                          {ev.severity}
                        </span>
                      )}
                      {ev.mitre_techniques && ev.mitre_techniques.length > 0 && (
                        <span className="text-xs text-gray-500 font-mono">
                          [{ev.mitre_techniques.join(', ')}]
                        </span>
                      )}
                    </>
                  ) : (
                    <>
                      <span className="font-mono text-xs text-gray-600 dark:text-gray-400">
                        {ev.action}
                      </span>
                      {ev.status && (
                        <span className="text-xs font-semibold text-gray-700 dark:text-gray-300">
                          {ev.status}
                        </span>
                      )}
                    </>
                  )}

                  {ev.hostname && (
                    <span className="text-xs text-gray-500">on {ev.hostname}</span>
                  )}
                  {ev.correlates_with_fired && (
                    <span className="ml-auto flex items-center gap-1 text-xs font-bold text-green-700 dark:text-green-400">
                      <ShieldCheck className="w-3 h-3" />
                      PURPLE HIT
                    </span>
                  )}
                  <span
                    className={clsx(
                      'text-xs text-gray-400',
                      !ev.correlates_with_fired && 'ml-auto',
                    )}
                  >
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
            );
          })}
        </div>
      </div>
    </div>
  );
}
