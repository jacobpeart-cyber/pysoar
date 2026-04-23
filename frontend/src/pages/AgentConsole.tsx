'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Send, Trash2, Plus, Wrench, ChevronDown, ChevronRight, ShieldAlert, CheckCircle2, AlertTriangle, Activity, XCircle } from 'lucide-react';
import clsx from 'clsx';
import { api } from '../api/client';

type ChatRole = 'user' | 'assistant' | 'system';

interface ToolCall {
  step: number;
  tool: string;
  args: Record<string, any>;
  result: any;
  blocked?: boolean;
  fallback?: boolean;
}

interface ChatMessage {
  id: string;
  role: ChatRole;
  content: string;
  tool_calls?: ToolCall[] | null;
  created_at?: string | null;
}

interface ChatSession {
  id: string;
  title: string;
  created_at?: string | null;
  updated_at?: string | null;
}

interface InvestigationCard {
  id: string;
  title: string;
  status: string;
  confidence_score: number;
  resolution_type?: string | null;
  findings_summary?: string | null;
  hypothesis?: string | null;
  created_at?: string | null;
  mitre_techniques?: string | null;
}

const VERDICT_OPTIONS = [
  { value: 'true_positive', label: 'True positive' },
  { value: 'false_positive', label: 'False positive' },
  { value: 'benign', label: 'Benign' },
  { value: 'inconclusive', label: 'Inconclusive' },
  { value: 'escalated', label: 'Escalated' },
];

const suggestedPrompts = [
  'Show me the top 5 high-risk UEBA users.',
  'What critical vulnerabilities are open right now?',
  'Any open forensic cases? Briefly summarize each.',
  'List the 3 most recent dark web findings.',
  'Are there remediation executions awaiting approval?',
  'Which assets are most exposed? Show me critical ones.',
];

const AgentConsole: React.FC = () => {
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [sending, setSending] = useState(false);
  const [authorizeActions, setAuthorizeActions] = useState(false);
  const [expandedTools, setExpandedTools] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [investigations, setInvestigations] = useState<InvestigationCard[]>([]);
  const [showInvestigations, setShowInvestigations] = useState(true);
  const [correctingId, setCorrectingId] = useState<string | null>(null);
  const [correctionVerdict, setCorrectionVerdict] = useState<string>('false_positive');
  const [correctionNote, setCorrectionNote] = useState<string>('');
  const [correctionBusy, setCorrectionBusy] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const loadSessions = async () => {
    try {
      const res = await api.get('/agentic/chat/sessions');
      const items: ChatSession[] = res.data?.items || [];
      setSessions(items);
      return items;
    } catch {
      setSessions([]);
      return [];
    }
  };

  const loadMessages = async (sessionId: string) => {
    setLoading(true);
    try {
      const res = await api.get(`/agentic/chat/sessions/${sessionId}/messages`);
      setMessages(res.data?.items || []);
    } catch {
      setMessages([]);
    } finally {
      setLoading(false);
    }
  };

  const loadInvestigations = async () => {
    try {
      const res = await api.get('/agentic/investigations');
      const items: InvestigationCard[] =
        res.data?.items ||
        (Array.isArray(res.data) ? res.data : []);
      // Most recent first; cap at 6.
      items.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
      setInvestigations(items.slice(0, 6));
    } catch {
      setInvestigations([]);
    }
  };

  useEffect(() => {
    (async () => {
      const items = await loadSessions();
      if (items.length > 0) {
        setActiveSessionId(items[0].id);
      }
      await loadInvestigations();
    })();
    // Poll investigations every 10s so auto-triage kickoffs and live
    // investigation progress appear without a page reload.
    const pollId = window.setInterval(() => {
      loadInvestigations();
    }, 10000);
    return () => window.clearInterval(pollId);
  }, []);

  const submitCorrection = async (invId: string) => {
    if (!correctionVerdict) return;
    setCorrectionBusy(true);
    try {
      await api.post(`/agentic/investigations/${invId}/correct`, {
        corrected_verdict: correctionVerdict,
        correction_note: correctionNote || undefined,
      });
      setCorrectingId(null);
      setCorrectionNote('');
      setCorrectionVerdict('false_positive');
      await loadInvestigations();
    } catch {
      setError('Correction failed. Try again.');
    } finally {
      setCorrectionBusy(false);
    }
  };

  useEffect(() => {
    if (activeSessionId) loadMessages(activeSessionId);
    else setMessages([]);
  }, [activeSessionId]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, sending]);

  const newSession = async () => {
    try {
      const res = await api.post('/agentic/chat/sessions', { title: 'New chat' });
      const created: ChatSession = res.data;
      setSessions((s) => [created, ...s]);
      setActiveSessionId(created.id);
      setMessages([]);
    } catch {
      setError('Failed to create session.');
    }
  };

  const deleteSession = async (id: string) => {
    try {
      await api.delete(`/agentic/chat/sessions/${id}`);
      setSessions((s) => s.filter((x) => x.id !== id));
      if (activeSessionId === id) {
        setActiveSessionId(null);
        setMessages([]);
      }
    } catch {
      setError('Failed to delete session.');
    }
  };

  const send = async (textArg?: string) => {
    const text = (textArg ?? input).trim();
    if (!text || sending) return;
    setError(null);
    let sid = activeSessionId;
    // If no session yet, create one inline so the first turn still persists
    if (!sid) {
      try {
        const res = await api.post('/agentic/chat/sessions', { title: text.slice(0, 60) });
        sid = res.data.id as string;
        setSessions((s) => [res.data, ...s]);
        setActiveSessionId(sid);
      } catch {
        setError('Failed to create session.');
        return;
      }
    }
    // Optimistic user bubble
    setMessages((m) => [...m, { id: `tmp-${Date.now()}`, role: 'user', content: text }]);
    setInput('');
    setSending(true);
    try {
      const res = await api.post('/agentic/chat', {
        query: text,
        session_id: sid,
        authorize_actions: authorizeActions,
      });
      const reply = res.data?.response || '(no response)';
      const tools: ToolCall[] = res.data?.interpretation?.tools_invoked || [];
      setMessages((m) => [
        ...m,
        { id: `tmp-reply-${Date.now()}`, role: 'assistant', content: reply, tool_calls: tools },
      ]);
      // Refresh session list so the title (and updated_at ordering) reflects latest turn
      loadSessions();
    } catch (e: any) {
      setMessages((m) => [
        ...m,
        { id: `err-${Date.now()}`, role: 'assistant', content: 'Request failed — check connectivity and try again.' },
      ]);
    } finally {
      setSending(false);
    }
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  const renderToolCall = (call: ToolCall, key: string) => {
    const open = expandedTools[key];
    const isBlocked = call.blocked || call.result?.blocked;
    const ok = call.result?.success !== false && !isBlocked;
    return (
      <div
        key={key}
        className={clsx(
          'border rounded-md mt-2 text-xs',
          isBlocked
            ? 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20'
            : ok
              ? 'border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-900'
              : 'border-orange-200 dark:border-orange-800 bg-orange-50 dark:bg-orange-900/20',
        )}
      >
        <button
          onClick={() => setExpandedTools((s) => ({ ...s, [key]: !s[key] }))}
          className="w-full flex items-center gap-2 px-3 py-2 text-left"
        >
          {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          <Wrench className="w-3 h-3 text-blue-600 dark:text-blue-400" />
          <span className="font-mono font-semibold text-gray-900 dark:text-white">{call.tool}</span>
          <span className="text-gray-500 dark:text-gray-400">step {call.step}</span>
          {isBlocked && (
            <span className="ml-auto flex items-center gap-1 text-red-700 dark:text-red-300">
              <ShieldAlert className="w-3 h-3" /> Blocked (authorize_actions=false)
            </span>
          )}
          {!isBlocked && ok && (
            <span className="ml-auto flex items-center gap-1 text-green-700 dark:text-green-300">
              <CheckCircle2 className="w-3 h-3" /> ok
            </span>
          )}
          {!isBlocked && !ok && (
            <span className="ml-auto flex items-center gap-1 text-orange-700 dark:text-orange-300">
              <AlertTriangle className="w-3 h-3" /> error
            </span>
          )}
        </button>
        {open && (
          <div className="px-3 pb-3 space-y-2">
            <div>
              <div className="text-[10px] uppercase tracking-wide text-gray-500 dark:text-gray-400">args</div>
              <pre className="bg-white dark:bg-gray-800 rounded p-2 overflow-x-auto text-gray-800 dark:text-gray-200">
                {JSON.stringify(call.args || {}, null, 2)}
              </pre>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wide text-gray-500 dark:text-gray-400">result</div>
              <pre className="bg-white dark:bg-gray-800 rounded p-2 overflow-x-auto text-gray-800 dark:text-gray-200 max-h-64">
                {JSON.stringify(call.result, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    );
  };

  const activeSession = useMemo(
    () => sessions.find((s) => s.id === activeSessionId),
    [sessions, activeSessionId],
  );

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)] gap-4 p-4">
      {/* Live Investigations panel — surfaces auto-triage kickoffs
          and ongoing investigations directly above the chat so an
          analyst can see what the agent did without leaving the
          console. */}
      {showInvestigations && investigations.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700">
          <div className="px-4 py-2 flex items-center gap-2 border-b border-gray-200 dark:border-gray-700">
            <Activity className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Live investigations</h2>
            <span className="text-xs text-gray-500 dark:text-gray-400">{investigations.length}</span>
            <button
              onClick={() => setShowInvestigations(false)}
              className="ml-auto text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300"
            >
              Hide
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 p-3">
            {investigations.map((inv) => {
              const running = inv.status === 'gathering_evidence' || inv.status === 'analyzing' || inv.status === 'reasoning' || inv.status === 'initiated';
              const verdict = inv.resolution_type;
              const verdictColor =
                verdict === 'true_positive' ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300'
                : verdict === 'false_positive' || verdict === 'benign' ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300'
                : verdict === 'escalated' ? 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300'
                : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300';
              const isAuto = /^auto-triage:/i.test(inv.title || '');
              return (
                <div key={inv.id} className="border border-gray-200 dark:border-gray-700 rounded p-2">
                  <div className="flex items-start gap-2 mb-1">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-1.5">
                        {isAuto && <span className="text-[9px] uppercase px-1 py-0.5 bg-purple-100 dark:bg-purple-900/30 text-purple-700 dark:text-purple-300 rounded">auto</span>}
                        {running && <span className="text-[9px] px-1 py-0.5 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 rounded animate-pulse">running</span>}
                        <span className="text-[11px] text-gray-500 dark:text-gray-400 truncate">{inv.created_at ? new Date(inv.created_at).toLocaleTimeString() : ''}</span>
                      </div>
                      <h3 className="text-xs font-semibold text-gray-900 dark:text-white truncate mt-0.5">{inv.title}</h3>
                    </div>
                    {verdict && (
                      <span className={clsx('text-[10px] font-semibold px-1.5 py-0.5 rounded whitespace-nowrap', verdictColor)}>
                        {verdict.replace(/_/g, ' ')} · {Math.round(inv.confidence_score || 0)}%
                      </span>
                    )}
                  </div>
                  {inv.findings_summary && (
                    <p className="text-[11px] text-gray-700 dark:text-gray-300 line-clamp-3">{inv.findings_summary}</p>
                  )}
                  {verdict && verdict !== 'inconclusive' && (
                    <div className="mt-1.5">
                      {correctingId === inv.id ? (
                        <div className="flex flex-col gap-1 mt-1 p-2 bg-gray-50 dark:bg-gray-900 rounded">
                          <select
                            value={correctionVerdict}
                            onChange={(e) => setCorrectionVerdict(e.target.value)}
                            className="text-xs border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 rounded px-1.5 py-0.5"
                          >
                            {VERDICT_OPTIONS.filter((v) => v.value !== verdict).map((v) => (
                              <option key={v.value} value={v.value}>{v.label}</option>
                            ))}
                          </select>
                          <textarea
                            value={correctionNote}
                            onChange={(e) => setCorrectionNote(e.target.value)}
                            placeholder="Why was the agent wrong? (optional but recommended — future investigations will see this note)"
                            rows={2}
                            className="text-xs border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 rounded px-1.5 py-1 resize-none"
                          />
                          <div className="flex gap-1">
                            <button
                              disabled={correctionBusy}
                              onClick={() => submitCorrection(inv.id)}
                              className="text-xs px-2 py-0.5 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-300 text-white rounded"
                            >
                              {correctionBusy ? 'Saving…' : 'Save correction'}
                            </button>
                            <button
                              disabled={correctionBusy}
                              onClick={() => { setCorrectingId(null); setCorrectionNote(''); }}
                              className="text-xs px-2 py-0.5 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded"
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      ) : (
                        <button
                          onClick={() => { setCorrectingId(inv.id); setCorrectionVerdict(verdict === 'true_positive' ? 'false_positive' : 'true_positive'); }}
                          className="text-[10px] inline-flex items-center gap-1 text-gray-500 hover:text-red-600 dark:hover:text-red-400"
                          title="Tell the agent this verdict is wrong"
                        >
                          <XCircle className="w-3 h-3" /> Mark verdict wrong
                        </button>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
      {showInvestigations === false && investigations.length > 0 && (
        <button
          onClick={() => setShowInvestigations(true)}
          className="text-xs text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-100 flex items-center gap-1 px-3 py-1 bg-white dark:bg-gray-800 rounded border border-gray-200 dark:border-gray-700 self-start"
        >
          <Activity className="w-3 h-3" /> Show {investigations.length} live investigation{investigations.length === 1 ? '' : 's'}
        </button>
      )}
      <div className="flex flex-1 min-h-0 gap-4">
      {/* Sidebar */}
      <aside className="w-72 flex-shrink-0 bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 flex flex-col">
        <div className="p-3 border-b border-gray-200 dark:border-gray-700">
          <button
            onClick={newSession}
            className="w-full flex items-center justify-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm font-medium"
          >
            <Plus className="w-4 h-4" /> New chat
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {sessions.length === 0 ? (
            <div className="p-4 text-xs text-gray-500 dark:text-gray-400">
              No sessions yet. Start a new chat to talk to the SOC agent.
            </div>
          ) : (
            sessions.map((s) => (
              <div
                key={s.id}
                className={clsx(
                  'px-3 py-2 border-b border-gray-100 dark:border-gray-700 cursor-pointer flex items-center justify-between group',
                  activeSessionId === s.id ? 'bg-blue-50 dark:bg-blue-900/20' : 'hover:bg-gray-50 dark:hover:bg-gray-700',
                )}
                onClick={() => setActiveSessionId(s.id)}
              >
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-gray-900 dark:text-white truncate">{s.title}</div>
                  <div className="text-[10px] text-gray-500 dark:text-gray-400">
                    {s.updated_at ? new Date(s.updated_at).toLocaleString() : ''}
                  </div>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    if (window.confirm('Delete this chat?')) deleteSession(s.id);
                  }}
                  className="opacity-0 group-hover:opacity-100 p-1 text-gray-400 hover:text-red-600 dark:hover:text-red-400"
                  title="Delete"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            ))
          )}
        </div>
      </aside>

      {/* Main chat */}
      <section className="flex-1 flex flex-col bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
        <header className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center gap-3">
          <div className="flex-1 min-w-0">
            <h1 className="text-lg font-bold text-gray-900 dark:text-white truncate">
              {activeSession?.title || 'Agent Console'}
            </h1>
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Ask the SOC agent to investigate, query, or act across the platform.
            </p>
          </div>
          <label className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={authorizeActions}
              onChange={(e) => setAuthorizeActions(e.target.checked)}
              className="rounded"
            />
            <span className="flex items-center gap-1">
              <ShieldAlert className="w-3.5 h-3.5" /> Authorize destructive actions
            </span>
          </label>
        </header>

        <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-4 bg-gray-50 dark:bg-gray-900">
          {error ? (
            <div className="text-sm text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded p-3">
              {error}
            </div>
          ) : null}

          {loading ? (
            <div className="text-sm text-gray-500 dark:text-gray-400">Loading messages…</div>
          ) : messages.length === 0 && !sending ? (
            <div className="max-w-xl mx-auto mt-8 space-y-3">
              <p className="text-sm text-gray-700 dark:text-gray-300">
                The agent can query alerts, incidents, UEBA, vulnerabilities, dark web
                findings, forensic cases, remediation executions, assets, threat intel,
                and more. Try one of these:
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {suggestedPrompts.map((p) => (
                  <button
                    key={p}
                    onClick={() => send(p)}
                    className="text-left text-sm text-gray-800 dark:text-gray-200 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded p-3 hover:border-blue-400 dark:hover:border-blue-500"
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            messages.map((m) => (
              <div key={m.id} className={clsx('flex', m.role === 'user' ? 'justify-end' : 'justify-start')}>
                <div
                  className={clsx(
                    'max-w-[70%] rounded-lg px-4 py-2 text-sm',
                    m.role === 'user'
                      ? 'bg-blue-600 text-white'
                      : 'bg-white dark:bg-gray-800 text-gray-900 dark:text-white border border-gray-200 dark:border-gray-700',
                  )}
                >
                  <div className="whitespace-pre-wrap">{m.content}</div>
                  {m.tool_calls && m.tool_calls.length > 0 ? (
                    <div>
                      {m.tool_calls.map((call, idx) => renderToolCall(call, `${m.id}-${idx}`))}
                    </div>
                  ) : null}
                </div>
              </div>
            ))
          )}

          {sending ? (
            <div className="flex justify-start">
              <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg px-4 py-2 text-sm text-gray-500 dark:text-gray-400">
                Agent is working…
              </div>
            </div>
          ) : null}
        </div>

        <div className="border-t border-gray-200 dark:border-gray-700 p-3 bg-white dark:bg-gray-800">
          <div className="flex gap-2 items-end">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={onKeyDown}
              placeholder="Ask the SOC agent… (Shift+Enter for newline)"
              rows={2}
              className="flex-1 resize-none border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-900 rounded px-3 py-2 text-sm text-gray-900 dark:text-white"
            />
            <button
              onClick={() => send()}
              disabled={!input.trim() || sending}
              className={clsx(
                'p-2 rounded text-white',
                input.trim() && !sending ? 'bg-blue-600 hover:bg-blue-700' : 'bg-blue-300 cursor-not-allowed',
              )}
            >
              <Send className="w-5 h-5" />
            </button>
          </div>
        </div>
      </section>
      </div>
    </div>
  );
};

export default AgentConsole;
