'use client';

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Send, Trash2, Plus, Wrench, ChevronDown, ChevronRight, ShieldAlert, CheckCircle2, AlertTriangle } from 'lucide-react';
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

  useEffect(() => {
    (async () => {
      const items = await loadSessions();
      if (items.length > 0) {
        setActiveSessionId(items[0].id);
      }
    })();
  }, []);

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
    <div className="flex h-[calc(100vh-4rem)] gap-4 p-4">
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
  );
};

export default AgentConsole;
