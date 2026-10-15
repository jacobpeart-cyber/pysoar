/**
 * War room panels (wave 5): join / leave, the incident timeline (list and
 * add), action item status and owner updates, and the artifact registry.
 * Writes are analyst+ on the server; viewers get the control disabled with
 * the reason. Lists render the server's rows or its error, never a default.
 */
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { LogIn, LogOut, Loader2, Star } from 'lucide-react';
import clsx from 'clsx';
import { collaborationApi } from '../api/endpoints';
import type { Row } from '../lib/apiRow';
import LoadErrorBanner from './LoadErrorBanner';
import ActionErrorBanner from './ActionErrorBanner';
import { ANALYST_ONLY_REASON } from '../lib/roles';
import type { RoleGate } from '../lib/roles';

const fieldCls = 'bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm placeholder-gray-500';
const fmt = (v: unknown) => (v ? new Date(String(v)).toLocaleString() : '--');

const TIMELINE_EVENT_TYPES = [
  'detection',
  'triage',
  'escalation',
  'containment',
  'eradication',
  'recovery',
  'communication',
  'decision',
  'action',
  'evidence_collected',
];
const ACTION_STATUSES = ['pending', 'in_progress', 'completed', 'blocked', 'cancelled'];

export function JoinLeave({
  roomId,
  participants,
  userId,
  gate,
}: {
  roomId: string;
  participants: string[];
  userId: string | undefined;
  gate: RoleGate;
}) {
  const qc = useQueryClient();
  const joined = !!userId && participants.includes(userId);
  const m = useMutation({
    mutationFn: () => (joined ? collaborationApi.leaveRoom(roomId) : collaborationApi.joinRoom(roomId)),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['warRooms'] }),
  });
  return (
    <div className="flex flex-col items-end">
      <button
        onClick={() => m.mutate()}
        disabled={!gate.isAnalyst || m.isPending}
        title={gate.isAnalyst ? undefined : ANALYST_ONLY_REASON}
        className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded text-sm flex items-center gap-2 disabled:opacity-50"
      >
        {m.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : joined ? <LogOut className="w-4 h-4" /> : <LogIn className="w-4 h-4" />}
        {joined ? 'Leave room' : 'Join room'}
      </button>
      {!gate.isAnalyst && <p className="text-xs text-gray-400 mt-1">{ANALYST_ONLY_REASON}</p>}
      {m.error ? (
        <div className="mt-2 max-w-xs">
          <ActionErrorBanner what={joined ? 'leave the room' : 'join the room'} error={m.error} />
        </div>
      ) : null}
    </div>
  );
}

export function TimelinePanel({ roomId, gate }: { roomId: string; gate: RoleGate }) {
  const qc = useQueryClient();
  const [keyOnly, setKeyOnly] = useState(false);
  const [form, setForm] = useState({ event_type: 'detection', description: '', event_time: '', is_key_event: false, mitre_technique: '' });
  const q = useQuery({
    queryKey: ['roomTimeline', roomId, keyOnly],
    queryFn: () => collaborationApi.getTimeline(roomId, { key_only: keyOnly || undefined, size: 200 }),
  });
  const add = useMutation({
    mutationFn: () =>
      collaborationApi.addTimelineEvent(roomId, {
        event_type: form.event_type,
        description: form.description.trim(),
        event_time: form.event_time ? new Date(form.event_time).toISOString() : undefined,
        is_key_event: form.is_key_event,
        mitre_technique: form.mitre_technique.trim() || undefined,
      }),
    onSuccess: () => {
      setForm((f) => ({ ...f, description: '', event_time: '', mitre_technique: '', is_key_event: false }));
      qc.invalidateQueries({ queryKey: ['roomTimeline', roomId] });
    },
  });
  const items: Row[] = Array.isArray(q.data?.items) ? q.data.items : [];
  return (
    <div className="space-y-4">
      <label className="flex items-center gap-2 text-sm text-gray-300">
        <input type="checkbox" checked={keyOnly} onChange={(e) => setKeyOnly(e.target.checked)} />
        Key events only
      </label>
      <LoadErrorBanner what="the incident timeline" error={q.error} />
      {q.isLoading ? <Loader2 className="w-5 h-5 animate-spin text-gray-400" /> : null}
      {q.data && items.length === 0 ? <p className="text-gray-500 text-sm">No timeline events recorded for this room.</p> : null}
      <ol className="space-y-2">
        {items.map((e) => (
          <li key={e.id} className={clsx('rounded p-3 text-sm', e.is_key_event ? 'bg-yellow-900/20 border border-yellow-700' : 'bg-gray-700/50')}>
            <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
              <span>{fmt(e.event_time ?? e.created_at)}</span>
              <span className="px-2 py-0.5 rounded bg-gray-900/50 text-gray-200">{String(e.event_type || 'event').replace(/_/g, ' ')}</span>
              {e.is_key_event ? <Star className="w-3 h-3 text-yellow-400" /> : null}
              {e.mitre_technique ? <span className="font-mono">{e.mitre_technique}</span> : null}
              <span>by {e.created_by || 'unknown'}</span>
            </div>
            <p className="text-gray-200 mt-1">{e.description}</p>
          </li>
        ))}
      </ol>
      <form
        className="border-t border-gray-700 pt-4 space-y-2"
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate();
        }}
      >
        <p className="text-sm text-gray-300">Add a timeline entry</p>
        <div className="flex flex-wrap gap-2">
          <select value={form.event_type} onChange={(e) => setForm({ ...form, event_type: e.target.value })} className={fieldCls} disabled={!gate.isAnalyst}>
            {TIMELINE_EVENT_TYPES.map((t) => (
              <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
            ))}
          </select>
          <input type="datetime-local" value={form.event_time} onChange={(e) => setForm({ ...form, event_time: e.target.value })} className={fieldCls} disabled={!gate.isAnalyst} title="When it happened (defaults to now)" />
          <input value={form.mitre_technique} onChange={(e) => setForm({ ...form, mitre_technique: e.target.value })} placeholder="ATT&CK id (optional)" className={fieldCls} disabled={!gate.isAnalyst} />
          <label className="flex items-center gap-1 text-sm text-gray-300">
            <input type="checkbox" checked={form.is_key_event} onChange={(e) => setForm({ ...form, is_key_event: e.target.checked })} disabled={!gate.isAnalyst} />
            Key event
          </label>
        </div>
        <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} rows={2} placeholder="What happened" className={`${fieldCls} w-full`} disabled={!gate.isAnalyst} />
        <button type="submit" disabled={!gate.isAnalyst || !form.description.trim() || add.isPending} title={gate.isAnalyst ? undefined : ANALYST_ONLY_REASON} className="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded text-sm disabled:opacity-50">
          {add.isPending ? 'Adding...' : 'Add entry'}
        </button>
        {!gate.isAnalyst && <p className="text-xs text-gray-400">{ANALYST_ONLY_REASON}</p>}
        <ActionErrorBanner what="add the timeline entry" error={add.error} />
      </form>
    </div>
  );
}

export function ArtifactsPanel({ roomId }: { roomId: string }) {
  const q = useQuery({ queryKey: ['roomArtifacts', roomId], queryFn: () => collaborationApi.getArtifacts(roomId, { size: 100 }) });
  const items: Row[] = Array.isArray(q.data?.items) ? q.data.items : [];
  return (
    <div className="space-y-3">
      <p className="text-xs text-gray-400">
        The artifact registry records metadata only (name, SHA-256, size, classification). PySOAR stores no file bytes for
        war room artifacts, so there is nothing to download here; fetch the file from where it was collected.
      </p>
      <LoadErrorBanner what="room artifacts" error={q.error} />
      {q.data && items.length === 0 ? <p className="text-gray-500 text-sm">No artifacts registered in this room.</p> : null}
      {items.length > 0 ? (
        <table className="w-full text-sm text-gray-300">
          <thead className="text-left text-xs text-gray-400">
            <tr><th>Name</th><th>Type</th><th>SHA-256</th><th>Size</th><th>Registered</th></tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.id} className="border-t border-gray-700 align-top">
                <td className="py-1">{a.file_name}</td>
                <td>{String(a.artifact_type || '--').replace(/_/g, ' ')}</td>
                <td className="font-mono text-xs break-all max-w-[12rem]">{a.file_hash || 'not recorded'}</td>
                <td>{typeof a.file_size_bytes === 'number' ? `${a.file_size_bytes.toLocaleString()} B` : '--'}</td>
                <td className="text-xs">{fmt(a.created_at)} by {a.uploaded_by || 'unknown'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      {typeof q.data?.total === 'number' && q.data.total > items.length ? (
        <p className="text-xs text-gray-400">Showing {items.length} of {q.data.total}.</p>
      ) : null}
    </div>
  );
}

/** Status and owner controls on one action item; the row re-reads from the server after a save. */
export function ActionItemControls({
  item,
  userId,
  gate,
}: {
  item: Row;
  userId: string | undefined;
  gate: RoleGate;
}) {
  const qc = useQueryClient();
  const [owner, setOwner] = useState<string>(item.assigned_to ?? '');
  const m = useMutation({
    mutationFn: (body: { status?: string; assigned_to?: string }) => collaborationApi.updateActionItem(String(item.id), body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['allActionItems'] }),
  });
  const disabled = !gate.isAnalyst || m.isPending;
  return (
    <div className="mt-4 border-t border-gray-700 pt-3 space-y-2">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <label className="text-gray-400">Status</label>
        <select
          value={item.status}
          onChange={(e) => m.mutate({ status: e.target.value })}
          disabled={disabled}
          title={gate.isAnalyst ? undefined : ANALYST_ONLY_REASON}
          className={fieldCls}
        >
          {ACTION_STATUSES.map((s) => (
            <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
          ))}
        </select>
        <label className="text-gray-400 ml-2">Owner</label>
        <input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="user id" className={fieldCls} disabled={disabled} />
        <button
          onClick={() => owner.trim() && m.mutate({ assigned_to: owner.trim() })}
          disabled={disabled || !owner.trim() || owner.trim() === (item.assigned_to ?? '')}
          className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-2 rounded text-sm disabled:opacity-50"
        >
          Set owner
        </button>
        {userId ? (
          <button
            onClick={() => {
              setOwner(userId);
              m.mutate({ assigned_to: userId });
            }}
            disabled={disabled || item.assigned_to === userId}
            className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-2 rounded text-sm disabled:opacity-50"
          >
            Assign to me
          </button>
        ) : null}
        {m.isPending ? <Loader2 className="w-4 h-4 animate-spin text-gray-400" /> : null}
      </div>
      {!gate.isAnalyst && <p className="text-xs text-gray-400">{ANALYST_ONLY_REASON}</p>}
      <p className="text-xs text-gray-500">The server does not clear an owner; assign someone else to change it.</p>
      <ActionErrorBanner what="update the action item" error={m.error} />
    </div>
  );
}
