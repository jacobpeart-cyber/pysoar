/**
 * Phishing simulation authoring (wave 5): template create and target group
 * membership. Without a template every campaign sends the placeholder body;
 * without members a launch has nobody to send to. Both writes are analyst+.
 */
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { X, Plus, Trash2 } from 'lucide-react';
import { api } from '../api/client';
import ActionErrorBanner from './ActionErrorBanner';
import { ANALYST_ONLY_REASON } from '../lib/roles';
import type { RoleGate } from '../lib/roles';

const field = 'w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-white text-sm placeholder-gray-500';

const TEMPLATE_CATEGORIES = [
  'credential_harvest',
  'malware_attachment',
  'link_click',
  'data_entry',
  'callback_phishing',
  'mfa_bypass',
  'qr_code',
];
const TEMPLATE_DIFFICULTIES = ['beginner', 'intermediate', 'advanced', 'expert'];

export function TemplateCreateModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [f, setF] = useState({
    name: '',
    description: '',
    category: 'credential_harvest',
    difficulty: 'intermediate',
    subject_line: '',
    sender_name: '',
    sender_email: '',
    html_body: '',
    text_body: '',
    landing_page_html: '',
    indicators: '',
    training_content_on_fail: '',
  });
  const m = useMutation({
    mutationFn: async () =>
      (
        await api.post('/phishing_sim/templates', {
          name: f.name.trim(),
          description: f.description.trim() || null,
          category: f.category,
          difficulty: f.difficulty,
          subject_line: f.subject_line.trim(),
          sender_name: f.sender_name.trim(),
          sender_email: f.sender_email.trim(),
          html_body: f.html_body,
          text_body: f.text_body || null,
          landing_page_html: f.landing_page_html || null,
          indicators_of_phishing: f.indicators.split('\n').map((s) => s.trim()).filter(Boolean),
          training_content_on_fail: f.training_content_on_fail || null,
        })
      ).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['phishing-templates'] });
      onClose();
    },
  });
  const set = (k: keyof typeof f) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setF({ ...f, [k]: e.target.value });
  const ready = f.name.trim() && f.subject_line.trim() && f.sender_name.trim() && f.sender_email.trim() && f.html_body.trim();
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-white">New phishing template</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            m.mutate();
          }}
        >
          <div className="grid grid-cols-2 gap-3">
            <label className="text-sm text-gray-300">Name *<input value={f.name} onChange={set('name')} className={field} /></label>
            <label className="text-sm text-gray-300">
              Category
              <select value={f.category} onChange={set('category')} className={field}>
                {TEMPLATE_CATEGORIES.map((c) => <option key={c} value={c}>{c.replace(/_/g, ' ')}</option>)}
              </select>
            </label>
            <label className="text-sm text-gray-300">
              Difficulty
              <select value={f.difficulty} onChange={set('difficulty')} className={field}>
                {TEMPLATE_DIFFICULTIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </label>
            <label className="text-sm text-gray-300">Subject line *<input value={f.subject_line} onChange={set('subject_line')} className={field} /></label>
            <label className="text-sm text-gray-300">Sender name *<input value={f.sender_name} onChange={set('sender_name')} className={field} /></label>
            <label className="text-sm text-gray-300">Sender email *<input value={f.sender_email} onChange={set('sender_email')} className={field} /></label>
          </div>
          <label className="block text-sm text-gray-300">Description<input value={f.description} onChange={set('description')} className={field} /></label>
          <label className="block text-sm text-gray-300">
            HTML body *
            <textarea value={f.html_body} onChange={set('html_body')} rows={6} className={`${field} font-mono`} placeholder={'<p>Your password expires today. <a href="{{tracking_link}}">Keep it</a></p>'} />
          </label>
          <p className="text-xs text-gray-400">
            Placeholders filled per recipient at send time: {'{{tracking_link}}'} (tracked click), {'{{report_link}}'} (report
            as phishing), {'{{tracking_pixel}}'} (open pixel; appended to HTML bodies that omit it). The URLs are built from
            PYSOAR_PUBLIC_URL, so opens and clicks are only recorded when that address reaches this server.
          </p>
          <label className="block text-sm text-gray-300">Plain-text body<textarea value={f.text_body} onChange={set('text_body')} rows={3} className={field} /></label>
          <label className="block text-sm text-gray-300">Landing page HTML (shown after a click)<textarea value={f.landing_page_html} onChange={set('landing_page_html')} rows={3} className={`${field} font-mono`} /></label>
          <label className="block text-sm text-gray-300">Red flags to teach (one per line)<textarea value={f.indicators} onChange={set('indicators')} rows={3} className={field} /></label>
          <label className="block text-sm text-gray-300">Training shown on failure<textarea value={f.training_content_on_fail} onChange={set('training_content_on_fail')} rows={2} className={field} /></label>
          <ActionErrorBanner what="create the template" error={m.error} />
          <div className="flex gap-2">
            <button type="submit" disabled={!ready || m.isPending} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm disabled:opacity-50">
              {m.isPending ? 'Creating...' : 'Create template'}
            </button>
            <button type="button" onClick={onClose} className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}

export interface GroupMember {
  name: string;
  email: string;
  role?: string | null;
  department?: string | null;
}

/**
 * Edit a target group's recipients. The draft is local until Save; Save
 * sends the whole list (PATCH replaces members) and the card re-reads the
 * group from the server.
 */
export function GroupMembersEditor({
  groupId,
  members,
  gate,
}: {
  groupId: string;
  members: GroupMember[];
  gate: RoleGate;
}) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<GroupMember[]>(members);
  const [row, setRow] = useState<GroupMember>({ name: '', email: '', role: '', department: '' });
  const [bulk, setBulk] = useState('');
  const m = useMutation({
    mutationFn: async (list: GroupMember[]) => (await api.patch(`/phishing_sim/target-groups/${groupId}`, { members: list })).data,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['phishing-target-groups'] });
      setOpen(false);
    },
  });
  const validEmail = (e: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
  const addRow = () => {
    if (!validEmail(row.email.trim())) return;
    setDraft([...draft, { name: row.name.trim(), email: row.email.trim(), role: row.role?.trim() || null, department: row.department?.trim() || null }]);
    setRow({ name: '', email: '', role: '', department: '' });
  };
  const addBulk = () => {
    // One recipient per line: "email" or "name, email".
    const parsed: GroupMember[] = [];
    for (const line of bulk.split('\n')) {
      const parts = line.split(',').map((s) => s.trim()).filter(Boolean);
      if (parts.length === 0) continue;
      const email = parts.find(validEmail);
      if (!email) continue;
      const name = parts.find((p) => p !== email) ?? '';
      parsed.push({ name, email, role: null, department: null });
    }
    setDraft([...draft, ...parsed]);
    setBulk('');
  };
  if (!open) {
    return (
      <div className="mt-4">
        <button
          onClick={() => {
            setDraft(members);
            setOpen(true);
          }}
          disabled={!gate.isAnalyst}
          title={gate.isAnalyst ? undefined : ANALYST_ONLY_REASON}
          className="text-sm text-blue-400 hover:text-blue-300 disabled:opacity-50"
        >
          {members.length ? `Edit ${members.length} member(s)` : 'Add members'}
        </button>
        {members.length === 0 && (
          <p className="text-xs text-amber-300 mt-1">No recipients: a campaign launched at this group has nobody to send to.</p>
        )}
        {!gate.isAnalyst && <p className="text-xs text-gray-400 mt-1">{ANALYST_ONLY_REASON}</p>}
      </div>
    );
  }
  const dupes = new Set(draft.map((d) => d.email.toLowerCase())).size !== draft.length;
  return (
    <div className="mt-4 border-t border-gray-700 pt-4 space-y-3">
      <p className="text-sm text-gray-300">Members ({draft.length})</p>
      {draft.length > 0 && (
        <ul className="space-y-1 text-sm text-gray-300 max-h-48 overflow-y-auto">
          {draft.map((d, i) => (
            <li key={`${d.email}-${i}`} className="flex items-center justify-between bg-gray-700/50 rounded px-2 py-1">
              <span>{d.name ? `${d.name} <${d.email}>` : d.email}{d.department ? ` · ${d.department}` : ''}</span>
              <button onClick={() => setDraft(draft.filter((_, j) => j !== i))} className="text-red-400 hover:text-red-300" title="Remove">
                <Trash2 className="w-4 h-4" />
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
        <input value={row.name} onChange={(e) => setRow({ ...row, name: e.target.value })} placeholder="Name" className={field} />
        <input value={row.email} onChange={(e) => setRow({ ...row, email: e.target.value })} placeholder="Email *" className={field} />
        <input value={row.role ?? ''} onChange={(e) => setRow({ ...row, role: e.target.value })} placeholder="Role" className={field} />
        <input value={row.department ?? ''} onChange={(e) => setRow({ ...row, department: e.target.value })} placeholder="Department" className={field} />
        <button onClick={addRow} disabled={!validEmail(row.email.trim())} className="bg-gray-700 hover:bg-gray-600 text-white rounded text-sm flex items-center justify-center gap-1 disabled:opacity-50">
          <Plus className="w-4 h-4" /> Add
        </button>
      </div>
      <div className="space-y-1">
        <textarea value={bulk} onChange={(e) => setBulk(e.target.value)} rows={3} placeholder={'Paste recipients, one per line: email  or  name, email'} className={field} />
        <button onClick={addBulk} disabled={!bulk.trim()} className="bg-gray-700 hover:bg-gray-600 text-white px-3 py-1 rounded text-sm disabled:opacity-50">
          Add pasted lines
        </button>
      </div>
      {dupes && <p className="text-xs text-amber-300">The list contains the same email more than once.</p>}
      <ActionErrorBanner what="save the members" error={m.error} />
      <div className="flex gap-2">
        <button onClick={() => m.mutate(draft)} disabled={m.isPending} className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded text-sm disabled:opacity-50">
          {m.isPending ? 'Saving...' : 'Save members'}
        </button>
        <button onClick={() => setOpen(false)} disabled={m.isPending} className="bg-gray-700 hover:bg-gray-600 text-white px-4 py-2 rounded text-sm">
          Cancel
        </button>
      </div>
    </div>
  );
}
