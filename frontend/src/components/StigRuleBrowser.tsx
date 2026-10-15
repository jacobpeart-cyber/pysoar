/**
 * STIG rule browser (wave 5): benchmark detail, the rules of one benchmark
 * (filtered by severity, paged), keyword search across the organisation's
 * imported benchmarks, and one rule's check and fix text. Read-only; every
 * field is the imported XCCDF content as stored.
 */
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Search, X } from 'lucide-react';
import clsx from 'clsx';
import { api } from '../lib/api';
import type { Row } from '../lib/apiRow';
import LoadErrorBanner from './LoadErrorBanner';

const PAGE = 100;
const sevClass: Record<string, string> = {
  high: 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300',
  medium: 'bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300',
  low: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300',
};
const catOf: Record<string, string> = { high: 'CAT I', medium: 'CAT II', low: 'CAT III' };

function Sev({ s }: { s?: string | null }) {
  const k = String(s || '').toLowerCase();
  return (
    <span className={clsx('px-2 py-0.5 rounded text-xs font-medium whitespace-nowrap', sevClass[k] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300')}>
      {catOf[k] ?? (s || 'unknown')}
    </span>
  );
}

function Drawer({ title, subtitle, onClose, children }: { title: string; subtitle?: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40" onClick={onClose}>
      <div className="w-full max-w-3xl h-full overflow-y-auto bg-white dark:bg-gray-800 p-6 space-y-4" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
            {subtitle && <p className="text-xs font-mono text-gray-500 break-all">{subtitle}</p>}
          </div>
          <button onClick={onClose} aria-label="Close" className="text-gray-500 hover:text-gray-800 dark:hover:text-gray-200">
            <X className="w-5 h-5" />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

const keysOf = (v: unknown): string => {
  if (!v) return 'none recorded';
  if (Array.isArray(v)) return v.join(', ') || 'none recorded';
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const list = Array.isArray(o.ids) ? (o.ids as unknown[]) : Array.isArray(o.controls) ? (o.controls as unknown[]) : null;
    if (list) return list.map(String).join(', ') || 'none recorded';
    const keys = Object.keys(o);
    return keys.length ? keys.map((k) => (o[k] === true || o[k] === null ? k : `${k}: ${JSON.stringify(o[k])}`)).join(', ') : 'none recorded';
  }
  return String(v);
};

export function StigRuleDetail({ ruleId, onClose }: { ruleId: string; onClose: () => void }) {
  const { data: r, error, isLoading } = useQuery<Row>({
    queryKey: ['stig-rule', ruleId],
    queryFn: async () => (await api.get(`/stig/rules/${encodeURIComponent(ruleId)}`)).data,
  });
  return (
    <Drawer title={r?.title || 'STIG rule'} subtitle={ruleId} onClose={onClose}>
      <LoadErrorBanner what="the STIG rule" error={error} />
      {isLoading && <p className="text-sm text-gray-500">Loading...</p>}
      {r && (
        <div className="space-y-4 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <Sev s={r.severity} />
            {r.stig_id && <span className="font-mono text-xs">{r.stig_id}</span>}
            {r.group_id && <span className="font-mono text-xs text-gray-500">group {r.group_id}</span>}
            <span className="text-xs text-gray-500">{r.is_automatable ? 'automatable check' : 'manual check'}</span>
          </div>
          {r.description && (
            <section>
              <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Discussion</h3>
              <p className="whitespace-pre-wrap text-gray-700 dark:text-gray-300">{r.description}</p>
            </section>
          )}
          <section>
            <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Check text</h3>
            <pre className="whitespace-pre-wrap text-xs bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded p-3">
              {r.check_text || 'The imported benchmark carries no check text for this rule.'}
            </pre>
          </section>
          <section>
            <h3 className="font-semibold text-gray-900 dark:text-white mb-1">Fix text</h3>
            <pre className="whitespace-pre-wrap text-xs bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded p-3">
              {r.fix_text || 'The imported benchmark carries no fix text for this rule.'}
            </pre>
          </section>
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            <div><dt className="text-gray-500">CCI</dt><dd className="font-mono break-all">{keysOf(r.cci)}</dd></div>
            <div><dt className="text-gray-500">NIST 800-53 controls</dt><dd className="font-mono break-all">{keysOf(r.nist_controls)}</dd></div>
          </dl>
        </div>
      )}
    </Drawer>
  );
}

export function StigBenchmarkDrawer({ benchmarkId, onClose }: { benchmarkId: string; onClose: () => void }) {
  const [severity, setSeverity] = useState('');
  const [skip, setSkip] = useState(0);
  const [ruleId, setRuleId] = useState<string | null>(null);
  const bench = useQuery<Row>({
    queryKey: ['stig-benchmark', benchmarkId],
    queryFn: async () => (await api.get(`/stig/benchmarks/${encodeURIComponent(benchmarkId)}`)).data,
  });
  const rules = useQuery<Row[]>({
    queryKey: ['stig-benchmark-rules', benchmarkId, severity, skip],
    queryFn: async () =>
      (await api.get(`/stig/benchmarks/${encodeURIComponent(benchmarkId)}/rules`, {
        params: { severity: severity || undefined, skip, limit: PAGE },
      })).data,
  });
  const b = bench.data;
  const list = Array.isArray(rules.data) ? rules.data : [];
  return (
    <Drawer title={b?.title || b?.benchmark_id || 'STIG benchmark'} subtitle={b?.benchmark_id || benchmarkId} onClose={onClose}>
      <LoadErrorBanner what="the benchmark" error={bench.error} />
      {b && (
        <div className="space-y-2 text-sm">
          <dl className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            <div><dt className="text-xs text-gray-500">Platform</dt><dd>{b.platform || 'not stated'}</dd></div>
            <div><dt className="text-xs text-gray-500">Version / release</dt><dd>{b.version || '-'} {b.release ? `(${b.release})` : ''}</dd></div>
            <div><dt className="text-xs text-gray-500">Rules</dt><dd>{b.total_rules} (CAT I {b.category_1_count}, CAT II {b.category_2_count}, CAT III {b.category_3_count})</dd></div>
            <div><dt className="text-xs text-gray-500">Last scan</dt><dd>{b.last_scan_at ? new Date(b.last_scan_at).toLocaleString() : 'never'}</dd></div>
          </dl>
          {b.description && <p className="text-gray-700 dark:text-gray-300 whitespace-pre-wrap">{b.description}</p>}
        </div>
      )}
      <div className="flex items-center gap-2 text-sm">
        <span>Severity</span>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setSkip(0); }} className="px-2 py-1 border border-gray-300 dark:border-gray-600 rounded bg-white dark:bg-gray-700">
          <option value="">all</option>
          <option value="high">CAT I (high)</option>
          <option value="medium">CAT II (medium)</option>
          <option value="low">CAT III (low)</option>
        </select>
      </div>
      <LoadErrorBanner what="the benchmark rules" error={rules.error} />
      {rules.isLoading && <p className="text-sm text-gray-500">Loading rules...</p>}
      {rules.data && list.length === 0 && <p className="text-sm text-gray-500">No rules match{skip ? ' on this page' : ''}.</p>}
      {list.length > 0 && (
        <table className="w-full text-sm">
          <thead className="text-left text-xs text-gray-500">
            <tr><th className="py-1">Severity</th><th>Rule</th><th>Title</th></tr>
          </thead>
          <tbody>
            {list.map((r) => (
              <tr key={r.id || r.rule_id} onClick={() => setRuleId(r.rule_id)} className="border-t border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer align-top">
                <td className="py-1"><Sev s={r.severity} /></td>
                <td className="font-mono text-xs pr-2">{r.stig_id || r.rule_id}</td>
                <td>{r.title}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div className="flex items-center gap-2 text-sm">
        <button disabled={skip === 0} onClick={() => setSkip(Math.max(0, skip - PAGE))} className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded disabled:opacity-50">Previous</button>
        <span className="text-gray-500">Rules {list.length ? skip + 1 : 0}-{skip + list.length}</span>
        <button disabled={list.length < PAGE} onClick={() => setSkip(skip + PAGE)} className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded disabled:opacity-50">Next</button>
      </div>
      {ruleId && <StigRuleDetail ruleId={ruleId} onClose={() => setRuleId(null)} />}
    </Drawer>
  );
}

export function StigRuleSearch() {
  const [input, setInput] = useState('');
  const [q, setQ] = useState('');
  const [ruleId, setRuleId] = useState<string | null>(null);
  const search = useQuery<Row[]>({
    queryKey: ['stig-rule-search', q],
    queryFn: async () => (await api.get('/stig/rules/search', { params: { q } })).data,
    enabled: q.length > 0,
  });
  const hits = Array.isArray(search.data) ? search.data : [];
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 space-y-3">
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setQ(input.trim());
        }}
      >
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Search imported STIG rules by keyword, rule id or STIG id"
          className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-sm"
        />
        <button type="submit" disabled={!input.trim()} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm flex items-center gap-2 disabled:opacity-50">
          <Search className="w-4 h-4" /> Search
        </button>
      </form>
      <LoadErrorBanner what="the rule search" error={search.error} />
      {search.isFetching && <p className="text-sm text-gray-500">Searching...</p>}
      {search.data && hits.length === 0 && <p className="text-sm text-gray-500">No imported rule matches &quot;{q}&quot;.</p>}
      {hits.length > 0 && (
        <ul className="divide-y divide-gray-100 dark:divide-gray-700 text-sm max-h-80 overflow-y-auto">
          {hits.map((h) => (
            <li key={`${h.benchmark}-${h.rule_id}`} className="py-2 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700 px-1" onClick={() => setRuleId(h.rule_id)}>
              <div className="flex items-center gap-2">
                <Sev s={h.severity} />
                <span className="font-mono text-xs">{h.rule_id}</span>
                <span className="text-xs text-gray-500">{h.benchmark}</span>
              </div>
              <p className="text-gray-800 dark:text-gray-200">{h.title}</p>
            </li>
          ))}
        </ul>
      )}
      {ruleId && <StigRuleDetail ruleId={ruleId} onClose={() => setRuleId(null)} />}
    </div>
  );
}
