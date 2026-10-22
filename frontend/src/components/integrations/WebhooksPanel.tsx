import { useState } from 'react';
import { Loader2, Plus, Trash2 } from 'lucide-react';
import clsx from 'clsx';
import LoadErrorBanner from '../LoadErrorBanner';
import ActionErrorBanner from '../ActionErrorBanner';
import { ADMIN_ONLY_REASON, ANALYST_ONLY_REASON } from '../../lib/roles';
import type { InstalledIntegration, WebhookEndpointRow } from './types';
import { errorDetailText, formatTime, httpStatusOf, webhookEventTypes } from './types';

interface Props {
  webhooks: WebhookEndpointRow[];
  total: number | null;
  loadError: unknown;
  installed: InstalledIntegration[];
  /** Names an install from its id (installed list and connector registry). */
  integrationLabel: (installedId: string) => string;
  canAdmin: boolean;
  canOperate: boolean;
  /** Opens the create form, pre-selecting this install when one is given. */
  onCreate: (integrationId: string | null) => void;
  testWebhook: (integrationId: string, webhookId: string) => Promise<unknown>;
  deleteWebhook: (integrationId: string, webhookId: string) => Promise<void>;
  /** Reloads the list after a delete. */
  onChanged: () => Promise<void> | void;
}

type TestOutcome = { kind: 'not_testable'; detail: string } | { kind: 'error'; error: unknown } | { kind: 'ok' };

const BTN =
  'px-3 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded hover:bg-gray-100 dark:hover:bg-gray-700 transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2';

/**
 * The organisation's registered webhook endpoints (`GET /integrations/webhooks`,
 * the stored rows), grouped by installed integration. Test answers 501 by
 * design and the server's reason is shown as given; delete asks first.
 */
export default function WebhooksPanel({
  webhooks,
  total,
  loadError,
  installed,
  integrationLabel,
  canAdmin,
  canOperate,
  onCreate,
  testWebhook,
  deleteWebhook,
  onChanged,
}: Props) {
  const [outcomes, setOutcomes] = useState<Record<string, TestOutcome>>({});
  const [busy, setBusy] = useState<Record<string, 'test' | 'delete'>>({});
  const [confirmDelete, setConfirmDelete] = useState<WebhookEndpointRow | null>(null);
  const [deleteError, setDeleteError] = useState<unknown>(null);

  const setBusyFor = (id: string, what: 'test' | 'delete' | null) =>
    setBusy((b) => {
      const next = { ...b };
      if (what) next[id] = what;
      else delete next[id];
      return next;
    });

  const runTest = async (w: WebhookEndpointRow) => {
    setBusyFor(w.id, 'test');
    try {
      await testWebhook(w.installed_id, w.id);
      setOutcomes((o) => ({ ...o, [w.id]: { kind: 'ok' } }));
    } catch (error) {
      if (httpStatusOf(error) === 501) {
        setOutcomes((o) => ({
          ...o,
          [w.id]: { kind: 'not_testable', detail: errorDetailText(error) || 'the server answered 501 not_implemented' },
        }));
      } else {
        setOutcomes((o) => ({ ...o, [w.id]: { kind: 'error', error } }));
      }
    } finally {
      setBusyFor(w.id, null);
    }
  };

  const doDelete = async (w: WebhookEndpointRow) => {
    setDeleteError(null);
    setBusyFor(w.id, 'delete');
    try {
      await deleteWebhook(w.installed_id, w.id);
      setConfirmDelete(null);
      await onChanged();
    } catch (error) {
      setDeleteError(error);
    } finally {
      setBusyFor(w.id, null);
    }
  };

  // Group by install, keeping the newest-first order of the list.
  const groups: { installedId: string; rows: WebhookEndpointRow[] }[] = [];
  for (const w of webhooks) {
    const g = groups.find((x) => x.installedId === w.installed_id);
    if (g) g.rows.push(w);
    else groups.push({ installedId: w.installed_id, rows: [w] });
  }

  return (
    <div className="space-y-6">
      <LoadErrorBanner what="webhook endpoints" error={loadError} />
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <p className="text-sm text-gray-600 dark:text-gray-400 max-w-3xl">
          Registered inbound endpoints per installed integration. PySOAR has no inbound webhook receiver yet, so these
          endpoints receive nothing and nothing updates their delivery counters until one exists.
        </p>
        <button
          onClick={() => onCreate(null)}
          disabled={!canAdmin || installed.length === 0}
          title={!canAdmin ? ADMIN_ONLY_REASON : installed.length === 0 ? 'Install an integration first' : undefined}
          className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-700 text-white px-4 py-2 rounded-lg text-sm transition disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Plus className="w-4 h-4" />
          New webhook endpoint
        </button>
      </div>
      {!canAdmin && <p className="text-xs text-gray-500 dark:text-gray-400">{ADMIN_ONLY_REASON}</p>}
      {!loadError && webhooks.length === 0 && (
        <p className="text-sm text-gray-500 dark:text-gray-400">No webhook endpoints. Create one on an installed integration.</p>
      )}
      {total !== null && total > webhooks.length && (
        <p className="text-xs text-gray-500 dark:text-gray-400">
          Showing the newest {webhooks.length} of {total}.
        </p>
      )}
      {groups.map((g) => (
        <section key={g.installedId} className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <h3 className="font-semibold">
              {integrationLabel(g.installedId)}
              <span className="ml-2 text-xs font-normal text-gray-500 dark:text-gray-400">
                {g.rows.length} endpoint{g.rows.length === 1 ? '' : 's'}
              </span>
            </h3>
            {installed.some((i) => i.id === g.installedId) && (
              <button
                onClick={() => onCreate(g.installedId)}
                disabled={!canAdmin}
                title={canAdmin ? 'Create an endpoint on this integration' : ADMIN_ONLY_REASON}
                className={BTN}
              >
                <Plus className="w-4 h-4" />
                Add endpoint
              </button>
            )}
          </div>
          {g.rows.map((w) => {
            const events = webhookEventTypes(w.event_types);
            const outcome = outcomes[w.id];
            const rowBusy = busy[w.id];
            return (
              <div
                key={w.id}
                className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 space-y-3"
              >
                <div className="flex justify-between items-start gap-3">
                  <div className="min-w-0">
                    <p className="font-mono text-sm break-all">
                      <span className="text-gray-500 dark:text-gray-400 mr-2">{w.http_method || 'POST'}</span>
                      {w.endpoint_path || '(no path)'}
                    </p>
                    <p className="text-xs font-mono text-gray-500 dark:text-gray-400 mt-1">{w.id}</p>
                  </div>
                  <span
                    className={clsx(
                      'px-3 py-1 rounded-full text-xs font-medium whitespace-nowrap',
                      w.is_active
                        ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100'
                        : 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-100',
                    )}
                  >
                    {w.is_active ? 'enabled' : 'disabled'}
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div>
                    <p className="text-gray-600 dark:text-gray-400">Event types</p>
                    <p className="font-medium break-words">{events.length ? events.join(', ') : 'none set'}</p>
                  </div>
                  <div>
                    <p className="text-gray-600 dark:text-gray-400">Last delivery</p>
                    <p className="font-medium">
                      {formatTime(w.last_received) ?? 'none received'}
                      {typeof w.received_count === 'number' ? ` · ${w.received_count} received` : ''}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-600 dark:text-gray-400">Created</p>
                    <p className="font-medium">{formatTime(w.created_at) ?? 'not recorded'}</p>
                  </div>
                </div>
                {outcome?.kind === 'not_testable' && (
                  <p className="text-sm text-gray-600 dark:text-gray-300">Not testable: {outcome.detail}</p>
                )}
                {outcome?.kind === 'ok' && (
                  <p className="text-sm text-gray-600 dark:text-gray-300">The server accepted the test request.</p>
                )}
                {outcome?.kind === 'error' && <ActionErrorBanner what="test the webhook endpoint" error={outcome.error} />}
                <div className="flex gap-2">
                  <button
                    onClick={() => runTest(w)}
                    disabled={!canOperate || !!rowBusy}
                    title={canOperate ? 'Asks the server to test this endpoint' : ANALYST_ONLY_REASON}
                    className={clsx(BTN, 'flex-1')}
                  >
                    {rowBusy === 'test' && <Loader2 className="w-4 h-4 animate-spin" />}
                    Test
                  </button>
                  <button
                    onClick={() => {
                      setDeleteError(null);
                      setConfirmDelete(w);
                    }}
                    disabled={!canAdmin || !!rowBusy}
                    title={canAdmin ? 'Delete this webhook endpoint' : ADMIN_ONLY_REASON}
                    className={clsx(BTN, 'text-red-600 dark:text-red-400')}
                    aria-label="Delete webhook endpoint"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            );
          })}
        </section>
      ))}

      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" aria-modal="true" role="dialog">
          <div
            className="absolute inset-0 bg-black/50 backdrop-blur-sm"
            onClick={() => !busy[confirmDelete.id] && setConfirmDelete(null)}
          />
          <div className="relative w-full max-w-md bg-white dark:bg-gray-900 rounded-lg shadow-2xl border border-gray-200 dark:border-gray-700 p-6 space-y-4">
            <h2 className="text-lg font-semibold">Delete webhook endpoint?</h2>
            <p className="text-sm text-gray-600 dark:text-gray-400">
              <span className="font-mono break-all">
                {confirmDelete.http_method || 'POST'} {confirmDelete.endpoint_path}
              </span>{' '}
              on {integrationLabel(confirmDelete.installed_id)} is removed from this organisation.
            </p>
            <ActionErrorBanner what="delete the webhook endpoint" error={deleteError} />
            <div className="flex justify-end gap-2">
              <button onClick={() => setConfirmDelete(null)} disabled={!!busy[confirmDelete.id]} className={BTN}>
                Cancel
              </button>
              <button
                onClick={() => doDelete(confirmDelete)}
                disabled={!!busy[confirmDelete.id]}
                className="px-4 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded flex items-center gap-2 disabled:opacity-50"
              >
                {busy[confirmDelete.id] && <Loader2 className="w-4 h-4 animate-spin" />}
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
