import { describeLoadError } from './loadError';

/**
 * A refused automation request (playbook authoring/run, builder run, rule
 * save) rendered the way the server reported it: the one-line
 * `HTTP 4xx · code: detail` summary plus every itemised reason the body
 * carries (`steps` for invalid_steps, `nodes` for not_implemented /
 * containment_requires_admin, `containment_steps`, `reason`, `message`,
 * and FastAPI's 422 validation list). Nothing is paraphrased.
 */
export interface ActionErrorDetail {
  summary: string;
  items: string[];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function str(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return '';
  }
}

function itemsFrom(body: Record<string, unknown>): string[] {
  const items: string[] = [];
  if (typeof body.message === 'string') items.push(body.message);
  if (typeof body.reason === 'string') items.push(body.reason);
  if (Array.isArray(body.steps)) {
    for (const raw of body.steps) {
      const s = asRecord(raw);
      if (!s) continue;
      items.push(`Step ${str(s.step)} (${str(s.action) || 'no action'}): ${str(s.error)}`);
    }
  }
  if (Array.isArray(body.nodes)) {
    for (const raw of body.nodes) {
      const n = asRecord(raw);
      if (n) {
        const type = n.node_type ? ` (${str(n.node_type)})` : '';
        items.push(`Node ${str(n.node_id)}${type}: ${str(n.reason) || 'cannot execute'}`);
      } else {
        items.push(`Node ${str(raw)}`);
      }
    }
  }
  if (Array.isArray(body.containment_steps) && body.containment_steps.length) {
    items.push(`Privileged steps: ${body.containment_steps.map(str).join(', ')}`);
  }
  // 400 unknown_action (remediation policies / manual execute)
  if (Array.isArray(body.unknown) && body.unknown.length) {
    items.push(`Unknown: ${body.unknown.map(str).join(', ')}`);
  }
  if (Array.isArray(body.allowed) && body.allowed.length) {
    items.push(`Allowed: ${body.allowed.map(str).join(', ')}`);
  }
  // 409 not_reversible (remediation rollback)
  if (Array.isArray(body.actions)) {
    for (const raw of body.actions) {
      const a = asRecord(raw);
      if (!a) continue;
      items.push(
        `${str(a.action_type) || 'action'}: ${str(a.status) || 'no status'}, ${a.reversible ? 'reversible' : 'not reversible'}`,
      );
    }
  }
  return items;
}

export function describeActionError(err: unknown): ActionErrorDetail {
  const summary = describeLoadError(err);
  const data = (err as { response?: { data?: unknown } })?.response?.data;
  const body = asRecord(data);
  if (!body) return { summary, items: [] };
  const items: string[] = [];
  const nested = asRecord(body.detail);
  if (nested) items.push(...itemsFrom(nested));
  items.push(...itemsFrom(body));
  if (Array.isArray(body.detail)) {
    // FastAPI request validation: [{loc, msg, type}]
    for (const raw of body.detail) {
      const v = asRecord(raw);
      if (!v) continue;
      const loc = Array.isArray(v.loc) ? v.loc.map(str).join('.') : '';
      items.push(loc ? `${loc}: ${str(v.msg)}` : str(v.msg));
    }
  }
  // The summary already carries `detail` when it is a string; drop repeats.
  return { summary, items: items.filter((m) => m && !summary.includes(m)) };
}
