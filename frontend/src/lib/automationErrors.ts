import { describeLoadError } from './loadError';

/**
 * A refused automation request (playbook authoring/run, builder run, rule
 * save) rendered the way the server reported it: the one-line
 * `HTTP 4xx · code: detail` summary plus every itemised reason the body
 * carries (`steps` for invalid_steps, `nodes` for not_implemented /
 * containment_requires_admin, `containment_steps`, `reason`, `message`,
 * `problems` for invalid_parameters, `fields` for missing_fields /
 * invalid_fields, the entries of an object `detail`, and FastAPI's 422
 * validation list). Nothing is paraphrased.
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
  // 422 invalid_rule (SIEM rule validate/create/update/import): [{field, message}]
  if (Array.isArray(body.field_errors)) {
    for (const raw of body.field_errors) {
      const fe = asRecord(raw);
      if (fe) items.push(`${str(fe.field) || 'rule'}: ${str(fe.message)}`);
      else items.push(str(raw));
    }
  }
  // 422 no_valid_rows (ITDR CSV import): [{line, error}] or plain strings;
  // request validation entries [{loc, msg}] and row errors [{row, reason}].
  if (Array.isArray(body.errors)) {
    for (const raw of body.errors) {
      const e = asRecord(raw);
      if (!e) items.push(str(raw));
      else if (e.line !== undefined) items.push(`Line ${str(e.line)}: ${str(e.error)}`);
      else if (Array.isArray(e.loc)) items.push(`${e.loc.map(str).join('.')}: ${str(e.msg)}`);
      else if (e.row !== undefined) items.push(`Row ${str(e.row)}: ${str(e.reason ?? e.error)}`);
      else items.push(str(e.error ?? e.message ?? e.msg));
    }
  }
  // 422 invalid_parameters (integration actions): ["name: reason", ...]
  if (Array.isArray(body.problems)) {
    for (const raw of body.problems) items.push(str(raw));
  }
  // 422 missing_fields / invalid_fields (integration install / configure): field names only.
  if (Array.isArray(body.fields) && body.fields.length) {
    const label =
      body.error === 'missing_fields' ? 'Missing fields' : body.error === 'invalid_fields' ? 'Invalid fields' : 'Fields';
    items.push(`${label}: ${body.fields.map(str).join(', ')}`);
  }
  // The app-wide validation handler nests the list: {details: {errors}}.
  const details = asRecord(body.details);
  if (details && Array.isArray(details.errors)) items.push(...itemsFrom({ errors: details.errors }));
  // 422 invalid_fair_input / invalid_field: the input at fault.
  if (typeof body.field === 'string' && body.field) items.push(`Field: ${body.field}`);
  // 409 agent_selection_required (OT actions): the capable agents to pick from.
  if (Array.isArray(body.agent_ids) && body.agent_ids.length) {
    items.push(`Capable agents: ${body.agent_ids.map(str).join(', ')}`);
  }
  // 502 darkweb_scan_failed: {source: {label, status, reason|error}}
  const sources = asRecord(body.sources);
  if (sources) {
    for (const [key, raw] of Object.entries(sources)) {
      const src = asRecord(raw);
      if (!src) continue;
      const why = str(src.error) || str(src.reason) || str(src.detail);
      items.push(`${str(src.label) || key}: ${str(src.status)}${why ? ` (${why})` : ''}`);
    }
  }
  // 409 invalid_transition (hunting sessions): the session's current status
  if (body.error === 'invalid_transition' && typeof body.status === 'string') {
    items.push(`Current status: ${body.status}`);
  }
  // 502 identity_provider_failed (ITDR): the provider's result block
  const result = asRecord(body.result);
  if (result) {
    const why = str(result.error) || str(result.detail);
    if (why) items.push(`${str(result.provider) || 'Provider'}: ${why}`);
  }
  return items;
}

/**
 * The `detail` member that describeLoadError would print, when it is an
 * object: `{detail: {error, detail: {...}}}`, `{error, detail: {...}}`, or a
 * `{detail: {...}}` with no error code. Printed as JSON in one line it reads
 * as noise, so its entries become items instead.
 */
function dictDetail(body: Record<string, unknown>): Record<string, unknown> | null {
  const nested = asRecord(body.detail);
  if (nested && typeof nested.error === 'string') return asRecord(nested.detail);
  if (typeof body.error === 'string') return asRecord(body.detail);
  return nested;
}

function entriesOf(dict: Record<string, unknown>): string[] {
  return Object.entries(dict)
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.map(str).join(', ') : str(v)}`);
}

export function describeActionError(err: unknown): ActionErrorDetail {
  let summary = describeLoadError(err);
  const data = (err as { response?: { data?: unknown } })?.response?.data;
  const body = asRecord(data);
  if (!body) return { summary, items: [] };
  const items: string[] = [];
  const dict = dictDetail(body);
  const structured = dict ?? (Array.isArray(body.detail) ? body.detail : null);
  if (structured) {
    // Keep the `HTTP 4xx · code` head; the object's (or the validation
    // list's) contents follow as items instead of one line of JSON.
    const json = str(structured);
    if (json && summary.endsWith(`: ${json}`)) summary = summary.slice(0, -(json.length + 2));
  }
  const nested = asRecord(body.detail);
  if (nested) items.push(...itemsFrom(nested));
  items.push(...itemsFrom(body));
  if (dict && dict !== nested) {
    const own = itemsFrom(dict);
    items.push(...(own.length ? own : entriesOf(dict)));
  } else if (dict && !itemsFrom(dict).length) {
    // `{detail: {...}}` with no code and nothing itemsFrom recognises.
    items.push(...entriesOf(dict));
  }
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
