import { normalizeFailure } from '../components/agentic/runtime';

/**
 * One line naming a failed request the way the server reported it:
 * `HTTP 500 · internal_error: detail`. Same normalisation the Agentic chat
 * error card uses, so every page reports failures with the server's key
 * instead of rendering an empty list.
 */
export function describeLoadError(err: unknown): string {
  const f = normalizeFailure(err);
  const head = f.status ? `HTTP ${f.status} · ${f.code}` : f.code;
  return f.detail ? `${head}: ${f.detail}` : head;
}
