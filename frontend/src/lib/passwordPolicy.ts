/**
 * A refused POST /auth/change-password, read the way the server reports it.
 * A policy failure is 400 with detail `{error: "password_policy", detail,
 * errors: [rule, ...]}`; other failures carry a string detail.
 */
export interface PasswordChangeFailure {
  summary: string;
  rules: string[];
}

export function passwordChangeFailure(err: unknown, fallback: string): PasswordChangeFailure {
  const data = (err as { response?: { data?: { detail?: unknown; message?: unknown } } } | null)?.response?.data;
  const detail = data?.detail;
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
    const d = detail as { detail?: unknown; errors?: unknown };
    const rules = Array.isArray(d.errors) ? d.errors.map(String).filter(Boolean) : [];
    const summary = rules.length
      ? 'The new password does not meet the password policy:'
      : typeof d.detail === 'string' && d.detail
        ? d.detail
        : fallback;
    return { summary, rules };
  }
  if (typeof detail === 'string' && detail) return { summary: detail, rules: [] };
  if (typeof data?.message === 'string' && data.message) return { summary: data.message, rules: [] };
  return { summary: err instanceof Error && err.message ? err.message : fallback, rules: [] };
}
