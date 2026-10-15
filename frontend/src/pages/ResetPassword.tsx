import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Shield, Loader2 } from 'lucide-react';
import { publicAuthApi } from '../api/publicAuth';

type TokenState =
  | { kind: 'checking' }
  | { kind: 'missing' }
  | { kind: 'valid'; expiresAt: string }
  | { kind: 'invalid'; reason: string }
  | { kind: 'done' };

function statusOf(err: unknown): number | null {
  const s = (err as { response?: { status?: number } } | null)?.response?.status;
  return typeof s === 'number' ? s : null;
}

function detailOf(err: unknown): string {
  const d = (err as { response?: { data?: { detail?: unknown } } } | null)?.response?.data?.detail;
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) {
    return d
      .map((x) => (x && typeof x === 'object' && 'msg' in x ? String((x as { msg: unknown }).msg) : String(x)))
      .join('; ');
  }
  return err instanceof Error ? err.message : 'request failed';
}

/**
 * Set-new-password page for a single-use reset token (/reset-password?token=...).
 * The token is checked on load (POST /auth/password-reset/validate, which
 * does not burn it) and spent on submit (POST /auth/password-reset/consume).
 * There is no self-service request form: tokens are minted only by an
 * administrator's remediation action and PySOAR has no channel that delivers
 * them, so the page says that instead of offering a form that sends nothing.
 */
export default function ResetPassword() {
  const [params] = useSearchParams();
  const token = params.get('token') || '';
  const [state, setState] = useState<TokenState>(token ? { kind: 'checking' } : { kind: 'missing' });
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!token) return;
    let cancelled = false;
    publicAuthApi
      .validateResetToken(token)
      .then((r) => {
        if (!cancelled) setState({ kind: 'valid', expiresAt: r.expires_at });
      })
      .catch((err) => {
        if (cancelled) return;
        const s = statusOf(err);
        setState({
          kind: 'invalid',
          reason:
            s === 410
              ? 'This reset link has expired. Ask your administrator for a new one.'
              : s === 404 || s === 422
                ? 'This reset link is not valid (it may already have been used). Ask your administrator for a new one.'
                : `The link could not be checked: ${s ? `HTTP ${s} · ` : ''}${detailOf(err)}`,
        });
      });
    return () => {
      cancelled = true;
    };
  }, [token]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (password.length < 12) {
      setError('The new password must be at least 12 characters.');
      return;
    }
    if (password !== confirm) {
      setError('The two passwords do not match.');
      return;
    }
    setSubmitting(true);
    try {
      await publicAuthApi.consumeResetToken(token, password);
      setState({ kind: 'done' });
    } catch (err) {
      const s = statusOf(err);
      setError(
        s === 410 || s === 404
          ? 'The reset link expired or was already used before the password was saved.'
          : `${s ? `HTTP ${s} · ` : ''}${detailOf(err)}`,
      );
    } finally {
      setSubmitting(false);
    }
  };

  const inputCls =
    'w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent';

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 px-4">
      <div className="max-w-md w-full">
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div className="p-3 bg-blue-600 rounded-xl">
              <Shield className="w-12 h-12 text-white" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-white">Set a new password</h1>
        </div>
        <div className="bg-gray-800 rounded-xl p-8 shadow-xl space-y-4">
          {state.kind === 'checking' && (
            <p className="text-gray-300 flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" /> Checking the reset link...
            </p>
          )}
          {state.kind === 'missing' && (
            <p className="text-sm text-gray-300">
              This page needs the reset link issued by your administrator. PySOAR has no self-service reset and
              does not email reset links; ask your administrator for one.
            </p>
          )}
          {state.kind === 'invalid' && (
            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
              <p className="text-sm text-red-400">{state.reason}</p>
            </div>
          )}
          {state.kind === 'done' && (
            <div className="space-y-2">
              <p className="text-sm text-green-400">Your password was changed. The reset link cannot be used again.</p>
              <p className="text-xs text-gray-400">
                A reset issued by your administrator also requires a password change, so the first sign-in asks you once
                more for a new password (enter the one you just set as the current password).
              </p>
            </div>
          )}
          {state.kind === 'valid' && (
            <form onSubmit={submit} className="space-y-4">
              <p className="text-xs text-gray-400">
                Link valid until {new Date(state.expiresAt).toLocaleString()}. It works once.
              </p>
              {error && (
                <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                  <p className="text-sm text-red-400">{error}</p>
                </div>
              )}
              <div>
                <label htmlFor="new-password" className="block text-sm font-medium text-gray-300 mb-1">
                  New password (12 characters minimum)
                </label>
                <input
                  id="new-password"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  className={inputCls}
                />
              </div>
              <div>
                <label htmlFor="confirm-password" className="block text-sm font-medium text-gray-300 mb-1">
                  Confirm new password
                </label>
                <input
                  id="confirm-password"
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  required
                  className={inputCls}
                />
              </div>
              <button
                type="submit"
                disabled={submitting}
                className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium rounded-lg flex items-center justify-center"
              >
                {submitting ? <Loader2 className="w-5 h-5 mr-2 animate-spin" /> : null}
                Set password
              </button>
            </form>
          )}
          <p className="text-center text-sm">
            <Link to="/login" className="text-blue-400 hover:text-blue-300">
              Back to sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
