import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Shield, Loader2 } from 'lucide-react';
import { publicAuthApi } from '../api/publicAuth';
import { passwordChangeFailure } from '../lib/passwordPolicy';

/** The limited token login issues for a forced change, or null for any other failure. */
function limitedTokenOf(err: unknown): string | null {
  const resp = (err as { response?: { status?: number; headers?: Record<string, unknown> } } | null)?.response;
  if (resp?.status !== 403) return null;
  const h = resp.headers ?? {};
  if (String(h['x-password-change-required'] ?? '').toLowerCase() !== 'true') return null;
  const t = h['x-limited-token'];
  return typeof t === 'string' && t ? t : null;
}

// The server's PasswordValidator rules (src/core/password_policy.py). Its 400
// answer carries one generic line, not the list, so the rules are shown here.
const PASSWORD_RULES = [
  '12 to 128 characters',
  'not a commonly used password',
  'not the same as your email address',
];
const CHANGE_STEP_MS = 5 * 60 * 1000;

/** The server's own wording for a refused login or MFA code. */
function loginErrorText(err: unknown, fallback: string): string {
  const data = (err as { response?: { data?: { detail?: unknown; message?: unknown } } } | null)?.response?.data;
  const detail = data?.detail ?? data?.message;
  return typeof detail === 'string' && detail ? detail : fallback;
}

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  // Set when the password was accepted but the account has MFA enabled.
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaExpiresAt, setMfaExpiresAt] = useState<number | null>(null);
  const [mfaCode, setMfaCode] = useState('');
  // Forced password change: the 5-minute limited token lives only here
  // (component state), never in storage, and is dropped after use.
  const [changeToken, setChangeToken] = useState<string | null>(null);
  const [changeExpiresAt, setChangeExpiresAt] = useState<number | null>(null);
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [notice, setNotice] = useState('');
  // Rules the server's password policy reported as failed (400 password_policy).
  const [policyRules, setPolicyRules] = useState<string[]>([]);
  const { login, completeMfaLogin } = useAuth();
  const navigate = useNavigate();

  const runLogin = async (pw: string) => {
    try {
      const result = await login(email, pw);
      if (result.mfaRequired) {
        setMfaToken(result.mfaToken);
        setMfaExpiresAt(Date.now() + result.expiresIn * 1000);
        setMfaCode('');
        return;
      }
      navigate('/');
    } catch (err) {
      const limited = limitedTokenOf(err);
      if (limited) {
        setChangeToken(limited);
        setChangeExpiresAt(Date.now() + CHANGE_STEP_MS);
        setCurrentPw(pw);
        setNewPw('');
        setConfirmPw('');
        setNotice('');
        return;
      }
      setError(loginErrorText(err, 'Invalid email or password'));
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setNotice('');
    setIsLoading(true);
    try {
      await runLogin(password);
    } finally {
      setIsLoading(false);
    }
  };

  const leaveChangeStep = (message: string) => {
    setChangeToken(null);
    setChangeExpiresAt(null);
    setCurrentPw('');
    setNewPw('');
    setConfirmPw('');
    setError(message);
  };

  const handleChangeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!changeToken) return;
    setError('');
    setPolicyRules([]);
    if (changeExpiresAt !== null && Date.now() > changeExpiresAt) {
      leaveChangeStep('The password-change step expired (5 minutes). Sign in again to restart it.');
      return;
    }
    if (newPw.length < 12 || newPw.length > 128) {
      setError('The new password must be 12 to 128 characters.');
      return;
    }
    if (newPw !== confirmPw) {
      setError('The two new passwords do not match.');
      return;
    }
    if (newPw === currentPw) {
      setError('The new password must differ from the current one.');
      return;
    }
    setIsLoading(true);
    try {
      await publicAuthApi.changePasswordWithLimitedToken(changeToken, currentPw, newPw);
      // The flag is cleared server side; sign in with the new password.
      const pw = newPw;
      setChangeToken(null);
      setChangeExpiresAt(null);
      setCurrentPw('');
      setNewPw('');
      setConfirmPw('');
      setPassword(pw);
      setNotice('Password changed. Signing you in with the new password.');
      await runLogin(pw);
    } catch (err) {
      const status = (err as { response?: { status?: number } } | null)?.response?.status;
      if (status === 401) {
        leaveChangeStep('The password-change token was refused (expired or already used). Sign in again to restart the step.');
      } else {
        const failure = passwordChangeFailure(err, 'Password change failed');
        setError(failure.summary);
        setPolicyRules(failure.rules);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaToken) return;
    setError('');
    if (mfaExpiresAt !== null && Date.now() > mfaExpiresAt) {
      setMfaToken(null);
      setError('The sign-in challenge expired (5 minutes). Enter your password again.');
      return;
    }
    setIsLoading(true);
    try {
      await completeMfaLogin(mfaToken, mfaCode.trim());
      navigate('/');
    } catch (err) {
      setError(loginErrorText(err, 'Invalid verification code'));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 px-4">
      <div className="max-w-md w-full">
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <div className="p-3 bg-blue-600 rounded-xl">
              <Shield className="w-12 h-12 text-white" />
            </div>
          </div>
          <h1 className="text-3xl font-bold text-white">PySOAR</h1>
          <p className="text-gray-400 mt-2">Security Orchestration, Automation & Response</p>
        </div>

        {changeToken ? (
          <form onSubmit={handleChangeSubmit} className="bg-gray-800 rounded-xl p-8 shadow-xl space-y-4">
            <div>
              <h2 className="text-xl font-semibold text-white mb-2">Set a new password</h2>
              <p className="text-sm text-gray-400">
                Your administrator requires a password change before you can sign in (for example after a password
                reset). This step expires 5 minutes after sign-in.
              </p>
            </div>
            {error && (
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                <p className="text-sm text-red-400">{error}</p>
                {policyRules.length > 0 && (
                  <ul className="list-disc ml-5 mt-1 text-sm text-red-400">
                    {policyRules.map((r) => <li key={r}>{r}</li>)}
                  </ul>
                )}
              </div>
            )}
            <div>
              <label htmlFor="current-password" className="block text-sm font-medium text-gray-300 mb-1">Current password</label>
              <input id="current-password" type="password" autoComplete="current-password" value={currentPw} onChange={(e) => setCurrentPw(e.target.value)} required className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
            <div>
              <label htmlFor="new-password" className="block text-sm font-medium text-gray-300 mb-1">New password</label>
              <input id="new-password" type="password" autoComplete="new-password" value={newPw} onChange={(e) => setNewPw(e.target.value)} required autoFocus className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
            <div>
              <label htmlFor="confirm-new-password" className="block text-sm font-medium text-gray-300 mb-1">Confirm new password</label>
              <input id="confirm-new-password" type="password" autoComplete="new-password" value={confirmPw} onChange={(e) => setConfirmPw(e.target.value)} required className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
            <div className="text-xs text-gray-400">
              <p>The server checks that the new password is:</p>
              <ul className="list-disc ml-5">
                {PASSWORD_RULES.map((r) => <li key={r}>{r}</li>)}
              </ul>
            </div>
            <button
              type="submit"
              disabled={isLoading || !currentPw || !newPw || !confirmPw}
              className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg flex items-center justify-center"
            >
              {isLoading ? <Loader2 className="w-5 h-5 mr-2 animate-spin" /> : null}
              Change password and sign in
            </button>
            <button type="button" onClick={() => leaveChangeStep('')} className="w-full text-sm text-gray-400 hover:text-gray-200">
              Back to sign in
            </button>
          </form>
        ) : mfaToken ? (
          <form onSubmit={handleMfaSubmit} className="bg-gray-800 rounded-xl p-8 shadow-xl">
            <h2 className="text-xl font-semibold text-white mb-2">Two-factor authentication</h2>
            <p className="text-sm text-gray-400 mb-6">
              Enter the 6-digit code from your authenticator app, or one of your unused backup codes.
            </p>
            {error && (
              <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                <p className="text-sm text-red-400">{error}</p>
              </div>
            )}
            <label htmlFor="mfa-code" className="block text-sm font-medium text-gray-300 mb-1">
              Verification code
            </label>
            <input
              id="mfa-code"
              value={mfaCode}
              onChange={(e) => setMfaCode(e.target.value)}
              autoComplete="one-time-code"
              autoFocus
              required
              className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
            <button
              type="submit"
              disabled={isLoading || !mfaCode.trim()}
              className="w-full mt-6 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors flex items-center justify-center"
            >
              {isLoading ? <Loader2 className="w-5 h-5 mr-2 animate-spin" /> : null}
              Verify
            </button>
            <button
              type="button"
              onClick={() => { setMfaToken(null); setError(''); }}
              className="w-full mt-3 text-sm text-gray-400 hover:text-gray-200"
            >
              Back to password
            </button>
          </form>
        ) : (
        <form onSubmit={handleSubmit} className="bg-gray-800 rounded-xl p-8 shadow-xl">
          <h2 className="text-xl font-semibold text-white mb-6">Sign in to your account</h2>

          {notice && (
            <div className="mb-4 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
              <p className="text-sm text-green-400">{notice}</p>
            </div>
          )}

          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
              <p className="text-sm text-red-400">{error}</p>
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-1">
                Email address
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="you@example.com"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-1">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full mt-6 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors flex items-center justify-center"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                Signing in...
              </>
            ) : (
              'Sign in'
            )}
          </button>
          <p className="mt-4 text-xs text-gray-400">
            Forgot your password? There is no self-service reset and PySOAR does not email reset links.
            Contact your administrator; a reset link issued for your account opens the set-new-password page.
          </p>
        </form>
        )}

        <p className="text-center text-gray-500 text-sm mt-6">
          PySOAR v0.1.0 &middot; Security Platform
        </p>
      </div>
    </div>
  );
}
