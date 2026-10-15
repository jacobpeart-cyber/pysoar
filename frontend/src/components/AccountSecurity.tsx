/**
 * Profile > Security: sign out every session (POST /auth/revoke-all) and the
 * TOTP MFA lifecycle (POST /mfa/setup -> /mfa/verify-setup, then
 * /mfa/backup-codes and /mfa/disable). Every state shown is the server's
 * answer; secrets and backup codes are displayed once and never stored here.
 */
import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { Shield, LogOut, Loader2, KeyRound } from 'lucide-react';
import { api } from '../lib/api';
import { apiClient } from '../api';
import ActionErrorBanner from './ActionErrorBanner';

const inputCls = 'w-full rounded-lg border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500';
const btn = 'inline-flex items-center gap-2 px-4 py-2 text-sm rounded-lg disabled:opacity-50 disabled:cursor-not-allowed';

export function SessionsPanel() {
  const [confirming, setConfirming] = useState(false);
  const m = useMutation({
    mutationFn: async () => (await api.post('/auth/revoke-all')).data,
    onSuccess: () => {
      // Every token for this account, this browser's included, is now
      // revoked server side; drop the local copies and start over.
      apiClient.clearToken();
      localStorage.removeItem('access_token');
      localStorage.removeItem('refresh_token');
      window.location.href = '/login';
    },
  });
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <div className="flex items-center gap-2 mb-4">
        <Shield className="w-5 h-5 text-gray-500" />
        <h2 className="text-lg font-semibold text-gray-900">Sessions</h2>
      </div>
      <p className="text-sm text-gray-600 mb-4">
        PySOAR does not keep a per-device session list, so it cannot show where you are signed in. If you suspect a
        token was exposed, sign out everywhere: every access and refresh token issued to your account is revoked,
        including this browser&apos;s, and you sign in again.
      </p>
      {confirming ? (
        <div className="flex flex-wrap gap-2">
          <button className={`${btn} bg-red-600 text-white hover:bg-red-700`} disabled={m.isPending} onClick={() => m.mutate()}>
            {m.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <LogOut className="w-4 h-4" />}
            Yes, sign out every session
          </button>
          <button className={`${btn} border border-gray-300 text-gray-700`} disabled={m.isPending} onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </div>
      ) : (
        <button className={`${btn} border border-red-300 text-red-700 hover:bg-red-50`} onClick={() => setConfirming(true)}>
          <LogOut className="w-4 h-4" />
          Sign out everywhere
        </button>
      )}
      <div className="mt-3">
        <ActionErrorBanner what="revoke your sessions" error={m.error} />
      </div>
    </div>
  );
}

function BackupCodes({ codes }: { codes: string[] }) {
  return (
    <div className="mt-3 p-3 bg-amber-50 border border-amber-200 rounded-lg">
      <p className="text-sm text-amber-900 mb-2">
        Backup codes: each works once in place of an authenticator code. They are shown only now; store them somewhere
        safe. Generating new codes invalidates these.
      </p>
      <ul className="grid grid-cols-2 gap-1 font-mono text-sm text-gray-900">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
    </div>
  );
}

type MfaKnown = 'unknown' | 'enabled' | 'disabled';

export function MfaPanel() {
  // GET /auth/me does not report whether MFA is on, so the page starts from
  // "unknown" and only records what this session's own calls proved.
  const [known, setKnown] = useState<MfaKnown>('unknown');
  const [setup, setSetup] = useState<{ secret: string; provisioning_uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [manageCode, setManageCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const start = useMutation({
    mutationFn: async () => (await api.post('/mfa/setup')).data,
    onSuccess: (d) => {
      setSetup({ secret: d.secret, provisioning_uri: d.provisioning_uri });
      setCodes(null);
      setNote(null);
      setCode('');
    },
  });
  const confirm = useMutation({
    mutationFn: async () =>
      (await api.post('/mfa/verify-setup', { secret: setup?.secret ?? '', code: code.trim() })).data,
    onSuccess: (d) => {
      setSetup(null);
      setKnown('enabled');
      setCodes(Array.isArray(d.backup_codes) ? d.backup_codes : null);
      setNote(String(d.message ?? 'MFA enabled'));
    },
  });
  const regenerate = useMutation({
    mutationFn: async () => (await api.post('/mfa/backup-codes', { code: manageCode.trim() })).data,
    onSuccess: (d) => {
      setKnown('enabled');
      setCodes(Array.isArray(d.backup_codes) ? d.backup_codes : null);
      setNote(String(d.message ?? 'Backup codes regenerated'));
      setManageCode('');
    },
  });
  const disable = useMutation({
    mutationFn: async () => (await api.post('/mfa/disable', { code: manageCode.trim() })).data,
    onSuccess: (d) => {
      setKnown('disabled');
      setCodes(null);
      setNote(String(d.message ?? 'MFA disabled'));
      setManageCode('');
    },
  });
  const busy = start.isPending || confirm.isPending || regenerate.isPending || disable.isPending;

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-4">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center">
          <KeyRound className="w-5 h-5 text-gray-600" />
        </div>
        <div>
          <h3 className="font-medium text-gray-900">Two-Factor Authentication (TOTP)</h3>
          <p className="text-sm text-gray-500">
            {known === 'enabled'
              ? 'Enabled: sign-in asks for an authenticator code.'
              : known === 'disabled'
                ? 'Disabled.'
                : 'Status not available: the profile endpoint does not report it. Set it up below, or manage it with a current code if it is already on.'}
          </p>
        </div>
      </div>

      {note && <p className="text-sm text-green-700">{note}.</p>}
      {codes && codes.length > 0 && <BackupCodes codes={codes} />}

      {setup ? (
        <div className="space-y-3 border-t border-gray-100 pt-4">
          <p className="text-sm text-gray-700">
            Add this key to your authenticator app (manual entry, time-based), then enter the 6-digit code it shows.
            Nothing is saved until the code checks out.
          </p>
          <div>
            <p className="text-xs text-gray-500">Secret key</p>
            <p className="font-mono text-sm break-all text-gray-900">{setup.secret}</p>
          </div>
          <details>
            <summary className="text-xs text-gray-500 cursor-pointer">otpauth URI (for apps that accept a pasted link)</summary>
            <p className="font-mono text-xs break-all text-gray-700 mt-1">{setup.provisioning_uri}</p>
          </details>
          <div className="flex flex-wrap gap-2 items-end">
            <label className="text-sm text-gray-700">
              Code
              <input value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" className={inputCls} />
            </label>
            <button className={`${btn} bg-blue-600 text-white hover:bg-blue-700`} disabled={busy || !code.trim()} onClick={() => confirm.mutate()}>
              {confirm.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Verify and enable
            </button>
            <button className={`${btn} border border-gray-300 text-gray-700`} disabled={busy} onClick={() => setSetup(null)}>
              Cancel
            </button>
          </div>
          <ActionErrorBanner what="enable MFA" error={confirm.error} />
        </div>
      ) : (
        known !== 'enabled' && (
          <div>
            <button className={`${btn} bg-blue-600 text-white hover:bg-blue-700`} disabled={busy} onClick={() => start.mutate()}>
              {start.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              <Shield className="w-4 h-4" />
              Set up MFA
            </button>
            <div className="mt-2">
              <ActionErrorBanner what="start MFA setup" error={start.error} />
            </div>
          </div>
        )
      )}

      {known !== 'disabled' && !setup && (
        <div className="border-t border-gray-100 pt-4 space-y-2">
          <p className="text-sm text-gray-700">Manage MFA (needs a current authenticator code):</p>
          <div className="flex flex-wrap gap-2 items-end">
            <label className="text-sm text-gray-700">
              Code
              <input value={manageCode} onChange={(e) => setManageCode(e.target.value)} autoComplete="one-time-code" className={inputCls} />
            </label>
            <button className={`${btn} border border-gray-300 text-gray-700`} disabled={busy || !manageCode.trim()} onClick={() => regenerate.mutate()}>
              {regenerate.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              New backup codes
            </button>
            <button className={`${btn} border border-red-300 text-red-700`} disabled={busy || !manageCode.trim()} onClick={() => disable.mutate()}>
              {disable.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Disable MFA
            </button>
          </div>
          <ActionErrorBanner what="regenerate backup codes" error={regenerate.error} />
          <ActionErrorBanner what="disable MFA" error={disable.error} />
        </div>
      )}
    </div>
  );
}
