import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { UseMutationResult } from '@tanstack/react-query';
import { Loader2, Plus, Save, TestTube, Trash2, X, CheckCircle, XCircle } from 'lucide-react';
import { identityApi } from '../../api/endpoints';
import type { SSOConfig, SSOConfigUpdate, SSOTestResult } from '../../api/endpoints';
import LoadErrorBanner from '../LoadErrorBanner';
import { useRoleGate, FULL_ADMIN_ONLY_REASON } from '../../lib/roles';
import { describeIdentityError, identityErrorKey } from './identityErrors';
import { btnDanger, btnPrimary, btnSecondary, fmtDate, inputCls, labelCls, useCustomRoles } from './identityShared';
import { ActionError, Chip, CopyValue, RoleSelect } from './IdentityUI';

/**
 * Settings > Identity > Single sign-on (OIDC). Contract: src/api/v1/endpoints/sso.py.
 *
 * - The stored client secret is never shown (the API returns only
 *   `client_secret_set`); leaving the field blank keeps it, "Clear" sends "".
 * - Enabling is a three-step flow the server enforces: save with SSO
 *   disabled, run Test connection (discovery + JWKS against the saved
 *   configuration), then save with SSO enabled.
 * - The trust fields (who the IdP may sign in) are editable only by a
 *   built-in admin without a custom role; for anyone else they render
 *   disabled with that reason, matching the server's 403 full_admin_required.
 */

interface FormState {
  protocol: string;
  display_name: string;
  issuer: string;
  client_id: string;
  scopes: string;
  discovery_url: string;
  email_claim: string;
  name_claim: string;
  groups_claim: string;
  groupMap: { group: string; role: string }[];
  jit_provisioning: boolean;
  default_role: string;
  domains: string;
  require_email_verified: boolean;
  trust_idp_mfa: boolean;
  enabled: boolean;
}

const EMPTY: FormState = {
  protocol: 'oidc',
  display_name: '',
  issuer: '',
  client_id: '',
  scopes: 'openid email profile',
  discovery_url: '',
  email_claim: 'email',
  name_claim: 'name',
  groups_claim: '',
  groupMap: [],
  jit_provisioning: false,
  default_role: 'viewer',
  domains: '',
  require_email_verified: true,
  trust_idp_mfa: true,
  enabled: false,
};

function fromConfig(c: SSOConfig): FormState {
  return {
    protocol: c.protocol || 'oidc',
    display_name: c.display_name ?? '',
    issuer: c.issuer,
    client_id: c.client_id,
    scopes: c.scopes,
    discovery_url: c.discovery_url ?? '',
    email_claim: c.email_claim,
    name_claim: c.name_claim,
    groups_claim: c.groups_claim ?? '',
    groupMap: Object.entries(c.group_role_map || {}).map(([group, role]) => ({ group, role })),
    jit_provisioning: c.jit_provisioning,
    default_role: c.default_role,
    domains: (c.allowed_email_domains || []).join(', '),
    require_email_verified: c.require_email_verified,
    trust_idp_mfa: c.trust_idp_mfa,
    enabled: c.enabled,
  };
}

function parseDomains(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((d) => d.trim())
    .filter(Boolean);
}

function toBody(f: FormState, secret: { value: string; clear: boolean }): SSOConfigUpdate {
  const map: Record<string, string> = {};
  for (const row of f.groupMap) {
    if (row.group.trim()) map[row.group.trim()] = row.role;
  }
  const body: SSOConfigUpdate = {
    protocol: f.protocol,
    display_name: f.display_name.trim() || null,
    issuer: f.issuer.trim(),
    client_id: f.client_id.trim(),
    scopes: f.scopes,
    discovery_url: f.discovery_url.trim() || null,
    email_claim: f.email_claim.trim(),
    name_claim: f.name_claim.trim(),
    groups_claim: f.groups_claim.trim() || null,
    group_role_map: map,
    jit_provisioning: f.jit_provisioning,
    default_role: f.default_role,
    allowed_email_domains: parseDomains(f.domains),
    require_email_verified: f.require_email_verified,
    trust_idp_mfa: f.trust_idp_mfa,
    enabled: f.enabled,
  };
  if (secret.clear) body.client_secret = '';
  else if (secret.value) body.client_secret = secret.value;
  return body;
}

export default function SSOConfigPanel() {
  const cfgQuery = useQuery({ queryKey: ['identity', 'sso'], queryFn: identityApi.getSso, retry: false });
  const notConfigured = identityErrorKey(cfgQuery.error) === 'sso_not_configured';
  const config = cfgQuery.data ?? null;
  const qc = useQueryClient();
  const [testResult, setTestResult] = useState<SSOTestResult | null>(null);
  const [notice, setNotice] = useState('');
  // Held here, not in the form: a test (pass or fail) updates last_tested_at,
  // which remounts the form, and the result must survive that.
  const test = useMutation({
    mutationFn: identityApi.testSso,
    onSuccess: (r) => {
      setTestResult(r);
      qc.invalidateQueries({ queryKey: ['identity', 'sso'] });
    },
    onError: () => {
      setTestResult(null);
      qc.invalidateQueries({ queryKey: ['identity', 'sso'] });
    },
  });

  if (cfgQuery.isLoading) {
    return (
      <p className="text-sm text-gray-500 flex items-center gap-2">
        <Loader2 className="w-4 h-4 animate-spin" /> Loading the SSO configuration...
      </p>
    );
  }
  if (cfgQuery.error && !notConfigured) {
    return <LoadErrorBanner what="the SSO configuration" error={cfgQuery.error} />;
  }
  // Remounted whenever the stored configuration changes, so the form starts
  // from what the server holds.
  const key = config ? `${config.id}:${config.updated_at ?? ''}:${config.last_tested_at ?? ''}` : 'none';
  return (
    <SSOForm
      key={key}
      config={config}
      notConfigured={notConfigured}
      testResult={testResult}
      setTestResult={setTestResult}
      test={test}
      notice={notice}
      setNotice={setNotice}
    />
  );
}

function SSOForm({
  config,
  notConfigured,
  testResult,
  setTestResult,
  test,
  notice,
  setNotice,
}: {
  config: SSOConfig | null;
  notConfigured: boolean;
  testResult: SSOTestResult | null;
  setTestResult: (r: SSOTestResult | null) => void;
  test: UseMutationResult<SSOTestResult, Error, void>;
  notice: string;
  setNotice: (n: string) => void;
}) {
  const gate = useRoleGate();
  const qc = useQueryClient();
  const roles = useCustomRoles();
  const [form, setForm] = useState<FormState>(() => (config ? fromConfig(config) : EMPTY));
  const [secret, setSecret] = useState('');
  const [clearSecret, setClearSecret] = useState(false);

  const saved = useMemo(() => (config ? fromConfig(config) : EMPTY), [config]);
  const dirty = JSON.stringify(form) !== JSON.stringify(saved) || Boolean(secret) || clearSecret;
  const providerChanged =
    config !== null && (form.issuer.trim() !== config.issuer || (form.discovery_url.trim() || null) !== (config.discovery_url || null));

  // A custom-role admin may edit only display_name, scopes, name_claim,
  // group_role_map and default_role, and cannot create or delete the configuration.
  const trustLocked = !gate.isFullAdmin;
  const createLocked = !config && !gate.isFullAdmin;
  const trustTitle = trustLocked ? FULL_ADMIN_ONLY_REASON : undefined;

  const save = useMutation({
    mutationFn: (body: SSOConfigUpdate) => identityApi.putSso(body),
    onSuccess: (data) => {
      qc.setQueryData(['identity', 'sso'], data);
      setSecret('');
      setClearSecret(false);
      setNotice(data.enabled ? 'Saved. Single sign-on is enabled.' : 'Saved. Single sign-on is disabled.');
    },
  });
  const remove = useMutation({
    mutationFn: identityApi.deleteSso,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['identity', 'sso'] });
      setForm(EMPTY);
      setTestResult(null);
      setNotice('The SSO configuration was deleted. Users it provisioned stay; they cannot sign in until SSO is configured again.');
    },
  });

  const set = <K extends keyof FormState>(k: K, v: FormState[K]) => {
    setNotice('');
    setForm((f) => ({ ...f, [k]: v }));
  };

  const enableReason: string | null = (() => {
    if (form.enabled && config?.enabled) return null; // turning it off is always allowed
    if (trustLocked) return FULL_ADMIN_ONLY_REASON;
    if (!config) return 'Save the configuration with SSO disabled first, then run Test connection.';
    if (providerChanged) return 'The issuer or discovery URL changed: save with SSO disabled and test again.';
    if (config.last_test_status !== 'ok') return 'Run a passing Test connection on the saved configuration first.';
    if (parseDomains(form.domains).length === 0) return 'List at least one allowed email domain first.';
    return null;
  })();
  const testReason: string | null = !config
    ? 'Save a configuration first: the test runs against the saved configuration.'
    : dirty
      ? 'Save your changes first: the test runs against the saved configuration.'
      : null;

  const disabledAll = createLocked;

  return (
    <section className="space-y-5">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Single sign-on (OpenID Connect)</h3>
        <p className="text-sm text-gray-500 dark:text-gray-400">
          Users whose email domain is listed sign in through your identity provider. Password sign-in keeps working
          for local accounts.
        </p>
      </div>

      {notConfigured && (
        <div className="text-sm rounded p-3 bg-gray-50 dark:bg-gray-900/40 border border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300">
          Not configured: this organisation has no single sign-on configuration yet [sso_not_configured].
          {createLocked && <> Creating one needs the built-in admin role without a custom role.</>}
        </div>
      )}

      {config && (
        <div className="grid gap-3 md:grid-cols-2">
          <CopyValue label="Redirect URI (register this at the identity provider)" value={config.redirect_uri} />
          <CopyValue label="Sign-in URL for this organisation" value={config.login_url} />
          <div className="text-sm text-gray-700 dark:text-gray-300">
            <span className={labelCls}>Discovery document used</span>
            <code className="text-xs break-all">{config.effective_discovery_url}</code>
          </div>
          <div className="text-sm text-gray-700 dark:text-gray-300 space-y-1">
            <span className={labelCls}>Status</span>
            <div className="flex flex-wrap gap-2 items-center">
              {config.enabled ? <Chip tone="green">enabled</Chip> : <Chip tone="gray">disabled</Chip>}
              {config.last_test_status === 'ok' ? (
                <Chip tone="green">last test passed</Chip>
              ) : config.last_test_status === 'failed' ? (
                <Chip tone="red">last test failed</Chip>
              ) : (
                <Chip tone="amber">not tested</Chip>
              )}
              <span className="text-xs text-gray-500">{fmtDate(config.last_tested_at)}</span>
            </div>
            {config.last_test_detail && <p className="text-xs text-gray-500 break-words">{config.last_test_detail}</p>}
          </div>
        </div>
      )}

      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          setNotice('');
          save.mutate(toBody(form, { value: secret, clear: clearSecret }));
        }}
      >
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label htmlFor="sso-protocol" className={labelCls}>Protocol</label>
            <select id="sso-protocol" className={inputCls} value={form.protocol} disabled={disabledAll}
              onChange={(e) => set('protocol', e.target.value)}>
              <option value="oidc">OpenID Connect</option>
              <option value="saml">SAML 2.0 (not implemented)</option>
            </select>
            {form.protocol === 'saml' && (
              <p className="text-xs text-amber-700 dark:text-amber-300 mt-1">
                SAML is not implemented: the server answers 501 not_implemented (saml_requires_xmlsec).
              </p>
            )}
          </div>
          <div>
            <label htmlFor="sso-display" className={labelCls}>Button label (display name)</label>
            <input id="sso-display" className={inputCls} value={form.display_name} disabled={disabledAll}
              placeholder="e.g. Okta" onChange={(e) => set('display_name', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-issuer" className={labelCls}>Issuer (https)</label>
            <input id="sso-issuer" className={inputCls} value={form.issuer} disabled={trustLocked} title={trustTitle}
              placeholder="https://login.example.com" onChange={(e) => set('issuer', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-discovery" className={labelCls}>Discovery URL (optional, issuer host)</label>
            <input id="sso-discovery" className={inputCls} value={form.discovery_url} disabled={trustLocked} title={trustTitle}
              placeholder="defaults to <issuer>/.well-known/openid-configuration"
              onChange={(e) => set('discovery_url', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-client" className={labelCls}>Client ID</label>
            <input id="sso-client" className={inputCls} value={form.client_id} disabled={trustLocked} title={trustTitle}
              onChange={(e) => set('client_id', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-secret" className={labelCls}>Client secret</label>
            <input id="sso-secret" type="password" autoComplete="new-password" className={inputCls} value={secret}
              disabled={trustLocked || clearSecret} title={trustTitle}
              placeholder={config?.client_secret_set ? 'A secret is stored (not shown). Type to replace it.' : 'No secret stored (public client, PKCE only)'}
              onChange={(e) => { setNotice(''); setSecret(e.target.value); }} />
            {config?.client_secret_set && (
              <label className="flex items-center gap-2 mt-1 text-xs text-gray-600 dark:text-gray-400">
                <input type="checkbox" checked={clearSecret} disabled={trustLocked} title={trustTitle}
                  onChange={(e) => { setClearSecret(e.target.checked); setSecret(''); }} />
                Clear the stored secret on save
              </label>
            )}
          </div>
          <div>
            <label htmlFor="sso-scopes" className={labelCls}>Scopes (must include openid)</label>
            <input id="sso-scopes" className={inputCls} value={form.scopes} disabled={disabledAll}
              onChange={(e) => set('scopes', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-domains" className={labelCls}>Allowed email domains</label>
            <input id="sso-domains" className={inputCls} value={form.domains} disabled={trustLocked} title={trustTitle}
              placeholder="example.com, example.org" onChange={(e) => set('domains', e.target.value)} />
            <p className="text-xs text-gray-500 mt-1">Discovery and provisioning are limited to these domains.</p>
          </div>
          <div>
            <label htmlFor="sso-email-claim" className={labelCls}>Email claim</label>
            <input id="sso-email-claim" className={inputCls} value={form.email_claim} disabled={trustLocked} title={trustTitle}
              onChange={(e) => set('email_claim', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-name-claim" className={labelCls}>Name claim</label>
            <input id="sso-name-claim" className={inputCls} value={form.name_claim} disabled={disabledAll}
              onChange={(e) => set('name_claim', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-groups-claim" className={labelCls}>Groups claim (optional)</label>
            <input id="sso-groups-claim" className={inputCls} value={form.groups_claim} disabled={trustLocked} title={trustTitle}
              placeholder="groups" onChange={(e) => set('groups_claim', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-default-role" className={labelCls}>Default role (no group matched)</label>
            <RoleSelect id="sso-default-role" value={form.default_role} custom={roles.custom} disabled={disabledAll}
              onChange={(v) => set('default_role', v)} />
          </div>
        </div>

        <div className="space-y-2">
          <span className={labelCls}>Group to role mapping (groups claim value to PySOAR role)</span>
          {roles.error ? (
            <p className="text-xs text-amber-700 dark:text-amber-300">
              Custom roles could not be listed, so only built-in roles are offered. {describeIdentityError(roles.error)}
            </p>
          ) : null}
          {form.groupMap.length === 0 && <p className="text-xs text-gray-500">No mappings: everyone receives the default role.</p>}
          {form.groupMap.map((row, i) => (
            <div key={i} className="flex gap-2 items-center">
              <input aria-label="IdP group" className={inputCls} value={row.group} disabled={disabledAll} placeholder="IdP group name"
                onChange={(e) => set('groupMap', form.groupMap.map((r, j) => (j === i ? { ...r, group: e.target.value } : r)))} />
              <RoleSelect value={row.role} custom={roles.custom} disabled={disabledAll}
                onChange={(v) => set('groupMap', form.groupMap.map((r, j) => (j === i ? { ...r, role: v } : r)))} />
              <button type="button" className={btnSecondary} aria-label="Remove mapping" disabled={disabledAll}
                onClick={() => set('groupMap', form.groupMap.filter((_, j) => j !== i))}>
                <X className="w-4 h-4" />
              </button>
            </div>
          ))}
          <button type="button" className={btnSecondary} disabled={disabledAll}
            onClick={() => set('groupMap', [...form.groupMap, { group: '', role: 'viewer' }])}>
            <Plus className="w-4 h-4" /> Add mapping
          </button>
        </div>

        <div className="grid gap-2 md:grid-cols-2 text-sm text-gray-700 dark:text-gray-300">
          <label className="flex items-start gap-2" title={trustTitle}>
            <input type="checkbox" checked={form.jit_provisioning} disabled={trustLocked}
              onChange={(e) => set('jit_provisioning', e.target.checked)} />
            <span>Create accounts on first sign-in (just-in-time provisioning)</span>
          </label>
          <label className="flex items-start gap-2" title={trustTitle}>
            <input type="checkbox" checked={form.require_email_verified} disabled={trustLocked && form.require_email_verified}
              onChange={(e) => set('require_email_verified', e.target.checked)} />
            <span>Require the provider to assert the email is verified</span>
          </label>
          <label className="flex items-start gap-2" title={trustTitle}>
            <input type="checkbox" checked={form.trust_idp_mfa} disabled={trustLocked}
              onChange={(e) => set('trust_idp_mfa', e.target.checked)} />
            <span>Trust the provider's MFA (off: users with PySOAR MFA also answer the PySOAR code)</span>
          </label>
          <label className="flex items-start gap-2" title={enableReason ?? undefined}>
            <input type="checkbox" checked={form.enabled} disabled={Boolean(enableReason)}
              onChange={(e) => set('enabled', e.target.checked)} />
            <span>
              Enabled
              {enableReason && <span className="block text-xs text-gray-500">{enableReason}</span>}
            </span>
          </label>
        </div>
        {trustLocked && (
          <p className="text-xs text-gray-500">
            Some fields are read-only for you. {FULL_ADMIN_ONLY_REASON}
          </p>
        )}

        {notice && <p className="text-sm text-green-700 dark:text-green-300">{notice}</p>}
        <ActionError error={save.error} />

        <div className="flex flex-wrap gap-2">
          <button type="submit" className={btnPrimary} disabled={disabledAll || save.isPending || !dirty}
            title={disabledAll ? FULL_ADMIN_ONLY_REASON : !dirty ? 'No changes to save' : undefined}>
            {save.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />} Save
          </button>
          <button type="button" className={btnSecondary} disabled={Boolean(testReason) || test.isPending}
            title={testReason ?? undefined} onClick={() => { setNotice(''); test.mutate(); }}>
            {test.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <TestTube className="w-4 h-4" />} Test connection
          </button>
          {config && (
            <button type="button" className={btnDanger} disabled={!gate.isFullAdmin || remove.isPending}
              title={!gate.isFullAdmin ? FULL_ADMIN_ONLY_REASON : undefined}
              onClick={() => {
                if (confirm('Delete the SSO configuration? Users it provisioned stay but cannot sign in through SSO.')) remove.mutate();
              }}>
              <Trash2 className="w-4 h-4" /> Delete
            </button>
          )}
        </div>
        {testReason && config && <p className="text-xs text-gray-500">{testReason}</p>}
      </form>

      <ActionError error={test.error} />
      <ActionError error={remove.error} />
      {testResult && (
        <div className="text-sm rounded p-3 border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20 space-y-1">
          <p className="font-medium text-green-800 dark:text-green-300 flex items-center gap-2">
            <CheckCircle className="w-4 h-4" /> Connection test passed ({fmtDate(testResult.tested_at)})
          </p>
          <p className="text-xs text-gray-700 dark:text-gray-300">
            Issuer {testResult.issuer}; {testResult.key_count} signing key(s)
            {testResult.key_ids.length ? ` (${testResult.key_ids.join(', ')})` : ''}.
          </p>
          <ul className="text-xs text-gray-700 dark:text-gray-300 list-disc ml-5 break-all">
            <li>Authorization: {testResult.authorization_endpoint}</li>
            <li>Token: {testResult.token_endpoint}</li>
            <li>JWKS: {testResult.jwks_uri}</li>
            {testResult.userinfo_endpoint && <li>Userinfo: {testResult.userinfo_endpoint}</li>}
            {testResult.scopes_supported.length > 0 && <li>Scopes supported: {testResult.scopes_supported.join(' ')}</li>}
            {testResult.id_token_signing_alg_values_supported.length > 0 && (
              <li>ID token algorithms: {testResult.id_token_signing_alg_values_supported.join(', ')}</li>
            )}
          </ul>
          {testResult.warnings.length > 0 && (
            <div className="text-xs text-amber-800 dark:text-amber-300">
              <p className="flex items-center gap-1 font-medium"><XCircle className="w-3 h-3" /> Warnings</p>
              <ul className="list-disc ml-5">{testResult.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
            </div>
          )}
          <p className="text-xs text-gray-500">
            The test checks discovery and signing keys only; the client secret is exercised by a real sign-in.
            {!config?.enabled && ' You can now enable SSO and save.'}
          </p>
        </div>
      )}
    </section>
  );
}
