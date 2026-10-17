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
 * Settings > Identity > Single sign-on (OIDC or SAML 2.0). Contract:
 * src/api/v1/endpoints/sso.py, src/identity/saml.py.
 *
 * - SAML: the IdP entity ID is `issuer`, the IdP metadata URL is
 *   `discovery_url`, our SP entity ID is `client_id` (blank = the SP metadata
 *   URL), and the IdP SSO URL, signing certificates, NameID format, signed
 *   response and clock skew travel in `saml`. Stored certificates are shown as
 *   fingerprints; the textarea replaces them, blank keeps them.
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

// SAML parts of the contract (src/schemas/identity.py SAMLConfigResponse,
// SAMLSettingsUpdate, SAMLTestResponse), layered on the shared SSO types.
interface SAMLCertificate {
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  sha256_fingerprint: string;
  expired: boolean;
}

interface SAMLConfig {
  sp_entity_id: string;
  acs_url: string;
  sp_metadata_url: string;
  metadata_url: string | null;
  idp_entity_id: string;
  idp_sso_url: string | null;
  idp_certificates: SAMLCertificate[];
  name_id_format: string;
  name_id_formats_supported: string[];
  want_assertions_signed: boolean;
  want_response_signed: boolean;
  clock_skew_seconds: number;
}

type SSOConfigWithSaml = SSOConfig & { saml?: SAMLConfig | null };

interface SAMLSettingsBody {
  idp_sso_url: string | null;
  /** Omitted keeps the stored certificates. */
  idp_certificates?: string[];
  name_id_format: string;
  want_assertions_signed: true;
  want_response_signed: boolean;
  clock_skew_seconds: number;
}

type SSOConfigBody = SSOConfigUpdate & { saml?: SAMLSettingsBody };

interface SAMLTestResult {
  status: string;
  protocol: 'saml';
  tested_at: string;
  source: 'metadata' | 'configuration';
  idp_entity_id: string;
  idp_sso_url: string;
  certificate_count: number;
  certificates: SAMLCertificate[];
  name_id_formats: string[];
  warnings: string[];
}

type AnyTestResult = SSOTestResult | SAMLTestResult;

function isSamlTest(r: AnyTestResult): r is SAMLTestResult {
  return (r as SAMLTestResult).protocol === 'saml';
}

const NAME_ID_FORMATS: { value: string; label: string }[] = [
  { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', label: 'emailAddress' },
  { value: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', label: 'persistent (recommended: survives email changes)' },
  { value: 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', label: 'unspecified' },
];

/** PEM blocks in the textarea; text without PEM markers is sent as one (base64 DER) certificate. */
function parseCertificates(text: string): string[] {
  const blocks = text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (blocks) return blocks;
  return text.trim() ? [text.trim()] : [];
}

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
  // SAML only
  idp_sso_url: string;
  /** New certificates to store; blank keeps the stored ones. */
  cert_text: string;
  name_id_format: string;
  want_response_signed: boolean;
  clock_skew_seconds: string;
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
  idp_sso_url: '',
  cert_text: '',
  name_id_format: NAME_ID_FORMATS[0].value,
  want_response_signed: false,
  clock_skew_seconds: '60',
};

function fromConfig(c: SSOConfigWithSaml): FormState {
  const s = c.saml ?? null;
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
    idp_sso_url: s?.idp_sso_url ?? '',
    cert_text: '',
    name_id_format: s?.name_id_format ?? NAME_ID_FORMATS[0].value,
    want_response_signed: s?.want_response_signed ?? false,
    clock_skew_seconds: String(s?.clock_skew_seconds ?? 60),
  };
}

function parseDomains(text: string): string[] {
  return text
    .split(/[\s,;]+/)
    .map((d) => d.trim())
    .filter(Boolean);
}

function toBody(f: FormState, secret: { value: string; clear: boolean }): SSOConfigBody {
  const map: Record<string, string> = {};
  for (const row of f.groupMap) {
    if (row.group.trim()) map[row.group.trim()] = row.role;
  }
  const saml = f.protocol === 'saml';
  const body: SSOConfigBody = {
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
    // SAML has no verified-email flag; the server stores false.
    require_email_verified: saml ? false : f.require_email_verified,
    trust_idp_mfa: f.trust_idp_mfa,
    enabled: f.enabled,
  };
  if (saml) {
    const skew = Number.parseInt(f.clock_skew_seconds, 10);
    body.saml = {
      idp_sso_url: f.idp_sso_url.trim() || null,
      name_id_format: f.name_id_format,
      want_assertions_signed: true,
      want_response_signed: f.want_response_signed,
      clock_skew_seconds: Number.isFinite(skew) ? skew : 60,
    };
    const certs = parseCertificates(f.cert_text);
    if (certs.length) body.saml.idp_certificates = certs;
    return body;
  }
  if (secret.clear) body.client_secret = '';
  else if (secret.value) body.client_secret = secret.value;
  return body;
}

export default function SSOConfigPanel() {
  const cfgQuery = useQuery({ queryKey: ['identity', 'sso'], queryFn: identityApi.getSso, retry: false });
  const notConfigured = identityErrorKey(cfgQuery.error) === 'sso_not_configured';
  const config: SSOConfigWithSaml | null = cfgQuery.data ?? null;
  const qc = useQueryClient();
  const [testResult, setTestResult] = useState<AnyTestResult | null>(null);
  const [notice, setNotice] = useState('');
  // Held here, not in the form: a test (pass or fail) updates last_tested_at,
  // which remounts the form, and the result must survive that.
  const test = useMutation({
    mutationFn: identityApi.testSso,
    onSuccess: (r) => {
      // The SAML branch of POST /settings/sso/test answers SAMLTestResponse.
      setTestResult(r as AnyTestResult);
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
  config: SSOConfigWithSaml | null;
  notConfigured: boolean;
  testResult: AnyTestResult | null;
  setTestResult: (r: AnyTestResult | null) => void;
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
  const isSaml = form.protocol === 'saml';
  const savedSaml = config?.protocol === 'saml' ? config.saml ?? null : null;
  const providerChanged =
    config !== null &&
    (form.protocol !== config.protocol ||
      form.issuer.trim() !== config.issuer ||
      (form.discovery_url.trim() || null) !== (config.discovery_url || null) ||
      (isSaml && ((form.idp_sso_url.trim() || null) !== (savedSaml?.idp_sso_url ?? null) || Boolean(form.cert_text.trim()))));

  // A custom-role admin may edit only display_name, scopes, name_claim,
  // group_role_map and default_role, and cannot create or delete the configuration.
  const trustLocked = !gate.isFullAdmin;
  const createLocked = !config && !gate.isFullAdmin;
  const trustTitle = trustLocked ? FULL_ADMIN_ONLY_REASON : undefined;

  const save = useMutation({
    mutationFn: (body: SSOConfigBody) => identityApi.putSso(body),
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
    if (providerChanged)
      return isSaml
        ? 'The IdP entity ID, metadata URL, SSO URL or certificates changed: save with SSO disabled and test again.'
        : 'The issuer or discovery URL changed: save with SSO disabled and test again.';
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
  // With a groups claim / attribute configured every login re-syncs roles from
  // the mapping, so the mapping and default role become trust settings too
  // (server: 403 full_admin_required).
  const mapLocked =
    disabledAll || (trustLocked && (isSaml || Boolean(form.groups_claim.trim()) || Boolean(config?.groups_claim)));
  const mapTitle = mapLocked && !disabledAll ? FULL_ADMIN_ONLY_REASON : undefined;

  return (
    <section className="space-y-5">
      <div>
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">Single sign-on (OpenID Connect or SAML 2.0)</h3>
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
          {savedSaml ? (
            <>
              <CopyValue label="SP entity ID / Audience (register this at the identity provider)" value={savedSaml.sp_entity_id} />
              <CopyValue label="ACS URL (HTTP-POST; register this at the identity provider)" value={savedSaml.acs_url} />
              <CopyValue label="SP metadata URL (import this at the identity provider)" value={savedSaml.sp_metadata_url} />
            </>
          ) : (
            <CopyValue label="Redirect URI (register this at the identity provider)" value={config.redirect_uri} />
          )}
          <CopyValue label="Sign-in URL for this organisation" value={config.login_url} />
          {!savedSaml && (
            <div className="text-sm text-gray-700 dark:text-gray-300">
              <span className={labelCls}>Discovery document used</span>
              <code className="text-xs break-all">{config.effective_discovery_url}</code>
            </div>
          )}
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
              <option value="saml">SAML 2.0</option>
            </select>
            {isSaml && (
              <p className="text-xs text-gray-500 mt-1">
                SP-initiated sign-in only: PySOAR sends an unsigned AuthnRequest (HTTP-Redirect) and accepts signed
                assertions posted to the ACS URL. Not supported: encrypted assertions, signed requests, Single Logout,
                IdP-initiated sign-in.
              </p>
            )}
          </div>
          <div>
            <label htmlFor="sso-display" className={labelCls}>Button label (display name)</label>
            <input id="sso-display" className={inputCls} value={form.display_name} disabled={disabledAll}
              placeholder="e.g. Okta" onChange={(e) => set('display_name', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-issuer" className={labelCls}>{isSaml ? 'IdP entity ID' : 'Issuer (https)'}</label>
            <input id="sso-issuer" className={inputCls} value={form.issuer} disabled={trustLocked} title={trustTitle}
              placeholder={isSaml ? 'e.g. http://www.okta.com/exk123' : 'https://login.example.com'}
              onChange={(e) => set('issuer', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-discovery" className={labelCls}>
              {isSaml ? 'IdP metadata URL (optional, https)' : 'Discovery URL (optional, issuer host)'}
            </label>
            <input id="sso-discovery" className={inputCls} value={form.discovery_url} disabled={trustLocked} title={trustTitle}
              placeholder={isSaml
                ? 'Test connection reads the SSO URL and certificates from it'
                : 'defaults to <issuer>/.well-known/openid-configuration'}
              onChange={(e) => set('discovery_url', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-client" className={labelCls}>{isSaml ? 'SP entity ID (optional)' : 'Client ID'}</label>
            <input id="sso-client" className={inputCls} value={form.client_id} disabled={trustLocked} title={trustTitle}
              placeholder={isSaml ? 'defaults to the SP metadata URL' : undefined}
              onChange={(e) => set('client_id', e.target.value)} />
          </div>
          {!isSaml && (
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
          )}
          {!isSaml && (
          <div>
            <label htmlFor="sso-scopes" className={labelCls}>Scopes (must include openid)</label>
            <input id="sso-scopes" className={inputCls} value={form.scopes} disabled={disabledAll}
              onChange={(e) => set('scopes', e.target.value)} />
          </div>
          )}
          {isSaml && (
          <div>
            <label htmlFor="sso-saml-sso-url" className={labelCls}>IdP single sign-on URL (HTTP-Redirect, https)</label>
            <input id="sso-saml-sso-url" className={inputCls} value={form.idp_sso_url} disabled={trustLocked} title={trustTitle}
              placeholder="filled from the metadata URL by Test connection"
              onChange={(e) => set('idp_sso_url', e.target.value)} />
          </div>
          )}
          <div>
            <label htmlFor="sso-domains" className={labelCls}>Allowed email domains</label>
            <input id="sso-domains" className={inputCls} value={form.domains} disabled={trustLocked} title={trustTitle}
              placeholder="example.com, example.org" onChange={(e) => set('domains', e.target.value)} />
            <p className="text-xs text-gray-500 mt-1">Discovery and provisioning are limited to these domains.</p>
          </div>
          <div>
            <label htmlFor="sso-email-claim" className={labelCls}>{isSaml ? 'Email attribute' : 'Email claim'}</label>
            <input id="sso-email-claim" className={inputCls} value={form.email_claim} disabled={trustLocked} title={trustTitle}
              onChange={(e) => set('email_claim', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-name-claim" className={labelCls}>{isSaml ? 'Name attribute' : 'Name claim'}</label>
            <input id="sso-name-claim" className={inputCls} value={form.name_claim} disabled={disabledAll}
              onChange={(e) => set('name_claim', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-groups-claim" className={labelCls}>{isSaml ? 'Groups attribute (default groups)' : 'Groups claim (optional)'}</label>
            <input id="sso-groups-claim" className={inputCls} value={form.groups_claim} disabled={trustLocked} title={trustTitle}
              placeholder="groups" onChange={(e) => set('groups_claim', e.target.value)} />
          </div>
          <div>
            <label htmlFor="sso-default-role" className={labelCls}>Default role (no group matched)</label>
            <RoleSelect id="sso-default-role" value={form.default_role} custom={roles.custom} disabled={mapLocked} title={mapTitle}
              onChange={(v) => set('default_role', v)} />
          </div>
        </div>

        {isSaml && (
          <div className="space-y-3 rounded border border-gray-200 dark:border-gray-700 p-3">
            <span className={labelCls}>IdP signing certificates</span>
            {savedSaml && savedSaml.idp_certificates.length > 0 ? (
              <ul className="text-xs text-gray-700 dark:text-gray-300 space-y-1">
                {savedSaml.idp_certificates.map((c) => (
                  <li key={c.sha256_fingerprint} className="break-all">
                    {c.expired ? <Chip tone="red">expired</Chip> : <Chip tone="green">valid</Chip>} {c.subject}; expires{' '}
                    {fmtDate(c.not_after)}; SHA-256 {c.sha256_fingerprint}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-gray-500">
                No certificate stored. Paste the IdP signing certificate, or set the metadata URL and run Test connection.
              </p>
            )}
            <label htmlFor="sso-saml-certs" className="sr-only">Replace the IdP signing certificates</label>
            <textarea id="sso-saml-certs" className={`${inputCls} font-mono text-xs`} rows={4} value={form.cert_text}
              disabled={trustLocked} title={trustTitle}
              placeholder="-----BEGIN CERTIFICATE----- ... (leave blank to keep the stored certificates; up to 4 for rollover)"
              onChange={(e) => set('cert_text', e.target.value)} />
            <div className="grid gap-4 md:grid-cols-2">
              <div>
                <label htmlFor="sso-saml-nameid" className={labelCls}>NameID format</label>
                <select id="sso-saml-nameid" className={inputCls} value={form.name_id_format} disabled={trustLocked} title={trustTitle}
                  onChange={(e) => set('name_id_format', e.target.value)}>
                  {NAME_ID_FORMATS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
                </select>
              </div>
              <div>
                <label htmlFor="sso-saml-skew" className={labelCls}>Allowed clock skew (seconds, 0 to 300)</label>
                <input id="sso-saml-skew" type="number" min={0} max={300} className={inputCls} value={form.clock_skew_seconds}
                  disabled={trustLocked} title={trustTitle} onChange={(e) => set('clock_skew_seconds', e.target.value)} />
              </div>
            </div>
            <div className="grid gap-2 md:grid-cols-2 text-sm text-gray-700 dark:text-gray-300">
              <label className="flex items-start gap-2" title="An unsigned assertion is never accepted.">
                <input type="checkbox" checked disabled readOnly />
                <span>Require signed assertions (always on)</span>
              </label>
              <label className="flex items-start gap-2" title={trustTitle}>
                <input type="checkbox" checked={form.want_response_signed} disabled={trustLocked && form.want_response_signed}
                  onChange={(e) => set('want_response_signed', e.target.checked)} />
                <span>Also require the whole Response to be signed</span>
              </label>
            </div>
          </div>
        )}

        <div className="space-y-2">
          <span className={labelCls}>Group to role mapping ({isSaml ? 'groups attribute' : 'groups claim'} value to PySOAR role)</span>
          {roles.error ? (
            <p className="text-xs text-amber-700 dark:text-amber-300">
              Custom roles could not be listed, so only built-in roles are offered. {describeIdentityError(roles.error)}
            </p>
          ) : null}
          {form.groupMap.length === 0 && <p className="text-xs text-gray-500">No mappings: everyone receives the default role.</p>}
          {form.groupMap.map((row, i) => (
            <div key={i} className="flex gap-2 items-center">
              <input aria-label="IdP group" className={inputCls} value={row.group} disabled={mapLocked} title={mapTitle} placeholder="IdP group name"
                onChange={(e) => set('groupMap', form.groupMap.map((r, j) => (j === i ? { ...r, group: e.target.value } : r)))} />
              <RoleSelect value={row.role} custom={roles.custom} disabled={mapLocked} title={mapTitle}
                onChange={(v) => set('groupMap', form.groupMap.map((r, j) => (j === i ? { ...r, role: v } : r)))} />
              <button type="button" className={btnSecondary} aria-label="Remove mapping" disabled={mapLocked} title={mapTitle}
                onClick={() => set('groupMap', form.groupMap.filter((_, j) => j !== i))}>
                <X className="w-4 h-4" />
              </button>
            </div>
          ))}
          <button type="button" className={btnSecondary} disabled={mapLocked} title={mapTitle}
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
          {isSaml ? (
            <p className="text-xs text-gray-500">
              SAML carries no verified-email flag: the email attribute of the signed assertion is trusted, so list only
              domains your IdP controls.
            </p>
          ) : (
            <label className="flex items-start gap-2" title={trustTitle}>
              <input type="checkbox" checked={form.require_email_verified} disabled={trustLocked && form.require_email_verified}
                onChange={(e) => set('require_email_verified', e.target.checked)} />
              <span>Require the provider to assert the email is verified</span>
            </label>
          )}
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
      {testResult && isSamlTest(testResult) && (
        <div className="text-sm rounded p-3 border border-green-200 dark:border-green-800 bg-green-50 dark:bg-green-900/20 space-y-1">
          <p className="font-medium text-green-800 dark:text-green-300 flex items-center gap-2">
            <CheckCircle className="w-4 h-4" /> SAML test passed ({fmtDate(testResult.tested_at)})
          </p>
          <p className="text-xs text-gray-700 dark:text-gray-300 break-all">
            {testResult.source === 'metadata'
              ? 'Read from the IdP metadata URL; the SSO URL and certificates below are now stored.'
              : 'Checked the stored settings locally; the IdP was not contacted.'}{' '}
            IdP {testResult.idp_entity_id}; SSO URL {testResult.idp_sso_url}; {testResult.certificate_count} certificate(s).
          </p>
          <ul className="text-xs text-gray-700 dark:text-gray-300 list-disc ml-5 break-all">
            {testResult.certificates.map((c) => (
              <li key={c.sha256_fingerprint}>{c.subject} (expires {fmtDate(c.not_after)}{c.expired ? ', expired' : ''})</li>
            ))}
            {testResult.name_id_formats.length > 0 && <li>NameID formats offered: {testResult.name_id_formats.join(', ')}</li>}
          </ul>
          {testResult.warnings.length > 0 && (
            <div className="text-xs text-amber-800 dark:text-amber-300">
              <p className="flex items-center gap-1 font-medium"><XCircle className="w-3 h-3" /> Warnings</p>
              <ul className="list-disc ml-5">{testResult.warnings.map((w) => <li key={w}>{w}</li>)}</ul>
            </div>
          )}
          <p className="text-xs text-gray-500">
            Signature checks against these certificates happen on a real sign-in.
            {!config?.enabled && ' You can now enable SSO and save.'}
          </p>
        </div>
      )}
      {testResult && !isSamlTest(testResult) && (
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
