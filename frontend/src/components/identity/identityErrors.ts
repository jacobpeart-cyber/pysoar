import { describeLoadError } from '../../lib/loadError';

/**
 * Readable sentences for the error keys the identity routes answer with
 * (src/api/v1/endpoints/sso.py, roles.py, scim_admin.py, users.py). Every
 * message keeps the server's key in brackets so an operator can grep the
 * audit log or the API docs for it. Unknown keys fall back to the generic
 * `HTTP <status> · <key>: <detail>` line.
 */

interface IdentityErrorBody {
  error?: string;
  detail?: unknown;
  reason?: string;
  fields?: string[];
  areas?: string[];
  area?: string;
  required?: string;
  tier?: string;
  domain?: string;
  value?: string;
  members?: number;
}

function bodyOf(err: unknown): { status: number | null; body: IdentityErrorBody | null } {
  const resp = (err as { response?: { status?: number; data?: unknown } } | null)?.response;
  const status = typeof resp?.status === 'number' ? resp.status : null;
  const data = resp?.data as { detail?: unknown; error?: unknown } | undefined;
  if (data && typeof data === 'object') {
    const nested = data.detail;
    if (nested && typeof nested === 'object' && !Array.isArray(nested) && typeof (nested as IdentityErrorBody).error === 'string') {
      return { status, body: nested as IdentityErrorBody };
    }
    if (typeof data.error === 'string') return { status, body: data as IdentityErrorBody };
  }
  return { status, body: null };
}

/** The error key the server answered with (`sso_not_configured`, `role_in_use`, ...), or null. */
export function identityErrorKey(err: unknown): string | null {
  return bodyOf(err).body?.error ?? null;
}

/** The HTTP status of a failed request, or null for a network failure. */
export function statusOf(err: unknown): number | null {
  return bodyOf(err).status;
}

const list = (xs?: string[]) => (xs && xs.length ? xs.join(', ') : 'unspecified');

export const SSO_TEST_REASONS: Record<string, string> = {
  provider_unreachable: 'the provider could not be reached (DNS, TLS or network, or the address is refused by the outbound guard because it is private or internal)',
  discovery_failed: 'the discovery document was missing, malformed, or its issuer does not match the configured issuer',
  jwks_failed: 'the signing keys (JWKS) could not be fetched or contained no keys',
};

export function describeIdentityError(err: unknown): string {
  const { body } = bodyOf(err);
  if (!body?.error) return describeLoadError(err);
  const d = typeof body.detail === 'string' ? body.detail : '';
  const k = body.error;
  const msg = (() => {
    switch (k) {
      // SSO configuration
      case 'not_implemented':
        return body.reason === 'saml_requires_xmlsec'
          ? 'SAML 2.0 is not implemented: verifying signed assertions needs xmlsec in the API image, which ships with a later identity package. Use OpenID Connect; Okta, Entra ID, Google, Auth0, Keycloak and Ping all support it.'
          : `Not implemented (${body.reason ?? 'no reason given'}).`;
      case 'unsupported_protocol':
        return 'Only OpenID Connect (oidc) is supported.';
      case 'missing_field':
        return `Required for OpenID Connect: ${list(body.fields)}.`;
      case 'invalid_issuer':
        return 'The issuer must be an https URL (OpenID Connect requires TLS).';
      case 'invalid_discovery_url':
        return 'The discovery URL must be an https URL.';
      case 'discovery_host_mismatch':
        return "The discovery URL must be on the issuer's host: a provider publishes its own configuration.";
      case 'invalid_scopes':
        return "The scopes must include 'openid'.";
      case 'invalid_email_domain':
        return `${body.domain ?? 'A value'} is not an email domain (write it as example.com).`;
      case 'unknown_role':
        return `${body.value ?? 'A role'} is neither a built-in role (admin, analyst, viewer) nor a custom role of this organisation.`;
      case 'email_claim_requires_unverified':
        return "The provider's email_verified covers its 'email' claim only. Keep the email claim 'email', or turn off 'Require verified email' to take the address from another claim.";
      case 'email_domain_claimed':
        return `The email domain ${body.domain ?? ''} is already claimed by another organisation's SSO configuration; a domain routes to one identity provider.`;
      case 'sso_test_required':
        return 'Enabling needs a passing connection test of the saved configuration: save with SSO disabled, run Test connection, then enable.';
      case 'allowed_email_domains_required':
        return 'List at least one allowed email domain before enabling SSO: discovery and provisioning are limited to those domains.';
      case 'full_admin_required':
        return body.fields?.length
          ? `Only a built-in admin without a custom role may change: ${list(body.fields)}.`
          : 'This needs the built-in admin role without a custom role.';
      case 'tier_exceeds_caller':
        return `This would grant more than you hold yourself in: ${list(body.areas)}.`;
      case 'sso_not_configured':
        return 'This organisation has no single sign-on configuration.';
      case 'sso_test_failed':
        return `Connection test failed: ${SSO_TEST_REASONS[body.reason ?? ''] ?? body.reason ?? 'unknown reason'}.`;
      // Roles
      case 'area_denied':
        return `Your role has no access to the ${body.area ?? ''} area.`;
      case 'insufficient_tier':
        return `Your role holds ${body.tier ?? 'a lower'} tier in ${body.area ?? 'this area'}; ${body.required ?? 'a higher tier'} is required.`;
      case 'privileged_field':
        return 'You cannot change your own role or status.';
      case 'role_not_found':
        return 'The custom role no longer exists in this organisation.';
      case 'role_name_taken':
        return 'A role with that name already exists.';
      case 'role_in_use':
        return `${body.members ?? 'Some'} user(s) hold this role; assign them another role before deleting it.`;
      case 'reserved_role_name':
        return 'admin, analyst and viewer are built-in role names (SSO group mappings use them); choose another name.';
      case 'unknown_area':
        return `Unknown area(s): ${list(body.areas)}. Reload the page to get the current catalogue.`;
      case 'invalid_role_name':
        return 'The role name must not be blank.';
      case 'invalid_tier':
        return 'Tiers must be none, read, write or admin.';
      case 'superuser_custom_role':
        return 'The platform superuser cannot hold a custom role.';
      // SCIM
      case 'scim_token_not_found':
        return 'The SCIM token no longer exists in this organisation.';
      case 'scim_group_not_found':
        return 'The SCIM group no longer exists (the identity provider may have deleted it).';
      case 'invalid_token_name':
        return 'The token name must not be blank.';
      case 'scim_group_store_unreadable':
        return 'The stored SCIM groups could not be read; the mapping was not changed.';
      case 'user_not_found':
        return 'The user was not found in this organisation (the platform superuser is never managed through SCIM).';
      case 'user_inactive':
        return 'Reactivate the account in PySOAR before linking it.';
      case 'not_local_account':
        return 'The account is already managed by the identity provider.';
      case 'not_scim_managed':
        return 'The account is not SCIM-managed.';
      case 'self_unlink':
        return 'You cannot take your own account out of identity-provider management; ask another admin.';
      case 'organization_required':
        return 'Your account belongs to no organisation; identity settings are per organisation.';
      // Login side
      case 'invalid_sso_code':
        return 'The single sign-on code is unknown, expired (60 seconds) or already used. Start the SSO sign-in again.';
      case 'sso_unavailable':
        return 'Single sign-on was disabled for this organisation.';
      case 'sso_managed':
        return 'This account signs in through your organisation’s identity provider; reset the password there.';
      default:
        return null;
    }
  })();
  if (msg === null) return describeLoadError(err);
  const extra = k === 'sso_test_failed' && d ? ` (${d})` : '';
  return `${msg}${extra} [${k}]`;
}

/** Login `?sso_error=<reason>` values from GET /auth/sso/callback and /start. */
export const SSO_LOGIN_ERRORS: Record<string, string> = {
  invalid_state: 'The sign-in request expired (10 minutes) or was already used. Start the SSO sign-in again.',
  idp_error: 'Your identity provider refused or cancelled the sign-in.',
  missing_code: 'Your identity provider returned without an authorization code.',
  sso_unavailable: 'Single sign-on is not available for this organisation (it may have been disabled).',
  provider_unreachable: 'PySOAR could not reach your identity provider.',
  discovery_failed: "Your identity provider's configuration could not be read or did not match.",
  jwks_failed: "Your identity provider's signing keys could not be fetched.",
  token_exchange_failed: 'Your identity provider refused the token exchange (check the client ID and secret).',
  invalid_id_token: 'The identity token from your provider failed verification.',
  email_missing: 'Your identity provider did not send an email address.',
  email_not_verified: 'Your identity provider reports the email address as not verified.',
  email_domain_not_allowed: "Your email domain is not allowed for this organisation's single sign-on.",
  user_not_provisioned: 'No PySOAR account exists for you and automatic provisioning is off. Ask your administrator.',
  account_conflict: 'A PySOAR account with your email exists in another organisation, so this sign-in cannot use it. Ask your administrator.',
  subject_mismatch: 'Your PySOAR account is bound to a different identity at the provider. Ask your administrator.',
  role_unresolved: 'Your role could not be determined from the group mapping. Ask your administrator.',
  user_inactive: 'Your PySOAR account is deactivated.',
  superuser_not_allowed: 'The platform operator account cannot sign in through single sign-on.',
  sso_failed: 'Single sign-on failed.',
};

export function describeSsoLoginError(reason: string): string {
  return `${SSO_LOGIN_ERRORS[reason] ?? 'Single sign-on failed.'} [${reason}]`;
}
