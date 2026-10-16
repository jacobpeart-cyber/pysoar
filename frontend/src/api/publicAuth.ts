import axios from 'axios';

/**
 * Calls made before the user holds a session: the login MFA challenge, the
 * SSO discover / code exchange and the password-reset token pages. They go
 * through a bare client because the session clients answer any 401 by
 * redirecting to /login, which would throw away the MFA challenge on a
 * mistyped code.
 */
const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api/v1',
  headers: { 'Content-Type': 'application/json' },
});

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/** POST /auth/sso/discover: whether the email's domain signs in through SSO. */
export interface SsoDiscovery {
  available: boolean;
  organization_slug: string | null;
  display_name: string | null;
  /** Relative URL the browser navigates to (GET) to start the login. */
  login_url: string | null;
}

/** POST /auth/sso/exchange answers like password login: tokens, or the MFA challenge. */
export type SsoExchangeResult =
  | ({ mfa_required?: false } & TokenPair)
  | { mfa_required: true; mfa_token: string; expires_in: number };

export const publicAuthApi = {
  /** Answers `{available: false}` and nothing else for a domain without enabled SSO. */
  discoverSso: async (email: string): Promise<SsoDiscovery> => {
    const response = await client.post('/auth/sso/discover', { email });
    return response.data;
  },

  /** One-time code from /login?sso= (60 s, single use); 401 invalid_sso_code / sso_unavailable. */
  exchangeSso: async (code: string): Promise<SsoExchangeResult> => {
    const response = await client.post('/auth/sso/exchange', { code });
    return response.data;
  },

  /** Second login step: a TOTP code or an unused backup code. */
  verifyMfa: async (mfaToken: string, code: string): Promise<TokenPair> => {
    const response = await client.post('/mfa/verify', { mfa_token: mfaToken, code });
    return response.data;
  },

  /** 200 with the expiry, 404 unknown token, 410 expired. Does not burn it. */
  validateResetToken: async (token: string): Promise<{ valid: boolean; expires_at: string }> => {
    const response = await client.post('/auth/password-reset/validate', { token });
    return response.data;
  },

  /**
   * Forced password change at login. `limitedToken` is the X-Limited-Token a
   * 403 "Password change required" login answer carries (5 minutes, accepted
   * only by this route). It is sent once in the header and never stored.
   */
  changePasswordWithLimitedToken: async (
    limitedToken: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<{ message: string }> => {
    const response = await client.post(
      '/auth/change-password',
      { current_password: currentPassword, new_password: newPassword },
      { headers: { Authorization: `Bearer ${limitedToken}` } },
    );
    return response.data;
  },

  /** Burns the token and sets the new password (12 characters minimum). */
  consumeResetToken: async (token: string, newPassword: string): Promise<{ status: string }> => {
    const response = await client.post('/auth/password-reset/consume', { token, new_password: newPassword });
    return response.data;
  },
};
