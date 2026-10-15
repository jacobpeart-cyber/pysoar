import axios from 'axios';

/**
 * Calls made before the user holds a session: the login MFA challenge and the
 * password-reset token pages. They go through a bare client because the
 * session clients answer any 401 by redirecting to /login, which would throw
 * away the MFA challenge on a mistyped code.
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

export const publicAuthApi = {
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
