import { api, apiClient } from './client';

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  user: {
    id: string;
    email: string;
    full_name: string | null;
    role: string;
    is_active: boolean;
    is_superuser: boolean;
  };
}

export interface UserProfile {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  is_superuser: boolean;
  organization_id: string | null;
  created_at: string;
  updated_at: string;
}

/** Body of POST /auth/login when the account has MFA enabled: no tokens yet. */
export interface MfaChallenge {
  mfa_required: true;
  mfa_token: string;
  expires_in: number;
}

export const authApi = {
  login: async (email: string, password: string): Promise<LoginResponse | MfaChallenge> => {
    const response = await api.post('/auth/login', { email, password });
    if (response.data?.mfa_required) {
      // The password was right but the account needs its second factor;
      // POST /mfa/verify trades this short-lived token for the session.
      return response.data as MfaChallenge;
    }
    const { access_token, refresh_token } = response.data;
    apiClient.setToken(access_token);
    apiClient.setRefreshToken(refresh_token);
    return response.data;
  },

  /** Store the session issued by POST /mfa/verify. */
  storeTokens: (accessToken: string, refreshToken: string): void => {
    apiClient.setToken(accessToken);
    apiClient.setRefreshToken(refreshToken);
  },

  logout: async (): Promise<void> => {
    try {
      await api.post('/auth/logout');
    } finally {
      apiClient.clearToken();
    }
  },

  refreshToken: async (): Promise<{ access_token: string }> => {
    const refreshToken = apiClient.getRefreshToken();
    if (!refreshToken) {
      throw new Error('No refresh token available');
    }
    const response = await api.post('/auth/refresh', { refresh_token: refreshToken });
    apiClient.setToken(response.data.access_token);
    return response.data;
  },

  getProfile: async (): Promise<UserProfile> => {
    const response = await api.get('/auth/me');
    return response.data;
  },

  changePassword: async (currentPassword: string, newPassword: string): Promise<void> => {
    await api.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
  },
};
