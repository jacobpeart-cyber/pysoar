import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authApi, apiClient } from '../api';
import { publicAuthApi } from '../api/publicAuth';

/** What a password login produced: a session, or an MFA challenge to answer. */
export type LoginResult = { mfaRequired: false } | { mfaRequired: true; mfaToken: string; expiresIn: number };

interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  is_superuser: boolean;
  organization_id: string | null;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<LoginResult>;
  completeMfaLogin: (mfaToken: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(apiClient.getToken());
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const initializeAuth = async () => {
      const storedToken = apiClient.getToken();
      if (storedToken && !apiClient.isTokenExpired()) {
        try {
          const userData = await authApi.getProfile();
          setUser(userData);
        } catch (error) {
          apiClient.clearToken();
          setToken(null);
        }
      }
      setIsLoading(false);
    };

    initializeAuth();
  }, []);

  const login = async (email: string, password: string): Promise<LoginResult> => {
    try {
      const response = await authApi.login(email, password);
      if ('mfa_required' in response && response.mfa_required) {
        return { mfaRequired: true, mfaToken: response.mfa_token, expiresIn: response.expires_in };
      }
      setToken(apiClient.getToken());
      // Fetch user profile since login response may not include user data
      const userData = await authApi.getProfile();
      setUser(userData);
      return { mfaRequired: false };
    } catch (error) {
      apiClient.clearToken();
      throw error;
    }
  };

  const completeMfaLogin = async (mfaToken: string, code: string) => {
    const tokens = await publicAuthApi.verifyMfa(mfaToken, code);
    authApi.storeTokens(tokens.access_token, tokens.refresh_token);
    setToken(tokens.access_token);
    try {
      setUser(await authApi.getProfile());
    } catch (error) {
      apiClient.clearToken();
      setToken(null);
      throw error;
    }
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } finally {
      apiClient.clearToken();
      setUser(null);
      setToken(null);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        isAuthenticated: !!user,
        login,
        completeMfaLogin,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
