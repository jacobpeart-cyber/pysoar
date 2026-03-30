import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { authApi, apiClient } from '../api';

interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  is_superuser: boolean;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
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

  const login = async (email: string, password: string) => {
    try {
      const response = await authApi.login(email, password);
      setToken(response.access_token);
      // Fetch user profile since login response may not include user data
      const userData = await authApi.getProfile();
      setUser(userData);
    } catch (error) {
      apiClient.clearToken();
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
