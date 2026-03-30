import axios, { AxiosInstance, AxiosError } from 'axios';
import { jwtDecode } from 'jwt-decode';

const API_URL = import.meta.env.VITE_API_URL || '/api/v1';

interface TokenPayload {
  exp: number;
  iat: number;
  sub: string;
}

class ApiClient {
  private axiosInstance: AxiosInstance;
  private refreshTimeout: NodeJS.Timeout | null = null;

  constructor() {
    this.axiosInstance = axios.create({
      baseURL: API_URL,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
    this.scheduleTokenRefresh();
  }

  private setupInterceptors() {
    // Request interceptor
    this.axiosInstance.interceptors.request.use((config) => {
      const token = this.getToken();
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Response interceptor
    this.axiosInstance.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        const status = error.response?.status;

        if (status === 401) {
          this.clearToken();
          window.location.href = '/login';
          return Promise.reject(new Error('Unauthorized. Please log in again.'));
        }

        if (status === 403) {
          return Promise.reject(new Error('Permission denied. You do not have access to this resource.'));
        }

        if (status === 429) {
          return Promise.reject(new Error('Rate limit exceeded. Please try again later.'));
        }

        if (status && status >= 500) {
          return Promise.reject(new Error('Server error. Please try again later.'));
        }

        return Promise.reject(error);
      }
    );
  }

  private scheduleTokenRefresh() {
    const token = this.getToken();
    if (!token) return;

    const expiresIn = this.getTokenExpiresIn();
    if (expiresIn <= 0) {
      this.clearToken();
      return;
    }

    // Refresh if token expires in less than 5 minutes
    const refreshTime = Math.max(0, (expiresIn - 300) * 1000);

    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
    }

    if (refreshTime > 0) {
      this.refreshTimeout = setTimeout(() => {
        this.autoRefreshToken();
      }, refreshTime);
    }
  }

  private async autoRefreshToken() {
    try {
      const refreshToken = this.getRefreshToken();
      if (refreshToken) {
        const response = await this.axiosInstance.post('/auth/refresh', {
          refresh_token: refreshToken,
        });
        this.setToken(response.data.access_token);
        this.scheduleTokenRefresh();
      }
    } catch (error) {
      this.clearToken();
      window.location.href = '/login';
    }
  }

  public getToken(): string | null {
    return localStorage.getItem('access_token');
  }

  public setToken(token: string): void {
    localStorage.setItem('access_token', token);
    this.scheduleTokenRefresh();
  }

  public getRefreshToken(): string | null {
    return localStorage.getItem('refresh_token');
  }

  public setRefreshToken(token: string): void {
    localStorage.setItem('refresh_token', token);
  }

  public clearToken(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
      this.refreshTimeout = null;
    }
  }

  public isTokenExpired(): boolean {
    const token = this.getToken();
    if (!token) return true;

    try {
      const decoded = jwtDecode<TokenPayload>(token);
      return decoded.exp * 1000 < Date.now();
    } catch {
      return true;
    }
  }

  private getTokenExpiresIn(): number {
    const token = this.getToken();
    if (!token) return 0;

    try {
      const decoded = jwtDecode<TokenPayload>(token);
      return decoded.exp - Math.floor(Date.now() / 1000);
    } catch {
      return 0;
    }
  }

  public getInstance(): AxiosInstance {
    return this.axiosInstance;
  }
}

export const apiClient = new ApiClient();
export const api = apiClient.getInstance();
