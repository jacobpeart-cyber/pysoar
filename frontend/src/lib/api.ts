import axios from 'axios';

const API_BASE_URL = '/api/v1';

// Types
export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  updated_at: string;
}

export interface Alert {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  source: string;
  created_at: string;
  updated_at: string;
}

export interface Incident {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  created_at: string;
  updated_at: string;
  alert_count?: number;
  alerts?: Alert[];
}

export interface IOC {
  id: string;
  value: string;
  ioc_type: string;
  threat_level: string;
  source: string | null;
  description: string | null;
  tags: string[] | null;
  is_active: boolean;
  first_seen: string;
  last_seen: string | null;
  created_at: string;
  updated_at: string;
}

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor — auto-refresh token on 401, then retry
let isRefreshing = false;
let refreshQueue: Array<(token: string) => void> = [];

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      const refreshToken = localStorage.getItem('refresh_token');
      if (!refreshToken) {
        localStorage.removeItem('access_token');
        window.location.href = '/login';
        return Promise.reject(error);
      }

      if (isRefreshing) {
        // Queue this request until refresh completes
        return new Promise((resolve) => {
          refreshQueue.push((newToken: string) => {
            originalRequest.headers.Authorization = `Bearer ${newToken}`;
            resolve(api(originalRequest));
          });
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const res = await axios.post(`${API_BASE_URL}/auth/refresh`, { refresh_token: refreshToken });
        const newToken = res.data.access_token;
        localStorage.setItem('access_token', newToken);
        if (res.data.refresh_token) localStorage.setItem('refresh_token', res.data.refresh_token);

        // Retry queued requests
        refreshQueue.forEach((cb) => cb(newToken));
        refreshQueue = [];

        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      } catch {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        window.location.href = '/login';
        return Promise.reject(error);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

// Auth API
export const authApi = {
  login: async (email: string, password: string) => {
    const response = await api.post('/auth/login', { email, password });
    return response.data;
  },
  me: async () => {
    const response = await api.get('/auth/me');
    return response.data;
  },
  refresh: async (refreshToken: string) => {
    const response = await api.post('/auth/refresh', { refresh_token: refreshToken });
    return response.data;
  },
};

// Alerts API
export const alertsApi = {
  list: async (params?: {
    page?: number;
    size?: number;
    status?: string;
    severity?: string;
    source?: string;
    search?: string;
    sort_by?: string;
    sort_order?: 'asc' | 'desc';
  }) => {
    const response = await api.get('/alerts', { params });
    return response.data;
  },
  get: async (id: string) => {
    const response = await api.get(`/alerts/${id}`);
    return response.data;
  },
  create: async (data: any) => {
    const response = await api.post('/alerts', data);
    return response.data;
  },
  update: async (id: string, data: any) => {
    const response = await api.patch(`/alerts/${id}`, data);
    return response.data;
  },
  delete: async (id: string) => {
    await api.delete(`/alerts/${id}`);
  },
  bulkAction: async (data: { alert_ids: string[]; action: string; value?: string }) => {
    const response = await api.post('/alerts/bulk', data);
    return response.data;
  },
  getStats: async () => {
    const response = await api.get('/alerts/stats');
    return response.data;
  },
};

// Incidents API
export const incidentsApi = {
  list: async (params?: { page?: number; size?: number; status?: string; severity?: string }) => {
    const response = await api.get('/incidents', { params });
    return response.data;
  },
  get: async (id: string) => {
    const response = await api.get(`/incidents/${id}`);
    return response.data;
  },
  create: async (data: any) => {
    const response = await api.post('/incidents', data);
    return response.data;
  },
  update: async (id: string, data: any) => {
    const response = await api.patch(`/incidents/${id}`, data);
    return response.data;
  },
  delete: async (id: string) => {
    await api.delete(`/incidents/${id}`);
  },
  getStats: async () => {
    const response = await api.get('/incidents/stats');
    return response.data;
  },
};

// IOCs API
export const iocsApi = {
  list: async (params?: { page?: number; size?: number; ioc_type?: string; threat_level?: string }) => {
    const response = await api.get('/iocs', { params });
    return response.data;
  },
  get: async (id: string) => {
    const response = await api.get(`/iocs/${id}`);
    return response.data;
  },
  create: async (data: any) => {
    const response = await api.post('/iocs', data);
    return response.data;
  },
  update: async (id: string, data: any) => {
    const response = await api.patch(`/iocs/${id}`, data);
    return response.data;
  },
  delete: async (id: string) => {
    await api.delete(`/iocs/${id}`);
  },
};

// Users API
export const usersApi = {
  list: async (params?: { page?: number; size?: number }) => {
    const response = await api.get('/users', { params });
    return response.data;
  },
  get: async (id: string) => {
    const response = await api.get(`/users/${id}`);
    return response.data;
  },
  create: async (data: any) => {
    const response = await api.post('/users', data);
    return response.data;
  },
  update: async (id: string, data: any) => {
    const response = await api.patch(`/users/${id}`, data);
    return response.data;
  },
  delete: async (id: string) => {
    await api.delete(`/users/${id}`);
  },
};

// Health API
export const healthApi = {
  check: async () => {
    const response = await api.get('/health');
    return response.data;
  },
};

// Playbooks API
export const playbooksApi = {
  list: async (params?: { page?: number; size?: number; status?: string; trigger_type?: string; category?: string }) => {
    const response = await api.get('/playbooks', { params });
    return response.data;
  },
  get: async (id: string) => {
    const response = await api.get(`/playbooks/${id}`);
    return response.data;
  },
  create: async (data: any) => {
    const response = await api.post('/playbooks', data);
    return response.data;
  },
  update: async (id: string, data: any) => {
    const response = await api.patch(`/playbooks/${id}`, data);
    return response.data;
  },
  delete: async (id: string) => {
    await api.delete(`/playbooks/${id}`);
  },
  execute: async (id: string, data?: { incident_id?: string; alert_id?: string; input_data?: any }) => {
    const response = await api.post(`/playbooks/${id}/execute`, data || {});
    return response.data;
  },
  getExecutions: async (id: string, params?: { page?: number; size?: number }) => {
    const response = await api.get(`/playbooks/${id}/executions`, { params });
    return response.data;
  },
};

// Assets API
export const assetsApi = {
  list: async (params?: { page?: number; size?: number; asset_type?: string; status?: string; criticality?: string; search?: string }) => {
    const response = await api.get('/assets', { params });
    return response.data;
  },
  get: async (id: string) => {
    const response = await api.get(`/assets/${id}`);
    return response.data;
  },
  create: async (data: any) => {
    const response = await api.post('/assets', data);
    return response.data;
  },
  update: async (id: string, data: any) => {
    const response = await api.patch(`/assets/${id}`, data);
    return response.data;
  },
  delete: async (id: string) => {
    await api.delete(`/assets/${id}`);
  },
};
