/**
 * Unified fetch wrapper that automatically fetches, caches,
 * and attaches CSRF tokens for mutating requests (POST, PUT, DELETE, PATCH).
 */

const API_BASE = import.meta.env?.VITE_API_BASE || 'http://localhost:5000/api';

let cachedCsrfToken = null;

export async function fetchCsrfToken() {
  try {
    const res = await fetch(`${API_BASE}/csrf-token`, {
      method: 'GET',
      credentials: 'include'
    });
    const json = await res.json();
    if (json.success && json.data?.csrfToken) {
      cachedCsrfToken = json.data.csrfToken;
      return cachedCsrfToken;
    }
  } catch (error) {
    console.error('Failed to obtain CSRF token:', error);
  }
  return null;
}

export async function apiRequest(endpoint, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = { ...(options.headers || {}) };

  // Attach CSRF header on state mutations
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    if (!cachedCsrfToken) {
      await fetchCsrfToken();
    }
    if (cachedCsrfToken) {
      headers['CSRF-Token'] = cachedCsrfToken;
    }
  }

  // Handle JSON body if not FormData
  let body = options.body;
  if (body && !(body instanceof FormData) && typeof body === 'object') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    method,
    headers,
    body,
    credentials: 'include'
  });

  // If CSRF token is rejected, refresh and retry once
  if (response.status === 403 && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    await fetchCsrfToken();
    if (cachedCsrfToken) {
      headers['CSRF-Token'] = cachedCsrfToken;
      return fetch(`${API_BASE}${endpoint}`, {
        ...options,
        method,
        headers,
        body,
        credentials: 'include'
      }).then(r => r.json());
    }
  }

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || 'Request failed');
  }

  return data;
}

// Authentication Helpers
export const authApi = {
  login: (credentials) => apiRequest('/auth/login', { method: 'POST', body: credentials }),
  register: (payload) => apiRequest('/auth/register', { method: 'POST', body: payload }),
  logout: () => apiRequest('/auth/logout', { method: 'POST' }),
  me: () => apiRequest('/auth/me', { method: 'GET' })
};

// Security Modules API
export const securityApi = {
  scanHeaders: (targetUrl) => apiRequest('/headershield/scan', { method: 'POST', body: { targetUrl } }),
  checkPhish: (url) => apiRequest('/phishcheck/check', { method: 'POST', body: { url } }),
  checkFileIntegrity: (formData) => apiRequest('/fileintegrity/check', { method: 'POST', body: formData }),
  getFileBaselines: () => apiRequest('/fileintegrity/baselines', { method: 'GET' }),
  getHistory: (params = '') => apiRequest(`/history${params}`, { method: 'GET' }),
  getDashboardSummary: () => apiRequest('/history/summary/dashboard', { method: 'GET' })
};

