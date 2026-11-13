/**
 * Unified fetch wrapper that automatically fetches, caches,
 * and attaches CSRF tokens for mutating requests (POST, PUT, DELETE, PATCH).
 */

const API_BASE = import.meta.env?.VITE_API_BASE || 'http://localhost:5000/api';

let cachedCsrfToken = null;

async function fetchCsrfToken() {
  try {
    const response = await fetch(`${API_BASE}/csrf-token`, {
      method: 'GET',
      credentials: 'include'
    });
    const json = await response.json();
    if (json.success && json.data?.csrfToken) {
      cachedCsrfToken = json.data.csrfToken;
      return cachedCsrfToken;
    }
  } catch (error) {
    console.error('Failed to obtain CSRF token:', error);
  }
  return null;
}

async function apiRequest(endpoint, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = { ...(options.headers || {}) };

  const needsCsrfToken = ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method);
  let body = options.body;
  if (body && typeof body === 'object' && !(body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }

  async function sendRequest() {
    if (needsCsrfToken && cachedCsrfToken) {
      headers['CSRF-Token'] = cachedCsrfToken;
      headers['X-CSRF-Token'] = cachedCsrfToken;
    }
    try {
      return await fetch(`${API_BASE}${endpoint}`, {
        ...options, method, headers, body, credentials: 'include'
      });
    } catch (error) {
      if (!(error instanceof TypeError)) throw error;
      throw new Error('Cannot reach the AuthGuard-X server. Start the app with node start.js from the project folder.');
    }
  }

  if (needsCsrfToken && !cachedCsrfToken) await fetchCsrfToken();
  let response = await sendRequest();
  if (needsCsrfToken && response.status === 403 && await fetchCsrfToken()) {
    response = await sendRequest();
  }

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.message || 'Request failed');
  }

  return data;
}

// Authentication Helpers
export const authenticationApi = {
  login: (credentials) => apiRequest('/auth/login', { method: 'POST', body: credentials }),
  register: (payload) => apiRequest('/auth/register', { method: 'POST', body: payload }),
  logout: () => apiRequest('/auth/logout', { method: 'POST' }),
  me: () => apiRequest('/auth/me', { method: 'GET' })
};

// Security Modules API
export const securityApi = {
  getApprovedHeaderHosts: () => apiRequest('/headershield/hosts'),
  scanHeaders: (targetUrl) => apiRequest('/headershield/scan', { method: 'POST', body: { targetUrl } }),
  checkPhishingUrl: (url) => apiRequest('/phishcheck/analyze', { method: 'POST', body: { url } }),
  checkFileIntegrity: (formData) => apiRequest('/fileintegrity/check', { method: 'POST', body: formData }),
  getFileBaselines: () => apiRequest('/fileintegrity/baselines', { method: 'GET' }),
  getHistory: (queryParameters = '') => apiRequest(`/history${queryParameters}`, { method: 'GET' }),
  getDashboardSummary: () => apiRequest('/history/summary/dashboard', { method: 'GET' })
};
