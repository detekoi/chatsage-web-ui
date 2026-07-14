export const API_BASE_URL = 'https://api.wildcat.chat';

let appSessionToken = null;

export function getToken() {
    if (!appSessionToken) {
        appSessionToken = localStorage.getItem('app_session_token');
    }
    return appSessionToken;
}

export function setToken(token) {
    appSessionToken = token;
    if (token) {
        localStorage.setItem('app_session_token', token);
    } else {
        localStorage.removeItem('app_session_token');
    }
}

export function clearToken() {
    setToken(null);
}

/**
 * Helper to perform authenticated API calls
 * @param {string} method - HTTP method (GET, POST, PUT, DELETE)
 * @param {string} path - URL path (e.g., '/api/bot/status')
 * @param {object} [body] - Optional request body to send as JSON
 * @returns {Promise<Response>} Fetch Response object
 */
export async function apiFetch(method, path, body = null) {
    const token = getToken();
    const headers = {
        'Authorization': `Bearer ${token}`
    };

    const options = { method, headers };

    if (body) {
        headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }

    return fetch(`${API_BASE_URL}${path}`, options);
}

export async function apiGet(path) {
    return apiFetch('GET', path);
}

export async function apiPost(path, body) {
    return apiFetch('POST', path, body);
}

export async function apiPut(path, body) {
    return apiFetch('PUT', path, body);
}

export async function apiDelete(path) {
    return apiFetch('DELETE', path);
}
