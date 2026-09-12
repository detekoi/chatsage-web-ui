import { showActionToast } from './ui.js';
import { t, getLanguage } from './i18n.js';

// app.wildcat.chat and api.wildcat.chat are two Hosting targets in front of the
// same webUi function, so this is a host change, not a backend change. Pointing
// at app keeps the whole OAuth round trip — start, callback, and landing — on
// one origin, which is what lets the host-only state cookie survive it.
export const API_BASE_URL = 'https://app.wildcat.chat';

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

export class AuthError extends Error {
    constructor(message) {
        super(message);
        this.name = 'AuthError';
    }
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
    
    if (!token) {
        showActionToast(t('toast.missingTokenLogin', {}, 'Authentication token missing. Please log in again.'), 'danger');
        throw new AuthError("No authentication token available");
    }

    const headers = {
        'Authorization': `Bearer ${token}`,
        // The server localizes the `message` it returns, which the dashboard renders straight into
        // a toast. Send the language actually on screen rather than letting the server guess from
        // Accept-Language, which reflects the browser rather than the user's choice here.
        'X-Locale': getLanguage()
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

/**
 * Reads an API response body as JSON, but survives a non-JSON body. A proxy
 * error page or a plain-text 408/429 would otherwise throw a SyntaxError and
 * hide the message the server sent.
 * @param {Response} res
 * @returns {Promise<object>} Parsed body, or `{ success: false, message }` built from the raw text.
 */
export async function readJson(res) {
    const text = await res.text();
    try {
        return JSON.parse(text);
    } catch {
        return { success: false, message: text.trim() || undefined };
    }
}
