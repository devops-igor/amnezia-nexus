/**
 * Amnezia Nexus — Universal API Client
 * Vanilla JS fetch wrapper with CSRF handling, session expiry management, and unified error handling.
 */
(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.API = factory();
        // Backward compatibility
        root.apiCall = function (url, method, body, options) {
            return root.API.request(url, Object.assign({}, options, { method: method || 'GET', body: body !== undefined ? body : null }));
        };
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    /**
     * Retrieve CSRF token from helper, meta tag, or cookie
     * @returns {string}
     */
    function getCsrfToken() {
        if (typeof window !== 'undefined' && typeof window.getCsrfToken === 'function') {
            const token = window.getCsrfToken();
            if (token) return token;
        }
        if (typeof document !== 'undefined') {
            const meta = document.querySelector('meta[name="csrf-token"]');
            if (meta && meta.getAttribute('content')) {
                return meta.getAttribute('content');
            }
            const match = document.cookie.match(/csrftoken=([^;]+)/);
            if (match && match[1]) {
                return match[1];
            }
        }
        return '';
    }

    // Ensure window.getCsrfToken is defined globally
    if (typeof window !== 'undefined' && !window.getCsrfToken) {
        window.getCsrfToken = getCsrfToken;
    }

    /**
     * Show error toast notification if UI or legacy showToast is available
     * @param {string} message
     */
    function notifyError(message) {
        if (typeof window === 'undefined') return;
        if (window.UI && typeof window.UI.toast === 'function') {
            window.UI.toast(message, 'error');
        } else if (typeof window.showToast === 'function') {
            window.showToast(message, 'error');
        }
    }

    /**
     * Core universal request handler
     * @param {string} url
     * @param {Object} [options={}]
     * @returns {Promise<any>}
     */
    async function request(url, options = {}) {
        const method = (options.method || 'GET').toUpperCase();
        const headers = Object.assign({}, options.headers || {});
        let body = options.body;

        // Auto-attach CSRF token if not provided
        if (!headers['X-CSRF-Token'] && !headers['x-csrf-token']) {
            const token = getCsrfToken();
            if (token) {
                headers['X-CSRF-Token'] = token;
            }
        }

        // Auto-detect JSON body
        const isFormData = typeof FormData !== 'undefined' && body instanceof FormData;
        const isBlob = typeof Blob !== 'undefined' && body instanceof Blob;
        const isArrayBuffer = typeof ArrayBuffer !== 'undefined' && body instanceof ArrayBuffer;
        const isUrlSearchParams = typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams;

        if (body !== null && body !== undefined && !isFormData && !isBlob && !isArrayBuffer && !isUrlSearchParams) {
            if (typeof body === 'object') {
                body = JSON.stringify(body);
            }
            if (!headers['Content-Type'] && !headers['content-type']) {
                headers['Content-Type'] = 'application/json';
            }
        }

        const fetchOptions = {
            method: method,
            headers: headers,
        };

        if (body !== null && body !== undefined && method !== 'GET' && method !== 'HEAD') {
            fetchOptions.body = body;
        }

        // Pass through credentials, signal, cache if provided
        if (options.credentials) fetchOptions.credentials = options.credentials;
        if (options.signal) fetchOptions.signal = options.signal;
        if (options.cache) fetchOptions.cache = options.cache;

        const res = await fetch(url, fetchOptions);

        // 401/403 Authentication & Session Expiry Handling
        if (res.status === 401 || res.status === 403) {
            try {
                const clone = res.clone();
                const jsonBody = await clone.json();
                if (jsonBody && jsonBody.password_change_required) {
                    if (typeof window !== 'undefined') {
                        window.location.href = '/change-password?forced=1';
                    }
                    const err = new Error('Password change required');
                    err.status = res.status;
                    err.data = jsonBody;
                    throw err;
                }
            } catch (parseErr) {
                if (parseErr && parseErr.message === 'Password change required') {
                    throw parseErr;
                }
            }

            if (typeof window !== 'undefined') {
                window.location.href = '/login';
            }
            const err = new Error('Session expired');
            err.status = res.status;
            throw err;
        }

        let data;
        const contentType = res.headers.get('content-type') || '';

        if (res.status === 204) {
            data = {};
        } else {
            try {
                if (contentType.includes('application/json')) {
                    data = await res.json();
                } else {
                    const text = await res.text();
                    try {
                        data = JSON.parse(text);
                    } catch (_) {
                        const match = text.match(/<title>([^<]+)<\/title>/i);
                        const errorMsg = match ? match[1].trim() : text.substring(0, 200).trim();
                        data = { error: errorMsg || `HTTP ${res.status}: ${res.statusText}` };
                    }
                }
            } catch (e) {
                data = { error: 'Failed to parse server response' };
            }
        }

        if (!res.ok) {
            const errorMsg = (data && (data.error || data.message)) || `HTTP ${res.status}: ${res.statusText}`;
            if (!options.silent) {
                notifyError(errorMsg);
            }
            const err = new Error(errorMsg);
            err.status = res.status;
            err.data = data;
            throw err;
        }

        return data;
    }

    /**
     * Convenience HTTP GET
     */
    function get(url, options = {}) {
        return request(url, Object.assign({}, options, { method: 'GET' }));
    }

    /**
     * Convenience HTTP POST
     */
    function post(url, body = null, options = {}) {
        return request(url, Object.assign({}, options, { method: 'POST', body: body }));
    }

    /**
     * Convenience HTTP PATCH
     */
    function patch(url, body = null, options = {}) {
        return request(url, Object.assign({}, options, { method: 'PATCH', body: body }));
    }

    /**
     * Convenience HTTP DELETE
     */
    function del(url, body = null, options = {}) {
        return request(url, Object.assign({}, options, { method: 'DELETE', body: body }));
    }

    return {
        request: request,
        get: get,
        post: post,
        patch: patch,
        delete: del,
        getCsrfToken: getCsrfToken,
    };
}));
