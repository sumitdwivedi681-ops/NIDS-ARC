/**
 * NIDS ARC API Client
 * Handles all API communication with the backend.
 */
const API = {
    baseUrl: '/api/v1',
    token: null,

    async request(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = { 'Content-Type': 'application/json', ...options.headers };
        if (this.token) headers['Authorization'] = `Bearer ${this.token}`;

        try {
            const response = await fetch(url, { ...options, headers });
            if (response.status === 401) {
                this.token = null;
                localStorage.removeItem('nids_arc_token');
                return { error: { code: 'AUTHENTICATION_ERROR', message: 'Session expired' } };
            }
            const data = await response.json();
            if (!response.ok) return { error: data.error || { message: 'Request failed' } };
            return data;
        } catch (err) {
            console.error('API Error:', err);
            return { error: { code: 'NETWORK_ERROR', message: 'Network error — is the API running?' } };
        }
    },

    get(endpoint) { return this.request(endpoint); },

    post(endpoint, body) {
        return this.request(endpoint, { method: 'POST', body: JSON.stringify(body) });
    },

    put(endpoint, body) {
        return this.request(endpoint, { method: 'PUT', body: JSON.stringify(body) });
    },

    // --- Auth ---
    async login(username, password) {
        const res = await this.post('/auth/login', { username, password });
        if (res.access_token) {
            this.token = res.access_token;
            localStorage.setItem('nids_arc_token', res.access_token);
            localStorage.setItem('nids_arc_refresh', res.refresh_token);
        }
        return res;
    },

    logout() {
        this.token = null;
        localStorage.removeItem('nids_arc_token');
        localStorage.removeItem('nids_arc_refresh');
    },

    loadToken() {
        this.token = localStorage.getItem('nids_arc_token');
        return !!this.token;
    },

    // --- Dashboard ---
    getDashboardOverview() { return this.get('/dashboard/overview'); },

    // --- Events ---
    getEvents(params = {}) {
        const qs = new URLSearchParams(params).toString();
        return this.get(`/events${qs ? '?' + qs : ''}`);
    },

    getEventStats(hours = 24) { return this.get(`/events/stats?hours=${hours}`); },
    getEvent(id) { return this.get(`/events/${id}`); },

    // --- Alerts ---
    getAlerts(params = {}) {
        const qs = new URLSearchParams(params).toString();
        return this.get(`/alerts${qs ? '?' + qs : ''}`);
    },

    getAlertStats() { return this.get('/alerts/stats'); },
    getAlert(id) { return this.get(`/alerts/${id}`); },
    updateAlert(id, data) { return this.put(`/alerts/${id}`, data); },

    // --- Other ---
    getEngines() { return this.get('/detections/engines'); },
    getThreatIntel() { return this.get('/threat-intel/stats'); },
    getResponseActions() { return this.get('/response/actions'); },
    getIncidents() { return this.get('/incidents'); },

    // --- Health ---
    getHealth() { return this.request('/health', { headers: {} }); },
};
