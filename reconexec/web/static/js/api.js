/**
 * API client for ReconHound EASM Dashboard
 */

class APIClient {
    constructor(baseURL = '/api/v1') {
        this.baseURL = baseURL;
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        
        try {
            console.log(`Making API request to: ${url}`);
            
            const response = await fetch(url, {
                headers: {
                    'Accept': 'application/json',
                    ...options.headers
                },
                ...options
            });

            console.log(`API response status: ${response.status}`);

            if (!response.ok) {
                if (response.status === 401) {
                    if (window.location.pathname !== '/login') {
                        window.location.href = '/login';
                    }
                    throw new Error("Session expired");
                }
                const errorText = await response.text();
                console.error(`API error response: ${errorText}`);
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();
            console.log(`API response data:`, data);
            return data;
        } catch (error) {
            console.error(`API request failed: ${endpoint}`, error);
            throw error;
        }
    }

    async getSummary() {
        return this.request('/summary');
    }

    async getGraphData() {
        return this.request('/graph');
    }

    // Removed getLeads() - Asset Selector is now 100% frontend-based using graph data

    async getAssets() {
        return this.request('/assets');
    }

    async getDatabases() {
        return this.request('/databases');
    }

    async selectDatabase(dbName) {
        return this.request('/databases/select', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name: dbName })
        });
    }

    async deleteDatabase(dbName) {
        return this.request('/databases/delete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name: dbName })
        });
    }

    getExportUrl(format = 'json') {
        return `${this.baseURL}/export?format=${format}`;
    }

    // Target Management & Active Scan APIs
    async getTargets() {
        return this.request('/targets');
    }

    async setTarget(target) {
        return this.request('/targets/set', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target, ip: target })
        });
    }

    async removeTarget(target) {
        return this.request('/targets/remove', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target, ip: target })
        });
    }

    async clearTargets() {
        return this.request('/targets/clear', {
            method: 'POST'
        });
    }

    async checkScanPermissions() {
        return this.request('/scan/check-permissions');
    }

    async startActiveScan(config = {}) {
        return this.request('/scan/active', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
    }

    async startNucleiScan(config = {}) {
        return this.request('/scan/nuclei', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
    }

    async cancelActiveScan(target = null, all = false, scanType = 'all') {
        return this.request('/scan/cancel', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target, all: all, scan_type: scanType })
        });
    }

    async unverifyServices(serviceIds = [], ipAddresses = []) {
        return this.request('/services/unverify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                service_ids: serviceIds,
                ip_addresses: ipAddresses
            })
        });
    }

    async getScanStatus() {
        return this.request('/scan/status');
    }

    async getScanLogs(limit = 100, target = null) {
        let endpoint = `/scan/logs?limit=${encodeURIComponent(limit)}`;
        if (target) {
            endpoint += `&target=${encodeURIComponent(target)}`;
        }
        return this.request(endpoint);
    }
}

// Global API client instance
window.api = new APIClient();



/**
 * Session Manager to auto-refresh JWT (Sliding Session)
 * Keeps the session alive as long as the user is actively using the dashboard.
 */
class SessionManager {
    constructor() {
        this.lastActiveTime = Date.now();
        this.refreshInterval = 10 * 60 * 1000; // Check every 10 minutes
        this.maxIdleTime = 15 * 60 * 1000; // If idle for > 15 mins, don't auto-refresh (let it expire naturally)
        
        // Track user activity
        const updateActivity = () => {
            this.lastActiveTime = Date.now();
        };
        
        window.addEventListener('mousemove', updateActivity, { passive: true });
        window.addEventListener('keydown', updateActivity, { passive: true });
        window.addEventListener('click', updateActivity, { passive: true });
        window.addEventListener('scroll', updateActivity, { passive: true });
        
        // Start background refresh loop
        setInterval(() => this.checkAndRefresh(), this.refreshInterval);
    }
    
    async checkAndRefresh() {
        const now = Date.now();
        const idleTime = now - this.lastActiveTime;
        
        if (idleTime < this.maxIdleTime) {
            try {
                const response = await fetch('/api/v1/auth/refresh', {
                    method: 'POST',
                    headers: { 'Accept': 'application/json' }
                });
                if (!response.ok) {
                    console.warn('[SessionManager] Silent JWT refresh failed', response.status);
                    if (response.status === 401) {
                        // The session actually expired server-side or cookie was cleared
                        if (typeof window.showToast === 'function') {
                            window.showToast('error', 'Session expired. Please login again.');
                        }
                        setTimeout(() => window.location.href = '/login', 2000);
                    }
                } else {
                    console.log('[SessionManager] JWT Session refreshed successfully (Sliding Session)');
                }
            } catch (err) {
                console.error('[SessionManager] Error refreshing session:', err);
            }
        }
    }
}

// Initialize session manager
if (window.location.pathname !== '/login') {
    window.sessionManager = new SessionManager();
}
