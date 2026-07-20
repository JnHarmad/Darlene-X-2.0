/**
 * Storage Module - Manages local storage for configuration and results
 */
class StorageManager {
    constructor() {
        this.prefix = 'darlene_x_2_';
    }

    /**
     * Save API configuration to localStorage
     */
    saveConfig(provider, apiKey) {
        const config = {
            provider,
            apiKey,
            timestamp: new Date().toISOString()
        };
        localStorage.setItem(this.prefix + 'config', JSON.stringify(config));
        return config;
    }

    /**
     * Get API configuration from localStorage
     */
    getConfig() {
        const config = localStorage.getItem(this.prefix + 'config');
        return config ? JSON.parse(config) : null;
    }

    /**
     * Clear configuration
     */
    clearConfig() {
        localStorage.removeItem(this.prefix + 'config');
    }

    /**
     * Save analysis results
     */
    saveResults(filename, results) {
        const key = this.prefix + 'results_' + filename;
        localStorage.setItem(key, JSON.stringify({
            filename,
            results,
            timestamp: new Date().toISOString()
        }));
    }

    /**
     * Get stored results
     */
    getResults(filename) {
        const key = this.prefix + 'results_' + filename;
        const data = localStorage.getItem(key);
        return data ? JSON.parse(data) : null;
    }

    /**
     * List all stored results
     */
    listResults() {
        const results = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith(this.prefix + 'results_')) {
                const data = JSON.parse(localStorage.getItem(key));
                results.push(data);
            }
        }
        return results;
    }

    /**
     * Clear all results
     */
    clearAllResults() {
        const keys = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith(this.prefix + 'results_')) {
                keys.push(key);
            }
        }
        keys.forEach(key => localStorage.removeItem(key));
    }
}

const storage = new StorageManager();
