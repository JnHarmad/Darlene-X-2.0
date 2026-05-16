/**
 * Manifest Analyzer - Extracts and analyzes AndroidManifest.xml
 */
class ManifestAnalyzer {
    constructor() {
        this.manifestData = null;
    }

    /**
     * Parse manifest from binary data
     */
    async analyze(manifestBuffer) {
        try {
            // Basic parsing - convert to string for initial analysis
            const manifestStr = this.bufferToString(manifestBuffer);
            
            this.manifestData = {
                raw: manifestStr,
                components: this.extractComponents(manifestStr),
                metadata: this.extractMetadata(manifestStr),
                timestamp: new Date().toISOString()
            };

            return this.manifestData;
        } catch (error) {
            throw new Error('Manifest analysis failed: ' + error.message);
        }
    }

    /**
     * Extract Android components (activities, services, receivers, providers)
     */
    extractComponents(manifestStr) {
        const components = {
            activities: [],
            services: [],
            broadcastReceivers: [],
            contentProviders: [],
            permissions: [],
            usesPermissions: []
        };

        // Simple pattern matching (in real scenario, use proper XML parsing)
        const patterns = {
            activities: /<activity[^>]*android:name="([^"]+)"/g,
            services: /<service[^>]*android:name="([^"]+)"/g,
            broadcastReceivers: /<receiver[^>]*android:name="([^"]+)"/g,
            contentProviders: /<provider[^>]*android:name="([^"]+)"/g,
            permissions: /<permission[^>]*android:name="([^"]+)"/g,
            usesPermissions: /<uses-permission[^>]*android:name="([^"]+)"/g
        };

        for (const [key, pattern] of Object.entries(patterns)) {
            let match;
            while ((match = pattern.exec(manifestStr)) !== null) {
                components[key].push(match[1]);
            }
        }

        return components;
    }

    /**
     * Extract metadata from manifest
     */
    extractMetadata(manifestStr) {
        const metadata = {
            package: this.extractAttribute(manifestStr, 'package'),
            versionCode: this.extractAttribute(manifestStr, 'android:versionCode'),
            versionName: this.extractAttribute(manifestStr, 'android:versionName'),
            minSdkVersion: this.extractAttribute(manifestStr, 'android:minSdkVersion'),
            targetSdkVersion: this.extractAttribute(manifestStr, 'android:targetSdkVersion'),
            maxSdkVersion: this.extractAttribute(manifestStr, 'android:maxSdkVersion')
        };

        return metadata;
    }

    /**
     * Extract specific attribute
     */
    extractAttribute(text, attribute) {
        const regex = new RegExp(`${attribute}="([^"]+)"`);
        const match = text.match(regex);
        return match ? match[1] : null;
    }

    /**
     * Convert buffer to string
     */
    bufferToString(buffer) {
        const view = new Uint8Array(buffer);
        let str = '';
        for (let i = 0; i < view.length; i++) {
            const byte = view[i];
            if (byte === 0) break;
            if (byte >= 32 && byte <= 126) {
                str += String.fromCharCode(byte);
            } else if (byte === 10 || byte === 13) {
                str += '\n';
            }
        }
        return str;
    }

    /**
     * Get analysis results
     */
    getResults() {
        return this.manifestData;
    }

    /**
     * Export manifest as JSON
     */
    exportAsJSON() {
        return JSON.stringify(this.manifestData, null, 2);
    }
}

const manifestAnalyzer = new ManifestAnalyzer();
