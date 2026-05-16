/**
 * API Analyzer - Detects suspicious API calls in DEX files
 */
class APIAnalyzer {
    constructor() {
        this.suspiciousAPIs = {
            'java/lang/Runtime': {
                category: 'Code Execution',
                methods: ['exec'],
                risk: 'CRITICAL'
            },
            'java/lang/reflect/Method': {
                category: 'Reflection',
                methods: ['invoke'],
                risk: 'HIGH'
            },
            'android/telephony/SmsManager': {
                category: 'SMS',
                methods: ['sendTextMessage', 'sendMultipartTextMessage'],
                risk: 'CRITICAL'
            },
            'android/net/Uri': {
                category: 'Data Access',
                methods: ['parse', 'fromFile'],
                risk: 'MEDIUM'
            },
            'java/net/URLConnection': {
                category: 'Network',
                methods: ['openConnection'],
                risk: 'MEDIUM'
            },
            'android/content/SharedPreferences': {
                category: 'Storage',
                methods: ['edit', 'getSharedPreferences'],
                risk: 'LOW'
            },
            'android/os/Debug': {
                category: 'Debugging',
                methods: ['isDebuggerConnected', 'waitForDebugger'],
                risk: 'MEDIUM'
            },
            'android/app/ActivityManager': {
                category: 'Task Management',
                methods: ['getRunningAppProcesses', 'killBackgroundProcesses'],
                risk: 'HIGH'
            },
            'android/location/LocationManager': {
                category: 'Location',
                methods: ['requestLocationUpdates'],
                risk: 'HIGH'
            },
            'android/telephony/TelephonyManager': {
                category: 'Device Info',
                methods: ['getDeviceId', 'getSubscriberId', 'getLine1Number'],
                risk: 'HIGH'
            }
        };
    }

    /**
     * Analyze DEX files for suspicious API calls
     */
    async analyzeDexFiles(dexBuffers) {
        const analysis = {
            suspicious_apis: [],
            api_calls: {},
            risk_level: 'LOW',
            timestamp: new Date().toISOString()
        };

        for (const { path, data } of dexBuffers) {
            const strings = await this.extractStringsFromDex(data);
            const foundAPIs = this.detectSuspiciousAPIs(strings);
            
            analysis.api_calls[path] = {
                total_strings: strings.length,
                suspicious_apis: foundAPIs
            };

            analysis.suspicious_apis.push(...foundAPIs);
        }

        // Calculate risk level
        analysis.risk_level = this.calculateRiskLevel(analysis.suspicious_apis);

        return analysis;
    }

    /**
     * Extract strings from DEX binary
     */
    async extractStringsFromDex(buffer) {
        const strings = [];
        const view = new Uint8Array(buffer);

        // DEX header is 0x70 bytes
        // String IDs start after header
        let currentString = '';
        let inString = false;

        for (let i = 0; i < view.length; i++) {
            const byte = view[i];

            if (byte >= 32 && byte <= 126) {
                currentString += String.fromCharCode(byte);
                inString = true;
            } else {
                if (inString && currentString.length > 2) {
                    strings.push(currentString);
                }
                currentString = '';
                inString = false;
            }
        }

        return strings;
    }

    /**
     * Detect suspicious API patterns
     */
    detectSuspiciousAPIs(strings) {
        const found = [];
        const seen = new Set();

        for (const str of strings) {
            for (const [className, apiInfo] of Object.entries(this.suspiciousAPIs)) {
                if (str.includes(className)) {
                    for (const method of apiInfo.methods) {
                        if (str.includes(method)) {
                            const key = `${className}.${method}`;
                            if (!seen.has(key)) {
                                found.push({
                                    api: key,
                                    category: apiInfo.category,
                                    risk: apiInfo.risk,
                                    string: str
                                });
                                seen.add(key);
                            }
                        }
                    }
                }
            }
        }

        return found;
    }

    /**
     * Calculate overall risk level
     */
    calculateRiskLevel(suspiciousAPIs) {
        if (suspiciousAPIs.length === 0) return 'LOW';

        const criticalCount = suspiciousAPIs.filter(a => a.risk === 'CRITICAL').length;
        const highCount = suspiciousAPIs.filter(a => a.risk === 'HIGH').length;

        if (criticalCount > 0) return 'CRITICAL';
        if (highCount >= 3) return 'HIGH';
        if (highCount > 0) return 'MEDIUM';

        return 'LOW';
    }

    /**
     * Group APIs by category
     */
    groupByCategory(suspiciousAPIs) {
        const grouped = {};
        for (const api of suspiciousAPIs) {
            if (!grouped[api.category]) {
                grouped[api.category] = [];
            }
            grouped[api.category].push(api);
        }
        return grouped;
    }

    /**
     * Get severity summary
     */
    getSeveritySummary(suspiciousAPIs) {
        return {
            critical: suspiciousAPIs.filter(a => a.risk === 'CRITICAL').length,
            high: suspiciousAPIs.filter(a => a.risk === 'HIGH').length,
            medium: suspiciousAPIs.filter(a => a.risk === 'MEDIUM').length,
            low: suspiciousAPIs.filter(a => a.risk === 'LOW').length
        };
    }
}

const apiAnalyzer = new APIAnalyzer();
