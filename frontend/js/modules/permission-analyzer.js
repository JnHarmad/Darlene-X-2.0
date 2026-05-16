/**
 * Permission Analyzer - Analyzes requested permissions for security risks
 */
class PermissionAnalyzer {
    constructor() {
        // Dangerous permissions that require user approval on Android 6+
        this.dangerousPermissions = [
            'android.permission.CAMERA',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
            'android.permission.READ_CALENDAR',
            'android.permission.WRITE_CALENDAR',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.RECORD_AUDIO',
            'android.permission.READ_CALL_LOG',
            'android.permission.WRITE_CALL_LOG',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_PHONE_NUMBERS',
            'android.permission.CALL_PHONE',
            'android.permission.ANSWER_PHONE_CALLS',
            'android.permission.READ_SMS',
            'android.permission.RECEIVE_SMS',
            'android.permission.SEND_SMS',
            'android.permission.RECEIVE_WAP_PUSH',
            'android.permission.RECEIVE_MMS',
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.ACCESS_MEDIA_LOCATION'
        ];

        // Suspicious permissions commonly used in malware
        this.suspiciousPermissions = [
            'android.permission.DISABLE_KEYGUARD',
            'android.permission.CHANGE_WIFI_STATE',
            'android.permission.ACCESS_WIFI_STATE',
            'android.permission.CHANGE_NETWORK_STATE',
            'android.permission.ACCESS_NETWORK_STATE',
            'android.permission.INTERNET',
            'android.permission.WRITE_APN_SETTINGS',
            'android.permission.MODIFY_PHONE_STATE',
            'android.permission.SYSTEM_ALERT_WINDOW',
            'android.permission.GET_ACCOUNTS',
            'android.permission.READ_LOGS',
            'android.permission.RESTART_PACKAGES',
            'android.permission.KILL_BACKGROUND_PROCESSES',
            'android.permission.VIBRATE',
            'android.permission.SEND_RESPOND_VIA_MESSAGE',
            'android.permission.USE_SIP'
        ];
    }

    /**
     * Analyze permissions from manifest data
     */
    analyze(manifestData) {
        const permissions = manifestData.components.usesPermissions || [];

        const analysis = {
            total: permissions.length,
            dangerous: [],
            suspicious: [],
            normal: [],
            riskScore: 0,
            timestamp: new Date().toISOString()
        };

        for (const permission of permissions) {
            if (this.dangerousPermissions.includes(permission)) {
                analysis.dangerous.push({
                    permission,
                    category: 'DANGEROUS',
                    description: this.getPermissionDescription(permission)
                });
            } else if (this.suspiciousPermissions.includes(permission)) {
                analysis.suspicious.push({
                    permission,
                    category: 'SUSPICIOUS',
                    description: this.getPermissionDescription(permission)
                });
            } else {
                analysis.normal.push({
                    permission,
                    category: 'NORMAL',
                    description: this.getPermissionDescription(permission)
                });
            }
        }

        // Calculate risk score
        analysis.riskScore = (analysis.dangerous.length * 10) + (analysis.suspicious.length * 3);

        return analysis;
    }

    /**
     * Get human-readable description for permission
     */
    getPermissionDescription(permission) {
        const descriptions = {
            'android.permission.CAMERA': 'Access device camera',
            'android.permission.READ_CONTACTS': 'Read contact list',
            'android.permission.READ_CALL_LOG': 'Read call history',
            'android.permission.READ_SMS': 'Read SMS messages',
            'android.permission.ACCESS_FINE_LOCATION': 'Get precise GPS location',
            'android.permission.INTERNET': 'Allow internet connection',
            'android.permission.SYSTEM_ALERT_WINDOW': 'Display over other apps',
            'android.permission.INSTALL_PACKAGES': 'Install unknown packages'
        };

        return descriptions[permission] || permission;
    }

    /**
     * Get permission groups
     */
    getGroupedPermissions(analysisResult) {
        return {
            dangerous: analysisResult.dangerous,
            suspicious: analysisResult.suspicious,
            normal: analysisResult.normal
        };
    }

    /**
     * Check for permission combinations that indicate malware
     */
    detectMaliciousCombinations(analysisResult) {
        const combinations = [];
        const permissions = analysisResult.dangerous.map(p => p.permission)
            .concat(analysisResult.suspicious.map(p => p.permission));

        // Suspicious combinations
        const suspiciousCombos = [
            {
                permissions: ['android.permission.SEND_SMS', 'android.permission.READ_SMS'],
                risk: 'HIGH',
                description: 'SMS manipulation capability'
            },
            {
                permissions: ['android.permission.READ_CONTACTS', 'android.permission.INTERNET'],
                risk: 'MEDIUM',
                description: 'Contacts exfiltration potential'
            },
            {
                permissions: ['android.permission.RECORD_AUDIO', 'android.permission.INTERNET'],
                risk: 'HIGH',
                description: 'Audio recording and transmission'
            },
            {
                permissions: ['android.permission.ACCESS_FINE_LOCATION', 'android.permission.INTERNET'],
                risk: 'HIGH',
                description: 'Location tracking potential'
            }
        ];

        for (const combo of suspiciousCombos) {
            if (combo.permissions.every(p => permissions.includes(p))) {
                combinations.push(combo);
            }
        }

        return combinations;
    }
}

const permissionAnalyzer = new PermissionAnalyzer();
