/**
 * Encryption Detector - Detects encryption and obfuscation techniques
 */
class EncryptionDetector {
    constructor() {
        this.encryptionPatterns = {
            'AES': /AES|javax\.crypto\.Cipher/,
            'DES': /DES|TripleDES/,
            'RSA': /RSA|java\.security\.KeyFactory/,
            'MD5': /MD5|MessageDigest\.getInstance\("MD5"\)/,
            'SHA': /SHA|MessageDigest\.getInstance\("SHA/,
            'HMAC': /HmacSHA|HmacMD5/
        };

        this.obfuscationPatterns = {
            'ProGuard': /R\.java|\.a\(|\.b\(|\.c\(/,
            'Reflection': /java\.lang\.reflect|forName|getMethod|invoke/,
            'StringObfuscation': /getBytes|concat|replace|substring/,
            'NativeCode': /\.so|LoadLibrary|System\.load/,
            'Base64Encoding': /android\.util\.Base64|Base64\.encode|Base64\.decode/
        };
    }

    /**
     * Analyze DEX files for encryption and obfuscation
     */
    async analyzeForEncryption(dexBuffers) {
        const analysis = {
            encryption_found: [],
            obfuscation_found: [],
            native_code: false,
            risk_level: 'LOW',
            timestamp: new Date().toISOString()
        };

        for (const { path, data } of dexBuffers) {
            const strings = await this.extractStrings(data);
            
            // Check for encryption
            for (const [algo, pattern] of Object.entries(this.encryptionPatterns)) {
                const matches = strings.filter(s => pattern.test(s));
                if (matches.length > 0) {
                    analysis.encryption_found.push({
                        algorithm: algo,
                        occurrences: matches.length,
                        dex_file: path
                    });
                }
            }

            // Check for obfuscation
            for (const [technique, pattern] of Object.entries(this.obfuscationPatterns)) {
                const matches = strings.filter(s => pattern.test(s));
                if (matches.length > 0) {
                    analysis.obfuscation_found.push({
                        technique,
                        occurrences: matches.length,
                        dex_file: path
                    });
                }
            }
        }

        // Calculate risk level
        analysis.risk_level = this.calculateRiskLevel(analysis);

        return analysis;
    }

    /**
     * Extract strings from DEX
     */
    async extractStrings(buffer) {
        const strings = [];
        const view = new Uint8Array(buffer);
        let current = '';

        for (let i = 0; i < view.length; i++) {
            const byte = view[i];
            if ((byte >= 32 && byte <= 126) || byte === 10) {
                current += String.fromCharCode(byte);
            } else {
                if (current.length > 3) {
                    strings.push(current);
                }
                current = '';
            }
        }

        return strings;
    }

    /**
     * Calculate risk level
     */
    calculateRiskLevel(analysis) {
        if (analysis.native_code && analysis.encryption_found.length > 0) {
            return 'CRITICAL';
        }
        if (analysis.obfuscation_found.length > 2) {
            return 'HIGH';
        }
        if (analysis.encryption_found.length > 0) {
            return 'MEDIUM';
        }
        return 'LOW';
    }

    /**
     * Get encryption methods used
     */
    getEncryptionMethods(analysis) {
        return analysis.encryption_found.map(e => e.algorithm);
    }

    /**
     * Get obfuscation techniques used
     */
    getObfuscationTechniques(analysis) {
        return analysis.obfuscation_found.map(o => o.technique);
    }

    /**
     * Get detailed report
     */
    getDetailedReport(analysis) {
        return {
            encryption: {
                found: analysis.encryption_found.length > 0,
                methods: this.getEncryptionMethods(analysis),
                details: analysis.encryption_found
            },
            obfuscation: {
                found: analysis.obfuscation_found.length > 0,
                techniques: this.getObfuscationTechniques(analysis),
                details: analysis.obfuscation_found
            },
            risk_level: analysis.risk_level
        };
    }
}

const encryptionDetector = new EncryptionDetector();
