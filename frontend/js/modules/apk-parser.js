/**
 * APK Parser Module - Extracts and parses APK file contents
 */
class APKParser {
    constructor() {
        this.zip = null;
        this.files = {};
    }

    /**
     * Load and parse APK file
     */
    async loadAPK(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onload = async (e) => {
                try {
                    this.zip = new JSZip();
                    await this.zip.loadAsync(e.target.result);
                    await this.extractFiles();
                    resolve({
                        filename: file.name,
                        size: file.size,
                        type: file.type,
                        lastModified: file.lastModified
                    });
                } catch (error) {
                    reject(new Error('Failed to parse APK: ' + error.message));
                }
            };

            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsArrayBuffer(file);
        });
    }

    /**
     * Extract key files from APK
     */
    async extractFiles() {
        this.files = {
            manifest: null,
            dex: [],
            resources: null,
            metaInf: {},
            libs: {},
            assets: {},
            other: {}
        };

        for (const [path, file] of Object.entries(this.zip.files)) {
            if (file.dir) continue;

            const data = await file.async('arraybuffer');

            if (path === 'AndroidManifest.xml') {
                this.files.manifest = data;
            } else if (path.startsWith('classes') && path.endsWith('.dex')) {
                this.files.dex.push({ path, data });
            } else if (path === 'resources.arsc') {
                this.files.resources = data;
            } else if (path.startsWith('META-INF/')) {
                this.files.metaInf[path] = data;
            } else if (path.startsWith('lib/')) {
                this.files.libs[path] = data;
            } else if (path.startsWith('assets/')) {
                this.files.assets[path] = data;
            } else {
                this.files.other[path] = data;
            }
        }

        return this.files;
    }

    /**
     * Get all file paths in APK
     */
    getFilePaths() {
        return Object.keys(this.zip.files).filter(f => !this.zip.files[f].dir);
    }

    /**
     * Get file content as text
     */
    async getFileAsText(path) {
        if (!this.zip.files[path]) return null;
        return await this.zip.files[path].async('text');
    }

    /**
     * Get file content as binary
     */
    async getFileAsBinary(path) {
        if (!this.zip.files[path]) return null;
        return await this.zip.files[path].async('arraybuffer');
    }

    /**
     * Get all file information
     */
    getFileInfo() {
        const info = {
            manifestPresent: !!this.files.manifest,
            dexFiles: this.files.dex.length,
            resourcesPresent: !!this.files.resources,
            metaInfFiles: Object.keys(this.files.metaInf).length,
            libraries: Object.keys(this.files.libs),
            assets: Object.keys(this.files.assets),
            totalFiles: this.getFilePaths().length
        };
        return info;
    }

    /**
     * Parse binary manifest XML (simplified)
     */
    parseManifestBinary(buffer) {
        // Convert binary manifest to readable format
        // This is a simplified parser - a full implementation would need
        // to understand Android's binary XML format
        const view = new Uint8Array(buffer);
        const text = String.fromCharCode(...view);
        return text;
    }

    /**
     * Decompress strings from DEX file (basic extraction)
     */
    async extractStringsFromDex(dexBuffer) {
        const strings = [];
        const view = new Uint8Array(dexBuffer);
        
        // Look for common string patterns
        let currentString = '';
        for (let i = 0; i < view.length; i++) {
            const byte = view[i];
            // ASCII printable characters
            if (byte >= 32 && byte <= 126) {
                currentString += String.fromCharCode(byte);
            } else {
                if (currentString.length > 3) {
                    strings.push(currentString);
                }
                currentString = '';
            }
        }
        
        return strings;
    }

    /**
     * Get certificate information from META-INF
     */
    async getCertificateInfo() {
        const certFiles = Object.keys(this.files.metaInf)
            .filter(f => f.endsWith('.RSA') || f.endsWith('.DSA'));
        
        return {
            certificates: certFiles,
            count: certFiles.length
        };
    }

    /**
     * Get app info from manifest
     */
    getAppInfo() {
        return {
            dexCount: this.files.dex.length,
            hasResources: !!this.files.resources,
            hasLibraries: Object.keys(this.files.libs).length > 0,
            certificateCount: Object.keys(this.files.metaInf).filter(
                f => f.endsWith('.RSA') || f.endsWith('.DSA')
            ).length
        };
    }
}

const apkParser = new APKParser();
