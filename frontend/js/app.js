/**
 * Main Application Logic - Orchestrates the entire analysis workflow
 */
class DarleneXApp {
    constructor() {
        this.currentFile = null;
        this.analysisResults = null;
        this.initializeEventListeners();
    }

    /**
     * Initialize all event listeners
     */
    initializeEventListeners() {
        // File upload
        const uploadArea = document.getElementById('uploadArea');
        const apkFile = document.getElementById('apkFile');

        uploadArea.addEventListener('click', () => apkFile.click());
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                this.handleFileUpload(e.dataTransfer.files[0]);
            }
        });

        apkFile.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                this.handleFileUpload(e.target.files[0]);
            }
        });

        // Configuration
        document.getElementById('saveConfig').addEventListener('click', () => {
            const provider = document.getElementById('apiProvider').value;
            const apiKey = document.getElementById('apiKey').value;
            if (apiKey.trim()) {
                llmIntegration.updateConfig(provider, apiKey);
                this.showNotification('Configuration saved', 'success');
            } else {
                this.showNotification('Please enter an API key', 'error');
            }
        });

        // Analysis buttons
        document.getElementById('btnManifest').addEventListener('click', () => this.analyzeManifest());
        document.getElementById('btnPermissions').addEventListener('click', () => this.analyzePermissions());
        document.getElementById('btnAPI').addEventListener('click', () => this.analyzeAPIs());
        document.getElementById('btnSignature').addEventListener('click', () => this.analyzeSignature());
        document.getElementById('btnEncryption').addEventListener('click', () => this.analyzeEncryption());
        document.getElementById('btnMalware').addEventListener('click', () => this.analyzeMalware());

        // Export
        document.getElementById('btnExportReport').addEventListener('click', () => this.exportReport());

        // Tab navigation
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
                document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
                e.target.classList.add('active');
                document.getElementById(e.target.dataset.tab).classList.add('active');
            });
        });

        // Error dismiss
        document.getElementById('btnCloseError').addEventListener('click', () => {
            document.getElementById('errorSection').style.display = 'none';
        });
    }

    /**
     * Handle file upload
     */
    async handleFileUpload(file) {
        if (!file.name.endsWith('.apk')) {
            this.showError('Please upload a valid APK file');
            return;
        }

        try {
            this.showProgress('Parsing APK file...', 10);
            this.currentFile = file;
            
            const fileInfo = await apkParser.loadAPK(file);
            this.showProgress('APK loaded successfully', 20);

            // Store app info
            this.analysisResults = {
                appInfo: apkParser.getAppInfo(),
                filename: file.name
            };

            // Enable analysis buttons
            document.querySelectorAll('.btn-analysis').forEach(btn => btn.disabled = false);
            
            this.showProgress('Ready for analysis', 100);
            setTimeout(() => document.getElementById('progressSection').style.display = 'none', 1000);
            
            this.showNotification('APK loaded successfully!', 'success');
        } catch (error) {
            this.showError(error.message);
        }
    }

    /**
     * Analyze manifest
     */
    async analyzeManifest() {
        if (!apkParser.files.manifest) {
            this.showError('Manifest data not found');
            return;
        }

        try {
            this.showProgress('Analyzing manifest...', 30);
            const manifestData = await manifestAnalyzer.analyze(apkParser.files.manifest);
            this.analysisResults.manifest = manifestData;
            this.showProgress('Manifest analysis complete', 100);

            // Display results
            this.displayManifestResults(manifestData);
            document.getElementById('resultsSection').style.display = 'block';
        } catch (error) {
            this.showError(error.message);
        }
    }

    /**
     * Analyze permissions
     */
    async analyzePermissions() {
        if (!this.analysisResults.manifest) {
            this.showError('Run manifest analysis first');
            return;
        }

        try {
            this.showProgress('Analyzing permissions...', 40);
            const permAnalysis = permissionAnalyzer.analyze(this.analysisResults.manifest);
            permAnalysis.maliciousCombinations = permissionAnalyzer.detectMaliciousCombinations(permAnalysis);
            this.analysisResults.permissions = permAnalysis;
            this.showProgress('Permission analysis complete', 100);

            this.displayPermissionsResults(permAnalysis);
            document.getElementById('resultsSection').style.display = 'block';
        } catch (error) {
            this.showError(error.message);
        }
    }

    /**
     * Analyze APIs
     */
    async analyzeAPIs() {
        if (!apkParser.files.dex || apkParser.files.dex.length === 0) {
            this.showError('No DEX files found');
            return;
        }

        try {
            this.showProgress('Analyzing APIs...', 50);
            const apiAnalysis = await apiAnalyzer.analyzeDexFiles(apkParser.files.dex);
            this.analysisResults.apis = apiAnalysis;
            this.showProgress('API analysis complete', 100);

            this.displayAPIResults(apiAnalysis);
            document.getElementById('resultsSection').style.display = 'block';
        } catch (error) {
            this.showError(error.message);
        }
    }

    /**
     * Analyze signature
     */
    async analyzeSignature() {
        try {
            this.showProgress('Analyzing signature...', 60);
            const certInfo = await apkParser.getCertificateInfo();
            const sigAnalysis = await signatureAnalyzer.analyzeSignature(certInfo);
            this.analysisResults.signature = sigAnalysis;
            this.showProgress('Signature analysis complete', 100);

            this.displaySignatureResults(sigAnalysis);
            document.getElementById('resultsSection').style.display = 'block';
        } catch (error) {
            this.showError(error.message);
        }
    }

    /**
     * Analyze encryption
     */
    async analyzeEncryption() {
        if (!apkParser.files.dex || apkParser.files.dex.length === 0) {
            this.showError('No DEX files found');
            return;
        }

        try {
            this.showProgress('Analyzing encryption...', 70);
            const encAnalysis = await encryptionDetector.analyzeForEncryption(apkParser.files.dex);
            this.analysisResults.encryption = encAnalysis;
            this.showProgress('Encryption analysis complete', 100);

            this.displayEncryptionResults(encAnalysis);
            document.getElementById('resultsSection').style.display = 'block';
        } catch (error) {
            this.showError(error.message);
        }
    }

    /**
     * Analyze with LLM (Malware detection)
     */
    async analyzeMalware() {
        if (!llmIntegration.isConfigured()) {
            this.showError('Please configure LLM API credentials first');
            return;
        }

        if (!this.analysisResults.manifest) {
            this.showError('Run manifest analysis first');
            return;
        }

        try {
            this.showProgress('Analyzing with AI...', 80);
            const llmAnalysis = await llmIntegration.analyzeWithLLM(this.analysisResults);
            this.analysisResults.llm = llmAnalysis;
            this.showProgress('Malware analysis complete', 100);

            this.displayMalwareResults(llmAnalysis);
            document.getElementById('resultsSection').style.display = 'block';
        } catch (error) {
            this.showError(error.message);
        }
    }

    /**
     * Display manifest results
     */
    displayManifestResults(data) {
        const manifestContent = document.getElementById('manifestContent');
        manifestContent.textContent = JSON.stringify(data, null, 2);
        document.querySelector('[data-tab="manifest"]').click();
    }

    /**
     * Display permissions results
     */
    displayPermissionsResults(data) {
        const permContent = document.getElementById('permissionsContent');
        let html = `<div class="item-list">`;
        html += `<h4>Dangerous Permissions (${data.dangerous.length})</h4>`;
        data.dangerous.forEach(p => {
            html += `<div class="list-item dangerous">
                <span class="list-item-name">${p.permission}</span>
                <span class="list-item-badge danger">DANGEROUS</span>
            </div>`;
        });

        html += `<h4 style="margin-top: 20px;">Suspicious Permissions (${data.suspicious.length})</h4>`;
        data.suspicious.forEach(p => {
            html += `<div class="list-item suspicious">
                <span class="list-item-name">${p.permission}</span>
                <span class="list-item-badge warning">SUSPICIOUS</span>
            </div>`;
        });
        html += `</div>`;

        permContent.innerHTML = html;
        document.querySelector('[data-tab="permissions"]').click();
    }

    /**
     * Display API results
     */
    displayAPIResults(data) {
        const apisContent = document.getElementById('apisContent');
        let html = `<div class="item-list">`;
        
        if (data.suspicious_apis.length === 0) {
            html += '<p>No suspicious APIs found</p>';
        } else {
            const grouped = apiAnalyzer.groupByCategory(data.suspicious_apis);
            for (const [category, apis] of Object.entries(grouped)) {
                html += `<h4>${category} (${apis.length})</h4>`;
                apis.forEach(api => {
                    const riskClass = api.risk === 'CRITICAL' ? 'dangerous' : api.risk === 'HIGH' ? 'suspicious' : '';
                    html += `<div class="list-item ${riskClass}">
                        <span class="list-item-name">${api.api}</span>
                        <span class="list-item-badge warning">${api.risk}</span>
                    </div>`;
                });
            }
        }

        html += `</div>`;
        apisContent.innerHTML = html;
        document.querySelector('[data-tab="apis"]').click();
    }

    /**
     * Display signature results
     */
    displaySignatureResults(data) {
        const sigContent = document.getElementById('risksContent');
        let html = `<div class="summary-card ${data.is_valid ? 'success' : 'danger'}">
            <h4>Signature Status</h4>
            <p>Signed: ${data.is_signed ? 'Yes' : 'No'}</p>
            <p>Valid: ${data.is_valid ? 'Yes' : 'No'}</p>
        </div>`;

        if (data.warnings.length > 0) {
            html += '<h4 style="margin-top: 20px;">Warnings</h4>';
            data.warnings.forEach(w => {
                html += `<div class="summary-card warning">
                    <p>${w.message}</p>
                </div>`;
            });
        }

        sigContent.innerHTML = html;
    }

    /**
     * Display encryption results
     */
    displayEncryptionResults(data) {
        const encContent = document.getElementById('risksContent');
        let html = `<div class="summary-card">
            <h4>Encryption & Obfuscation Detection</h4>
            <p>Risk Level: <strong>${data.risk_level}</strong></p>
            <p>Encryption Methods: ${data.encryption_found.length}</p>
            <p>Obfuscation Techniques: ${data.obfuscation_found.length}</p>
        </div>`;

        if (data.encryption_found.length > 0) {
            html += '<h4>Encryption Found</h4>';
            data.encryption_found.forEach(e => {
                html += `<div class="list-item"><span>${e.algorithm}</span></div>`;
            });
        }

        encContent.innerHTML = html;
    }

    /**
     * Display malware results
     */
    displayMalwareResults(data) {
        const malContent = document.getElementById('risksContent');
        malContent.innerHTML = `<div class="summary-card">
            <h4>AI-Powered Malware Analysis</h4>
            <p><strong>Provider:</strong> ${data.provider}</p>
            <pre>${data.analysis}</pre>
        </div>`;
    }

    /**
     * Export report
     */
    exportReport() {
        if (!this.analysisResults) {
            this.showError('No analysis results to export');
            return;
        }

        const report = reportGenerator.generateReport(
            this.currentFile.name,
            this.analysisResults,
            this.analysisResults.llm
        );

        reportGenerator.downloadReport(report, 'json');
        this.showNotification('Report exported as JSON', 'success');
    }

    /**
     * Show progress
     */
    showProgress(message, percentage) {
        const section = document.getElementById('progressSection');
        section.style.display = 'block';
        document.getElementById('progressText').textContent = message;
        document.getElementById('progressFill').style.width = percentage + '%';
    }

    /**
     * Show error
     */
    showError(message) {
        const errorSection = document.getElementById('errorSection');
        document.getElementById('errorMessage').textContent = message;
        errorSection.style.display = 'block';
        document.getElementById('progressSection').style.display = 'none';
    }

    /**
     * Show notification
     */
    showNotification(message, type = 'info') {
        console.log(`[${type.toUpperCase()}] ${message}`);
        // Could implement toast notifications here
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new DarleneXApp();
});
