/**
 * Report Generator - Generates analysis reports in various formats
 */
class ReportGenerator {
    /**
     * Generate comprehensive report
     */
    generateReport(filename, allAnalysis, llmAnalysis = null) {
        const report = {
            metadata: {
                filename,
                timestamp: new Date().toISOString(),
                analyzer_version: '1.0.0'
            },
            app_info: allAnalysis.appInfo,
            summary: this.generateSummary(allAnalysis),
            detailed_analysis: {
                manifest: allAnalysis.manifest,
                permissions: allAnalysis.permissions,
                apis: allAnalysis.apis,
                signature: allAnalysis.signature,
                encryption: allAnalysis.encryption
            },
            risk_assessment: this.generateRiskAssessment(allAnalysis),
            llm_analysis: llmAnalysis,
            recommendations: this.generateRecommendations(allAnalysis)
        };

        return report;
    }

    /**
     * Generate summary
     */
    generateSummary(analysis) {
        const manifest = analysis.manifest || {};
        return {
            package_name: manifest.metadata?.package,
            version_code: manifest.metadata?.versionCode,
            version_name: manifest.metadata?.versionName,
            min_sdk: manifest.metadata?.minSdkVersion,
            target_sdk: manifest.metadata?.targetSdkVersion,
            components: {
                activities: manifest.components?.activities?.length || 0,
                services: manifest.components?.services?.length || 0,
                receivers: manifest.components?.broadcastReceivers?.length || 0,
                providers: manifest.components?.contentProviders?.length || 0
            },
            total_permissions: analysis.permissions?.total || 0,
            dangerous_permissions: analysis.permissions?.dangerous?.length || 0,
            suspicious_permissions: analysis.permissions?.suspicious?.length || 0
        };
    }

    /**
     * Generate risk assessment
     */
    generateRiskAssessment(analysis) {
        const riskScores = {
            permissions: analysis.permissions?.riskScore || 0,
            api: analysis.apis?.suspicious_apis?.length || 0,
            encryption: analysis.encryption?.encryption_found?.length || 0,
            malicious_combos: analysis.permissions?.maliciousCombinations?.length || 0
        };

        const totalRisk = Object.values(riskScores).reduce((a, b) => a + b, 0);
        const overallRisk = this.calculateOverallRisk(totalRisk, analysis);

        return {
            overall_risk_level: overallRisk,
            risk_scores: riskScores,
            malicious_combinations: analysis.permissions?.maliciousCombinations || []
        };
    }

    /**
     * Calculate overall risk level
     */
    calculateOverallRisk(score, analysis) {
        if (analysis.apis?.risk_level === 'CRITICAL') return 'CRITICAL';
        if (score >= 50) return 'CRITICAL';
        if (score >= 30) return 'HIGH';
        if (score >= 15) return 'MEDIUM';
        return 'LOW';
    }

    /**
     * Generate recommendations
     */
    generateRecommendations(analysis) {
        const recommendations = [];

        // Permission-based recommendations
        if (analysis.permissions?.dangerous?.length > 5) {
            recommendations.push({
                priority: 'HIGH',
                category: 'Permissions',
                message: 'High number of dangerous permissions. Investigate before installation.'
            });
        }

        // API-based recommendations
        if (analysis.apis?.suspicious_apis?.length > 0) {
            recommendations.push({
                priority: 'HIGH',
                category: 'APIs',
                message: `${analysis.apis.suspicious_apis.length} suspicious APIs detected. Request source code review.`
            });
        }

        // Encryption recommendations
        if (analysis.encryption?.obfuscation_found?.length > 0) {
            recommendations.push({
                priority: 'MEDIUM',
                category: 'Obfuscation',
                message: 'Code obfuscation detected. May indicate malicious intent.'
            });
        }

        // Signature recommendations
        if (!analysis.signature?.is_signed) {
            recommendations.push({
                priority: 'MEDIUM',
                category: 'Signature',
                message: 'APK is not properly signed. Proceed with caution.'
            });
        }

        return recommendations;
    }

    /**
     * Export report as JSON
     */
    exportJSON(report) {
        return JSON.stringify(report, null, 2);
    }

    /**
     * Export report as HTML
     */
    exportHTML(report) {
        const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Darlene-X Report - ${report.metadata.filename}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1, h2 { color: #333; }
        .risk-level { font-weight: bold; padding: 10px; border-radius: 4px; }
        .risk-critical { background: #ffcccc; color: #cc0000; }
        .risk-high { background: #ffddcc; color: #ff6600; }
        .risk-medium { background: #ffffcc; color: #ffaa00; }
        .risk-low { background: #ccffcc; color: #00aa00; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f0f0f0; }
        .permission-list, .api-list { margin: 10px 0; }
        .permission-item, .api-item { padding: 8px; margin: 5px 0; background: #f9f9f9; border-left: 3px solid #ddd; }
        .dangerous { border-left-color: #ff0000; }
        .suspicious { border-left-color: #ff9900; }
        .recommendation { padding: 10px; margin: 10px 0; border-left: 4px solid #0066cc; background: #f0f8ff; }
        .footer { margin-top: 20px; padding-top: 10px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Darlene-X Security Analysis Report</h1>
        <p><strong>File:</strong> ${report.metadata.filename}</p>
        <p><strong>Analysis Date:</strong> ${report.metadata.timestamp}</p>

        <h2>Risk Assessment</h2>
        <div class="risk-level risk-${report.risk_assessment.overall_risk_level.toLowerCase()}">
            Overall Risk Level: ${report.risk_assessment.overall_risk_level}
        </div>

        <h2>Application Summary</h2>
        <table>
            <tr><td>Package Name</td><td>${report.summary.package_name || 'N/A'}</td></tr>
            <tr><td>Version</td><td>${report.summary.version_name || 'N/A'} (${report.summary.version_code || 'N/A'})</td></tr>
            <tr><td>Min SDK</td><td>${report.summary.min_sdk || 'N/A'}</td></tr>
            <tr><td>Target SDK</td><td>${report.summary.target_sdk || 'N/A'}</td></tr>
        </table>

        <h2>Permissions Analysis</h2>
        <p>Total Permissions: ${report.summary.total_permissions}</p>
        <p>Dangerous: ${report.summary.dangerous_permissions} | Suspicious: ${report.summary.suspicious_permissions}</p>

        <h2>Recommendations</h2>
        ${report.recommendations.map(rec => `
            <div class="recommendation">
                <strong>[${rec.priority}]</strong> ${rec.category}: ${rec.message}
            </div>
        `).join('')}

        <div class="footer">
            <p>Report generated by Darlene-X v1.0.0</p>
        </div>
    </div>
</body>
</html>
        `;
        return html;
    }

    /**
     * Export report as CSV
     */
    exportCSV(report) {
        let csv = 'Darlene-X Analysis Report\n\n';
        csv += `File,${report.metadata.filename}\n`;
        csv += `Date,${report.metadata.timestamp}\n`;
        csv += `Overall Risk,${report.risk_assessment.overall_risk_level}\n\n`;

        csv += 'Permissions Summary\n';
        csv += `Total,${report.summary.total_permissions}\n`;
        csv += `Dangerous,${report.summary.dangerous_permissions}\n`;
        csv += `Suspicious,${report.summary.suspicious_permissions}\n\n`;

        csv += 'Recommendations\n';
        report.recommendations.forEach(rec => {
            csv += `"${rec.priority}","${rec.category}","${rec.message}"\n`;
        });

        return csv;
    }

    /**
     * Download report
     */
    downloadReport(report, format = 'json') {
        let content, filename, mimeType;

        switch (format) {
            case 'html':
                content = this.exportHTML(report);
                filename = `report-${Date.now()}.html`;
                mimeType = 'text/html';
                break;
            case 'csv':
                content = this.exportCSV(report);
                filename = `report-${Date.now()}.csv`;
                mimeType = 'text/csv';
                break;
            case 'json':
            default:
                content = this.exportJSON(report);
                filename = `report-${Date.now()}.json`;
                mimeType = 'application/json';
        }

        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }
}

const reportGenerator = new ReportGenerator();
