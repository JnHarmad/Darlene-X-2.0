/**
 * LLM integration removed for privacy.
 * Use ../web/ (serverless, local-only Darlene-X_2.0) instead.
 */
class LLMIntegration {
    constructor() {
        this.config = null;
    }
    updateConfig() {
        throw new Error('Cloud LLM analysis is disabled. Use web/ for fully offline analysis.');
    }
    isConfigured() {
        return false;
    }
    async analyzeWithLLM() {
        throw new Error('Cloud LLM analysis is disabled. Open web/index.html via a local HTTP server.');
    }
}
const llmIntegration = new LLMIntegration();
