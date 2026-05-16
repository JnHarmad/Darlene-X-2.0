/**
 * LLM Integration Module - Handles API calls to AI providers
 */
class LLMIntegration {
    constructor() {
        this.config = storage.getConfig();
    }

    /**
     * Update configuration
     */
    updateConfig(provider, apiKey) {
        this.config = { provider, apiKey };
        storage.saveConfig(provider, apiKey);
    }

    /**
     * Analyze APK using LLM
     */
    async analyzeWithLLM(analysisResults) {
        if (!this.config) {
            throw new Error('LLM configuration not set. Please provide API credentials.');
        }

        const prompt = this.buildAnalysisPrompt(analysisResults);

        try {
            let response;
            switch (this.config.provider) {
                case 'openai':
                    response = await this.callOpenAI(prompt);
                    break;
                case 'anthropic':
                    response = await this.callAnthropic(prompt);
                    break;
                case 'google':
                    response = await this.callGoogle(prompt);
                    break;
                default:
                    throw new Error('Unknown LLM provider');
            }

            return {
                provider: this.config.provider,
                analysis: response,
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            throw new Error(`LLM analysis failed: ${error.message}`);
        }
    }

    /**
     * Call OpenAI API
     */
    async callOpenAI(prompt) {
        const response = await fetch('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${this.config.apiKey}`
            },
            body: JSON.stringify({
                model: 'gpt-4',
                messages: [
                    {
                        role: 'system',
                        content: 'You are a security expert analyzing Android APK files for malware. Provide a detailed security assessment.'
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                temperature: 0.7,
                max_tokens: 1000
            })
        });

        if (!response.ok) {
            throw new Error(`OpenAI API error: ${response.status}`);
        }

        const data = await response.json();
        return data.choices[0].message.content;
    }

    /**
     * Call Anthropic API
     */
    async callAnthropic(prompt) {
        const response = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': this.config.apiKey,
                'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({
                model: 'claude-3-opus-20240229',
                max_tokens: 1000,
                system: 'You are a security expert analyzing Android APK files for malware. Provide a detailed security assessment.',
                messages: [
                    {
                        role: 'user',
                        content: prompt
                    }
                ]
            })
        });

        if (!response.ok) {
            throw new Error(`Anthropic API error: ${response.status}`);
        }

        const data = await response.json();
        return data.content[0].text;
    }

    /**
     * Call Google Gemini API
     */
    async callGoogle(prompt) {
        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${this.config.apiKey}`,
            {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    system_instruction: {
                        parts: {
                            text: 'You are a security expert analyzing Android APK files for malware. Provide a detailed security assessment.'
                        }
                    },
                    contents: {
                        parts: {
                            text: prompt
                        }
                    }
                })
            }
        );

        if (!response.ok) {
            throw new Error(`Google API error: ${response.status}`);
        }

        const data = await response.json();
        return data.candidates[0].content.parts[0].text;
    }

    /**
     * Build analysis prompt
     */
    buildAnalysisPrompt(results) {
        return `
Please analyze this Android APK security assessment and provide:
1. A risk classification (LOW, MEDIUM, HIGH, CRITICAL)
2. Key security concerns
3. Detected malware indicators
4. Recommendations for further investigation

Analysis Data:
${JSON.stringify(results, null, 2)}

Please provide a structured security assessment.
        `;
    }

    /**
     * Check if LLM is configured
     */
    isConfigured() {
        return !!this.config && !!this.config.apiKey;
    }

    /**
     * Get current provider
     */
    getProvider() {
        return this.config ? this.config.provider : null;
    }
}

const llmIntegration = new LLMIntegration();
