# Darlene-X Frontend - Browser-Based APK Analysis

## Overview

Darlene-X is now a **frontend-only** APK security analysis framework that runs entirely in your browser. No server required! All processing happens locally on your machine, with only external API calls going to LLM providers (OpenAI, Anthropic, or Google Gemini).

## Architecture

```
frontend/
├── index.html                 # Main UI
├── css/
│   └── style.css             # Styling
└── js/
    ├── app.js                # Main orchestrator
    ├── modules/
    │   ├── storage.js        # Local storage management
    │   ├── apk-parser.js     # APK extraction (using JSZip)
    │   ├── manifest-analyzer.js      # AndroidManifest parsing
    │   ├── permission-analyzer.js    # Permission risk assessment
    │   ├── api-analyzer.js           # Suspicious API detection
    │   ├── signature-analyzer.js     # Certificate validation
    │   ├── encryption-detector.js    # Encryption/obfuscation detection
    │   ├── llm-integration.js        # LLM API integration
    │   └── report-generator.js       # Report generation
```

## Features

### 🎯 Local Analysis Modules

1. **Manifest Analysis**
   - Extracts AndroidManifest.xml
   - Parses components (activities, services, receivers, providers)
   - Identifies app metadata

2. **Permission Analysis**
   - Detects dangerous permissions (Android 6+)
   - Identifies suspicious permission combinations
   - Calculates permission-based risk score

3. **API Analysis**
   - Scans DEX files for suspicious API calls
   - Detects code execution, reflection, SMS manipulation, etc.
   - Categorizes by risk level (CRITICAL, HIGH, MEDIUM, LOW)

4. **Signature Analysis**
   - Validates APK signatures
   - Checks certificate validity
   - Detects signature spoofing attempts

5. **Encryption Detection**
   - Identifies encryption algorithms (AES, RSA, DES, SHA, HMAC)
   - Detects obfuscation techniques (ProGuard, reflection, native code)
   - Calculates obfuscation risk level

### 🤖 AI-Powered Analysis

- Integrates with OpenAI (GPT-4), Anthropic (Claude), or Google (Gemini)
- Uses local API keys stored in browser localStorage
- Provides expert-level malware assessment

### 📊 Report Generation

- Export analysis as JSON, HTML, or CSV
- Detailed risk assessment
- Actionable recommendations
- Timestamps and version tracking

## Getting Started

### 1. Open the Application

Simply open `index.html` in a modern web browser:

```bash
# Option A: Direct file open
open frontend/index.html

# Option B: Using Python's built-in server
cd frontend
python -m http.server 8000
# Then visit http://localhost:8000
```

### 2. Configure LLM Provider (Optional)

1. Go to **Configuration** section
2. Choose your AI provider:
   - **OpenAI**: Requires API key from https://platform.openai.com
   - **Anthropic**: Requires API key from https://console.anthropic.com
   - **Google**: Requires API key from https://makersuite.google.com
3. Paste your API key
4. Click "Save Configuration"

**Note**: API keys are stored in browser's localStorage only - they never leave your machine except for API calls.

### 3. Upload APK File

1. Click the upload area or drag-and-drop an APK file
2. The app will parse the APK (extracts manifest, DEX files, etc.)

### 4. Run Analysis Modules

Click any analysis button to run that module:

- 📋 **Manifest Analysis**: Parse app structure
- 🔐 **Permissions Check**: Evaluate permission risks
- 🔌 **Suspicious APIs**: Detect dangerous API calls
- 🔑 **Signature Analysis**: Validate APK signing
- 🔒 **Encryption Detection**: Find obfuscation
- ⚠️ **Malware Detection**: AI-powered analysis

### 5. Review Results

Results are displayed in tabs:
- **Summary**: Quick overview
- **Manifest**: App components
- **Permissions**: Permission breakdown
- **APIs**: Suspicious API calls
- **Risk Assessment**: Combined risk analysis
- **Raw Data**: Full JSON data

### 6. Export Report

Click **📥 Export Report** to download analysis as JSON, HTML, or CSV.

## Browser Requirements

- **Modern browser** with:
  - FileReader API
  - localStorage
  - Fetch API
  - JavaScript ES6+

**Tested on:**
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## How It Works

### APK Processing Flow

1. **Load APK**: JSZip library extracts ZIP contents (APK is a ZIP file)
2. **Parse Manifest**: Extract and analyze AndroidManifest.xml
3. **Scan DEX**: Extract strings from DEX files (Dalvik bytecode)
4. **Analyze Permissions**: Cross-reference with known dangerous permissions
5. **Detect APIs**: Pattern matching for suspicious API calls
6. **Check Signature**: Validate certificate chain
7. **AI Analysis**: Send structured data to LLM for expert assessment
8. **Generate Report**: Compile all findings into report

### Data Flow

```
APK File
    ↓
JSZip Parser (extract ZIP)
    ↓
Manifest → Parse XML components
    ↓ DEX → Extract strings
    ↓ Certs → Check signatures
    ↓
Local Analysis Modules
    ↓
LLM Integration (optional)
    ↓
Report Generator
    ↓
Export (JSON/HTML/CSV)
```

## API Integration Details

### OpenAI Integration

```javascript
// Uses GPT-4 for analysis
POST https://api.openai.com/v1/chat/completions
Authorization: Bearer YOUR_API_KEY
```

### Anthropic Integration

```javascript
// Uses Claude 3 for analysis
POST https://api.anthropic.com/v1/messages
x-api-key: YOUR_API_KEY
```

### Google Integration

```javascript
// Uses Gemini for analysis
POST https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=YOUR_API_KEY
```

## Configuration Persistence

All settings are stored locally in browser localStorage under `darlene_x_*` keys:

- `darlene_x_config`: API provider and key
- `darlene_x_results_*`: Analysis results per file

**Privacy**: Nothing is sent to our servers. Everything stays on your machine.

## Limitations & Future Improvements

### Current Limitations

- Basic manifest parsing (doesn't decode binary XML completely)
- DEX string extraction via pattern matching (not full decompilation)
- No signature verification (just presence check)
- Requires external LLM for intelligence analysis

### Future Enhancements

- [ ] Full binary XML decoding
- [ ] DEX decompilation integration
- [ ] YARA rule engine in browser
- [ ] Offline LLM models (via WebAssembly)
- [ ] Network traffic analysis
- [ ] Historical trend analysis
- [ ] Export to threat intelligence systems
- [ ] Multi-file batch analysis

## Development

### Adding New Analysis Modules

Create a new file in `js/modules/`:

```javascript
class MyAnalyzer {
    analyze(data) {
        // Your analysis logic
        return {
            findings: [],
            risk_level: 'MEDIUM'
        };
    }
}

const myAnalyzer = new MyAnalyzer();
```

Then add to `app.js`:

```javascript
async analyzeMyModule() {
    const result = await myAnalyzer.analyze(this.analysisResults);
    this.analysisResults.myModule = result;
    // Display results
}
```

### Modifying UI

Edit `index.html` for layout and `css/style.css` for styling.

## Troubleshooting

### APK Not Parsing

- Ensure file is a valid APK (actually a ZIP file)
- Check browser console for errors
- Try with a different APK

### API Key Not Working

- Verify API key is correct
- Check if API provider is active (not disabled)
- Ensure sufficient API credits
- Check browser console for actual error message

### Performance Issues

- Large DEX files may take time to parse
- Close other browser tabs
- Clear browser cache
- Try a different browser

## Security & Privacy

✅ **All Processing is Local**
- APK never leaves your machine
- Only API calls go to LLM providers
- API keys stored in browser localStorage only
- No telemetry or tracking

⚠️ **When Using LLM API**
- API provider sees the analysis data you send
- API keys are needed for authentication
- Follow provider's privacy policy

## License

Part of the Darlene-X framework for APK security analysis.

## Support

For issues or feature requests, check the main Darlene-X documentation.

---

**Version**: 1.0.0  
**Last Updated**: 2026-05-17
