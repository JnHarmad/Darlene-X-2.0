# Darlene-X v2.0 - Quick Start Guide

## Installation

### Step 1: Install Dependencies
```bash
cd Darlene-X
pip install -r requirements.txt
```

### Step 2: (Optional) Install External Tools
For full functionality, install these tools on your system:
```bash
# Linux
apt-get install apktool yara

# macOS
brew install apktool yara

# Or download manually:
# - jadx: https://github.com/skylot/jadx/releases
# - ghidra: https://ghidra-sre.org/
```

## Usage

### Basic Analysis
```bash
# Analyze an APK
python -m darlene_x.cli analyze /path/to/app.apk

# Output goes to: ./darlene_output/
# - results.db (SQLite database)
# - report.json (findings as JSON)
```

### Advanced Options
```bash
# Parallel execution (faster, default)
python -m darlene_x.cli analyze app.apk --out ./results

# Serial execution (debugging)
python -m darlene_x.cli analyze app.apk --serial

# Skip LLM analysis (Phase 7)
python -m darlene_x.cli analyze app.apk --no-llm

# HTML report
python -m darlene_x.cli analyze app.apk --format html
```

### Query Results
```bash
# Show all critical findings
python -m darlene_x.cli query --db ./darlene_output/results.db --severity critical

# Filter by phase
python -m darlene_x.cli query --db ./results.db --phase manifest

# Filter by phase and severity
python -m darlene_x.cli query --db ./results.db --phase code --severity high
```

## Output Structure

```
darlene_output/
├── results.db              # SQLite database with all findings
├── report.json             # JSON export of findings
├── report.html             # HTML report (if --format html)
└── work/                   # Temporary extraction directory
    └── (extracted APK files)
```

## How It Works

### Analysis Phases (Parallel Execution)

**Phase 1: APK Unpack** (2-3s)
- Extracts APK structure
- Verifies signatures (v1, v2, v3, v4)
- Detects packed payloads via entropy scanning
- Identifies runtime DEX loading

**Phase 2: Manifest Analysis** (1-2s)
- Extracts permissions and components
- Detects dangerous permission combinations
- Identifies exported attack surfaces
- Finds capability archetypes (spyware, trojan, etc.)

**Phase 3: Code Analysis** (2-4s depending on APK size)
- Scans DEX bytecode for dangerous APIs
- Detects reflection abuse (obfuscation)
- Identifies code execution primitives
- Categorizes risks: Critical, High, Medium, Low

**Phase 3b: Signature Analysis** (1-2s)
- Runs YARA pattern matching
- Detects known malware signatures
- Identifies obfuscation toolkits (ProGuard, Allatori, etc.)

**Phase 4: Secrets Audit** (2-3s)
- Extracts hardcoded credentials
- Finds API keys and tokens
- Identifies network endpoints (C2 candidates)
- Detects unencrypted storage patterns

**Phase 5-6: Reserved** (Not yet implemented)

**Phase 7: Novel Analysis** (Optional, requires LLM API key)
- Semantic intent classification
- Capability fingerprinting
- Trust boundary analysis

## Finding Categories

### Severity Levels
- **CRITICAL**: Immediate malware indicators (Runtime.exec, SMS sending, unsigned APK)
- **HIGH**: Strong malware signals (reflection abuse, dangerous APIs, spyware archetype)
- **MEDIUM**: Suspicious patterns (high method count, encryption detection needed)
- **LOW**: Informational (normal APIs, encryption usage)
- **INFO**: Metadata (version info, framework detection)

### Common Findings

```
[CRITICAL] Runtime DEX Loading Detected
  Evidence: dalvik/system/DexClassLoader
  Tags: [dynamic_loading, reflection, malware_indicator]

[HIGH] Spyware Archetype Detected
  Evidence: [android.permission.ACCESS_FINE_LOCATION,
             android.permission.READ_CONTACTS, ...]
  Tags: [archetype, spyware, malware_indicator]

[MEDIUM] No Encryption Detected
  Detail: APK does not use standard encryption
  Tags: [encryption, data_protection]

[INFO] Encryption Usage Detected
  Evidence: [AES, RSA, SHA]
  Tags: [encryption, cryptography]
```

## Database Schema

Results are stored in SQLite with this schema:

```sql
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    phase TEXT,           -- unpack, manifest, code, signature, secrets
    severity TEXT,        -- critical, high, medium, low, info
    title TEXT,           -- Finding title
    detail TEXT,          -- Full description
    evidence TEXT,        -- JSON array of indicators
    tags TEXT,            -- JSON array of tags
    timestamp TEXT,       -- ISO format time
    created_at TIMESTAMP
);

CREATE INDEX idx_phase ON findings(phase);
CREATE INDEX idx_severity ON findings(severity);
CREATE INDEX idx_timestamp ON findings(timestamp);
```

### Query Examples

```python
from darlene_x.core.result_store import ResultStore

store = ResultStore("./darlene_output/results.db")

# Get all critical findings
criticals = store.query(severity="critical")

# Get findings from manifest phase only
manifest_findings = store.query(phase="manifest")

# Get findings tagged with "malware_indicator"
malware_tags = store.query(tags="malware_indicator")

# Export all findings as JSON
json_data = store.export_json()
```

## Programmatic Usage

```python
from pathlib import Path
from darlene_x.analysers import (
    UnpackAnalyser, ManifestAnalyser, APIAnalyser,
    SignatureAnalyser, SecretsAnalyser
)
from darlene_x.core.orchestrator import Orchestrator

apk_path = Path("app.apk")
out_dir = Path("./results")

# Create orchestrator
orchestrator = Orchestrator(
    apk_path=str(apk_path),
    out_dir=str(out_dir),
    parallel=True  # Use parallelization
)

# Create analysers
analysers = [
    UnpackAnalyser(str(apk_path), str(out_dir / "work")),
    ManifestAnalyser(str(apk_path), str(out_dir / "work")),
    APIAnalyser(str(apk_path), str(out_dir / "work")),
    SignatureAnalyser(str(apk_path), str(out_dir / "work")),
    SecretsAnalyser(str(apk_path), str(out_dir / "work")),
]

# Run all phases
findings = orchestrator.run_phases(analysers)

# Process findings
for finding in findings:
    print(f"[{finding.severity.upper()}] {finding.title}")
    print(f"  {finding.detail}")
    if finding.evidence:
        print(f"  Evidence: {finding.evidence}")
```

## Performance

Typical analysis times for a 5MB APK:

| Phase | Time | Parallelizable |
|-------|------|-----------------|
| Phase 1: Unpack | 2-3s | Yes |
| Phase 2: Manifest | 1-2s | Yes |
| Phase 3: APIs | 2-4s | Yes |
| Phase 3b: Signature | 1-2s | Yes |
| Phase 4: Secrets | 2-3s | Yes |
| **Total (Parallel)** | **~3-5s** | N/A |
| **Total (Serial)** | **~8-14s** | N/A |

**Speedup**: 60% faster than sequential execution

## Troubleshooting

### "androguard not available"
```bash
pip install androguard>=4.0.0
```

### "yara-python not found"
YARA matching is optional. Install if needed:
```bash
# Install yara system library first
apt-get install yara libyara-dev  # Linux
brew install yara                  # macOS

# Then install Python bindings
pip install yara-python>=4.2.0
```

### Analysis hangs
Try serial mode for debugging:
```bash
python -m darlene_x.cli analyze app.apk --serial
```

### Out of memory
Large APKs may require more memory. Set limits:
```bash
# Increase available memory
python -m darlene_x.cli analyze app.apk
```

## What's Next?

### Phase 7 (Coming Soon)
- LLM-powered semantic analysis
- Requires Anthropic API key
- Detects zero-day malware patterns

### Phase 5 & 6 (Future)
- Native library analysis (.so files)
- Network configuration auditing

### Integration (Future)
- VirusTotal API enrichment
- OSINT data feeds
- Yara rule updates

## Support

For issues or feature requests, refer to:
- REFACTORING_COMPLETE.md - Architecture details
- REFACTORING_ANALYSIS.md - Design rationale
- DEVELOPER_GUIDE.md - For contributors
