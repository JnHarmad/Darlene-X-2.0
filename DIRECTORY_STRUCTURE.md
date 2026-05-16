# 📁 Complete Directory Structure - Stage 1 Complete

## Workspace Layout

```
Darlene-X/                                    (Project Root)
├── pyproject.toml                           ✓ NEW - Package config
├── STAGE1_COMPLETE.md                       ✓ NEW - Implementation details
├── STAGE1_SUMMARY.md                        ✓ NEW - This stage summary
├── DEVELOPER_GUIDE.md                       ✓ NEW - How to add analysers
├── ARCHITECTURE_COMPARISON.md               ✓ Before/after structure
├── REFACTORING_ANALYSIS.md                  ✓ Gap analysis (reference)
│
├── darlene_x/                               (Main Package)
│   ├── __init__.py                          (Package marker)
│   ├── cli.py                               ✓ NEW - Click CLI (160 lines)
│   │
│   ├── core/                                ✓ NEW - Core Infrastructure
│   │   ├── __init__.py                      ✓ Exports all
│   │   ├── base.py                          ✓ Finding + BaseAnalyser (95 lines)
│   │   ├── tool_runner.py                   ✓ Subprocess wrapper (70 lines)
│   │   ├── orchestrator.py                  ✓ Parallel execution (160 lines)
│   │   └── result_store.py                  ✓ SQLite storage (180 lines)
│   │
│   ├── analysers/                           ✓ NEW - Analysis Phases
│   │   ├── __init__.py                      ✓ Package marker
│   │   ├── unpack.py                        ⏳ TBD (Stage 2)
│   │   ├── manifest.py                      ⏳ TBD (Stage 2)
│   │   ├── code.py                          ⏳ TBD (Stage 2)
│   │   ├── secrets.py                       ⏳ TBD (Stage 2)
│   │   ├── native.py                        ⏳ TBD (Stage 3)
│   │   ├── network.py                       ⏳ TBD (Stage 3)
│   │   │
│   │   └── novel/                           ✓ NEW - Novel Layer
│   │       ├── __init__.py                  ✓ Package marker
│   │       ├── composer.py                  ⏳ TBD (Stage 4)
│   │       ├── llm_classifier.py            ⏳ TBD (Stage 4)
│   │       ├── trust_graph.py               ⏳ TBD (Stage 4)
│   │       └── dga_detect.py                ⏳ TBD (Stage 4)
│   │
│   ├── modules/                             (Legacy Code - Being Migrated)
│   │   ├── __init__.py
│   │   ├── apk_unpack_decompile.py          → Will migrate to analysers/unpack.py
│   │   ├── manifest_analysis.py             → Will migrate to analysers/manifest.py
│   │   ├── suspicious_api_calls.py          → Will merge into analysers/code.py
│   │   ├── signature_analysis.py            → Will merge into analysers/code.py
│   │   ├── encryption_state_db.py           → Will migrate to analysers/secrets.py
│   │   ├── banner_display.py                → Keep (UI utility)
│   │   ├── report_generator.py              → Keep (now works with unified format)
│   │   ├── decide_malicious.py              → DELETE (replaced by orchestrator)
│   │   ├── usb_connection.py                → DELETE (not for static analysis)
│   │   ├── darlene_x_cli.py                 → DELETE (replaced by cli.py)
│   │   └── templates/
│   │       └── report_template.html
│   │
│   ├── scripts/                             (Utility Scripts)
│   │   └── yara_rules/
│   │       ├── boot_persistency.yar
│   │       ├── hidden_payloads.yar
│   │       └── obfuscation.yar
│   │
│   ├── test/                                (Existing Tests - To Update)
│   │   ├── test_banner_display.py
│   │   ├── test_db_encryption.py
│   │   ├── test_device_detex.py
│   │   ├── test_fishy_api.py
│   │   ├── test_manifest_analysis.py
│   │   ├── test_report_generator.py
│   │   ├── test_signature.py
│   │   └── test_unpack.py
│   │
│   ├── output/                              (Results from Previous Runs)
│   │   └── (sample APK analysis results)
│   │
│   └── reports/                             (Generated Reports)
│       ├── report.html
│       └── report.json
│
├── requirements.txt                         (Legacy - Use pyproject.toml)
├── README.md
└── ...other files

```

---

## 📊 File Count & Status

### Stage 1: Core Infrastructure ✓ COMPLETE
| Component | Files | Lines | Status |
|-----------|-------|-------|--------|
| Core | 5 | 595 | ✓ Complete |
| CLI | 2 | 240 | ✓ Complete |
| **Total** | **7** | **835** | **✓ Complete** |

### Stage 2: Analyser Integration ⏳ NEXT
| Component | Files | Lines | Status |
|-----------|-------|-------|--------|
| analysers/unpack.py | 1 | ~60 | ⏳ Pending |
| analysers/manifest.py | 1 | ~60 | ⏳ Pending |
| analysers/code.py | 1 | ~100 | ⏳ Pending |
| analysers/secrets.py | 1 | ~80 | ⏳ Pending |
| Integration | - | ~30 | ⏳ Pending |
| **Total** | **5** | **~330** | **⏳ Estimated** |

### Stage 3: Fill Gaps ⏳ FUTURE
| Component | Files | Lines | Status |
|-----------|-------|-------|--------|
| analysers/native.py | 1 | ~100 | ⏳ Pending |
| analysers/network.py | 1 | ~100 | ⏳ Pending |
| **Total** | **2** | **~200** | **⏳ Estimated** |

### Stage 4: Novel Layer ⏳ FUTURE
| Component | Files | Lines | Status |
|-----------|-------|-------|--------|
| novel/composer.py | 1 | ~80 | ⏳ Pending |
| novel/llm_classifier.py | 1 | ~100 | ⏳ Pending |
| novel/trust_graph.py | 1 | ~150 | ⏳ Pending |
| novel/dga_detect.py | 1 | ~80 | ⏳ Pending |
| **Total** | **4** | **~410** | **⏳ Estimated** |

---

## 🔄 Data Flow Visualization

```
User Command
    │
    └─→ darlene_x analyze app.apk --out ./results
           │
           └─→ cli.py: analyze()
                  │
                  ├─ Create Orchestrator
                  ├─ Create Analysers
                  │   ├─ UnpackAnalyser (extends BaseAnalyser)
                  │   ├─ ManifestAnalyser (extends BaseAnalyser)
                  │   └─ ... more analysers
                  │
                  └─→ orchestrator.run_phases(analysers)
                         │
                         ├─ Partition analysers (standard vs novel)
                         │
                         ├─ ThreadPoolExecutor (4 workers)
                         │   ├─ Thread 1: UnpackAnalyser.run()
                         │   ├─ Thread 2: ManifestAnalyser.run()
                         │   ├─ Thread 3: CodeAnalyser.run()
                         │   └─ Thread 4: SecretsAnalyser.run()
                         │
                         ├─ Collect findings from all threads
                         │
                         ├─ ResultStore.save(findings)
                         │   └─ SQLite: INSERT into results.db
                         │
                         ├─ Run novel phases serially
                         │   ├─ CapabilityComposer.run(prior_findings)
                         │   ├─ LLMClassifier.run(prior_findings)
                         │   └─ ... more novel phases
                         │
                         └─ Return all findings

Results
    │
    ├─→ ./results/results.db (SQLite)
    ├─→ ./results/report.html
    ├─→ ./results/report.json
    └─→ CLI output (Rich terminal formatting)
```

---

## 🎯 Key Dependencies

### Core (Always Needed)
```toml
click>=8.1           # CLI framework
rich>=13.0          # Terminal output
androguard>=3.4     # APK parsing
networkx>=3.2       # Graph analysis
loguru>=0.7         # Logging
```

### Optional (For Extended Features)
```toml
anthropic>=0.25     # LLM API (Phase 7 only)
semgrep>=1.60       # Code pattern matching
reportlab>=4.0      # PDF generation
jinja2>=3.1         # HTML templating
```

### External Tools (Not Bundled)
These must be installed separately via system package manager:
- `apktool` — APK unpacking
- `jadx` — Java source reconstruction
- `yara` — Pattern matching
- `semgrep` — Code analysis
- `trufflehog` — Secret scanning
- `ghidra` — Reverse engineering (optional)

---

## ✅ Verification Checklist

Run these to verify Stage 1 is working:

### 1. Check File Structure
```bash
ls -la darlene_x/core/
# Should show: base.py, tool_runner.py, orchestrator.py, result_store.py, __init__.py

ls -la darlene_x/analysers/
# Should show: __init__.py, novel/

ls -la darlene_x/analysers/novel/
# Should show: __init__.py
```

### 2. Check Imports
```bash
cd c:\Users\03ata\Darlene_X\Darlene-X
python3 -c "from darlene_x.core import Finding, BaseAnalyser, Orchestrator, ResultStore; print('✓ All imports OK')"
```

### 3. Check CLI
```bash
python3 darlene_x/cli.py --help
# Should show: analyze command, query command, options
```

### 4. Create Test Finding
```bash
python3 << 'EOF'
from darlene_x.core import Finding, ResultStore
f = Finding('test_phase', 'high', 'Test Title', 'Test Detail', ['evidence1'], ['tag1'])
print(f'✓ Finding: {f}')
store = ResultStore('./test.db')
store.save([f])
results = store.query(severity='high')
print(f'✓ Stored and queried: {len(results)} findings')
EOF
```

---

## 📝 Notes

### Why This Structure?

1. **core/** — Reusable infrastructure, no analysis logic
2. **analysers/** — All analysis phases, consistent interface
3. **novel/** — Semantic layer (depends on other phases)
4. **modules/** — Legacy code (gradually migrating)
5. **cli.py** — Single entry point

### Naming Conventions

- **Analyser classes**: `<Phase>Analyser` (e.g., `UnpackAnalyser`)
- **Finding tags**: lowercase, hyphen-separated (e.g., `cve-2017-13156`)
- **Severity**: lowercase enum (critical, high, medium, info)
- **Methods**: snake_case, underscored private methods

### Python Version

- **Minimum**: Python 3.10
- **Recommended**: Python 3.11+
- **Type hints**: Used throughout (PEP 484)

---

## 🚀 Quick Start

### Install (Development Mode)
```bash
cd c:\Users\03ata\Darlene_X\Darlene-X
pip install -e .
```

### Run CLI
```bash
darlene-x analyze sample.apk --out ./results
```

### Query Results
```bash
darlene-x query ./results/results.db --severity high
```

### Manual Test
```python
from darlene_x.core import Finding, ResultStore

f1 = Finding('manifest', 'high', 'Dangerous perm', 'Has RECORD_AUDIO')
f2 = Finding('code', 'critical', 'Hardcoded credentials', 'Found AWS key')

store = ResultStore('./test.db')
store.save([f1, f2])

# Query
findings = store.query(severity='critical')
summary = store.get_summary()
print(summary)
```

---

## 📞 Questions?

Refer to:
- **DEVELOPER_GUIDE.md** — How to add new analysers
- **STAGE1_COMPLETE.md** — What each file does
- **Docstrings** in code files — Detailed usage

---

**Status**: ✅ Stage 1 Complete | 🟡 Ready for Stage 2 | 📅 2025-05-16
