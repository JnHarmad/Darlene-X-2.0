# Developer Quick Reference - New Architecture

## 🏗️ How to Add a New Analyser

Every analyser follows the same pattern. Example: Creating Phase 5 (Native Library Analysis)

### Step 1: Create the File
Create `darlene_x/analysers/native.py`:

```python
from darlene_x.core import BaseAnalyser, Finding

class NativeAnalyser(BaseAnalyser):
    """Analyze native .so files for security issues."""
    
    name = "native"  # Must be unique
    
    def run(self) -> list[Finding]:
        """Execute analysis phase."""
        findings = []
        
        # Your analysis logic here
        # ...
        
        # Create findings
        self._finding(
            severity="high",
            title="Suspicious JNI export",
            detail="Native library exports DexClassLoader",
            evidence=["lib/libnative.so", "Java_com_example_Loader"],
            tags=["jni", "dynamic_loading"]
        )
        
        return self.findings  # BaseAnalyser accumulates these
```

### Step 2: Register in CLI
Edit `darlene_x/cli.py`:

```python
from darlene_x.analysers.native import NativeAnalyser

@cli.command()
def analyze(apk: str, out: str, no_llm: bool, serial: bool):
    # ... existing code ...
    
    analysers = [
        UnpackAnalyser(str(apk_path), str(out_dir)),
        ManifestAnalyser(str(apk_path), str(out_dir)),
        CodeAnalyser(str(apk_path), str(out_dir)),
        SecretsAnalyser(str(apk_path), str(out_dir)),
        NativeAnalyser(str(apk_path), str(out_dir)),  # NEW
    ]
```

### Step 3: Done!
The orchestrator automatically:
- ✓ Runs in parallel with other phases
- ✓ Saves findings to SQLite
- ✓ Handles exceptions gracefully
- ✓ Passes findings to novel layer

---

## 🔧 How to Use tool_runner

When executing external tools (apktool, jadx, semgrep, etc.):

```python
from darlene_x.core import tool_runner

# Run apktool
stdout, stderr, code = tool_runner.run(
    ["apktool", "d", self.apk_path, "-o", "output"],
    timeout=60
)

if code == 0:
    # Success
    print(stdout)
elif code == -1 and "not installed" in stderr:
    # Tool missing - log and continue
    self._finding("info", "Tool skipped", f"apktool not installed")
else:
    # Other error
    self._finding("info", "Decompilation failed", stderr)

# Check tool availability
if not tool_runner.exists("jadx"):
    self._finding("info", "JADX not available", "...")
```

**Benefits:**
- No try/except needed
- Tool missing → graceful skip, not crash
- Timeout handled automatically
- Consistent return format

---

## 📊 How to Create Findings

All findings follow the same structure:

```python
# Simple finding
self._finding(
    severity="high",
    title="Action title",
    detail="Full description with implications"
)

# Detailed finding with evidence
self._finding(
    severity="critical",
    title="Privilege escalation chain detected",
    detail="Exported component FileProvider flows to Runtime.exec via Intent",
    evidence=[
        "com.example.FileProvider",
        "com.example.SuspiciousActivity",
        "Runtime.exec"
    ],
    tags=["privilege_escalation", "cwe-200", "data_exposure"]
)
```

**Severity Levels:**
- `critical` - Immediate exploitation risk
- `high` - Serious security issue
- `medium` - Potential vulnerability
- `info` - Informational finding, no direct risk

**Standard Tags:**
- **CVE/CWE**: `cve-2017-13156`, `cwe-200`
- **Category**: `permission_abuse`, `data_exposure`, `privilege_escalation`
- **Attack Type**: `dropper`, `spyware`, `banking_trojan`, `ransomware`
- **Technique**: `dynamic_loading`, `reflection_abuse`, `obfuscation`

---

## 💾 How to Query Results

After analysis completes, findings are in SQLite:

```python
from darlene_x.core import ResultStore

store = ResultStore("./results/results.db")

# Get all HIGH findings
findings = store.query(severity="high")

# Get findings from specific phase
findings = store.query(phase="manifest", limit=50)

# Filter by tags
findings = store.query(tags=["cve-2017-13156"], limit=20)

# Get summary
summary = store.get_summary()
print(f"Total: {summary['total_findings']}")
print(f"By severity: {summary['by_severity']}")
print(f"By phase: {summary['by_phase']}")

# Export to JSON
results = store.export_json()
```

---

## 🚀 How Orchestrator Runs Everything

```python
from darlene_x.core import Orchestrator

orch = Orchestrator(
    apk_path="app.apk",
    out_dir="./results",
    parallel=True  # False for debugging
)

analysers = [
    UnpackAnalyser(...),
    ManifestAnalyser(...),
    CodeAnalyser(...),
    # ... more analysers ...
]

# This does the heavy lifting:
findings = orch.run_phases(analysers)
```

**What happens internally:**
1. Groups analysers by `depends_on_all` flag
2. Launches standard phases in ThreadPoolExecutor (4 workers)
3. Waits for all to complete
4. Saves findings to SQLite
5. Runs novel phases sequentially (they get `prior_findings`)
6. Returns all findings

**Error Handling:**
- One failed phase doesn't crash others
- Failed phase returns empty `[]`
- Errors logged but orchestration continues
- Graceful degradation throughout

---

## 🎯 Execution Modes

### Normal (Default)
```bash
darlene-x analyze app.apk --out ./results
```
- Phases 1-6 run in parallel
- Phase 7 (novel) runs after
- LLM classification included (costs $)
- Results in SQLite + HTML/JSON

### Fast Mode (Skip LLM)
```bash
darlene-x analyze app.apk --out ./results --no-llm
```
- Same as normal but skips LLM phase
- 50% faster
- No API costs
- All other phases complete

### Debug Mode (Serial Execution)
```bash
darlene-x analyze app.apk --out ./results --serial
```
- All phases run one-by-one
- Easier to debug individual phases
- Logging more detailed
- Slower, but cleaner output

---

## 🗂️ File Structure After Complete Build

```
darlene_x/
├── core/
│   ├── __init__.py         # Exports: Finding, BaseAnalyser, Orchestrator, etc.
│   ├── base.py             # Finding dataclass, BaseAnalyser ABC
│   ├── tool_runner.py      # Subprocess wrapper
│   ├── orchestrator.py     # Parallel execution engine
│   └── result_store.py     # SQLite storage + query
│
├── analysers/
│   ├── __init__.py
│   ├── unpack.py           # Phase 1 (unpacking, sig verification)
│   ├── manifest.py         # Phase 2 (manifest audit)
│   ├── code.py             # Phase 3 (code analysis)
│   ├── secrets.py          # Phase 4 (strings, secrets, IoCs)
│   ├── native.py           # Phase 5 (native libs)
│   ├── network.py          # Phase 6 (network config)
│   └── novel/
│       ├── __init__.py
│       ├── composer.py     # Capability fingerprinting
│       ├── llm_classifier.py  # LLM intent classification
│       ├── trust_graph.py  # Trust boundary graphs
│       └── dga_detect.py   # C2 detection
│
├── modules/                # Legacy code (being phased out) (DELETED)
├── cli.py                  # Click CLI entry point (DELETED)
└── __init__.py
```

---

## ✅ Checklist for New Analyzer

- [ ] Inherits from `BaseAnalyser`
- [ ] Sets `name` class variable
- [ ] Implements `run()` → returns `list[Finding]`
- [ ] Uses `self._finding()` to accumulate findings
- [ ] Uses `tool_runner.run()` for subprocesses
- [ ] Handles exceptions gracefully
- [ ] Registered in `cli.py`
- [ ] Tested with sample APK

---

## 🐛 Common Issues & Fixes

### Issue: "Tool not installed"
**Cause**: External tool (apktool, jadx, etc.) not in PATH

**Fix**: 
```bash
# Check which tools available
darlene-x status  # (if you implement this command)

# Install missing tool
# Windows: choco install apktool
# Linux: apt-get install apktool
# macOS: brew install apktool
```

### Issue: "Phase timed out"
**Cause**: Analysis took longer than 120s (default timeout)

**Fix**:
- Increase timeout in tool_runner.run() call
- Or use --serial mode to debug which phase is slow

### Issue: "Analyser crash stops pipeline"
**Cause**: Unhandled exception in run()

**Fix**:
- Add try/except in run() method
- Log error with self._finding()
- Return self.findings (may be empty)

---

## 📚 References

- [Finding Data Structure](darlene_x/core/base.py) - Full schema
- [BaseAnalyser ABC](darlene_x/core/base.py) - Parent class reference
- [ResultStore API](darlene_x/core/result_store.py) - Query methods
- [Orchestrator](darlene_x/core/orchestrator.py) - Execution engine


NEW ADDITION:
FOLLOW THE android_apk_static_analysis_playbook.html for the actual plan follow up
other than that author has decided to make this framework to be deployed on browser without any server dependency
also an explainable ai system will be implemented too
our MAIN FOCUS is to develop a framework to investigate on andorid apk
and declare the degree of maliciousness

THE DETECTION LOGIC MUST INCLUDE:
UNPACK DECOMPILATION OF APK
SIGNATURE BASED ANALYSIS (YARA POWERED)
SUSPICIOUS API CALLS
ENCRYPTION STATE OF DB FOUND IN APK (CLIENT DETAILS ARE SOMETIMES EXPOSED HERE)
C2 SERVER DETAILS IF FOUND
MANIFEST ANALYSIS (PERMISSION, CERTIFICATES,CONTENT PROVIDER, BROAD CAST RECEIVER, MINIMUM SDK, TARGET SDK, ACTIVITIES)

THE REPORT MUST BE CONSOLODATED WITH FILE DETAILS, ANALYSIS RESULTS OF EVERY MODULE, ALONG WITH A SAFENESS GRADE FROM OUR FRAMEWORK (RISKOMETER KINDA) ALONG WITH HASH