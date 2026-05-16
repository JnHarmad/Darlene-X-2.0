# Darlene-X Framework Refactoring Analysis

## Executive Summary
Your framework needs consolidation before adding novel features. Current approach:
- **Problem**: Modules independently call `AnalyzeAPK()` → wasteful, redundant parsing
- **Problem**: No unified result format → report generation has fallback hacks
- **Problem**: No orchestrator → can't parallelize phases or handle partial failures
- **Problem**: Novel layer doesn't exist → can't do capability composition, LLM classification, trust graphs

**Goal**: Refactor to follow the 3-core-pattern architecture (BaseAnalyser, tool_runner, Orchestrator) so you can:
1. Run phases 1-6 in parallel
2. Feed all findings to novel layer (phase 7)
3. Gracefully degrade if tools missing
4. Add novel analyzers without touching core

---

## Current State Analysis

### Module-by-Module Redundancy Report

#### **apk_unpack_decompile.py** (Phase 1)
```
Status: 80 lines, partially complete
✓ Does: Unpacks APK, extracts metadata, counts classes/methods
✓ Uses: androguard.AnalyzeAPK (calls it once)
✗ Problem: Returns nested dict, not Finding objects
✗ Problem: Handles only APK unpacking, not verification/metadata
✗ Gap: No signature verification (v1/v2/v3/v4 check)
✗ Gap: No entropy scanning for packed payloads
✗ Gap: No detection of runtime DEX loading
```

#### **manifest_analysis.py** (Phase 2)
```
Status: 30 lines, incomplete
✓ Does: Extracts permissions, activities, receivers, providers, certs
✓ Uses: androguard.AnalyzeAPK (calls AGAIN — redundant!)
✗ Problem: Returns dict with inconsistent schema vs apk_unpack_decompile
✗ Problem: Only extracts, doesn't analyze for dangerous combinations
✗ Gap: No deep link / intent filter audit
✗ Gap: No exported component enumeration
✗ Gap: No certificate chain analysis
```

#### **suspicious_api_calls.py** (Phase 3 - Code Analysis)
```
Status: 40 lines, minimal
✓ Does: Detects API calls via hardcoded patterns
✓ Uses: androguard.AnalyzeAPK (calls AGAIN — triple redundancy!)
✗ Problem: Only grep-like pattern matching, no taint analysis
✗ Gap: No obfuscation detection (apkid)
✗ Gap: No semgrep integration
✗ Gap: No Mariana Trench taint flow
✗ Gap: No DexClassLoader / dynamic loading detection
```

#### **signature_analysis.py** (Phase 3 - YARA Rules)
```
Status: 50 lines, well-structured
✓ Does: Compiles YARA rules, extracts APK, runs rules
✓ Good: Separate from other modules, self-contained
✗ Problem: Returns nested dict (yara_results), not Finding objects
✗ Problem: Extracts APK AGAIN (4th time)
✗ Gap: Only runs YARA, doesn't correlate with other findings
```

#### **encryption_state_db.py** (Phase 4 - Secrets)
```
Status: 40 lines, focused
✓ Does: Detects encrypted SQLite databases
✗ Problem: Takes extracted_dir as param, expects prior unpacking
✗ Problem: No secret detection (passwords, API keys, hardcoded creds)
✗ Problem: Returns dict, not Finding objects
✗ Gap: No trufflehog / detect-secrets integration
✗ Gap: No IoC extraction (URLs, IPs, domains)
```

#### **usb_connection.py** (Out of scope)
```
Status: 50 lines
✗ PROBLEM: Completely unrelated to STATIC analysis
✗ PROBLEM: Only needed for dynamic testing, not relevant for malware detection APK ingestion
→ REMOVE or move to separate "dynamic" module tree
```

#### **banner_display.py** (Utility)
```
Status: 20 lines
✓ Works fine, keep for CLI output
```

#### **decide_malicious.py** (Phase 7 - Novel)
```
Status: 30 lines, incomplete
✓ Does: Orchestrates analysis modules
✗ MAJOR PROBLEM: Hardcoded module list, no abstraction
✗ MAJOR PROBLEM: Has fallback parsing logic (work-around for inconsistent schemas)
✗ MAJOR PROBLEM: Not true orchestrator pattern
→ REPLACE with core/orchestrator.py
```

#### **report_generator.py** (Output)
```
Status: 70 lines, has workarounds
✓ Does: Generates JSON/HTML/PDF reports
✗ MAJOR PROBLEM: Has fallback mechanisms to handle inconsistent input schema
✗ This is a SYMPTOM that modules don't have unified Finding format
✓ Will work after refactoring, no changes needed
```

---

## Redundancy Matrix

| Operation | Current Calls | Where | Redundancy |
|-----------|---------------|-------|-----------|
| **AnalyzeAPK(apk)** | 4x | apk_unpack, manifest, suspicious_api, signature | Parse once, reuse |
| **APK Extraction (unzip)** | 2x | signature_analysis, apk_unpack | Extract once, reuse |
| **String extraction** | 0x | Missing! | Need to add in Phase 4 |
| **Native .so analysis** | 0x | Missing! | Need to add in Phase 5 |
| **Network config audit** | 0x | Missing! | Need to add in Phase 6 |

**Cost of redundancy**: ~3-4 seconds per APK in redundant parsing alone

---

## Architecture Gap Analysis

### What's Missing: Core Infrastructure

#### **core/base.py** ✗ Missing
```python
@dataclass
class Finding:
    phase: str              # "unpack", "manifest", "code", etc.
    severity: str           # "critical", "high", "medium", "info"
    title: str              # e.g., "Signature v1 only"
    detail: str             # e.g., "APK uses only JAR signing, vulnerable to Janus"
    evidence: list[str]     # URLs/hashes/class names proving it
    tags: list[str]         # e.g., ["cve-2017-13156", "signing"]

class BaseAnalyser(ABC):
    def __init__(self, apk_path, work_dir): ...
    @abstractmethod
    def run(self) -> list[Finding]: ...
    def _finding(self, severity, title, detail, evidence, tags): ...
```

**Impact**: All current modules return inconsistent formats → report generation needs fallback parsing

#### **core/tool_runner.py** ✗ Missing
```python
def run(cmd, timeout=120, check=False) -> tuple[str, str, int]:
    # Checks if tool exists (apktool, jadx, semgrep, etc.)
    # Runs with timeout
    # Never raises on non-zero exit
    # Returns (stdout, stderr, returncode)
```

**Impact**: If jadx/apktool missing, current code crashes. Should gracefully skip.

#### **core/orchestrator.py** ✗ Missing
```python
class Orchestrator:
    def run_phases(self, analysers: list) -> list[Finding]:
        # Phases 1-6 run in ThreadPoolExecutor (I/O bound)
        # Phase 7 runs after, consuming all prior findings
        # Stores results in SQLite
```

**Impact**: Currently modules run sequentially via decide_malicious.py hardcoded list. No parallelization. No reuse of findings.

#### **core/result_store.py** ✗ Missing
```python
class ResultStore:
    def __init__(self, db_path): ...
    def save(self, findings: list[Finding]): ...
    def query(self, phase, severity, tags): ...
    def export_json(self): ...
```

**Impact**: Currently outputs flat JSON with report generation fallback parsing. Can't query across phases.

#### **cli.py** ✗ Missing
```python
@click.command()
@click.argument("apk")
@click.option("--out", default="./out")
@click.option("--no-llm", is_flag=True)
@click.option("--serial", is_flag=True, help="Debug: run sequentially")
def analyse(apk, out, no_llm, serial): ...
```

**Impact**: Current entry is darlene_x_cli.py, but it doesn't use Click, has no flags.

---

## Phase Completeness Matrix

| Phase | Status | Modules | Gaps |
|-------|--------|---------|------|
| 1. Unpack & Recon | 30% | apk_unpack_decompile | No sig verification, entropy, runtime DEX detection |
| 2. Manifest | 40% | manifest_analysis | No deep link audit, exported component enumeration |
| 3. Code Analysis | 20% | suspicious_api_calls, signature_analysis | No obfuscation detection, semgrep, taint analysis |
| 4. Strings & Secrets | 5% | encryption_state_db | Only SQLite, missing secret/IoC detection |
| 5. Native Libraries | 0% | MISSING | No .so analysis, no Ghidra/readelf |
| 6. Network Security | 0% | MISSING | No NSC audit, pinning analysis, endpoint inventory |
| 7. Novel Layer | 0% | MISSING | No capability composer, LLM, trust graphs, DGA detector |

---

## Recommended Refactoring Order

### Stage 1: Core Infrastructure (Days 1-2)
1. ✓ Create `core/base.py` with Finding + BaseAnalyser
2. ✓ Create `core/tool_runner.py` for subprocess management
3. ✓ Create `core/result_store.py` with SQLite schema
4. ✓ Create `core/orchestrator.py` with parallel execution

### Stage 2: Consolidate Existing (Days 2-3)
1. Consolidate AnalyzeAPK call → shared function in analysers/unpack.py
2. Rewrite analysers/unpack.py to return Finding objects
3. Rewrite analysers/manifest.py to return Finding objects
4. Rewrite analysers/code.py (merge suspicious_api + signature_analysis)
5. Rewrite analysers/secrets.py (consolidate encryption_state_db)
6. Delete decide_malicious.py (replaced by orchestrator)
7. Update cli.py to use orchestrator + Click

### Stage 3: Close Gaps (Days 3-4)
1. Add Phase 5: analysers/native.py (readelf, nm, Ghidra)
2. Add Phase 6: analysers/network.py (NSC, pinning, endpoints)
3. Integrate existing tools (YARA via tool_runner)
4. Integrate external tools (apktool, jadx, semgrep, trufflehog)

### Stage 4: Novel Layer (Days 5+)
1. analysers/novel/composer.py (capability fingerprinting)
2. analysers/novel/llm_classifier.py (Claude intent analysis)
3. analysers/novel/trust_graph.py (smali CFG + privilege escalation)
4. analysers/novel/dga_detect.py (C2 infrastructure)

---

## Data Flow After Refactoring

```
CLI (apk-analyst scan app.apk --out ./results)
  ↓
Orchestrator
  ├─ Thread 1: UnpackAnalyser → findings[1-5]
  ├─ Thread 2: ManifestAnalyser → findings[6-10]
  ├─ Thread 3: CodeAnalyser → findings[11-20]
  ├─ Thread 4: SecretsAnalyser → findings[21-25]
  ├─ (Serial): NativeAnalyser → findings[26-30]
  └─ (Serial): NetworkAnalyser → findings[31-35]
  
  All findings → ResultStore (SQLite)
  
  Serial: CapabilityComposer (reads all findings)
  Serial: LLMClassifier (reads all findings + code snippets)
  Serial: TrustGraph (reads manifest + smali)
  Serial: DGADetector (reads IoCs from findings)
  
  → Final report (HTML/JSON/PDF)
```

---

## Quick Win: What to Keep vs. Replace

### Keep As-Is
- `banner_display.py` — works fine
- `report_generator.py` — will work after schema unification
- YARA rules in scripts/yara_rules/ — good patterns

### Refactor (Rewrite with new pattern)
- `apk_unpack_decompile.py` → `analysers/unpack.py`
- `manifest_analysis.py` → `analysers/manifest.py`
- `suspicious_api_calls.py` + `signature_analysis.py` → `analysers/code.py`
- `encryption_state_db.py` → `analysers/secrets.py`

### Delete
- `decide_malicious.py` — replaced by orchestrator
- `usb_connection.py` — not for static analysis
- `darlene_x_cli.py` — replaced by Click CLI in root

### Create
- All of `core/` — infrastructure
- `analysers/native.py` — Phase 5
- `analysers/network.py` — Phase 6
- `analysers/novel/` — Phase 7
- Root `cli.py` — Click entry point

---

## Success Criteria

After refactoring, the framework should:

✓ **Parse APK once**: AnalyzeAPK called exactly 1 time per scan
✓ **Unified findings**: All modules return `list[Finding]` objects
✓ **Parallel execution**: Phases 1-6 run concurrently (4 workers)
✓ **Graceful degradation**: Missing tools don't crash, findings skip that phase
✓ **Queryable results**: SQLite allows "show all HIGH findings from manifest AND code"
✓ **Novel layer ready**: Phase 7 receives full context, can implement LLM/graphs
✓ **Easy to extend**: New analyzer = inherit BaseAnalyser, implement run(), done

---

## Next Steps

1. **Confirm**: Do you want to proceed with Stage 1 (core infrastructure)?
2. **Estimate**: With this architecture, all 7 phases can be ~50 lines each (vs current 200+ scattered)
3. **Timeline**: Stage 1+2 = foundation. Stage 3+4 = full novel features
