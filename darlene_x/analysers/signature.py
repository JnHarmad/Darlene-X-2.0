"""
Phase 3b: Signature Analysis - YARA Pattern Matching

Responsibilities:
- Compile and run YARA rules against extracted APK contents
- Detect known malware patterns
- Identify obfuscation techniques via patterns
- Detect packing and unpacking stubs
- Match against threat intelligence

Returns Finding objects for:
- Matched YARA rules
- Known malware signatures
- Suspicious patterns
- Toolkit identifications
"""

import logging
import os
import zipfile
from pathlib import Path
from typing import List, Dict
import tempfile

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

from ..core.base import BaseAnalyser, Finding

log = logging.getLogger(__name__)


class SignatureAnalyser(BaseAnalyser):
    """
    Analyser for pattern-based detection using YARA rules.
    
    Phase: 3 (Signature Analysis)
    Input: APK file path
    Output: List of Finding objects
    """
    
    name = "signature"
    
    def __init__(self, apk_path: str, work_dir: str):
        super().__init__(apk_path, work_dir)
        self.rules = None
        self.extracted_dir = None
    
    def run(self) -> List[Finding]:
        """Execute signature analysis."""
        try:
            if not HAS_YARA:
                log.warning("yara-python not available - skipping signature analysis")
                self.findings.append(
                    self._finding(
                        severity="info",
                        title="YARA not available",
                        detail="yara-python package not installed - signature analysis skipped",
                        tags=["dependency", "skipped"]
                    )
                )
                return self.findings
            
            self._load_rules()
            self._extract_apk()
            self._run_yara_scan()
            self._detect_obfuscation_signatures()
            
            log.info(f"Signature analysis complete: {len(self.findings)} findings")
            return self.findings
            
        except Exception as e:
            log.error(f"Signature analysis failed: {e}")
            self.findings.append(
                self._finding(
                    severity="medium",
                    title="Signature Analysis Error",
                    detail=f"Failed to run signature analysis: {str(e)}",
                    evidence=[str(e)],
                    tags=["analysis_error"]
                )
            )
            return self.findings
        finally:
            self._cleanup()
    
    def _load_rules(self):
        """Load YARA rules from project directory."""
        try:
            rules_dir = Path(__file__).parent.parent / "scripts" / "yara_rules"
            
            if not rules_dir.exists():
                log.warning(f"YARA rules directory not found: {rules_dir}")
                return
            
            rule_files = list(rules_dir.glob("*.yar"))
            if not rule_files:
                log.warning("No YARA rule files found")
                return
            
            # Load all rules
            rule_source = ""
            for rule_file in rule_files:
                try:
                    with open(rule_file) as f:
                        rule_source += f"\n\n// === {rule_file.name} ===\n"
                        rule_source += f.read()
                except Exception as e:
                    log.warning(f"Failed to load rule file {rule_file}: {e}")
            
            if rule_source:
                self.rules = yara.compile(source=rule_source)
                log.debug(f"Loaded {len(rule_files)} YARA rule files")
        
        except Exception as e:
            log.warning(f"Failed to load YARA rules: {e}")
    
    def _extract_apk(self):
        """Extract APK contents to temporary directory."""
        try:
            self.extracted_dir = Path(tempfile.mkdtemp(prefix="darlene_apk_"))
            
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                zf.extractall(self.extracted_dir)
            
            log.debug(f"APK extracted to {self.extracted_dir}")
        except Exception as e:
            log.error(f"Failed to extract APK: {e}")
            raise
    
    def _run_yara_scan(self):
        """Run YARA rules against extracted APK."""
        if not self.rules or not self.extracted_dir:
            return
        
        try:
            # Scan all files in extracted APK
            for root, dirs, files in os.walk(self.extracted_dir):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, self.extracted_dir)
                    
                    try:
                        matches = self.rules.match(file_path)
                        
                        for match in matches:
                            self.findings.append(
                                self._finding(
                                    severity=self._get_severity_from_rule(match.rule),
                                    title=f"YARA Rule Match: {match.rule}",
                                    detail=f"File {rel_path} matched YARA rule '{match.rule}'",
                                    evidence=[rel_path, match.rule],
                                    tags=["yara", "signature", "pattern_match"]
                                )
                            )
                    except Exception as e:
                        log.debug(f"Failed to scan {file_path}: {e}")
        
        except Exception as e:
            log.error(f"YARA scan failed: {e}")
    
    def _detect_obfuscation_signatures(self):
        """Detect known obfuscation toolkits."""
        try:
            if not self.extracted_dir:
                return
            
            # Check for known obfuscation signatures
            obfuscation_markers = {
                "proguard": ["proguard", "proguard.cfg"],
                "yguard": ["yguard"],
                "zelix": ["zelix"],
                "allatori": ["allatori"],
            }
            
            for root, dirs, files in os.walk(self.extracted_dir):
                for filename in files:
                    filename_lower = filename.lower()
                    for toolkit, markers in obfuscation_markers.items():
                        for marker in markers:
                            if marker in filename_lower:
                                self.findings.append(
                                    self._finding(
                                        severity="medium",
                                        title=f"{toolkit.capitalize()} Obfuscator Detected",
                                        detail=f"APK contains markers of {toolkit} obfuscator in {filename}",
                                        evidence=[filename],
                                        tags=["obfuscation", toolkit]
                                    )
                                )
        
        except Exception as e:
            log.debug(f"Obfuscation signature detection failed: {e}")
    
    @staticmethod
    def _get_severity_from_rule(rule_name: str) -> str:
        """Determine severity based on rule name patterns."""
        rule_lower = rule_name.lower()
        
        if any(x in rule_lower for x in ["malware", "trojan", "ransomware", "spyware", "critical"]):
            return "critical"
        elif any(x in rule_lower for x in ["backdoor", "exploit", "high", "suspicious"]):
            return "high"
        elif any(x in rule_lower for x in ["medium", "pup", "suspicious_api"]):
            return "medium"
        else:
            return "info"
    
    def _cleanup(self):
        """Clean up temporary files."""
        if self.extracted_dir and self.extracted_dir.exists():
            try:
                import shutil
                shutil.rmtree(self.extracted_dir)
                log.debug(f"Cleaned up {self.extracted_dir}")
            except Exception as e:
                log.warning(f"Failed to cleanup {self.extracted_dir}: {e}")
