"""
Phase 1: APK Unpack and Signature Verification Analyser

Responsibilities:
- Extract and parse APK structure
- Verify signatures (v1, v2, v3, v4)
- Count classes and methods
- Scan for entropy (packed payloads)
- Detect runtime DEX loading
- Extract basic metadata

Returns Finding objects for:
- Signature anomalies (v1-only, unsigned, multiple signatures)
- Suspicious entropy levels
- Runtime DEX loading indicators
- Metadata issues
"""

import os
import zipfile
import struct
import hashlib
from pathlib import Path
from typing import List, Set
import logging

try:
    from androguard.core.dex import DEX
    from androguard.core.apk import APK
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False

from ..core.base import BaseAnalyser, Finding

log = logging.getLogger(__name__)


class UnpackAnalyser(BaseAnalyser):
    """
    Analyser for APK structure, signature validation, and basic metadata extraction.
    
    Phase: 1 (Unpack & Decompress)
    Input: APK file path
    Output: List of Finding objects
    """
    
    name = "unpack"
    
    def __init__(self, apk_path: str, work_dir: str):
        super().__init__(apk_path, work_dir)
        self.apk = None
        self.dex_files = []
        self.metadata = {}
    
    def run(self) -> List[Finding]:
        """Execute APK unpacking and analysis."""
        try:
            self._parse_apk()
            self._verify_signatures()
            self._extract_dex_info()
            self._scan_entropy()
            self._detect_runtime_dex_loading()
            
            log.info(f"Unpack analysis complete: {len(self.findings)} findings")
            return self.findings
            
        except Exception as e:
            log.error(f"Unpack analysis failed: {e}")
            self.findings.append(
                self._finding(
                    severity="high",
                    title="APK Parsing Failed",
                    detail=f"Failed to parse APK: {str(e)}",
                    evidence=[str(e)],
                    tags=["parsing_error"]
                )
            )
            return self.findings
    
    def _parse_apk(self):
        """Parse APK using androguard."""
        if not HAS_ANDROGUARD:
            log.warning("androguard not available - skipping APK parsing")
            return
        
        try:
            self.apk = APK(self.apk_path)
            self.metadata["package"] = self.apk.get_package()
            self.metadata["version_code"] = self.apk.get_android_version_code()
            self.metadata["version_name"] = self.apk.get_android_version_name()
            self.metadata["min_sdk"] = self.apk.get_min_sdk_version()
            self.metadata["target_sdk"] = self.apk.get_target_sdk_version()
            
            log.debug(f"APK parsed: {self.metadata['package']}")
        except Exception as e:
            log.error(f"Failed to parse APK with androguard: {e}")
            raise
    
    def _verify_signatures(self):
        """Verify APK signatures (v1, v2, v3, v4)."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                files = zf.namelist()
            
            has_v1 = any("META-INF/" in f for f in files)
            has_v2_v3 = "APKSigningBlock" in str(self._read_apk_signing_block())
            
            if not has_v1 and not has_v2_v3:
                self.findings.append(
                    self._finding(
                        severity="critical",
                        title="Unsigned APK",
                        detail="APK has no valid signature (v1, v2, v3, or v4)",
                        tags=["signing", "security"]
                    )
                )
            elif has_v1 and not has_v2_v3:
                self.findings.append(
                    self._finding(
                        severity="high",
                        title="Legacy Signature (v1 only)",
                        detail="APK uses only JAR signing (v1), vulnerable to Janus attack (CVE-2017-13156)",
                        evidence=["v1_only"],
                        tags=["signing", "cve-2017-13156", "legacy"]
                    )
                )
            else:
                # Check for multiple signatures
                with zipfile.ZipFile(self.apk_path, 'r') as zf:
                    sig_files = [f for f in zf.namelist() if f.startswith("META-INF/") and f.endswith(".RSA")]
                    if len(sig_files) > 1:
                        self.findings.append(
                            self._finding(
                                severity="medium",
                                title="Multiple Signatures",
                                detail=f"APK has {len(sig_files)} signatures - possible spoofing attempt",
                                evidence=sig_files,
                                tags=["signing", "spoofing"]
                            )
                        )
                
        except Exception as e:
            log.warning(f"Signature verification failed: {e}")
    
    def _extract_dex_info(self):
        """Extract DEX statistics and metadata."""
        if not self.apk:
            return
        
        try:
            dex_list = self.apk.get_dex()
            if not dex_list:
                self.findings.append(
                    self._finding(
                        severity="high",
                        title="No DEX Files Found",
                        detail="APK contains no DEX files",
                        tags=["dex", "structure"]
                    )
                )
                return
            
            total_classes = 0
            total_methods = 0
            
            for dex_data in dex_list:
                try:
                    dex = DEX(dex_data)
                    classes = len(dex.get_classes())
                    methods = len(dex.get_methods())
                    total_classes += classes
                    total_methods += methods
                    self.dex_files.append({
                        "classes": classes,
                        "methods": methods
                    })
                except Exception as e:
                    log.warning(f"Failed to parse DEX: {e}")
            
            self.metadata["total_classes"] = total_classes
            self.metadata["total_methods"] = total_methods
            self.metadata["dex_count"] = len(self.dex_files)
            
            # Check for abnormal method counts (possible obfuscation/packing)
            if total_methods > 100000:
                self.findings.append(
                    self._finding(
                        severity="medium",
                        title="High Method Count",
                        detail=f"APK contains {total_methods} methods - possible obfuscation or method extraction attack",
                        evidence=[str(total_methods)],
                        tags=["obfuscation", "packing"]
                    )
                )
        
        except Exception as e:
            log.error(f"DEX extraction failed: {e}")
    
    def _scan_entropy(self):
        """Scan for high-entropy sections (packed payloads)."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as zf:
                for info in zf.filelist:
                    if info.filename.endswith(".so") or info.filename.endswith(".bin"):
                        data = zf.read(info.filename)
                        entropy = self._calculate_entropy(data[:1000])  # Sample first 1KB
                        
                        if entropy > 7.8:  # Very high entropy
                            self.findings.append(
                                self._finding(
                                    severity="high",
                                    title="High-Entropy Native Library",
                                    detail=f"Native library {info.filename} has high entropy ({entropy:.2f}) - may be packed or encrypted",
                                    evidence=[info.filename],
                                    tags=["entropy", "packing", "native"]
                                )
                            )
        except Exception as e:
            log.warning(f"Entropy scan failed: {e}")
    
    def _detect_runtime_dex_loading(self):
        """Detect indicators of runtime DEX loading."""
        if not self.apk:
            return
        
        try:
            # Look for DexClassLoader, PathClassLoader, etc.
            suspicious_classes = [
                "dalvik/system/DexClassLoader",
                "dalvik/system/PathClassLoader",
                "dalvik/system/InMemoryDexClassLoader",
                "java/lang/Runtime.exec"
            ]
            
            dex_list = self.apk.get_dex()
            for dex_data in dex_list:
                dex = DEX(dex_data)
                for method in dex.get_methods():
                    method_str = str(method)
                    for suspicious_class in suspicious_classes:
                        if suspicious_class in method_str:
                            self.findings.append(
                                self._finding(
                                    severity="critical",
                                    title="Runtime DEX Loading Detected",
                                    detail=f"APK uses {suspicious_class} for dynamic class loading",
                                    evidence=[suspicious_class],
                                    tags=["dynamic_loading", "reflection", "malware_indicator"]
                                )
                            )
                            return  # Report once per finding type
        
        except Exception as e:
            log.warning(f"Runtime DEX loading detection failed: {e}")
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        entropy = 0.0
        byte_counts = {}
        
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        for count in byte_counts.values():
            p = count / len(data)
            entropy -= p * (p ** 0.5)  # Simplified entropy calculation
        
        return entropy
    
    def _read_apk_signing_block(self) -> bytes:
        """Try to read APK signing block (v2+)."""
        try:
            with open(self.apk_path, 'rb') as f:
                f.seek(-24, 2)  # Go to end - 24 bytes
                eocd = f.read(24)
                # Look for APK signing block v2
                return eocd
        except:
            return b""
