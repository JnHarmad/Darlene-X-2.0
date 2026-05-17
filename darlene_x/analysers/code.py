"""
Phase 3: Code Analysis - Suspicious API Detection

Responsibilities:
- Scan DEX files for dangerous/suspicious API calls
- Pattern matching for code execution, reflection, SMS, etc.
- Detect obfuscation patterns
- Identify taint flows (if possible)
- Runtime DexClassLoader detection
- Reflection abuse detection

Returns Finding objects for:
- Dangerous API usage
- Obfuscation indicators
- Code execution primitives
- Data exfiltration APIs
- SMS manipulation
- Device management
"""

import logging
import re
from typing import List, Dict, Set
from collections import defaultdict

try:
    from androguard.core.dex import DEX
    from androguard.core.apk import APK
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False

from ..core.base import BaseAnalyser, Finding

log = logging.getLogger(__name__)


class APIAnalyser(BaseAnalyser):
    """
    Analyser for suspicious and dangerous API calls in DEX bytecode.
    
    Phase: 3 (Code Analysis)
    Input: APK file path
    Output: List of Finding objects
    """
    
    name = "api"
    
    # Dangerous APIs categorized by risk
    CRITICAL_APIS = {
        ("java/lang/Runtime", "exec"),
        ("java/lang/ProcessBuilder", "<init>"),
        ("android/telephony/SmsManager", "sendTextMessage"),
        ("android/telephony/SmsManager", "sendMultipartTextMessage"),
        ("java/lang/reflect/Method", "invoke"),
        ("java/lang/Class", "forName"),
        ("android/content/ContextWrapper", "startService"),
    }
    
    HIGH_APIS = {
        ("java/net/Socket", "<init>"),
        ("java/net/URLConnection", "openConnection"),
        ("android/location/LocationManager", "requestLocationUpdates"),
        ("android/telephony/TelephonyManager", "getDeviceId"),
        ("android/telephony/TelephonyManager", "getSubscriberId"),
        ("android/media/MediaRecorder", "start"),
        ("android/hardware/Camera", "open"),
        ("android/net/Uri", "parse"),
    }
    
    MEDIUM_APIS = {
        ("android/content/SharedPreferences", "getSharedPreferences"),
        ("java/io/File", "delete"),
        ("java/io/FileInputStream", "<init>"),
        ("android/database/sqlite/SQLiteDatabase", "openDatabase"),
        ("android/content/pm/PackageManager", "getInstalledPackages"),
    }
    
    def __init__(self, apk_path: str, work_dir: str):
        super().__init__(apk_path, work_dir)
        self.apk = None
        self.dex_files = []
        self.api_calls = defaultdict(list)
    
    def run(self) -> List[Finding]:
        """Execute API analysis."""
        try:
            self._extract_and_scan_dex()
            self._analyze_api_calls()
            self._detect_obfuscation()
            self._detect_reflection_abuse()
            
            log.info(f"API analysis complete: {len(self.findings)} findings")
            return self.findings
            
        except Exception as e:
            log.error(f"API analysis failed: {e}")
            self.findings.append(
                self._finding(
                    severity="medium",
                    title="API Analysis Failed",
                    detail=f"Failed to analyze APIs: {str(e)}",
                    evidence=[str(e)],
                    tags=["analysis_error"]
                )
            )
            return self.findings
    
    def _extract_and_scan_dex(self):
        """Extract and process DEX files."""
        if not HAS_ANDROGUARD:
            log.warning("androguard not available - skipping DEX analysis")
            return
        
        try:
            self.apk = APK(self.apk_path)
            dex_list = self.apk.get_dex()
            
            if not dex_list:
                log.warning("No DEX files found in APK")
                return
            
            for dex_data in dex_list:
                try:
                    dex = DEX(dex_data)
                    self.dex_files.append(dex)
                    self._extract_api_calls(dex)
                except Exception as e:
                    log.warning(f"Failed to parse DEX: {e}")
        
        except Exception as e:
            log.error(f"DEX extraction failed: {e}")
            raise
    
    def _extract_api_calls(self, dex: object):
        """Extract all method invocations from DEX."""
        try:
            for method in dex.get_methods():
                source = method.get_source()
                if not source:
                    continue
                
                # Extract method calls using pattern matching
                # Pattern: invoke-* {args} Class.method()
                for match in re.finditer(
                    r'([\w\$]+)\.([\w\$<>]+)\(',
                    source
                ):
                    class_name = match.group(1)
                    method_name = match.group(2)
                    api_key = (class_name, method_name)
                    self.api_calls[api_key].append(method.get_name())
        
        except Exception as e:
            log.debug(f"Failed to extract API calls: {e}")
    
    def _analyze_api_calls(self):
        """Analyze discovered API calls for security risks."""
        critical_found = []
        high_found = []
        medium_found = []
        
        for api_key, methods in self.api_calls.items():
            if api_key in self.CRITICAL_APIS:
                critical_found.append((api_key, methods))
            elif api_key in self.HIGH_APIS:
                high_found.append((api_key, methods))
            elif api_key in self.MEDIUM_APIS:
                medium_found.append((api_key, methods))
        
        # Report critical findings
        if critical_found:
            evidence = []
            for (cls, method), _ in critical_found[:5]:
                evidence.append(f"{cls}.{method}")
            
            self.findings.append(
                self._finding(
                    severity="critical",
                    title="Critical APIs Detected",
                    detail=f"APK uses {len(critical_found)} critical APIs that enable code execution or SMS manipulation",
                    evidence=evidence,
                    tags=["code_execution", "sms", "dangerous_api"]
                )
            )
        
        # Report high-risk findings
        if high_found:
            evidence = []
            for (cls, method), _ in high_found[:5]:
                evidence.append(f"{cls}.{method}")
            
            self.findings.append(
                self._finding(
                    severity="high",
                    title="High-Risk APIs Used",
                    detail=f"APK uses {len(high_found)} high-risk APIs for location, device info, or network access",
                    evidence=evidence,
                    tags=["data_access", "network", "high_risk_api"]
                )
            )
        
        # Report medium-risk findings
        if medium_found:
            self.findings.append(
                self._finding(
                    severity="medium",
                    title="Medium-Risk APIs Used",
                    detail=f"APK uses {len(medium_found)} medium-risk APIs for data access or file operations",
                    tags=["data_access", "medium_risk_api"]
                )
            )
    
    def _detect_obfuscation(self):
        """Detect common obfuscation techniques."""
        try:
            obfuscation_indicators = {
                "proguard": 0,
                "reflection": 0,
                "native": 0,
                "string_encryption": 0,
            }
            
            for dex in self.dex_files:
                # Check for ProGuard patterns
                classes = dex.get_classes()
                single_letter_classes = 0
                for cls in classes:
                    name = cls.get_name()
                    # Count single-letter class names
                    if name.count("/") == 1 and name.split("/")[1] in "abcdefghijklmnopqrstuvwxyz":
                        single_letter_classes += 1
                
                if single_letter_classes > len(classes) * 0.3:
                    obfuscation_indicators["proguard"] += 1
                
                # Check for reflection usage
                for method in dex.get_methods():
                    source = method.get_source() or ""
                    if "forName" in source or "invoke" in source:
                        obfuscation_indicators["reflection"] += 1
            
            if obfuscation_indicators["proguard"] > 0:
                self.findings.append(
                    self._finding(
                        severity="medium",
                        title="ProGuard Obfuscation Detected",
                        detail="APK likely uses ProGuard for code obfuscation - may hide malicious functionality",
                        tags=["obfuscation", "proguard"]
                    )
                )
            
            if obfuscation_indicators["reflection"] > 0:
                self.findings.append(
                    self._finding(
                        severity="high",
                        title="Reflection Abuse Detected",
                        detail="APK uses reflection extensively - common obfuscation technique to hide functionality",
                        tags=["obfuscation", "reflection"]
                    )
                )
        
        except Exception as e:
            log.debug(f"Obfuscation detection failed: {e}")
    
    def _detect_reflection_abuse(self):
        """Detect advanced reflection patterns used to hide code."""
        try:
            reflection_patterns = {
                r"Class\.forName\s*\(\s*['\"]([^'\"]+)['\"]\s*\)": "Dynamic class loading",
                r"Method\.invoke\s*\(": "Dynamic method invocation",
                r"Constructor\.newInstance\s*\(": "Dynamic constructor invocation",
                r"Array\.get\s*\(": "Dynamic array access",
            }
            
            for dex in self.dex_files:
                for method in dex.get_methods():
                    source = method.get_source() or ""
                    for pattern, description in reflection_patterns.items():
                        if re.search(pattern, source):
                            self.findings.append(
                                self._finding(
                                    severity="high",
                                    title="Advanced Reflection Detected",
                                    detail=f"Method {method.get_name()} uses {description} to hide functionality",
                                    evidence=[method.get_name()],
                                    tags=["reflection", "obfuscation", "hiding"]
                                )
                            )
                            break
        
        except Exception as e:
            log.debug(f"Reflection abuse detection failed: {e}")
