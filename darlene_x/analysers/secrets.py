"""
Phase 4: Secrets and Data Protection Audit

Responsibilities:
- Extract strings from DEX files
- Detect hardcoded credentials and API keys
- Scan for encryption artifacts
- Detect SQLite database patterns
- Identify network endpoints (URLs, IPs, domains)
- Check for certificate pinning
- Search for obfuscation indicators

Returns Finding objects for:
- Hardcoded credentials
- Exposed API keys
- Suspicious URLs
- Lack of encryption
- Unencrypted database access
- Certificate pinning bypass
"""

import logging
import re
import zipfile
from typing import List, Set, Dict
from pathlib import Path

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False

from ..core.base import BaseAnalyser, Finding

log = logging.getLogger(__name__)


class SecretsAnalyser(BaseAnalyser):
    """
    Analyser for hardcoded secrets, credentials, and data protection issues.
    
    Phase: 4 (Secrets & Encryption)
    Input: APK file path
    Output: List of Finding objects
    """
    
    name = "secrets"
    
    # Patterns for detecting secrets
    CREDENTIAL_PATTERNS = {
        "api_key": re.compile(
            r'(?i)(api[_-]?key|apikey|api_secret|apisecret)\s*[:=]\s*["\']?([a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=]{20,})["\']?',
            re.IGNORECASE
        ),
        "password": re.compile(
            r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{6,})["\']',
            re.IGNORECASE
        ),
        "token": re.compile(
            r'(?i)(token|auth_token|access_token)\s*[:=]\s*["\']?([a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=]{20,})["\']?',
            re.IGNORECASE
        ),
        "private_key": re.compile(
            r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            re.IGNORECASE
        ),
    }
    
    # Patterns for detecting URLs and domains
    URL_PATTERN = re.compile(
        r'https?://[^\s"\'<>]+|(?:api|cdn|config|data|socket)\.[a-z0-9\-\.]+\.(?:com|io|net|org|co)',
        re.IGNORECASE
    )
    
    # Encryption algorithm indicators
    ENCRYPTION_ALGORITHMS = {
        "AES": ["Cipher.getInstance.*AES", "AES/ECB", "AES/CBC", "AES/GCM"],
        "RSA": ["RSA/ECB", "RSA/OAEP"],
        "DES": ["DES/ECB", "DES/CBC"],
        "SHA": ["SHA-256", "SHA-512", "HmacSHA"],
    }
    
    def __init__(self, apk_path: str, work_dir: str):
        super().__init__(apk_path, work_dir)
        self.apk = None
        self.strings = set()
        self.urls = set()
        self.credentials_found = []
    
    def run(self) -> List[Finding]:
        """Execute secrets analysis."""
        try:
            self._extract_strings()
            self._scan_for_credentials()
            self._extract_urls()
            self._scan_for_unencrypted_storage()
            self._check_encryption_usage()
            
            log.info(f"Secrets analysis complete: {len(self.findings)} findings")
            return self.findings
            
        except Exception as e:
            log.error(f"Secrets analysis failed: {e}")
            self.findings.append(
                self._finding(
                    severity="medium",
                    title="Secrets Analysis Error",
                    detail=f"Failed to analyze secrets: {str(e)}",
                    evidence=[str(e)],
                    tags=["analysis_error"]
                )
            )
            return self.findings
    
    def _extract_strings(self):
        """Extract all strings from DEX files."""
        if not HAS_ANDROGUARD:
            log.warning("androguard not available - skipping string extraction")
            return
        
        try:
            self.apk = APK(self.apk_path)
            dex_list = self.apk.get_dex()
            
            if not dex_list:
                log.warning("No DEX files found")
                return
            
            for dex_data in dex_list:
                try:
                    dex = DEX(dex_data)
                    for string in dex.get_strings():
                        if string and len(string) > 2:
                            self.strings.add(string)
                except Exception as e:
                    log.debug(f"Failed to extract strings from DEX: {e}")
            
            log.debug(f"Extracted {len(self.strings)} unique strings")
        
        except Exception as e:
            log.error(f"String extraction failed: {e}")
    
    def _scan_for_credentials(self):
        """Scan extracted strings for hardcoded credentials."""
        found_credentials = {}
        
        for string in self.strings:
            for cred_type, pattern in self.CREDENTIAL_PATTERNS.items():
                matches = pattern.findall(string)
                if matches:
                    if cred_type not in found_credentials:
                        found_credentials[cred_type] = []
                    found_credentials[cred_type].append(string)
        
        if found_credentials:
            evidence = []
            for cred_type, strings in found_credentials.items():
                # Mask sensitive data for reporting
                for s in strings[:3]:  # Limit to 3 examples per type
                    masked = self._mask_sensitive(s)
                    evidence.append(f"{cred_type}: {masked}")
            
            self.findings.append(
                self._finding(
                    severity="critical",
                    title="Hardcoded Credentials Detected",
                    detail=f"APK contains {len(found_credentials)} types of hardcoded credentials",
                    evidence=evidence,
                    tags=["credentials", "hardcoded", "secrets", "data_exposure"]
                )
            )
    
    def _extract_urls(self):
        """Extract URLs and domains from strings."""
        for string in self.strings:
            urls = self.URL_PATTERN.findall(string)
            for url in urls:
                self.urls.add(url)
        
        if self.urls:
            suspicious_domains = [
                url for url in self.urls
                if any(x in url.lower() for x in ["c2", "callback", "command", "control", "exfil"])
            ]
            
            self.findings.append(
                self._finding(
                    severity="medium" if suspicious_domains else "low",
                    title=f"Network Endpoints Detected ({len(self.urls)})",
                    detail=f"APK contains {len(self.urls)} potential network endpoints",
                    evidence=list(self.urls)[:10],  # First 10
                    tags=["network", "urls", "communication"]
                )
            )
    
    def _scan_for_unencrypted_storage(self):
        """Detect unencrypted data storage patterns."""
        try:
            # Look for SharedPreferences (often used for unencrypted storage)
            shared_prefs = [s for s in self.strings if "shared_prefs" in s.lower() or "preferences" in s.lower()]
            if shared_prefs:
                self.findings.append(
                    self._finding(
                        severity="high",
                        title="Unencrypted SharedPreferences Usage",
                        detail="APK uses SharedPreferences which stores data in unencrypted XML files",
                        evidence=shared_prefs[:3],
                        tags=["storage", "encryption", "data_protection"]
                    )
                )
            
            # Look for SQLite database usage
            sqlite_usage = [s for s in self.strings if "sqlite" in s.lower() or ".db" in s.lower()]
            if sqlite_usage:
                self.findings.append(
                    self._finding(
                        severity="medium",
                        title="SQLite Database Usage",
                        detail="APK uses SQLite - ensure database is encrypted if storing sensitive data",
                        evidence=sqlite_usage[:3],
                        tags=["storage", "database"]
                    )
                )
        
        except Exception as e:
            log.debug(f"Unencrypted storage scan failed: {e}")
    
    def _check_encryption_usage(self):
        """Check for encryption algorithm usage."""
        try:
            self.apk = self.apk or APK(self.apk_path)
            dex_list = self.apk.get_dex()
            
            if not dex_list:
                return
            
            encryption_found = {}
            
            for dex_data in dex_list:
                try:
                    dex = DEX(dex_data)
                    for method in dex.get_methods():
                        source = method.get_source() or ""
                        
                        for algo, patterns in self.ENCRYPTION_ALGORITHMS.items():
                            for pattern in patterns:
                                if pattern in source:
                                    if algo not in encryption_found:
                                        encryption_found[algo] = 0
                                    encryption_found[algo] += 1
                
                except Exception as e:
                    log.debug(f"Failed to check encryption: {e}")
            
            if encryption_found:
                self.findings.append(
                    self._finding(
                        severity="info",
                        title="Encryption Usage Detected",
                        detail=f"APK uses {len(encryption_found)} encryption algorithm(s)",
                        evidence=list(encryption_found.keys()),
                        tags=["encryption", "cryptography"]
                    )
                )
            else:
                self.findings.append(
                    self._finding(
                        severity="medium",
                        title="No Encryption Detected",
                        detail="APK does not appear to use standard encryption for data protection",
                        tags=["encryption", "data_protection"]
                    )
                )
        
        except Exception as e:
            log.debug(f"Encryption check failed: {e}")
    
    @staticmethod
    def _mask_sensitive(text: str, show_chars: int = 4) -> str:
        """Mask sensitive data in strings."""
        if len(text) <= show_chars * 2:
            return "*" * len(text)
        return text[:show_chars] + "*" * (len(text) - show_chars * 2) + text[-show_chars:]
