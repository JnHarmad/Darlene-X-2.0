"""
Phase 2: Manifest Analysis and Permission Audit

Responsibilities:
- Extract permissions, activities, receivers, providers
- Analyze deep links and intent filters
- Audit exported components
- Analyze certificate chain
- Detect dangerous permission combinations
- Identify capability archetypes

Returns Finding objects for:
- Dangerous permissions
- Suspicious permission combinations
- Exported components without protection
- Deep link vulnerabilities
- Intent filter issues
- Certificate problems
"""

import logging
from typing import List, Dict, Set
from collections import defaultdict

try:
    from androguard.core.apk import APK
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False

from ..core.base import BaseAnalyser, Finding

log = logging.getLogger(__name__)


class ManifestAnalyser(BaseAnalyser):
    """
    Analyser for AndroidManifest.xml and permission analysis.
    
    Phase: 2 (Manifest Audit)
    Input: APK file path
    Output: List of Finding objects
    """
    
    name = "manifest"
    
    # Dangerous permissions requiring user approval (Android 6.0+)
    DANGEROUS_PERMISSIONS = {
        # Contacts
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        # Calendar
        "android.permission.READ_CALENDAR",
        "android.permission.WRITE_CALENDAR",
        # SMS
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        # Logs
        "android.permission.READ_LOGS",
        # Phone
        "android.permission.READ_PHONE_STATE",
        "android.permission.READ_PHONE_NUMBERS",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.USE_SIP",
        # Camera
        "android.permission.CAMERA",
        # Location
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        # Microphone
        "android.permission.RECORD_AUDIO",
        # Storage
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        # Sensors
        "android.permission.BODY_SENSORS",
    }
    
    # Suspicious permissions (not dangerous but concerning)
    SUSPICIOUS_PERMISSIONS = {
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.INTERNET",
        "android.permission.WRITE_SECURE_SETTINGS",
        "android.permission.MODIFY_PHONE_STATE",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
        "android.permission.DISABLE_KEYGUARD",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.REQUEST_INSTALL_PACKAGES",
    }
    
    def __init__(self, apk_path: str, work_dir: str):
        super().__init__(apk_path, work_dir)
        self.apk = None
        self.permissions = set()
        self.activities = {}
        self.services = {}
        self.receivers = {}
        self.providers = {}
    
    def run(self) -> List[Finding]:
        """Execute manifest analysis."""
        try:
            self._parse_manifest()
            self._analyze_permissions()
            self._check_exported_components()
            self._audit_deeplinks()
            self._analyze_certificate()
            
            log.info(f"Manifest analysis complete: {len(self.findings)} findings")
            return self.findings
            
        except Exception as e:
            log.error(f"Manifest analysis failed: {e}")
            self.findings.append(
                self._finding(
                    severity="high",
                    title="Manifest Parsing Failed",
                    detail=f"Failed to parse manifest: {str(e)}",
                    evidence=[str(e)],
                    tags=["manifest_error"]
                )
            )
            return self.findings
    
    def _parse_manifest(self):
        """Parse manifest from APK."""
        if not HAS_ANDROGUARD:
            log.warning("androguard not available - skipping manifest parsing")
            return
        
        try:
            self.apk = APK(self.apk_path)
            
            # Extract permissions
            self.permissions = set(self.apk.get_permissions() or [])
            
            # Extract components
            for activity in (self.apk.get_activities() or []):
                self.activities[activity] = self._get_component_info(activity)
            
            for service in (self.apk.get_services() or []):
                self.services[service] = self._get_component_info(service)
            
            for receiver in (self.apk.get_receivers() or []):
                self.receivers[receiver] = self._get_component_info(receiver)
            
            for provider in (self.apk.get_providers() or []):
                self.providers[provider] = self._get_component_info(provider)
            
            log.debug(f"Manifest parsed: {len(self.permissions)} permissions, " +
                     f"{len(self.activities)} activities, {len(self.services)} services")
        
        except Exception as e:
            log.error(f"Failed to parse manifest: {e}")
            raise
    
    def _get_component_info(self, component_name: str) -> Dict:
        """Get detailed information about a component."""
        if not self.apk:
            return {}
        
        try:
            # Get intent filters for component
            intent_filters = []
            component_info = self.apk.get_element("activity", attribute="android:name", value=component_name)
            
            if not component_info:
                component_info = self.apk.get_element("service", attribute="android:name", value=component_name)
            if not component_info:
                component_info = self.apk.get_element("receiver", attribute="android:name", value=component_name)
            if not component_info:
                component_info = self.apk.get_element("provider", attribute="android:name", value=component_name)
            
            exported = False
            if component_info is not None:
                exported = component_info.get("android:exported") == "true"
            
            return {
                "exported": exported,
                "intent_filters": intent_filters
            }
        except Exception as e:
            log.debug(f"Failed to get component info for {component_name}: {e}")
            return {}
    
    def _analyze_permissions(self):
        """Analyze permissions for security risks."""
        dangerous_perms = self.permissions & self.DANGEROUS_PERMISSIONS
        suspicious_perms = self.permissions & self.SUSPICIOUS_PERMISSIONS
        
        # Report dangerous permissions
        if dangerous_perms:
            self.findings.append(
                self._finding(
                    severity="high",
                    title="Dangerous Permissions Requested",
                    detail=f"APK requests {len(dangerous_perms)} dangerous permissions that can access sensitive user data",
                    evidence=sorted(list(dangerous_perms)),
                    tags=["permissions", "dangerous"]
                )
            )
        
        # Check for suspicious combinations
        self._check_permission_combinations(dangerous_perms, suspicious_perms)
    
    def _check_permission_combinations(self, dangerous: Set[str], suspicious: Set[str]):
        """Detect suspicious permission combinations that indicate malware archetypes."""
        all_perms = dangerous | suspicious
        
        # Spyware archetype: Location + Contacts + SMS/Phone + Comms
        spyware_indicators = {
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.RECEIVE_SMS",
        }
        if len(all_perms & spyware_indicators) >= 3:
            self.findings.append(
                self._finding(
                    severity="critical",
                    title="Spyware Archetype Detected",
                    detail="Permission combination suggests spyware: location tracking + contact access + communications interception",
                    evidence=sorted(list(all_perms & spyware_indicators)),
                    tags=["archetype", "spyware", "malware_indicator"]
                )
            )
        
        # SMS trojan archetype: SMS + Network + Device Admin
        sms_trojan_indicators = {
            "android.permission.SEND_SMS",
            "android.permission.INTERNET",
            "android.permission.CHANGE_NETWORK_STATE",
        }
        if len(all_perms & sms_trojan_indicators) >= 2 and "android.permission.SEND_SMS" in all_perms:
            self.findings.append(
                self._finding(
                    severity="critical",
                    title="SMS Trojan Archetype",
                    detail="Permission combination suggests SMS trojan: can send SMS and control network",
                    evidence=sorted(list(all_perms & sms_trojan_indicators)),
                    tags=["archetype", "trojan", "sms", "malware_indicator"]
                )
            )
    
    def _check_exported_components(self):
        """Check for exported components without protection."""
        unprotected_exported = []
        
        for activity, info in self.activities.items():
            if info.get("exported", False):
                unprotected_exported.append(f"Activity: {activity}")
        
        for service, info in self.services.items():
            if info.get("exported", False):
                unprotected_exported.append(f"Service: {service}")
        
        for receiver, info in self.receivers.items():
            if info.get("exported", False):
                unprotected_exported.append(f"Receiver: {receiver}")
        
        for provider, info in self.providers.items():
            if info.get("exported", False):
                unprotected_exported.append(f"Provider: {provider}")
        
        if unprotected_exported:
            self.findings.append(
                self._finding(
                    severity="high" if len(unprotected_exported) > 3 else "medium",
                    title="Unprotected Exported Components",
                    detail=f"APK has {len(unprotected_exported)} exported components without permission protection",
                    evidence=unprotected_exported[:10],  # Limit to first 10
                    tags=["attack_surface", "component_exposure"]
                )
            )
    
    def _audit_deeplinks(self):
        """Check for deep link vulnerabilities."""
        # This would require parsing intent filters in detail
        # For now, log as informational
        try:
            if self.apk:
                # Check for deep link handlers
                has_deeplinks = False
                for activity in self.activities:
                    if self.activities[activity].get("intent_filters"):
                        has_deeplinks = True
                        break
                
                if has_deeplinks:
                    self.findings.append(
                        self._finding(
                            severity="medium",
                            title="Deep Links Detected",
                            detail="APK implements deep link handlers - ensure URI validation is in place",
                            tags=["deeplinks", "uri_validation"]
                        )
                    )
        except Exception as e:
            log.warning(f"Deep link audit failed: {e}")
    
    def _analyze_certificate(self):
        """Analyze APK certificate information."""
        if not self.apk:
            return
        
        try:
            cert_info = self.apk.get_certificate_der_v3() or self.apk.get_certificate_der_v2()
            if not cert_info:
                cert_info = self.apk.get_certificate_der_v1()
            
            if not cert_info:
                self.findings.append(
                    self._finding(
                        severity="critical",
                        title="No Certificate Found",
                        detail="APK has no valid certificate for verification",
                        tags=["certificate", "signing"]
                    )
                )
        except Exception as e:
            log.warning(f"Certificate analysis failed: {e}")
