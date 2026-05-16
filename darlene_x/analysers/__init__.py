"""
Analysis Modules

Six standard phases (1-6) for comprehensive static APK malware analysis:
1. unpack - APK unpacking, signature verification, entropy scanning
2. manifest - Manifest audit, permissions, exported components, deep links
3. code - Code analysis, dangerous APIs, obfuscation, taint flows
4. secrets - String extraction, secret detection, IoC identification
5. native - Native library analysis, JNI, native imports
6. network - Network config audit, certificate pinning, endpoints

Plus Phase 7 (novel) for semantic analysis:
- composer - Capability fingerprinting from permission combinations
- llm_classifier - LLM-powered intent classification
- trust_graph - Trust boundary violation detection
- dga_detect - Domain generation algorithm detection
"""

__all__ = []
