"""
Base classes and data structures for all analysers.

Every analysis phase inherits from BaseAnalyser and produces Finding objects.
This unified interface allows the orchestrator to treat all phases identically
and enables parallel execution with consistent result aggregation.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Any
from datetime import datetime


@dataclass
class Finding:
    """
    Represents a single security finding or observation.
    
    Attributes:
        phase: Name of the analysis phase (e.g., "unpack", "manifest", "code")
        severity: Risk level - "critical", "high", "medium", "info"
        title: Short, actionable title of the finding
        detail: Full description with context and implications
        evidence: List of specific indicators (class names, hashes, IPs, etc.)
        tags: Categorical tags for filtering and correlation (e.g., ["cve-2017-13156", "signing"])
        timestamp: ISO format timestamp when finding was generated
    """
    phase: str
    severity: str
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        """Convert to dict for JSON serialization."""
        return asdict(self)

    def __str__(self) -> str:
        """Human-readable representation."""
        return f"[{self.severity.upper()}] {self.phase}: {self.title}"


class BaseAnalyser(ABC):
    """
    Abstract base class for all analysis phases.
    
    Subclasses must implement run() to return a list of Finding objects.
    The orchestrator treats all subclasses identically, enabling:
    - Parallel phase execution
    - Graceful failure handling
    - Consistent result aggregation
    - Result storage in SQLite
    
    Attributes:
        name: Short identifier (e.g., "unpack", "manifest")
        apk_path: Absolute path to the APK being analyzed
        work_dir: Temporary working directory for extraction/decompilation
        findings: Accumulated list of Finding objects
        depends_on_all: If True, this analyser runs after all others (for novel layer)
    """
    
    name: str = ""
    depends_on_all: bool = False

    def __init__(self, apk_path: str, work_dir: str):
        """
        Initialize the analyser.
        
        Args:
            apk_path: Full path to APK file
            work_dir: Working directory for temporary files
        """
        self.apk_path = apk_path
        self.work_dir = work_dir
        self.findings: list[Finding] = []
        self.prior_findings: list[Finding] = []  # Populated by orchestrator for novel layer

    @abstractmethod
    def run(self) -> list[Finding]:
        """
        Execute the analysis phase.
        
        Returns:
            List of Finding objects representing discovered issues/observations.
            Empty list if no findings in this phase.
        """
        pass

    def _finding(
        self,
        severity: str,
        title: str,
        detail: str,
        evidence: list[str] = None,
        tags: list[str] = None,
    ) -> Finding:
        """
        Helper to create and accumulate a finding.
        
        Args:
            severity: One of "critical", "high", "medium", "info"
            title: Short actionable title
            detail: Full description with implications
            evidence: List of indicators (class names, URLs, hashes, etc.)
            tags: Categorical tags for filtering
            
        Returns:
            The created Finding object (already appended to self.findings)
        """
        f = Finding(
            phase=self.name,
            severity=severity,
            title=title,
            detail=detail,
            evidence=evidence or [],
            tags=tags or [],
        )
        self.findings.append(f)
        return f

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name}, findings={len(self.findings)})"
