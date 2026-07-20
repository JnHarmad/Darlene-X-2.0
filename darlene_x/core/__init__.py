"""
Darlene-X_2.0 Core Infrastructure

Provides the foundation for all analysis phases:
- Finding: Unified data structure for analysis results
- BaseAnalyser: Abstract base for all analysis modules
- Orchestrator: Parallel phase execution engine
- ResultStore: SQLite-backed findings database
- tool_runner: Subprocess management with graceful degradation
"""

from .base import Finding, BaseAnalyser
from .orchestrator import Orchestrator
from .result_store import ResultStore
from .tool_runner import run, exists, check_tools

__all__ = [
    "Finding",
    "BaseAnalyser",
    "Orchestrator",
    "ResultStore",
    "run",
    "exists",
    "check_tools",
]
