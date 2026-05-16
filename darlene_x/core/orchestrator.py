"""
Orchestrator for parallel analysis phase execution.

Runs all phases in a controlled sequence:
1. Phases 1-6 (standard analysers) run in parallel (I/O bound)
2. Phase 7 (novel analysers) runs after, with full context from prior phases

Handles:
- Parallel ThreadPoolExecutor management
- Result aggregation and persistence
- Error handling (one failed phase doesn't stop others)
- Graceful degradation (missing tools don't crash pipeline)
"""

import concurrent.futures
import logging
from pathlib import Path
from typing import List

from .base import BaseAnalyser, Finding
from .result_store import ResultStore

log = logging.getLogger(__name__)


class Orchestrator:
    """
    Manages analysis phase execution with parallel + sequential stages.
    """

    def __init__(self, apk_path: str, out_dir: str, parallel: bool = True):
        """
        Initialize orchestrator.

        Args:
            apk_path: Path to APK file to analyze
            out_dir: Output directory for results
            parallel: If True, run standard phases in parallel (default True)
        """
        self.apk_path = apk_path
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.parallel = parallel
        self.store = ResultStore(str(self.out_dir / "results.db"))
        self.all_findings: List[Finding] = []

        log.debug(
            f"Orchestrator initialized: apk={apk_path}, out={out_dir}, parallel={parallel}"
        )

    def run_phases(self, analysers: List[BaseAnalyser]) -> List[Finding]:
        """
        Execute analysis phases.

        Phases without depends_on_all run in parallel (ThreadPoolExecutor).
        Phases with depends_on_all=True run sequentially after, receiving all prior findings.

        Args:
            analysers: List of BaseAnalyser instances to execute

        Returns:
            Aggregated list of all findings from all phases
        """
        # Partition analysers
        standard = [a for a in analysers if not getattr(a, "depends_on_all", False)]
        novel = [a for a in analysers if getattr(a, "depends_on_all", False)]

        log.info(f"Running {len(standard)} standard phases, {len(novel)} novel phases")

        # Phase 1-6: Run in parallel
        self.all_findings = self._run_standard_phases(standard)

        # Phase 7: Run serially, with full context
        self.all_findings.extend(self._run_novel_phases(novel))

        return self.all_findings

    def _run_standard_phases(self, analysers: List[BaseAnalyser]) -> List[Finding]:
        """
        Run standard analysis phases in parallel.

        Args:
            analysers: List of standard BaseAnalyser instances

        Returns:
            Aggregated findings from all phases
        """
        findings = []

        if not analysers:
            return findings

        if not self.parallel:
            # Serial execution (for debugging)
            for analyser in analysers:
                try:
                    phase_findings = self._execute_phase(analyser)
                    findings.extend(phase_findings)
                    self.store.save(phase_findings)
                except Exception as e:
                    log.error(f"Phase {analyser.name} failed: {e}", exc_info=True)
            return findings

        # Parallel execution with ThreadPoolExecutor
        max_workers = min(4, len(analysers))  # Max 4 concurrent tasks
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_analyser = {
                executor.submit(self._execute_phase, a): a for a in analysers
            }

            for future in concurrent.futures.as_completed(future_to_analyser):
                analyser = future_to_analyser[future]
                try:
                    phase_findings = future.result()
                    findings.extend(phase_findings)
                    self.store.save(phase_findings)
                    log.info(f"Phase '{analyser.name}' completed: {len(phase_findings)} findings")
                except Exception as e:
                    log.error(f"Phase '{analyser.name}' failed: {e}", exc_info=True)

        return findings

    def _run_novel_phases(self, analysers: List[BaseAnalyser]) -> List[Finding]:
        """
        Run novel (semantic) analysis phases serially.

        Novel phases depend on findings from all prior phases, so they must run after.

        Args:
            analysers: List of novel BaseAnalyser instances (with depends_on_all=True)

        Returns:
            Aggregated findings from all novel phases
        """
        findings = []

        for analyser in analysers:
            try:
                # Populate prior_findings for the novel analyser
                analyser.prior_findings = self.all_findings
                phase_findings = self._execute_phase(analyser)
                findings.extend(phase_findings)
                self.store.save(phase_findings)
                log.info(
                    f"Novel phase '{analyser.name}' completed: {len(phase_findings)} findings"
                )
            except Exception as e:
                log.error(f"Novel phase '{analyser.name}' failed: {e}", exc_info=True)

        return findings

    def _execute_phase(self, analyser: BaseAnalyser) -> List[Finding]:
        """
        Execute a single analysis phase.

        Args:
            analyser: BaseAnalyser instance

        Returns:
            List of findings from this phase
        """
        log.debug(f"Executing phase: {analyser.name}")
        try:
            findings = analyser.run()
            log.debug(f"Phase {analyser.name}: {len(findings)} findings")
            return findings if findings else []
        except Exception as e:
            log.error(f"Phase {analyser.name} raised exception: {e}", exc_info=True)
            # Graceful degradation: return empty list, don't crash pipeline
            return []

    def get_summary(self) -> dict:
        """
        Get analysis summary from result store.

        Returns:
            Dict with finding counts by phase and severity
        """
        return self.store.get_summary()

    def export_results(self) -> dict:
        """
        Export all results as JSON structure.

        Returns:
            Dict ready for JSON serialization
        """
        return self.store.export_json()
