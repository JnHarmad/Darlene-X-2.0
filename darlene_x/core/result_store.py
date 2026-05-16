"""
Result storage and querying via SQLite.

Provides a persistent, queryable store for all findings across phases.
Allows filtering by phase, severity, tags, and exporting results.

Schema:
    findings (id, phase, severity, title, detail, evidence, tags, timestamp)

This eliminates the need for flat JSON files and enables queries like:
    "Show all HIGH findings from manifest AND code phases"
    "What findings are tagged with cve-2017-13156?"
    "Get all findings with critical severity from today's scan"
"""

import sqlite3
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Optional

from .base import Finding

log = logging.getLogger(__name__)


class ResultStore:
    """SQLite-backed findings storage with query interface."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phase TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        detail TEXT NOT NULL,
        evidence TEXT,
        tags TEXT,
        timestamp TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_phase ON findings(phase);
    CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_timestamp ON findings(timestamp);
    """

    def __init__(self, db_path: str):
        """
        Initialize the result store.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize database schema."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.executescript(self.SCHEMA)
                conn.commit()
            log.debug(f"ResultStore initialized at {self.db_path}")
        except Exception as e:
            log.error(f"Failed to initialize ResultStore: {e}")
            raise

    def save(self, findings: List[Finding]):
        """
        Save findings to database.

        Args:
            findings: List of Finding objects to persist
        """
        if not findings:
            return

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                for finding in findings:
                    cursor.execute(
                        """
                        INSERT INTO findings
                        (phase, severity, title, detail, evidence, tags, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            finding.phase,
                            finding.severity,
                            finding.title,
                            finding.detail,
                            json.dumps(finding.evidence),
                            json.dumps(finding.tags),
                            finding.timestamp,
                        ),
                    )
                conn.commit()
                log.debug(f"Saved {len(findings)} findings to ResultStore")
        except Exception as e:
            log.error(f"Failed to save findings: {e}")
            raise

    def query(
        self,
        phase: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
        limit: int = 1000,
    ) -> List[Finding]:
        """
        Query findings with optional filters.

        Args:
            phase: Filter by analysis phase (e.g., "manifest")
            severity: Filter by severity (e.g., "high")
            tags: Filter by any of these tags (OR logic)
            limit: Max results to return

        Returns:
            List of Finding objects matching criteria

        Example:
            >>> store = ResultStore("results.db")
            >>> findings = store.query(severity="high", limit=50)
            >>> findings = store.query(phase="manifest", tags=["exported_component"])
        """
        sql = "SELECT * FROM findings WHERE 1=1"
        params = []

        if phase:
            sql += " AND phase = ?"
            params.append(phase)

        if severity:
            sql += " AND severity = ?"
            params.append(severity)

        sql += " ORDER BY severity DESC, created_at DESC LIMIT ?"
        params.append(limit)

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(sql, params)
                rows = cursor.fetchall()

                findings = []
                for row in rows:
                    finding = Finding(
                        phase=row["phase"],
                        severity=row["severity"],
                        title=row["title"],
                        detail=row["detail"],
                        evidence=json.loads(row["evidence"] or "[]"),
                        tags=json.loads(row["tags"] or "[]"),
                        timestamp=row["timestamp"],
                    )
                    
                    # If tag filter specified, check if any tags match
                    if tags and not any(t in finding.tags for t in tags):
                        continue
                    
                    findings.append(finding)

                return findings
        except Exception as e:
            log.error(f"Query failed: {e}")
            return []

    def get_summary(self) -> dict:
        """
        Get summary statistics of findings.

        Returns:
            Dict with counts by phase and severity
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Count by severity
                cursor.execute(
                    "SELECT severity, COUNT(*) as count FROM findings GROUP BY severity"
                )
                severity_counts = {row[0]: row[1] for row in cursor.fetchall()}

                # Count by phase
                cursor.execute(
                    "SELECT phase, COUNT(*) as count FROM findings GROUP BY phase"
                )
                phase_counts = {row[0]: row[1] for row in cursor.fetchall()}

                # Total
                cursor.execute("SELECT COUNT(*) FROM findings")
                total = cursor.fetchone()[0]

                return {
                    "total_findings": total,
                    "by_severity": severity_counts,
                    "by_phase": phase_counts,
                }
        except Exception as e:
            log.error(f"Failed to get summary: {e}")
            return {"total_findings": 0, "by_severity": {}, "by_phase": {}}

    def export_json(self) -> dict:
        """
        Export all findings as JSON structure.

        Returns:
            Dict with metadata and findings array
        """
        try:
            findings = self.query(limit=10000)
            summary = self.get_summary()

            return {
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "database": str(self.db_path),
                    **summary,
                },
                "findings": [f.to_dict() for f in findings],
            }
        except Exception as e:
            log.error(f"Failed to export JSON: {e}")
            return {"metadata": {}, "findings": []}

    def clear(self):
        """Clear all findings (for fresh analysis)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM findings")
                conn.commit()
            log.debug("ResultStore cleared")
        except Exception as e:
            log.error(f"Failed to clear ResultStore: {e}")
