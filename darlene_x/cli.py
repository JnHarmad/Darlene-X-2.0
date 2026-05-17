"""
Darlene-X Flask REST API - Backend server for APK analysis

Provides REST endpoints for:
- APK upload and analysis
- Result querying
- Configuration management

To run:
    python -m darlene_x.api
    # Server starts on http://localhost:5000
"""

import logging
import sys
from pathlib import Path
from typing import Optional
import json
import tempfile
import uuid

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from loguru import logger

console = Console()



@click.group()
@click.version_option(version="2.0.0", prog_name="darlene-x")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging")
def cli(verbose):
    """
    Darlene-X: Advanced APK Malware Analysis Framework
    
    Performs comprehensive static analysis of Android APK files using:
    - Manifest auditing
    - Permission analysis  
    - API call detection
    - Signature verification
    - Secret scanning
    - LLM-powered classification (Phase 7)
    """
    if verbose:
        logger.enable("darlene_x")
        logging.basicConfig(level=logging.DEBUG)


@cli.command()
@click.argument("apk", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--out",
    "-o",
    type=click.Path(),
    default="./darlene_output",
    help="Output directory for results [default: ./darlene_output]"
)
@click.option(
    "--serial",
    is_flag=True,
    help="Run phases sequentially (debug mode, slower)"
)
@click.option(
    "--no-llm",
    is_flag=True,
    help="Skip Phase 7 (LLM classification)"
)
@click.option(
    "--format",
    type=click.Choice(["json", "html", "pdf"]),
    default="json",
    help="Output report format [default: json]"
)
def analyze(
    apk: str,
    out: str,
    serial: bool,
    no_llm: bool,
    format: str
):
    """
    Analyze an APK file for malware and security issues.
    
    Performs 6 standard phases of analysis:
    1. APK Unpacking - Signature verification, metadata extraction
    2. Manifest Audit - Permissions, components, deep links
    3. Code Analysis - Dangerous APIs, obfuscation detection
    4. Secrets Scanning - Hardcoded credentials, network endpoints
    5. Native Analysis - .so file inspection (future)
    6. Network Audit - Certificate pinning, endpoints (future)
    
    Optional Phase 7: LLM Classification (requires --anthropic-key)
    """
    apk_path = Path(apk).resolve()
    out_dir = Path(out).resolve()
    
    if not apk_path.exists():
        console.print(f"[red]ERROR: APK not found: {apk_path}[/red]")
        sys.exit(1)
    
    # Show banner
    _show_banner()
    
    # Create output directory
    out_dir.mkdir(parents=True, exist_ok=True)
    
    console.print(f"[cyan]APK: {apk_path.name}[/cyan] ({apk_path.stat().st_size / (1024*1024):.2f} MB)")
    console.print(f"[cyan]Output: {out_dir}[/cyan]")
    console.print(f"[cyan]Parallel: {not serial}[/cyan]")
    console.print()
    
    try:
        # Import here to avoid dependency issues
        from ..analysers import (
            UnpackAnalyser,
            ManifestAnalyser,
            APIAnalyser,
            SignatureAnalyser,
            SecretsAnalyser,
        )
        from ..core.orchestrator import Orchestrator
        from ..core.result_store import ResultStore
        
        # Create work directory
        work_dir = out_dir / "work"
        work_dir.mkdir(exist_ok=True)
        
        # Initialize orchestrator
        orchestrator = Orchestrator(
            apk_path=str(apk_path),
            out_dir=str(out_dir),
            parallel=not serial
        )
        
        # Create analysers
        analysers = [
            UnpackAnalyser(str(apk_path), str(work_dir)),
            ManifestAnalyser(str(apk_path), str(work_dir)),
            APIAnalyser(str(apk_path), str(work_dir)),
            SignatureAnalyser(str(apk_path), str(work_dir)),
            SecretsAnalyser(str(apk_path), str(work_dir)),
        ]
        
        # Run analysis with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Running analysis phases...", total=None)
            
            # Execute orchestrator
            all_findings = orchestrator.run_phases(analysers)
            
            progress.stop_task(task)
        
        # Report results
        console.print()
        _report_findings(all_findings, out_dir)
        
        # Generate report
        console.print()
        console.print("[cyan]Generating reports...[/cyan]")
        
        if format == "json":
            _export_json(all_findings, out_dir)
            console.print(f"[green]✓ JSON report: {out_dir}/report.json[/green]")
        elif format == "html":
            _export_html(all_findings, out_dir)
            console.print(f"[green]✓ HTML report: {out_dir}/report.html[/green]")
        
        console.print(f"[green]✓ Results stored in: {out_dir}[/green]")
        console.print(f"[cyan]Database: {out_dir}/results.db[/cyan]")
        
    except Exception as e:
        console.print(f"[red]ERROR: {str(e)}[/red]")
        import traceback
        if console._legacy_windows:
            traceback.print_exc()
        else:
            console.print_exception()
        sys.exit(1)


@cli.command()
@click.option(
    "--db",
    type=click.Path(exists=True),
    required=True,
    help="Path to results.db"
)
@click.option(
    "--phase",
    type=str,
    help="Filter by phase (unpack, manifest, api, signature, secrets)"
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    help="Filter by severity"
)
def query(db: str, phase: Optional[str], severity: Optional[str]):
    """
    Query results from analysis database.
    """
    try:
        from ..core.result_store import ResultStore
        
        store = ResultStore(db)
        
        # Build query
        findings = store.query(phase=phase, severity=severity)
        
        if not findings:
            console.print("[yellow]No findings found[/yellow]")
            return
        
        # Group by phase
        by_phase = {}
        for finding in findings:
            phase_name = finding.phase
            if phase_name not in by_phase:
                by_phase[phase_name] = []
            by_phase[phase_name].append(finding)
        
        # Display results
        for phase_name, phase_findings in sorted(by_phase.items()):
            console.print(f"\n[bold cyan]{phase_name.upper()}[/bold cyan]")
            for finding in phase_findings:
                severity_color = {
                    "critical": "red",
                    "high": "bright_red",
                    "medium": "yellow",
                    "low": "blue",
                    "info": "green"
                }.get(finding.severity, "white")
                
                console.print(f"  [{severity_color}]{finding.severity.upper()}[/{severity_color}] {finding.title}")
                console.print(f"    {finding.detail}")
                if finding.evidence:
                    console.print(f"    Evidence: {', '.join(finding.evidence[:3])}")
    
    except Exception as e:
        console.print(f"[red]ERROR: {str(e)}[/red]")
        sys.exit(1)


def _show_banner():
    """Display Darlene-X banner."""
    banner = """
    ╔═══════════════════════════════════════╗
    ║     DARLENE-X v2.0 - APK Analyzer     ║
    ║   Refactored Architecture Framework   ║
    ╚═══════════════════════════════════════╝
    """
    console.print(Panel(banner.strip(), style="cyan"))


def _report_findings(findings, out_dir):
    """Generate and display findings summary."""
    # Group by severity
    by_severity = {}
    by_phase = {}
    
    for finding in findings:
        severity = finding.severity
        phase = finding.phase
        
        if severity not in by_severity:
            by_severity[severity] = 0
        by_severity[severity] += 1
        
        if phase not in by_phase:
            by_phase[phase] = 0
        by_phase[phase] += 1
    
    # Display summary
    severity_order = ["critical", "high", "medium", "low", "info"]
    summary_text = "SUMMARY: "
    for sev in severity_order:
        if sev in by_severity:
            color_map = {
                "critical": "red",
                "high": "bright_red",
                "medium": "yellow",
                "low": "blue",
                "info": "green"
            }
            summary_text += f"[{color_map.get(sev)}]{sev.upper()} {by_severity[sev]}[/{color_map.get(sev)}] "
    
    console.print(summary_text)
    console.print()
    
    # Top findings
    console.print("[bold]TOP FINDINGS:[/bold]")
    critical = [f for f in findings if f.severity == "critical"]
    for finding in critical[:5]:
        console.print(f"  [red]●[/red] {finding.title}")


def _export_json(findings, out_dir):
    """Export findings as JSON."""
    import json
    
    out_file = out_dir / "report.json"
    data = {
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings]
    }
    
    with open(out_file, "w") as f:
        json.dump(data, f, indent=2)


def _export_html(findings, out_dir):
    """Export findings as HTML (basic)."""
    out_file = out_dir / "report.html"
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Darlene-X Analysis Report</title>
        <style>
            body { font-family: Arial; margin: 20px; }
            .critical { color: red; font-weight: bold; }
            .high { color: orangered; font-weight: bold; }
            .medium { color: orange; }
            .low { color: blue; }
            .finding { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <h1>Darlene-X APK Analysis Report</h1>
    """
    
    by_phase = {}
    for finding in findings:
        if finding.phase not in by_phase:
            by_phase[finding.phase] = []
        by_phase[finding.phase].append(finding)
    
    for phase, phase_findings in sorted(by_phase.items()):
        html += f"<h2>{phase.upper()}</h2>"
        for finding in phase_findings:
            html += f"""
            <div class="finding">
                <p class="{finding.severity}">{finding.severity.upper()}: {finding.title}</p>
                <p>{finding.detail}</p>
                {f'<p>Evidence: {", ".join(finding.evidence[:3])}</p>' if finding.evidence else ''}
            </div>
            """
    
    html += """
    </body>
    </html>
    """
    
    with open(out_file, "w") as f:
        f.write(html)


if __name__ == "__main__":
    cli()
