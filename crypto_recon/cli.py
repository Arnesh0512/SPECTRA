"""
crypto_recon.cli
================
Command-line interface entry point for crypto-recon.
Coordinates target directory audits, live endpoint scans, Mosca quantum risk analysis,
and CycloneDX 1.6 CBOM JSON generation.
"""

from pathlib import Path
from typing import List, Optional
import sys

from rich.console import Console
from rich.table import Table
import typer

from crypto_recon.config import ScanConfig
from crypto_recon.engine import CryptoAnalysisEngine
from crypto_recon.scanners import MasterScanner, ScanResults
from crypto_recon.utils.logger import (
    BANNER,
    console,
    log_error,
    log_header,
    log_info,
    log_step,
    log_success,
    log_warning,
)

app = typer.Typer(
    name="crypto-recon",
    help="Enterprise Multi-Domain Cryptographic Inventory & CycloneDX 1.6 CBOM Generator",
    add_completion=False,
)


@app.command()
def scan(
    target: Path = typer.Option(
        Path("."),
        "--target",
        "-t",
        help="Root path of codebase/system to scan.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    output: Path = typer.Option(
        Path("cbom.json"),
        "--output",
        "-o",
        help="Destination path for CycloneDX 1.6 CBOM JSON document.",
        resolve_path=True,
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to custom config.yaml configuration file.",
        resolve_path=True,
    ),
    endpoint: Optional[List[str]] = typer.Option(
        None,
        "--endpoint",
        "-e",
        help="Network endpoint(s) to scan via live TLS handshake (e.g. example.com:443). Can be repeated.",
    ),
    fail_on_critical: bool = typer.Option(
        False,
        "--fail-on-critical",
        help="Return a non-zero exit code if CRITICAL cryptographic vulnerabilities or breached Mosca inequalities are detected.",
    ),
) -> None:
    """Run an end-to-end multi-domain cryptographic scan and export a CycloneDX 1.6 CBOM."""
    console.print(BANNER, style="bold cyan")
    log_header("Initializing Reconnaissance Engine")

    # 1. Load Configuration
    if config_file and config_file.is_file():
        log_info(f"Loading custom configuration from: {config_file}")
        config = ScanConfig.load(config_file)
    else:
        config = ScanConfig()

    # Override endpoints if passed via CLI
    if endpoint:
        config.network.endpoints = endpoint

    # 2. Execute Scanners across all domains
    scanner = MasterScanner(config)
    results: ScanResults = scanner.scan_all(
        target_dir=target,
        endpoints=config.network.endpoints,
    )

    if results.total_count == 0:
        log_warning("No cryptographic primitives, artifacts, or configs detected in scan scope.")
        return

    # 3. Normalize, Correlate, Evaluate Mosca, and Build CBOM
    engine = CryptoAnalysisEngine(config)
    cbom, correlated, mosca_evals = engine.process(
        raw_findings=results.all_findings,
        output_file=output,
    )

    # 4. Render Summary Tables
    _print_findings_summary(correlated)
    _print_quantum_risk_summary(mosca_evals)

    log_success(f"CycloneDX 1.6 CBOM successfully generated: {output}")

    # 5. Check failure conditions
    critical_breaches = any(
        m.risk_level == "CRITICAL" for m in mosca_evals.values()
    ) or any(
        any(f.get("severity") == "CRITICAL" for f in a.primary_asset.security_findings)
        for a in correlated
    )

    if fail_on_critical and critical_breaches:
        log_error("Critical cryptographic or quantum risks discovered. Exiting with status code 1.")
        sys.exit(1)


@app.command()
def mosca(
    target_year: int = typer.Option(
        2033,
        "--year",
        "-y",
        help="Target year for Cryptanalytically Relevant Quantum Computer (CRQC) realization.",
    ),
    shelf_life: int = typer.Option(
        7,
        "--shelf-life",
        "-x",
        help="Required data confidentiality shelf-life horizon (years).",
    ),
    migration_time: int = typer.Option(
        3,
        "--migration-time",
        "-m",
        help="Estimated time needed to complete post-quantum migration (years).",
    ),
) -> None:
    """Print an interactive Mosca Theorem inequality status report."""
    console.print(BANNER, style="bold cyan")
    log_header("Mosca's Theorem Quantum Risk Model Evaluation")

    current_year = 2026
    z = max(1, target_year - current_year)
    breached = (shelf_life + migration_time) > z

    table = Table(title="Mosca Inequality Parameters (X + Y > Z)")
    table.add_column("Parameter", style="cyan", justify="left")
    table.add_column("Value", style="bold white", justify="center")
    table.add_column("Description", style="white", justify="left")

    table.add_row("X (Shelf-Life)", f"{shelf_life} yrs", "Required data confidentiality horizon")
    table.add_row("Y (Migration Time)", f"{migration_time} yrs", "Time needed to re-engineer & deploy PQC")
    table.add_row("Z (Collapse Horizon)", f"{z} yrs", f"Years remaining until CRQC ({target_year})")
    table.add_row(
        "Inequality (X + Y > Z)",
        f"{shelf_life + migration_time} > {z}",
        "[bold red]BREACHED[/bold red]" if breached else "[bold green]SAFE[/bold green]",
    )

    console.print(table)
    if breached:
        log_error("Urgent Action Required: Classical key exchanges are vulnerable to Store-Now-Decrypt-Later (SNDL) attacks.")
    else:
        log_info("Inequality currently holds. Proactive quantum-safe roadmapping recommended.")


@app.command()
def version() -> None:
    """Display tool version and specification compliance."""
    console.print("[bold cyan]crypto-recon[/bold cyan] version [bold white]1.0.0[/bold white]")
    console.print("CycloneDX Specification: [bold green]1.6 (Cryptographic Properties CBOM)[/bold green]")
    console.print("PQC Standards: [bold green]NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)[/bold green]")


def _print_findings_summary(correlated_assets: list) -> None:
    """Displays a summary table of correlated cryptographic assets."""
    table = Table(title="Discovered Cryptographic Assets")
    table.add_column("Domain", style="cyan", width=12)
    table.add_column("Asset Name", style="bold white", width=30)
    table.add_column("Algorithm / Primitive", style="magenta", width=25)
    table.add_column("Location", style="dim white", width=40)
    table.add_column("Findings", style="red", width=10)

    for item in correlated_assets[:25]:  # Show top 25
        asset = item.primary_asset
        issues_count = len(asset.security_findings)
        issues_str = f"[bold red]{issues_count}[/bold red]" if issues_count > 0 else "[green]0[/green]"
        table.add_row(
            asset.source_domain,
            asset.name[:28],
            f"{asset.algorithm} ({asset.primitive})"[:24],
            asset.location[-38:],
            issues_str,
        )

    console.print(table)
    if len(correlated_assets) > 25:
        log_info(f"...and {len(correlated_assets) - 25} additional asset(s) indexed in full CBOM output.")


def _print_quantum_risk_summary(mosca_evals: dict) -> None:
    """Displays a summary table of Mosca quantum evaluations."""
    table = Table(title="Mosca Quantum Risk Assessment Summary")
    table.add_column("Risk Level", style="bold", width=14)
    table.add_column("Count", justify="center", width=8)
    table.add_column("SNDL Exposed", justify="center", width=14)
    table.add_column("PQC Action Required", width=45)

    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "QUANTUM_SAFE"]
    for lvl in levels:
        matches = [m for m in mosca_evals.values() if m.risk_level == lvl]
        count = len(matches)
        if count == 0:
            continue
        sndl_count = sum(1 for m in matches if m.sndl_vulnerable)
        style = "red" if lvl in ["CRITICAL", "HIGH"] else ("yellow" if lvl == "MEDIUM" else "green")

        sample_remediation = matches[0].recommended_pqc_replacement if matches else "None"
        table.add_row(
            f"[{style}]{lvl}[/{style}]",
            str(count),
            str(sndl_count),
            sample_remediation[:44],
        )

    console.print(table)


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()