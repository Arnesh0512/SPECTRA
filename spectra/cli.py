"""
spectra.cli
================
Interactive Terminal User Interface (TUI) command-line interface for Spectra.
Guides users through scan parameters, executes domain discovery with progress bars,
evaluates Mosca quantum risk across scenarios, and generates CycloneDX 1.6 CBOMs.
"""

from pathlib import Path
from typing import List, Optional
import sys

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
import typer

from spectra.config import ScanConfig, ScanTargets, ScannerToggles, SourceScannerConfig, NetworkConfig, OutputConfig
from spectra.engine import CryptoAnalysisEngine
from spectra.scanners import MasterScanner, ScanResults
from spectra.utils.logger import (
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
    fail_on_critical: bool = typer.Option(
        False,
        "--fail-on-critical",
        help="Return a non-zero exit code if CRITICAL vulnerabilities or breached Mosca inequalities are detected.",
    ),
) -> None:
    """Run an interactive TUI wizard to configure and execute a multi-domain cryptographic scan."""
    console.print(BANNER, style="bold cyan")

    # --- Interactive TUI Setup Wizard ---
    log_header("Step 1: Target & Output Configuration")
    target_str = Prompt.ask("Enter target codebase directory path", default=".")
    target_path = Path(target_str).resolve()
    
    output_str = Prompt.ask("Enter destination CBOM output file path", default="cbom.json")
    output_path = Path(output_str).resolve()

    log_header("Step 2: Source Code Exclusions & Options")
    default_excludes = ".git, node_modules, vendor, target, dist, build, .venv, venv, __pycache__"
    exclude_input = Prompt.ask(
        "Enter directories to exclude [dim](comma-separated)[/dim]",
        default=default_excludes
    )
    excluded_dirs = [d.strip() for d in exclude_input.split(",") if d.strip()]

    log_header("Step 3: Scanner Modules Configuration")
    console.print("[bold underline]Source Scanners Selection:[/bold underline]")
    scan_source = Confirm.ask("  ↳ Scan codebase source files", default=True)
    scan_deps = Confirm.ask("  ↳ Scan Depedency", default=True)

    console.print("\n[bold underline]Artifact Scanners Selection:[/bold underline]")
    scan_certs = Confirm.ask("  ↳ Scan X.509 Certificates (.pem, .crt)", default=True)
    scan_docker = Confirm.ask("  ↳ Scan Docker container files (Dockerfile, compose)", default=True)
    scan_binaries = Confirm.ask("  ↳ Scan binary executable files (.so, .dll, .exe)", default=True)
    scan_runtime_artifacts = Confirm.ask("  ↳ Scan runtime packages and processes", default=True)
    enable_artifacts = scan_certs or scan_docker or scan_binaries or scan_runtime_artifacts

    console.print("\n[bold underline]Infrastructure Scanners Selection:[/bold underline]")
    scan_terraform = Confirm.ask("  ↳ Scan Terraform / IaC configurations (.tf)", default=True)
    scan_cloud_hsm = Confirm.ask("  ↳ Scan Cloud KMS / HSM references (AWS/Azure)", default=True)
    enable_infra = scan_terraform or scan_cloud_hsm

    console.print("\n[bold underline]Network Domain Inspection:[/bold underline]")
    enable_network = Confirm.ask("Scan live remote TLS endpoints / web servers?", default=False)
    endpoints: List[str] = []
    if enable_network:
        endpoints_input = Prompt.ask("Enter domain endpoints [dim](comma-separated, e.g., example.com:443, api.internal:443)[/dim]", default="")
        endpoints = [e.strip() for e in endpoints_input.split(",") if e.strip()]

    # --- Build ScanConfig Programmatically ---
    config = ScanConfig(
        scan_targets=ScanTargets(
            project_root=str(target_path),
            domains=endpoints,
            nginx_config_paths=[]
        ),
        scanners=ScannerToggles(
            enable_source=scan_source,
            enable_artifacts=enable_artifacts,
            enable_runtime=scan_runtime_artifacts,
            enable_infrastructure=enable_infra,
            enable_network=enable_network,
            scan_dependencies=scan_deps,
        ),
        source_scanner=SourceScannerConfig(
            use_ripgrep=True,  # Always true
            excluded_directories=excluded_dirs
        ),
        network=NetworkConfig(endpoints=endpoints),
        output=OutputConfig(output_file=str(output_path))
    )

    log_header("Step 4: Executing Multi-Domain Reconnaissance")
    scanner = MasterScanner(config)

    # Execute scanners with Rich Progress Bar per step
    with Progress(
        SpinnerColumn("dots", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        
        task_init = progress.add_task("[cyan]Initializing scanners & credential discovery...", total=100)
        progress.update(task_init, advance=100)

        task_scan = progress.add_task("[green]Running AST, Dependency, & Domain Scanners...", total=100)
        results: ScanResults = scanner.scan_all(
            target_dir=target_path,
            endpoints=endpoints,
        )
        progress.update(task_scan, advance=100)

    if results.total_count == 0:
        log_warning("No cryptographic primitives, artifacts, or configs detected in scan scope.")
        return

    log_success(f"Discovered {results.total_count} raw cryptographic finding(s) across domains.")

    # --- Engine Processing & CBOM Synthesis with Progress Bars ---
    with Progress(
        SpinnerColumn("monkey", style="magenta"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        
        task_engine = progress.add_task("[magenta]Executing Crypto Analysis, COCOMO Sizing, & Mosca Evaluation...", total=100)
        engine = CryptoAnalysisEngine(config)
        cbom, correlated, mosca_evals = engine.process(
            raw_findings=results.all_findings,
            output_file=output_path,
            target_dir=target_path,
        )
        progress.update(task_engine, advance=100)

    # --- Render Summary Tables ---
    _print_findings_summary(correlated)
    _print_quantum_risk_summary(mosca_evals)

    log_success(f"CycloneDX 1.6 CBOM successfully generated and saved to: {output_path}")

    # Check failure conditions
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
    """Displays separate Mosca quantum risk assessment tables for Optimistic, Central, and Pessimistic scenarios."""
    scenarios = ["optimistic", "central", "pessimistic"]
    levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "QUANTUM_SAFE"]

    for scenario in scenarios:
        table = Table(title=f"Mosca Quantum Risk Assessment ({scenario.capitalize()} Scenario)")
        table.add_column("Risk Level", style="bold", width=16)
        table.add_column("Count", justify="center", width=10)
        table.add_column("SNDL Exposed", justify="center", width=16)
        table.add_column("PQC Action Required", width=40)

        has_rows = False
        for lvl in levels:
            matches = [m for m in mosca_evals.values() if getattr(m, "scenario_name", "central") == scenario and m.risk_level == lvl]
            count = len(matches)
            if count == 0:
                continue
            
            has_rows = True
            sndl_count = sum(1 for m in matches if m.sndl_vulnerable)
            style = "red" if lvl in ["CRITICAL", "HIGH"] else ("yellow" if lvl == "MEDIUM" else "green")
            sample_remediation = matches[0].recommended_pqc_replacement if matches else "None"

            table.add_row(
                f"[{style}]{lvl}[/{style}]",
                str(count),
                str(sndl_count),
                sample_remediation[:39],
            )

        if has_rows:
            console.print(table)
            console.print()  # Spacing between tables


def main() -> None:
    """Console script entry point."""
    app()


if __name__ == "__main__":
    main()