"""
crypto_recon.utils.logger
=========================
Centralized terminal logging, banners, and status output using Rich.
"""

import logging
from typing import Optional
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.text import Text

# Shared rich console instance
console = Console()


def setup_logger(verbose: bool = False) -> logging.Logger:
    """Configures the standard Python logging system with RichHandler."""
    log_level = logging.DEBUG if verbose else logging.INFO

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                console=console,
                rich_tracebacks=True,
                show_path=False,
                markup=True
            )
        ]
    )
    return logging.getLogger("crypto_recon")


logger = setup_logger()


def print_banner(version: str = "1.0.0") -> None:
    """Renders the CLI startup banner with quantum styling."""
    title = Text("CRYPTO-RECON", style="bold cyan")
    subtitle = Text(f"Enterprise Cryptographic Discovery & PQC Risk Engine (v{version})", style="italic white")
    panel_content = Text.assemble(title, "\n", subtitle)

    console.print(
        Panel(
            panel_content,
            border_style="bright_blue",
            expand=False,
            padding=(1, 4)
        )
    )


def log_step(step_name: str) -> None:
    """Prints a highlighted step indicator."""
    console.print(f"\n[bold green]➜[/bold green] [bold white]{step_name}[/bold white]")


def log_info(message: str) -> None:
    """Prints an informational message."""
    console.print(f"  [cyan]ℹ[/cyan] {message}")


def log_success(message: str) -> None:
    """Prints a success message."""
    console.print(f"  [bold green]✔[/bold green] {message}")


def log_warning(message: str) -> None:
    """Prints a warning message."""
    console.print(f"  [bold yellow]⚠[/bold yellow] {message}")


def log_error(message: str) -> None:
    """Prints an error message."""
    console.print(f"  [bold red]✖[/bold red] {message}")