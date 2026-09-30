"""
spectra.utils
====================
Utility modules for terminal logging, Rich banners, and safe shell execution.
"""

from .logger import (
    console,
    BANNER,
    setup_logger,
    logger,
    print_banner,
    log_step,
    log_info,
    log_success,
    log_warning,
    log_error,
    log_header,
)
from .shell import (
    command_exists,
    get_command_path,
    run_command,
    extract_printable_strings,
)
from .docker_client import (
    DockerContainerClient,
    UnixSocketHTTPConnection,
)

__all__ = [
    "console",
    "BANNER",
    "setup_logger",
    "logger",
    "print_banner",
    "log_step",
    "log_info",
    "log_success",
    "log_warning",
    "log_error",
    "log_header",
    "command_exists",
    "get_command_path",
    "run_command",
    "extract_printable_strings",
    "DockerContainerClient",
    "UnixSocketHTTPConnection",
]