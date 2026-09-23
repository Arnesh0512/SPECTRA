"""
spectra.utils.shell
========================
Safe subprocess execution wrappers and binary resolution helpers.
Provides unified execution for shell tools (rg, readelf, ldd, strings)
with timeout protection and non-zero exit code tolerance.
"""

import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple


def command_exists(command_name: str) -> bool:
    """Checks if an executable binary is present in the host system PATH."""
    return shutil.which(command_name) is not None


def get_command_path(command_name: str) -> Optional[str]:
    """Returns the full resolved path of a binary if found in PATH, else None."""
    return shutil.which(command_name)


def run_command(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 60,
    check: bool = False
) -> Tuple[int, str, str]:
    """
    Safely executes an external command.

    Returns:
        Tuple of (exit_code, stdout_string, stderr_string)
    """
    binary = cmd[0]
    if not command_exists(binary):
        return -1, "", f"Executable '{binary}' was not found in system PATH."

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=check
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -2, "", f"Command '{' '.join(cmd)}' timed out after {timeout} seconds."
    except Exception as exc:
        return -3, "", f"Execution failure for '{' '.join(cmd)}': {str(exc)}"


def extract_printable_strings(file_path: Path, min_length: int = 4, limit: int = 50000) -> List[str]:
    """
    Extracts printable ASCII/UTF-8 strings from binary files.
    Prefers system 'strings' binary for performance, with a pure Python fallback.
    """
    if command_exists("strings"):
        code, stdout, _ = run_command(["strings", "-n", str(min_length), str(file_path)])
        if code == 0:
            lines = stdout.splitlines()
            return lines[:limit]

    # Pure Python fallback
    collected_strings: List[str] = []
    current_chars: List[str] = []

    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024 * 1024)  # 1MB limit for safety
            for byte in chunk:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_chars.append(chr(byte))
                else:
                    if len(current_chars) >= min_length:
                        collected_strings.append("".join(current_chars))
                        if len(collected_strings) >= limit:
                            break
                    current_chars = []
            if len(current_chars) >= min_length:
                collected_strings.append("".join(current_chars))
    except Exception:
        return []

    return collected_strings