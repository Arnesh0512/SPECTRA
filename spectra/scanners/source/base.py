"""
spectra.scanners.source.base
=================================
Abstract base class and data schemas for source code cryptographic scanners.
Guarantees identical finding structures across all supported programming languages.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
import subprocess
from spectra.utils.shell import command_exists, run_command
from .rules import RuleEngine, DEFAULT_RULE_ENGINE


@dataclass
class SourceFinding:
    """Standardized finding representation produced by any source code or dependency scanner."""
    source_domain: str = "source_code"
    language: str = ""
    file_path: str = ""
    line_number: int = 0
    column_number: int = 0
    code_snippet: str = ""
    primitive: str = "unknown"
    algorithm: str = "unknown"
    key_size: Optional[int] = None
    mode: Optional[str] = None
    padding: Optional[str] = None
    curve: Optional[str] = None
    operation: Optional[str] = None
    quantum_safe: bool = False
    nist_status: str = "unknown"
    # Call-graph & LOC metrics for dynamic Y calculation
    direct_calls: int = 0
    transitive_calls: int = 0
    call_depth: int = 0
    loc: int = 0
    security_findings: List[Dict[str, str]] = field(default_factory=list)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts finding dataclass to a plain serializable dictionary."""
        return {
            "source_domain": self.source_domain,
            "language": self.language,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "code_snippet": self.code_snippet,
            "primitive": self.primitive,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "mode": self.mode,
            "padding": self.padding,
            "curve": self.curve,
            "operation": self.operation,
            "quantum_safe": self.quantum_safe,
            "nist_status": self.nist_status,
            "direct_calls": self.direct_calls,
            "transitive_calls": self.transitive_calls,
            "call_depth": self.call_depth,
            "loc": self.loc,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata
        }


class BaseSourceScanner(ABC):
    """Abstract base class that all language parsers must implement."""

    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        self.rule_engine = rule_engine or DEFAULT_RULE_ENGINE

    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """Returns list of file extensions handled by this scanner."""
        pass

    @abstractmethod
    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        """Parses a single source file and returns discovered cryptographic operations."""
        pass

    def extract_snippet(self, file_path: Path, line_number: int, context: int = 1) -> str:
        """Reads surrounding lines of code to provide context for the finding."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            start = max(0, line_number - 1 - context)
            end = min(len(lines), line_number + context)
            return "".join(lines[start:end]).strip()
        except Exception:
            return ""

    def compute_call_metrics(self, file_path: Path, symbol_name: str) -> tuple[int, int, int, int]:
        """
        Calculates file LOC and uses ripgrep to trace direct callers and recursive 
        transitive upstream callers (blast radius).
        """
        # 1. Calculate file Lines of Code (LOC)
        loc = 0
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                loc = len(f.readlines())
        except Exception:
            loc = 10

        if not symbol_name:
            return 0, 0, 0, loc

        project_root = file_path.parent.parent
        direct_call_files: Set[str] = set()
        transitive_call_files: Set[str] = set()
        
        # Fallback to python fallback walker or ripgrep execution
        if not command_exists("rg"):
            return 0, 0, 0, loc

        # Step 2: Find direct callers referencing symbol_name or importing the module file stem
        file_stem = file_path.stem
        search_terms = [symbol_name, file_stem]
        
        queue = set()
        visited_files = {str(file_path.resolve())}

        for term in search_terms:
            if len(term) < 2:
                continue
            cmd = ["rg", "-w", "--no-heading", "--line-number", term, str(project_root)]
            code, stdout, _ = run_command(cmd)
            if code in (0, 1) and stdout:
                for line in stdout.splitlines():
                    parts = line.split(":", 2)
                    if len(parts) >= 2:
                        matched_file = str(Path(parts[0]).resolve())
                        if matched_file not in visited_files:
                            direct_call_files.add(matched_file)
                            queue.add(matched_file)
                            visited_files.add(matched_file)

        direct_calls_count = len(direct_call_files)

        # Step 3: Recursively trace transitive callers (upstream functions calling the callers) via BFS
        current_depth = 1 if direct_calls_count > 0 else 0
        max_depth = current_depth

        while queue and current_depth < 4:  # Limit depth to 4 levels to maintain high scan performance
            next_queue = set()
            for caller_file in queue:
                caller_stem = Path(caller_file).stem
                if len(caller_stem) < 2:
                    continue
                
                cmd = ["rg", "-w", "--no-heading", caller_stem, str(project_root)]
                code, stdout, _ = run_command(cmd)
                if code in (0, 1) and stdout:
                    for line in stdout.splitlines():
                        parts = line.split(":", 2)
                        if len(parts) >= 1:
                            upstream_file = str(Path(parts[0]).resolve())
                            if upstream_file not in visited_files:
                                visited_files.add(upstream_file)
                                transitive_call_files.add(upstream_file)
                                next_queue.add(upstream_file)
            
            if next_queue:
                current_depth += 1
                max_depth = max(max_depth, current_depth)
                queue = next_queue
            else:
                break

        return direct_calls_count, len(transitive_call_files), max_depth, loc