"""
spectra.scanners.source.base
=================================
Abstract base class and data schemas for source code cryptographic scanners.
Guarantees identical finding structures across all supported programming languages.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
from .rules import RuleEngine, DEFAULT_RULE_ENGINE


@dataclass
class SourceFinding:
    """Standardized finding representation produced by any source code scanner."""
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
    quantum_safe: bool = False
    nist_status: str = "unknown"
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
            "quantum_safe": self.quantum_safe,
            "nist_status": self.nist_status,
            "security_findings": self.security_findings,
            "raw_metadata": self.raw_metadata
        }


class BaseSourceScanner(ABC):
    """Abstract base class that all language parsers must implement."""

    def __init__(self, rule_engine: Optional[RuleEngine] = None):
        self.rule_engine = rule_engine or DEFAULT_RULE_ENGINE

    @abstractmethod
    def supported_extensions(self) -> List[str]:
        """Returns list of file extensions handled by this scanner (e.g., ['.py'])."""
        pass

    @abstractmethod
    def parse_file(self, file_path: Path) -> List[SourceFinding]:
        """
        Parses a single source file and returns discovered cryptographic operations.
        Must handle parser syntax errors gracefully without raising unhandled exceptions.
        """
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