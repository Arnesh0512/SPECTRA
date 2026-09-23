"""
crypto_recon.scanners.source.rules
==================================
Loads and caches declarative YAML detection rules for algorithms,
libraries, and language-specific invocation patterns.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Pattern
import re
import yaml


@dataclass
class AlgorithmRule:
    id: str
    name: str
    primitive: str
    quantum_safe: bool
    nist_status: str
    patterns: List[str] = field(default_factory=list)
    weak_modes: List[str] = field(default_factory=list)
    compiled_patterns: List[Pattern] = field(default_factory=list)

    def __post_init__(self):
        self.compiled_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.patterns
        ]


@dataclass
class LibraryCallPattern:
    call: Optional[str] = None
    class_name: Optional[str] = None
    method: Optional[str] = None
    algo_id: Optional[str] = None
    default_algo_id: Optional[str] = None
    flag_insecure: bool = False
    flag_insecure_modes: List[str] = field(default_factory=list)
    flag_insecure_algorithms: List[str] = field(default_factory=list)
    extract_args: Dict[str, str] = field(default_factory=dict)
    extract_transformation: Dict[str, str] = field(default_factory=dict)
    extract_algorithm: Dict[str, str] = field(default_factory=dict)
    extract_algorithm_param: Optional[str] = None
    flag_insecure_if: Dict[str, int] = field(default_factory=dict)


@dataclass
class LibraryRule:
    name: str
    imports: List[str] = field(default_factory=list)
    headers: List[str] = field(default_factory=list)
    call_patterns: List[LibraryCallPattern] = field(default_factory=list)


class RuleEngine:
    """Singleton-style rule manager that caches parsed YAML rule definitions."""

    def __init__(self, rules_dir: Optional[Path] = None):
        if rules_dir is None:
            rules_dir = Path(__file__).resolve().parent / "rules"
        self.rules_dir = rules_dir
        self.algorithms: Dict[str, AlgorithmRule] = {}
        self.libraries_by_language: Dict[str, List[LibraryRule]] = {}
        self.load_rules()

    def load_rules(self) -> None:
        """Parses algorithms.yaml and all libraries_*.yaml files."""
        # 1. Universal Algorithms
        algo_file = self.rules_dir / "algorithms.yaml"
        if algo_file.exists():
            with open(algo_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                for item in data.get("algorithms", []):
                    algo = AlgorithmRule(
                        id=item["id"],
                        name=item["name"],
                        primitive=item["primitive"],
                        quantum_safe=item.get("quantum_safe", False),
                        nist_status=item.get("nist_status", "unknown"),
                        patterns=item.get("patterns", []),
                        weak_modes=item.get("weak_modes", [])
                    )
                    self.algorithms[algo.id] = algo

        # 2. Language-Specific Library Rules
        for lib_file in self.rules_dir.glob("libraries_*.yaml"):
            lang = lib_file.stem.replace("libraries_", "")
            with open(lib_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                rules: List[LibraryRule] = []
                for lib_entry in data.get("libraries", []):
                    call_patterns = []
                    for cp in lib_entry.get("call_patterns", []):
                        call_patterns.append(LibraryCallPattern(
                            call=cp.get("call"),
                            class_name=cp.get("class"),
                            method=cp.get("method"),
                            algo_id=cp.get("algo_id"),
                            default_algo_id=cp.get("default_algo_id"),
                            flag_insecure=cp.get("flag_insecure", False),
                            flag_insecure_modes=cp.get("flag_insecure_modes", []),
                            flag_insecure_algorithms=cp.get("flag_insecure_algorithms", []),
                            extract_args=cp.get("extract_args", {}),
                            extract_transformation=cp.get("extract_transformation", {}),
                            extract_algorithm=cp.get("extract_algorithm", {}),
                            extract_algorithm_param=cp.get("extract_algorithm_param"),
                            flag_insecure_if=cp.get("flag_insecure_if", {})
                        ))
                    rules.append(LibraryRule(
                        name=lib_entry.get("name", "unnamed"),
                        imports=lib_entry.get("imports", []),
                        headers=lib_entry.get("headers", []),
                        call_patterns=call_patterns
                    ))
                self.libraries_by_language[lang] = rules

    def match_algorithm_by_name_or_pattern(self, query: str) -> Optional[AlgorithmRule]:
        """Tries to map an algorithm string or constant name to a known AlgorithmRule."""
        clean_q = query.strip()
        for algo in self.algorithms.values():
            if algo.name.lower() == clean_q.lower() or algo.id.lower() == clean_q.lower():
                return algo
            for pattern in algo.compiled_patterns:
                if pattern.search(clean_q):
                    return algo
        return None

    def get_library_rules_for_language(self, language: str) -> List[LibraryRule]:
        """Returns loaded rules for a given language domain (python, jvm, js_ts, compiled)."""
        return self.libraries_by_language.get(language, [])


# Global shared instance
DEFAULT_RULE_ENGINE = RuleEngine()