"""
spectra.scanners.source
============================
Unified source code scanner coordinating dynamic rule-driven pre-filtering (ripgrep),
language-specific AST parsers, and project manifest dependency scanning.
"""

from pathlib import Path
import re
from typing import Dict, List, Set, Optional

from spectra.config import ScanConfig
from spectra.utils.logger import log_info, log_step, log_warning
from spectra.utils.shell import command_exists, run_command

from .base import BaseSourceScanner, SourceFinding
from .python_scanner import PythonASTScanner
from .jvm_scanner import JVMScanner
from .js_ts_scanner import JSTSSParser
from .cpp_scanner import CPPScanner
from .go_scanner import GoScanner
from .rust_scanner import RustScanner
from .dependency_scanner import DependencyScanner
from .rules import DEFAULT_RULE_ENGINE, RuleEngine


class SourceScanOrchestrator:
    """Manages discovery and AST/manifest dispatch across all supported source code files."""

    def __init__(self, config: ScanConfig, rule_engine: RuleEngine = DEFAULT_RULE_ENGINE):
        self.config = config
        self.rule_engine = rule_engine
        self.scanners: List[BaseSourceScanner] = [
            PythonASTScanner(rule_engine=self.rule_engine),
            JVMScanner(rule_engine=self.rule_engine),
            JSTSSParser(rule_engine=self.rule_engine),
            CPPScanner(rule_engine=self.rule_engine),
            GoScanner(rule_engine=self.rule_engine),
            RustScanner(rule_engine=self.rule_engine),
        ]
        self.ext_to_scanner: Dict[str, BaseSourceScanner] = {}
        self.ecosystem_to_scanner: Dict[str, BaseSourceScanner] = {}
        
        for scanner in self.scanners:
            for ext in scanner.supported_extensions():
                self.ext_to_scanner[ext] = scanner
            
            lang_name = scanner.__class__.__name__.lower()
            if "python" in lang_name:
                self.ecosystem_to_scanner["python"] = scanner
            elif "js" in lang_name:
                self.ecosystem_to_scanner["javascript"] = scanner
                self.ecosystem_to_scanner["typescript"] = scanner
            elif "go" in lang_name:
                self.ecosystem_to_scanner["go"] = scanner
            elif "jvm" in lang_name:
                self.ecosystem_to_scanner["java"] = scanner
                self.ecosystem_to_scanner["kotlin"] = scanner
            elif "rust" in lang_name:
                self.ecosystem_to_scanner["rust"] = scanner
            elif "cpp" in lang_name:
                self.ecosystem_to_scanner["cpp"] = scanner

        self.dependency_scanner = DependencyScanner()

        # Build dynamic regex pattern for pre-filtering
        self.dynamic_crypto_regex = self._build_dynamic_regex()

    def scan(self, target_dir: Path) -> List[SourceFinding]:
        """Executes the complete multi-tier scan pipeline on the target directory."""
        log_step(f"Scanning source code in: {target_dir}")
        all_findings: List[SourceFinding] = []
        excluded = self.config.source_scanner.excluded_directories

        # 1. Dependency Analysis & Deep Disk/Function Scanning (Phase 2)
        dep_findings = self.dependency_scanner.scan_directory(
            target_dir, 
            excluded_dirs=excluded, 
            scanners_map=self.ecosystem_to_scanner
        )
        log_info(f"Discovered {len(dep_findings)} crypto dependency declaration(s) and function mappings.")
        all_findings.extend(dep_findings)

        # 2. Tier 1: Discover candidate files with crypto signatures
        candidate_files = self._find_candidates(target_dir)
        log_info(f"Identified {len(candidate_files)} candidate crypto source file(s) for deep analysis.")

        # 3. Tier 2: Deep AST / syntax analysis
        for file_path in candidate_files:
            ext = file_path.suffix.lower()
            scanner = self.ext_to_scanner.get(ext)
            if scanner:
                findings = scanner.parse_file(file_path)
                all_findings.extend(findings)

        log_info(f"Source scan completed with {len(all_findings)} finding(s).")
        return all_findings

    def _find_candidates(self, target_dir: Path) -> Set[Path]:
        """Finds candidate files via ripgrep if enabled/available, else uses Python fallback."""
        if self.config.source_scanner.use_ripgrep and command_exists("rg"):
            return self._run_ripgrep_filter(target_dir)
        return self._run_python_fallback_filter(target_dir)

    def _build_dynamic_regex(self) -> str:
        """
        Dynamically derives regex search tokens from all registered YAML rules
        and component catalogs.
        """
        raw_tokens: Set[str] = set()

        # 1. Pull imports and headers from loaded YAML libraries
        for lang, lib_rules in self.rule_engine.libraries_by_language.items():
            for lib in lib_rules:
                for imp in lib.imports:
                    raw_tokens.add(imp.split(".")[0])
                    raw_tokens.add(imp.replace(".", r"[/\\.]"))
                for hdr in lib.headers:
                    raw_tokens.add(hdr.replace("/", r"[/\\.]"))

                for cp in lib.call_patterns:
                    if cp.class_name:
                        raw_tokens.add(cp.class_name)
                    if cp.call and "." in cp.call:
                        raw_tokens.add(cp.call.split(".")[0])

        # 2. Ingest catalog anchors from dependencies rules
        for pkg in self.dependency_scanner.catalog:
            raw_tokens.add(pkg["name"])
            for alias in pkg.get("aliases", []):
                raw_tokens.add(alias)

        sorted_tokens = sorted(
            [re.escape(t).replace(r"\[/\\\.\]", r"[/\\.]") for t in raw_tokens if len(t) >= 3],
            key=len,
            reverse=True
        )
        return r"\b(" + "|".join(sorted_tokens) + r")"

    def _run_ripgrep_filter(self, target_dir: Path) -> Set[Path]:
        """Executes optimized ripgrep subprocess with exclusion and multiline matching."""
        candidates: Set[Path] = set()
        ext_globs = [g for ext in self.ext_to_scanner.keys() for g in ("-g", f"*{ext}")]
        exclude_globs = [g for ex in self.config.source_scanner.excluded_directories for g in ("-g", f"!**/{ex}/**")]

        cmd = [
            "rg", "-l", "--no-messages", "--color", "never", "--mmap", "--max-filesize", "5M",
            "-e", self.dynamic_crypto_regex, *ext_globs, *exclude_globs, str(target_dir)
        ]

        exit_code, stdout, stderr = run_command(cmd)
        if exit_code in (0, 1):
            for line in stdout.splitlines():
                if line.strip():
                    candidates.add(Path(line.strip()).resolve())
            return candidates

        log_warning(f"ripgrep returned code {exit_code} ({stderr.strip()}), falling back to Python file walker.")
        return self._run_python_fallback_filter(target_dir)

    def _run_python_fallback_filter(self, target_dir: Path) -> Set[Path]:
        """High-throughput pure-Python fallback candidate search."""
        candidates: Set[Path] = set()
        compiled_regex = re.compile(self.dynamic_crypto_regex, re.IGNORECASE)
        excluded_dirs = set(self.config.source_scanner.excluded_directories)
        max_lines = self.config.source_scanner.max_header_lines_checked

        for path in target_dir.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self.ext_to_scanner:
                continue
            if any(part in excluded_dirs for part in path.parts):
                continue

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    header_content = "".join([f.readline() for _ in range(max_lines)])
                    if compiled_regex.search(header_content):
                        candidates.add(path.resolve())
            except Exception:
                continue

        return candidates